#![cfg(test)]
//! P0 #1 adversarial tests: the 2-of-3 committee threshold must be counted over
//! DISTINCT signer pubkeys. A single leaked/compromised key replayed twice must
//! never satisfy the threshold on its own.

use crate::*;
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::testutils::{Address as _, Ledger as _};

/// Minimal stand-in for NullifierRegistry — accepts every spend. mpc_settle only
/// needs `spend(caller, nullifier) -> bool` to succeed; the registry's own
/// double-spend/authorization logic is that contract's concern, not this test's.
#[contract]
struct MockNullifierRegistry;

#[contractimpl]
impl MockNullifierRegistry {
    pub fn spend(_env: Env, _caller: Address, _nullifier: BytesN<32>) -> bool {
        true
    }
}

/// Mock mpc_settlement verifier that ACCEPTS every proof. Used to exercise the
/// post-verification signal-binding path (B1/B2).
#[contract]
struct MockVerifierAccept;

#[contractimpl]
impl MockVerifierAccept {
    pub fn verify(_env: Env, _proof: Bytes, _signals: Bytes) -> bool {
        true
    }
}

/// Mock verifier that REJECTS every proof — an invalid proof must abort settle.
#[contract]
struct MockVerifierReject;

#[contractimpl]
impl MockVerifierReject {
    pub fn verify(_env: Env, _proof: Bytes, _signals: Bytes) -> bool {
        false
    }
}

/// Encode a u128 into the low 16 bytes of a 32-byte field element (matches the
/// contract's `fr32_to_i128`, which reads bytes[16..32] big-endian).
fn enc_u128(v: u128) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[16..32].copy_from_slice(&v.to_be_bytes());
    a
}

/// Replicate the contract's `hash_to_field`: shift the 32-byte hash right by one
/// byte (out[0] = 0, out[1..32] = h[0..31]).
fn hash_field(h: &[u8; 32]) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..31 {
        o[i + 1] = h[i];
    }
    o
}

/// Serialize mpc_settlement public signals as the contract's `parse_public_signals`
/// expects: a big-endian u32 word count followed by that many 32-byte words.
fn build_signals(env: &Env, words: &[[u8; 32]]) -> Bytes {
    let mut b = Bytes::new(env);
    b.extend_from_array(&(words.len() as u32).to_be_bytes());
    for w in words {
        b.extend_from_array(w);
    }
    b
}

/// Build a full, VALID mpc_settlement public-signal blob (11 words) for the
/// harness pool (poolId=1, chainId=27, empty state root [0;32]).
#[allow(clippy::too_many_arguments)]
fn valid_signals(
    env: &Env,
    nullifier_a: &BytesN<32>,
    nullifier_b: &BytesN<32>,
    out_a: &BytesN<32>,
    out_b: &BytesN<32>,
    assoc_root: &[u8; 32],
    batch_hash: &[u8; 32],
    deadline: u128,
) -> Bytes {
    let words: [[u8; 32]; 11] = [
        nullifier_a.to_array(),
        nullifier_b.to_array(),
        out_a.to_array(),
        out_b.to_array(),
        [0u8; 32],               // [4] stateRoot = empty root (known at init)
        *assoc_root,             // [5] associationRoot
        hash_field(batch_hash),  // [6] hashToField(batch_hash)
        enc_u128(1),             // [7] poolId
        enc_u128(27),            // [8] chainId
        [0u8; 32],               // [9] matchedAmount7dp (unbound here)
        enc_u128(deadline),      // [10] deadlineLedger
    ];
    build_signals(env, &words)
}

fn keypair(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk_bytes(env: &Env, sk: &SigningKey) -> BytesN<32> {
    BytesN::from_array(env, &sk.verifying_key().to_bytes())
}

fn sign_hash(env: &Env, sk: &SigningKey, batch_hash: &BytesN<32>) -> BytesN<64> {
    let sig = sk.sign(&batch_hash.to_array());
    BytesN::from_array(env, &sig.to_bytes())
}

struct Harness {
    env: Env,
    pool: ShieldedPoolClient<'static>,
}

fn setup() -> Harness {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let usdc = Address::generate(&env);
    let verifier = Address::generate(&env); // unused unless set_mpc_verifier is called

    let nullreg_id = env.register(MockNullifierRegistry, ());

    let pool_id = env.register(
        ShieldedPool,
        (admin.clone(), usdc.clone(), verifier.clone(), nullreg_id.clone(), 12u32, 1u32, 27u32),
    );
    let pool = ShieldedPoolClient::new(&env, &pool_id);

    Harness { env, pool }
}

#[test]
fn mpc_settle_rejects_duplicate_signer_replay() {
    let h = setup();
    let env = &h.env;

    let sk1 = keypair(1);
    let sk2 = keypair(2);
    let sk3 = keypair(3);
    let pk1 = pk_bytes(env, &sk1);
    let pk2 = pk_bytes(env, &sk2);
    let pk3 = pk_bytes(env, &sk3);
    h.pool.set_committee(&Vec::from_array(env, [pk1.clone(), pk2.clone(), pk3.clone()]));

    let batch_hash = BytesN::from_array(env, &[7u8; 32]);
    let sig1 = sign_hash(env, &sk1, &batch_hash);

    let nullifier_a = BytesN::from_array(env, &[1u8; 32]);
    let nullifier_b = BytesN::from_array(env, &[2u8; 32]);
    let out_a = BytesN::from_array(env, &[3u8; 32]);
    let out_b = BytesN::from_array(env, &[4u8; 32]);
    let new_root = BytesN::from_array(env, &[5u8; 32]);

    // Same key/signature submitted twice — must be rejected even though the
    // array length (2) meets ceil(2*3/3) = 2.
    let signer_pubkeys = Vec::from_array(env, [pk1.clone(), pk1.clone()]);
    let signatures = Vec::from_array(env, [sig1.clone(), sig1.clone()]);

    let result = h.pool.try_mpc_settle(
        &nullifier_a, &nullifier_b, &out_a, &out_b, &new_root, &batch_hash,
        &signer_pubkeys, &signatures, &None, &None,
    );
    assert!(result.is_err(), "duplicate signer must not satisfy the committee threshold");
}

// ---- Phase 4 inbound CCTP duplicate-nonce (spec §8.4) ----

#[test]
fn cctp_deposit_duplicate_nonce_no_second_note() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let verifier = env.register(MockVerifierAccept, ());
    let nullreg = env.register(MockNullifierRegistry, ());
    let pool_id = env.register(
        ShieldedPool,
        (admin.clone(), Address::generate(&env), verifier, nullreg, 12u32, 1u32, 27u32),
    );
    let pool = ShieldedPoolClient::new(&env, &pool_id);
    let dep_verifier = env.register(MockVerifierAccept, ());
    pool.set_deposit_verifier(&dep_verifier);

    // Register the deposited asset (asset_id = recipient_hash(token)).
    let sac = env.register_stellar_asset_contract_v2(admin.clone());
    let asset = sac.address();
    let asset_id = recip_hash(&env, &asset);
    pool.register_asset(&BytesN::from_array(&env, &asset_id), &asset);

    let nonce = BytesN::from_array(&env, &[0xA1u8; 32]);
    let enc = BytesN::from_array(&env, &[0xB2u8; 32]);
    let policy = BytesN::from_array(&env, &[0xC3u8; 32]);
    let commitment = BytesN::from_array(&env, &[0xD4u8; 32]);
    let new_root = BytesN::from_array(&env, &[0xE5u8; 32]);
    let (amount7, amount6): (u128, u128) = (1_000_000, 100_000); // 100_000*10 == 1_000_000

    // 14-word deposit signals bound to the args the contract checks.
    let words: [[u8; 32]; 14] = [
        commitment.to_array(),          // [0]
        enc_u128(4),                    // [1] op = DEPOSIT_NOTE_MINT
        enc_u128(3),                    // [2] sourceDomain
        enc_u128(27),                   // [3] destinationDomain = STELLAR_CCTP_DOMAIN
        hash_field(&nonce.to_array()),  // [4] cctpNonceHash
        enc_u128(1),                    // [5] burnTxHash (nonzero; auditability only)
        enc_u128(amount6),              // [6] amount6dp
        enc_u128(amount7),              // [7] amount7dp
        asset_id,                       // [8] assetIdHash = recipient_hash(asset)
        recip_hash(&env, &pool_id),     // [9] recipientPool = recipient_hash(pool)
        hash_field(&enc.to_array()),    // [10] encryptedNotePayloadHash
        hash_field(&policy.to_array()), // [11] policyIdHash
        enc_u128(1),                    // [12] poolId
        enc_u128(27),                   // [13] chainId
    ];
    let signals = build_signals(&env, &words);
    let proof = Bytes::from_array(&env, &[0u8; 8]);

    // First deposit succeeds and records the nonce.
    let leaf = pool.receive_cctp_deposit(&3u32, &nonce, &asset, &(amount7 as i128), &commitment, &new_root, &enc, &policy, &proof, &signals);
    assert_eq!(leaf, 0, "first deposit registers leaf 0");
    assert_eq!(pool.note_supply(&BytesN::from_array(&env, &asset_id)), amount7 as i128, "supply credited once");

    // Replaying the SAME CCTP nonce must be rejected (no second note).
    let r = pool.try_receive_cctp_deposit(&3u32, &nonce, &asset, &(amount7 as i128), &commitment, &new_root, &enc, &policy, &proof, &signals);
    assert!(r.is_err(), "a duplicate CCTP nonce must not mint a second note");
    assert_eq!(pool.note_supply(&BytesN::from_array(&env, &asset_id)), amount7 as i128, "supply unchanged after duplicate");
}

// ---- Phase 4 outbound CCTP (withdraw_cctp) binding (spec §8.6) ----

/// 18-word withdraw-circuit signals for a CCTP exit (op = WITHDRAW_CCTP) with the
/// destination bindings at [13..16].
fn cctp_signals(env: &Env, amount: u128, dest_domain: u128, dest_recip: [u8; 32], max_fee: u128, finality: u128) -> Bytes {
    let words: [[u8; 32]; 18] = [
        [1u8; 32],               // [0] nullifierHash
        enc_u128(2),             // [1] operationType = WITHDRAW_CCTP
        enc_u128(amount),        // [2] amount
        [0u8; 32],               // [3] recipientHash (unused here)
        [0u8; 32],               // [4] relayerFee
        enc_u128(999_999),       // [5] deadlineLedger
        [0u8; 32],               // [6] stateRoot (empty, known)
        [0u8; 32],               // [7] associationRoot (default 0)
        enc_u128(1),             // [8] poolId
        enc_u128(27),            // [9] chainId
        [0u8; 32], [0u8; 32], [0u8; 32], // [10-12] quote/intent/fill
        enc_u128(dest_domain),   // [13] destinationDomain
        dest_recip,              // [14] destinationRecipient
        enc_u128(max_fee),       // [15] maxFee
        enc_u128(finality),      // [16] minFinalityThreshold
        [0u8; 32],               // [17] assetId (unused by withdraw_cctp)
    ];
    build_signals(env, &words)
}

#[test]
fn withdraw_cctp_rejects_unsupported_domain() {
    let w = setup_withdraw();
    let env = &w.env;
    let recip = [0x55u8; 32];
    // proof + arg both use an unsupported domain (99) -> UnsupportedDomain.
    let signals = cctp_signals(env, 1_000_000, 99, recip, 0, 2000);
    let proof = Bytes::from_array(env, &[0u8; 8]);
    let r = w.pool.try_withdraw_cctp(&w.to, &proof, &signals, &99u32, &BytesN::from_array(env, &recip), &0i128, &2000u32);
    assert!(r.is_err(), "an unsupported destination domain must be rejected before burn");
}

#[test]
fn withdraw_cctp_rejects_relayer_recipient_mutation() {
    let w = setup_withdraw();
    let env = &w.env;
    let recip = [0x55u8; 32];
    let signals = cctp_signals(env, 1_000_000, 3, recip, 0, 2000);
    let proof = Bytes::from_array(env, &[0u8; 8]);
    // relayer swaps the destination recipient -> WrongDestRecipient.
    let r = w.pool.try_withdraw_cctp(&w.to, &proof, &signals, &3u32, &BytesN::from_array(env, &[0xEEu8; 32]), &0i128, &2000u32);
    assert!(r.is_err(), "a relayer-mutated destination recipient must be rejected");
}

#[test]
fn withdraw_cctp_rejects_relayer_fee_mutation() {
    let w = setup_withdraw();
    let env = &w.env;
    let recip = [0x55u8; 32];
    let signals = cctp_signals(env, 1_000_000, 3, recip, 500, 2000);
    let proof = Bytes::from_array(env, &[0u8; 8]);
    // relayer inflates max_fee -> WrongMaxFee.
    let r = w.pool.try_withdraw_cctp(&w.to, &proof, &signals, &3u32, &BytesN::from_array(env, &recip), &9_999i128, &2000u32);
    assert!(r.is_err(), "a relayer-mutated max_fee must be rejected");
}

#[test]
fn withdraw_cctp_rejects_wrong_finality() {
    let w = setup_withdraw();
    let env = &w.env;
    let recip = [0x55u8; 32];
    let signals = cctp_signals(env, 1_000_000, 3, recip, 0, 2000);
    let proof = Bytes::from_array(env, &[0u8; 8]);
    // relayer changes the finality threshold -> WrongFinality.
    let r = w.pool.try_withdraw_cctp(&w.to, &proof, &signals, &3u32, &BytesN::from_array(env, &recip), &0i128, &1000u32);
    assert!(r.is_err(), "a mutated min_finality_threshold must be rejected");
}

// ---- Phase 2 withdraw asset-binding (spec §6.4/§6.6/§6.8) ----

/// Replicate the contract's recipient_hash: sha256(strkey[56]) then hash_to_field
/// (leading zero byte + first 31 bytes).
fn recip_hash(env: &Env, to: &Address) -> [u8; 32] {
    let s = to.to_string();
    let mut buf = [0u8; 56];
    s.copy_into_slice(&mut buf);
    let sha: [u8; 32] = env.crypto().sha256(&Bytes::from_slice(env, &buf)).to_array();
    let mut out = [0u8; 32];
    for i in 0..31 {
        out[i + 1] = sha[i];
    }
    out
}

struct WithdrawHarness {
    env: Env,
    pool: ShieldedPoolClient<'static>,
    to: Address,
    token_admin: soroban_sdk::token::StellarAssetClient<'static>,
    asset_id: BytesN<32>,
}

fn setup_withdraw() -> WithdrawHarness {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let usdc = Address::generate(&env);
    let verifier = env.register(MockVerifierAccept, ()); // accepts the withdraw proof
    let nullreg = env.register(MockNullifierRegistry, ());
    let pool_id = env.register(
        ShieldedPool,
        (admin.clone(), usdc, verifier, nullreg, 12u32, 1u32, 27u32),
    );
    let pool = ShieldedPoolClient::new(&env, &pool_id);

    // Register an asset backed by a real SAC and fund the pool with it.
    let sac = env.register_stellar_asset_contract_v2(admin.clone());
    let token_addr = sac.address();
    let asset_id = BytesN::from_array(&env, &[0x44u8; 32]);
    pool.register_asset(&asset_id, &token_addr);
    let token_admin = soroban_sdk::token::StellarAssetClient::new(&env, &token_addr);
    token_admin.mint(&pool_id, &10_000_000i128);

    let to = Address::generate(&env);
    WithdrawHarness { env, pool, to, token_admin, asset_id }
}

/// Build a valid 18-word withdraw public-signal blob (assoc root = 0 default,
/// state root = empty root, poolId=1, chainId=27).
fn withdraw_signals(env: &Env, to: &Address, withdrawn: u128, asset_id_bytes: [u8; 32]) -> Bytes {
    let words: [[u8; 32]; 18] = [
        [1u8; 32],                 // [0] nullifierHash
        enc_u128(1),               // [1] operationType = OP_WITHDRAW_PUBLIC
        enc_u128(withdrawn),       // [2] withdrawnValue
        recip_hash(env, to),       // [3] recipientHash
        [0u8; 32],                 // [4] relayerFee
        enc_u128(999_999),         // [5] deadlineLedger
        [0u8; 32],                 // [6] stateRoot (empty root, known)
        [0u8; 32],                 // [7] associationRoot (default 0)
        enc_u128(1),               // [8] poolId
        enc_u128(27),              // [9] chainId
        [0u8; 32], [0u8; 32], [0u8; 32],           // [10-12] quote/intent/fill
        [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32],// [13-16] cctp dest fields
        asset_id_bytes,            // [17] assetId
    ];
    build_signals(env, &words)
}

#[test]
fn withdraw_selects_token_by_asset_and_debits_supply() {
    let w = setup_withdraw();
    let env = &w.env;
    let token = soroban_sdk::token::TokenClient::new(env, &w.token_admin.address);
    let signals = withdraw_signals(env, &w.to, 4_000_000, w.asset_id.to_array());
    let proof = Bytes::from_array(env, &[0u8; 8]);

    w.pool.withdraw(&w.to, &proof, &signals);

    assert_eq!(token.balance(&w.to), 4_000_000, "recipient receives the asset's token");
    assert_eq!(w.pool.note_supply(&w.asset_id), -4_000_000, "note supply debited by withdrawnValue");
}

#[test]
fn withdraw_unknown_asset_rejected() {
    let w = setup_withdraw();
    let env = &w.env;
    // signal[17] points at an asset that was never registered -> fail closed.
    let signals = withdraw_signals(env, &w.to, 1_000_000, [0x99u8; 32]);
    let proof = Bytes::from_array(env, &[0u8; 8]);
    let result = w.pool.try_withdraw(&w.to, &proof, &signals);
    assert!(result.is_err(), "withdraw for an unregistered asset must fail closed");
}

// ---- Phase 3 atomic USDC->XLM RFQ swap (spec §7) ----

struct SwapHarness {
    env: Env,
    pool: ShieldedPoolClient<'static>,
    user: Address,
    solver_usdc_to: Address,
    usdc: soroban_sdk::token::TokenClient<'static>,
    xlm: soroban_sdk::token::TokenClient<'static>,
    usdc_asset: [u8; 32],
    xlm_asset: [u8; 32],
    solver_sk: SigningKey,
    solver_pk: BytesN<32>,
}

fn setup_swap() -> SwapHarness {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let verifier = env.register(MockVerifierAccept, ());
    let nullreg = env.register(MockNullifierRegistry, ());
    let pool_id = env.register(
        ShieldedPool,
        (admin.clone(), Address::generate(&env), verifier, nullreg, 12u32, 1u32, 27u32),
    );
    let pool = ShieldedPoolClient::new(&env, &pool_id);

    // Two assets: USDC (input) and XLM (output), both funded into the pool.
    let usdc_sac = env.register_stellar_asset_contract_v2(admin.clone());
    let xlm_sac = env.register_stellar_asset_contract_v2(admin.clone());
    let usdc_asset = [0x01u8; 32];
    let xlm_asset = [0x02u8; 32];
    pool.register_asset(&BytesN::from_array(&env, &usdc_asset), &usdc_sac.address());
    pool.register_asset(&BytesN::from_array(&env, &xlm_asset), &xlm_sac.address());
    soroban_sdk::token::StellarAssetClient::new(&env, &usdc_sac.address()).mint(&pool_id, &10_000_000i128);
    soroban_sdk::token::StellarAssetClient::new(&env, &xlm_sac.address()).mint(&pool_id, &50_000_000i128);

    // Authorized solver.
    let solver_sk = keypair(9);
    let solver_pk = pk_bytes(&env, &solver_sk);
    pool.set_authorized_solver(&solver_pk, &true);

    SwapHarness {
        user: Address::generate(&env),
        solver_usdc_to: Address::generate(&env),
        usdc: soroban_sdk::token::TokenClient::new(&env, &usdc_sac.address()),
        xlm: soroban_sdk::token::TokenClient::new(&env, &xlm_sac.address()),
        usdc_asset, xlm_asset, solver_sk, solver_pk, pool, env,
    }
}

/// Withdraw-circuit public signals for an atomic RFQ swap (op = RFQ_ATOMIC_SWAP,
/// input asset = USDC, quote/intent/fill bound).
fn swap_signals(env: &Env, withdrawn: u128, usdc_asset: [u8; 32], quote_h: &[u8; 32], intent_h: &[u8; 32], fill_h: &[u8; 32]) -> Bytes {
    let words: [[u8; 32]; 18] = [
        [1u8; 32],               // [0] nullifierHash
        enc_u128(5),             // [1] operationType = RFQ_ATOMIC_SWAP
        enc_u128(withdrawn),     // [2] withdrawnValue (solver credit base)
        [0u8; 32],               // [3] recipientHash (unused by swap; bound via solver sig)
        [0u8; 32],               // [4] relayerFee
        enc_u128(999_999),       // [5] deadlineLedger
        [0u8; 32],               // [6] stateRoot (empty, known)
        [0u8; 32],               // [7] associationRoot (default 0)
        enc_u128(1),             // [8] poolId
        enc_u128(27),            // [9] chainId
        hash_field(quote_h),     // [10] quoteHash (field)
        hash_field(intent_h),    // [11] intentHash
        hash_field(fill_h),      // [12] fillReceiptHash
        [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], // [13-16] cctp dest fields
        usdc_asset,              // [17] assetId (input = USDC)
    ];
    build_signals(env, &words)
}

/// Compute the solver swap_hash exactly as the contract does and sign it.
fn sign_swap(env: &Env, sk: &SigningKey, quote_h: &[u8; 32], out_asset: &[u8; 32], quoted: i128, min: i128, price: i128, user: &Address) -> BytesN<64> {
    let recip = recip_hash(env, user);
    let mut terms = Bytes::new(env);
    terms.extend_from_array(quote_h);
    terms.extend_from_array(out_asset);
    terms.extend_from_array(&quoted.to_be_bytes());
    terms.extend_from_array(&min.to_be_bytes());
    terms.extend_from_array(&price.to_be_bytes());
    terms.extend_from_array(&recip);
    let swap_hash: [u8; 32] = env.crypto().sha256(&terms).to_array();
    let sig = sk.sign(&swap_hash);
    BytesN::from_array(env, &sig.to_bytes())
}

const PRICE_SCALE_TEST: i128 = 1_000_000_000;

#[test]
fn rfq_atomic_swap_delivers_xlm_and_credits_solver() {
    let h = setup_swap();
    let env = &h.env;
    let (quote_h, intent_h, fill_h) = ([0x10u8; 32], [0x11u8; 32], [0x12u8; 32]);
    let signals = swap_signals(env, 4_000_000, h.usdc_asset, &quote_h, &intent_h, &fill_h);
    let proof = Bytes::from_array(env, &[0u8; 8]);
    let (quoted, min, price) = (2_000_000i128, 1_900_000i128, 500_000_000i128); // 4M * 0.5 = 2M
    let sig = sign_swap(env, &h.solver_sk, &quote_h, &h.xlm_asset, quoted, min, price, &h.user);

    h.pool.rfq_settle_atomic_swap(
        &h.user, &h.solver_usdc_to, &proof, &signals,
        &BytesN::from_array(env, &quote_h), &BytesN::from_array(env, &intent_h), &BytesN::from_array(env, &fill_h),
        &BytesN::from_array(env, &h.xlm_asset), &quoted, &min, &price, &h.solver_pk, &sig,
    );

    assert_eq!(h.xlm.balance(&h.user), quoted, "user receives XLM >= min_output");
    assert_eq!(h.usdc.balance(&h.solver_usdc_to), 4_000_000, "solver credited USDC");
    assert_eq!(h.pool.note_supply(&BytesN::from_array(env, &h.usdc_asset)), -4_000_000, "USDC note left the shielded set");
}

#[test]
fn rfq_atomic_swap_rejects_relayer_amount_mutation() {
    let h = setup_swap();
    let env = &h.env;
    let (quote_h, intent_h, fill_h) = ([0x10u8; 32], [0x11u8; 32], [0x12u8; 32]);
    let signals = swap_signals(env, 4_000_000, h.usdc_asset, &quote_h, &intent_h, &fill_h);
    let proof = Bytes::from_array(env, &[0u8; 8]);
    // Solver signs quoted=2_000_000; relayer submits a LARGER quoted output (3M).
    let sig = sign_swap(env, &h.solver_sk, &quote_h, &h.xlm_asset, 2_000_000, 1_900_000, 500_000_000, &h.user);
    let result = h.pool.try_rfq_settle_atomic_swap(
        &h.user, &h.solver_usdc_to, &proof, &signals,
        &BytesN::from_array(env, &quote_h), &BytesN::from_array(env, &intent_h), &BytesN::from_array(env, &fill_h),
        &BytesN::from_array(env, &h.xlm_asset), &3_000_000i128, &1_900_000i128, &500_000_000i128, &h.solver_pk, &sig,
    );
    assert!(result.is_err(), "a relayer-inflated output amount must break the solver signature");
}

#[test]
fn rfq_atomic_swap_rejects_under_delivery() {
    let h = setup_swap();
    let env = &h.env;
    let (quote_h, intent_h, fill_h) = ([0x10u8; 32], [0x11u8; 32], [0x12u8; 32]);
    let signals = swap_signals(env, 4_000_000, h.usdc_asset, &quote_h, &intent_h, &fill_h);
    let proof = Bytes::from_array(env, &[0u8; 8]);
    // quoted < min -> UnderDelivered.
    let sig = sign_swap(env, &h.solver_sk, &quote_h, &h.xlm_asset, 1_000_000, 2_000_000, 500_000_000, &h.user);
    let result = h.pool.try_rfq_settle_atomic_swap(
        &h.user, &h.solver_usdc_to, &proof, &signals,
        &BytesN::from_array(env, &quote_h), &BytesN::from_array(env, &intent_h), &BytesN::from_array(env, &fill_h),
        &BytesN::from_array(env, &h.xlm_asset), &1_000_000i128, &2_000_000i128, &500_000_000i128, &h.solver_pk, &sig,
    );
    assert!(result.is_err(), "quoted output below min_output must be rejected");
}

#[test]
fn rfq_atomic_swap_rejects_same_asset() {
    let h = setup_swap();
    let env = &h.env;
    let (quote_h, intent_h, fill_h) = ([0x10u8; 32], [0x11u8; 32], [0x12u8; 32]);
    let signals = swap_signals(env, 4_000_000, h.usdc_asset, &quote_h, &intent_h, &fill_h);
    let proof = Bytes::from_array(env, &[0u8; 8]);
    // output asset == input (USDC) -> SameAssetSwap.
    let sig = sign_swap(env, &h.solver_sk, &quote_h, &h.usdc_asset, 2_000_000, 1_900_000, 500_000_000, &h.user);
    let result = h.pool.try_rfq_settle_atomic_swap(
        &h.user, &h.solver_usdc_to, &proof, &signals,
        &BytesN::from_array(env, &quote_h), &BytesN::from_array(env, &intent_h), &BytesN::from_array(env, &fill_h),
        &BytesN::from_array(env, &h.usdc_asset), &2_000_000i128, &1_900_000i128, &500_000_000i128, &h.solver_pk, &sig,
    );
    assert!(result.is_err(), "an output asset equal to the input asset must be rejected");
}

#[test]
fn rfq_atomic_swap_rejects_wrong_price() {
    let h = setup_swap();
    let env = &h.env;
    let (quote_h, intent_h, fill_h) = ([0x10u8; 32], [0x11u8; 32], [0x12u8; 32]);
    let signals = swap_signals(env, 4_000_000, h.usdc_asset, &quote_h, &intent_h, &fill_h);
    let proof = Bytes::from_array(env, &[0u8; 8]);
    // priceScaled=500M with input 4M implies quoted=2M; the solver signs a quoted
    // of 2.5M (>= min) that does NOT satisfy the fixed-point rule -> WrongPrice.
    let (quoted, min, price) = (2_500_000i128, 1_900_000i128, PRICE_SCALE_TEST / 2);
    let sig = sign_swap(env, &h.solver_sk, &quote_h, &h.xlm_asset, quoted, min, price, &h.user);
    let result = h.pool.try_rfq_settle_atomic_swap(
        &h.user, &h.solver_usdc_to, &proof, &signals,
        &BytesN::from_array(env, &quote_h), &BytesN::from_array(env, &intent_h), &BytesN::from_array(env, &fill_h),
        &BytesN::from_array(env, &h.xlm_asset), &quoted, &min, &price, &h.solver_pk, &sig,
    );
    assert!(result.is_err(), "quoted output not matching floor(input*price/SCALE) must be rejected");
}

#[test]
fn rfq_atomic_swap_rejects_unauthorized_solver() {
    let h = setup_swap();
    let env = &h.env;
    let (quote_h, intent_h, fill_h) = ([0x10u8; 32], [0x11u8; 32], [0x12u8; 32]);
    let signals = swap_signals(env, 4_000_000, h.usdc_asset, &quote_h, &intent_h, &fill_h);
    let proof = Bytes::from_array(env, &[0u8; 8]);
    let rogue = keypair(77);
    let rogue_pk = pk_bytes(env, &rogue);
    let sig = sign_swap(env, &rogue, &quote_h, &h.xlm_asset, 2_000_000, 1_900_000, 500_000_000, &h.user);
    let result = h.pool.try_rfq_settle_atomic_swap(
        &h.user, &h.solver_usdc_to, &proof, &signals,
        &BytesN::from_array(env, &quote_h), &BytesN::from_array(env, &intent_h), &BytesN::from_array(env, &fill_h),
        &BytesN::from_array(env, &h.xlm_asset), &2_000_000i128, &1_900_000i128, &500_000_000i128, &rogue_pk, &sig,
    );
    assert!(result.is_err(), "a quote signed by an unauthorized solver must be rejected");
}

// ---- Phase 2 asset registry (spec §6.5/§6.8) ----

#[test]
fn register_asset_and_lookup_token() {
    let h = setup();
    let env = &h.env;
    let sac = env.register_stellar_asset_contract_v2(Address::generate(env));
    let token = sac.address();
    let asset_id = BytesN::from_array(env, &[0x11u8; 32]);

    h.pool.register_asset(&asset_id, &token);
    assert_eq!(h.pool.get_asset_token(&asset_id), token, "registered asset resolves to its token");
    assert_eq!(h.pool.note_supply(&asset_id), 0, "fresh asset starts at zero note supply");
    // proof_of_reserves = (supply, vault balance); both 0 for a fresh SAC.
    assert_eq!(h.pool.proof_of_reserves(&asset_id), (0, 0));
}

#[test]
fn unknown_asset_lookup_rejected() {
    let h = setup();
    let env = &h.env;
    let asset_id = BytesN::from_array(env, &[0x22u8; 32]);
    // No default to USDC — an unregistered asset must fail closed.
    assert!(h.pool.try_get_asset_token(&asset_id).is_err(), "unknown asset must not resolve to any token");
    assert!(h.pool.try_vault_balance(&asset_id).is_err(), "unknown asset has no vault balance");
}

#[test]
fn register_asset_twice_rejected() {
    let h = setup();
    let env = &h.env;
    let sac = env.register_stellar_asset_contract_v2(Address::generate(env));
    let asset_id = BytesN::from_array(env, &[0x33u8; 32]);
    h.pool.register_asset(&asset_id, &sac.address());
    let sac2 = env.register_stellar_asset_contract_v2(Address::generate(env));
    assert!(h.pool.try_register_asset(&asset_id, &sac2.address()).is_err(), "re-registering an asset_id must be rejected");
}

/// B1 (spec §5.1): once a committee exists, an mpc_verifier is MANDATORY. Valid,
/// threshold-met committee signatures alone must NOT settle when no verifier is
/// configured — the previous fail-open path (settle on sigs-only) is forbidden.
#[test]
fn mpc_settle_rejects_when_verifier_unset() {
    let h = setup();
    let env = &h.env;

    let sk1 = keypair(1);
    let sk2 = keypair(2);
    let sk3 = keypair(3);
    let pk1 = pk_bytes(env, &sk1);
    let pk2 = pk_bytes(env, &sk2);
    let pk3 = pk_bytes(env, &sk3);
    h.pool.set_committee(&Vec::from_array(env, [pk1.clone(), pk2.clone(), pk3.clone()]));
    // Deliberately do NOT call set_mpc_verifier.

    let batch_hash = BytesN::from_array(env, &[7u8; 32]);
    let sig1 = sign_hash(env, &sk1, &batch_hash);
    let sig2 = sign_hash(env, &sk2, &batch_hash);

    let nullifier_a = BytesN::from_array(env, &[1u8; 32]);
    let nullifier_b = BytesN::from_array(env, &[2u8; 32]);
    let out_a = BytesN::from_array(env, &[3u8; 32]);
    let out_b = BytesN::from_array(env, &[4u8; 32]);
    let new_root = BytesN::from_array(env, &[5u8; 32]);

    let signer_pubkeys = Vec::from_array(env, [pk1.clone(), pk2.clone()]);
    let signatures = Vec::from_array(env, [sig1.clone(), sig2.clone()]);

    let result = h.pool.try_mpc_settle(
        &nullifier_a, &nullifier_b, &out_a, &out_b, &new_root, &batch_hash,
        &signer_pubkeys, &signatures, &None, &None,
    );
    assert!(result.is_err(), "committee sigs alone must not settle when no mpc_verifier is configured (fail closed)");
}

/// Full B1/B2 harness: committee + accepting verifier + canonical association
/// root set, so a well-formed proof passes and adversarial variants fail.
struct ProofHarness {
    h: Harness,
    signer_pubkeys: Vec<BytesN<32>>,
    signatures: Vec<BytesN<64>>,
    batch_hash: BytesN<32>,
    batch_arr: [u8; 32],
    nullifier_a: BytesN<32>,
    nullifier_b: BytesN<32>,
    out_a: BytesN<32>,
    out_b: BytesN<32>,
    new_root: BytesN<32>,
    assoc: [u8; 32],
    proof: Bytes,
}

fn setup_proof(accept: bool) -> ProofHarness {
    let h = setup();
    let env = &h.env;

    let sk1 = keypair(1);
    let sk2 = keypair(2);
    let sk3 = keypair(3);
    let pk1 = pk_bytes(env, &sk1);
    let pk2 = pk_bytes(env, &sk2);
    let pk3 = pk_bytes(env, &sk3);
    h.pool.set_committee(&Vec::from_array(env, [pk1.clone(), pk2.clone(), pk3.clone()]));

    let verifier_id = if accept {
        env.register(MockVerifierAccept, ())
    } else {
        env.register(MockVerifierReject, ())
    };
    h.pool.set_mpc_verifier(&verifier_id);

    // Canonical ASP root the proof must bind to.
    let assoc = [9u8; 32];
    h.pool.set_association_root(&BytesN::from_array(env, &assoc));

    let batch_arr = [7u8; 32];
    let batch_hash = BytesN::from_array(env, &batch_arr);
    let sig1 = sign_hash(env, &sk1, &batch_hash);
    let sig2 = sign_hash(env, &sk2, &batch_hash);
    let signer_pubkeys = Vec::from_array(env, [pk1.clone(), pk2.clone()]);
    let signatures = Vec::from_array(env, [sig1, sig2]);

    ProofHarness {
        signer_pubkeys,
        signatures,
        batch_hash,
        batch_arr,
        nullifier_a: BytesN::from_array(env, &[1u8; 32]),
        nullifier_b: BytesN::from_array(env, &[2u8; 32]),
        out_a: BytesN::from_array(env, &[3u8; 32]),
        out_b: BytesN::from_array(env, &[4u8; 32]),
        new_root: BytesN::from_array(env, &[5u8; 32]),
        assoc,
        proof: Bytes::from_array(env, &[0xabu8; 8]),
        h,
    }
}

/// B1: accepting verifier + well-formed proof + all bound signals correct -> ok.
#[test]
fn mpc_settle_accepts_valid_proof() {
    let p = setup_proof(true);
    let env = &p.h.env;
    let signals = valid_signals(env, &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.assoc, &p.batch_arr, 999_999);
    let result = p.h.pool.try_mpc_settle(
        &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.new_root, &p.batch_hash,
        &p.signer_pubkeys, &p.signatures, &Some(p.proof.clone()), &Some(signals),
    );
    assert!(result.is_ok(), "valid proof + correct signals must settle: {:?}", result);
}

/// §9.6: fewer than threshold signatures (1 of 2/3) must be rejected.
#[test]
fn mpc_settle_rejects_threshold_minus_one() {
    let p = setup_proof(true);
    let env = &p.h.env;
    let signals = valid_signals(env, &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.assoc, &p.batch_arr, 999_999);
    let one_pk = Vec::from_array(env, [p.signer_pubkeys.get(0).unwrap()]);
    let one_sig = Vec::from_array(env, [p.signatures.get(0).unwrap()]);
    let result = p.h.pool.try_mpc_settle(
        &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.new_root, &p.batch_hash,
        &one_pk, &one_sig, &Some(p.proof.clone()), &Some(signals),
    );
    assert!(result.is_err(), "below-threshold committee signatures must be rejected");
}

/// §9.6: a signer pubkey not in the registered committee must be rejected.
#[test]
fn mpc_settle_rejects_unknown_signer() {
    let p = setup_proof(true);
    let env = &p.h.env;
    let signals = valid_signals(env, &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.assoc, &p.batch_arr, 999_999);
    let rogue = keypair(50); // not in committee {1,2,3}
    let rogue_pk = pk_bytes(env, &rogue);
    let rogue_sig = sign_hash(env, &rogue, &p.batch_hash);
    let pks = Vec::from_array(env, [p.signer_pubkeys.get(0).unwrap(), rogue_pk]);
    let sigs = Vec::from_array(env, [p.signatures.get(0).unwrap(), rogue_sig]);
    let result = p.h.pool.try_mpc_settle(
        &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.new_root, &p.batch_hash,
        &pks, &sigs, &Some(p.proof.clone()), &Some(signals),
    );
    assert!(result.is_err(), "an unregistered committee signer must be rejected");
}

/// §9.6: the proof's batchHash signal must match the batch_hash argument.
#[test]
fn mpc_settle_rejects_wrong_batch_hash() {
    let p = setup_proof(true);
    let env = &p.h.env;
    // Signals bind a DIFFERENT batch ([8;32]); committee sigs + arg are over [7;32].
    let other_batch = [8u8; 32];
    let signals = valid_signals(env, &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.assoc, &other_batch, 999_999);
    let result = p.h.pool.try_mpc_settle(
        &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.new_root, &p.batch_hash,
        &p.signer_pubkeys, &p.signatures, &Some(p.proof.clone()), &Some(signals),
    );
    assert!(result.is_err(), "a proof bound to a different batch hash must be rejected");
}

/// §9.6: committee signatures over a different batch must not settle this batch.
#[test]
fn mpc_settle_rejects_signature_for_different_batch() {
    let p = setup_proof(true);
    let env = &p.h.env;
    // Sigs (from setup) are over [7;32]; submit batch_hash [8;32] with matching signals.
    let other_batch = [8u8; 32];
    let other_hash = BytesN::from_array(env, &other_batch);
    let signals = valid_signals(env, &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.assoc, &other_batch, 999_999);
    let result = p.h.pool.try_mpc_settle(
        &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.new_root, &other_hash,
        &p.signer_pubkeys, &p.signatures, &Some(p.proof.clone()), &Some(signals),
    );
    assert!(result.is_err(), "committee signatures over a different batch must be rejected");
}

/// B1: a proof the verifier rejects must abort settlement.
#[test]
fn mpc_settle_rejects_invalid_proof() {
    let p = setup_proof(false);
    let env = &p.h.env;
    let signals = valid_signals(env, &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.assoc, &p.batch_arr, 999_999);
    let result = p.h.pool.try_mpc_settle(
        &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.new_root, &p.batch_hash,
        &p.signer_pubkeys, &p.signatures, &Some(p.proof.clone()), &Some(signals),
    );
    assert!(result.is_err(), "a verifier-rejected proof must not settle");
}

/// B2: signals[5] (associationRoot) != canonical ASP root -> reject. The prover
/// must not choose its own compliance root.
#[test]
fn mpc_settle_rejects_wrong_association_root() {
    let p = setup_proof(true);
    let env = &p.h.env;
    let wrong_assoc = [0xEEu8; 32]; // != canonical [9;32]
    let signals = valid_signals(env, &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &wrong_assoc, &p.batch_arr, 999_999);
    let result = p.h.pool.try_mpc_settle(
        &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.new_root, &p.batch_hash,
        &p.signer_pubkeys, &p.signatures, &Some(p.proof.clone()), &Some(signals),
    );
    assert!(result.is_err(), "proof binding a non-canonical association root must be rejected");
}

/// B2: signals[10] (deadlineLedger) in the past -> reject. Stale matches must
/// not execute.
#[test]
fn mpc_settle_rejects_expired_deadline() {
    let p = setup_proof(true);
    let env = &p.h.env;
    // Advance the ledger past the deadline encoded in the signals.
    env.ledger().with_mut(|li| li.sequence_number = 1000);
    let signals = valid_signals(env, &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.assoc, &p.batch_arr, 10);
    let result = p.h.pool.try_mpc_settle(
        &p.nullifier_a, &p.nullifier_b, &p.out_a, &p.out_b, &p.new_root, &p.batch_hash,
        &p.signer_pubkeys, &p.signatures, &Some(p.proof.clone()), &Some(signals),
    );
    assert!(result.is_err(), "an expired deadlineLedger must be rejected");
}

/// P0 #2/#3 / P3 #23: once an mpc_verifier is configured, a proof is
/// MANDATORY — committee signatures alone must never be enough. This is the
/// exact gap the plan flagged before the verifier was wired in; guard against
/// it regressing (e.g. someone "fixing" a proof-plumbing bug by silently
/// falling back to sig-only settlement).
#[test]
fn mpc_settle_rejects_missing_proof_when_verifier_configured() {
    let h = setup();
    let env = &h.env;

    let sk1 = keypair(1);
    let sk2 = keypair(2);
    let sk3 = keypair(3);
    let pk1 = pk_bytes(env, &sk1);
    let pk2 = pk_bytes(env, &sk2);
    let pk3 = pk_bytes(env, &sk3);
    h.pool.set_committee(&Vec::from_array(env, [pk1.clone(), pk2.clone(), pk3.clone()]));

    // Any address works here — set_mpc_verifier just needs to be Some(_); the
    // missing-proof panic fires before the verifier contract is ever invoked.
    let dummy_verifier = Address::generate(env);
    h.pool.set_mpc_verifier(&dummy_verifier);

    let batch_hash = BytesN::from_array(env, &[7u8; 32]);
    let sig1 = sign_hash(env, &sk1, &batch_hash);
    let sig2 = sign_hash(env, &sk2, &batch_hash);

    let nullifier_a = BytesN::from_array(env, &[1u8; 32]);
    let nullifier_b = BytesN::from_array(env, &[2u8; 32]);
    let out_a = BytesN::from_array(env, &[3u8; 32]);
    let out_b = BytesN::from_array(env, &[4u8; 32]);
    let new_root = BytesN::from_array(env, &[5u8; 32]);

    let signer_pubkeys = Vec::from_array(env, [pk1.clone(), pk2.clone()]);
    let signatures = Vec::from_array(env, [sig1.clone(), sig2.clone()]);

    // Valid, threshold-met committee signatures but NO proof — must still be rejected.
    let result = h.pool.try_mpc_settle(
        &nullifier_a, &nullifier_b, &out_a, &out_b, &new_root, &batch_hash,
        &signer_pubkeys, &signatures, &None, &None,
    );
    assert!(result.is_err(), "valid committee sigs alone must not settle once a ZK verifier is configured — a proof is mandatory");
}

// ---- Phase 6 priced cross-asset MPC settlement (spec §10) ----

struct PricedHarness {
    h: Harness,
    signer_pubkeys: Vec<BytesN<32>>,
    signatures: Vec<BytesN<64>>,
    batch_hash: BytesN<32>,
    batch_arr: [u8; 32],
    assoc: [u8; 32],
    proof: Bytes,
    asset_x: [u8; 32],
    asset_y: [u8; 32],
    na: BytesN<32>, nb: BytesN<32>, oa: BytesN<32>, ob: BytesN<32>, new_root: BytesN<32>,
}

fn setup_priced(accept: bool) -> PricedHarness {
    let h = setup();
    let env = &h.env;
    let sk1 = keypair(1); let sk2 = keypair(2); let sk3 = keypair(3);
    let pk1 = pk_bytes(env, &sk1); let pk2 = pk_bytes(env, &sk2); let pk3 = pk_bytes(env, &sk3);
    h.pool.set_committee(&Vec::from_array(env, [pk1.clone(), pk2.clone(), pk3.clone()]));

    let pv = if accept { env.register(MockVerifierAccept, ()) } else { env.register(MockVerifierReject, ()) };
    h.pool.set_mpc_priced_verifier(&pv);

    let assoc = [9u8; 32];
    h.pool.set_association_root(&BytesN::from_array(env, &assoc));

    // Register both assets (cross-asset requires each registered).
    let sacx = env.register_stellar_asset_contract_v2(Address::generate(env));
    let sacy = env.register_stellar_asset_contract_v2(Address::generate(env));
    let asset_x = [0x01u8; 32];
    let asset_y = [0x02u8; 32];
    h.pool.register_asset(&BytesN::from_array(env, &asset_x), &sacx.address());
    h.pool.register_asset(&BytesN::from_array(env, &asset_y), &sacy.address());

    let batch_arr = [7u8; 32];
    let batch_hash = BytesN::from_array(env, &batch_arr);
    let sig1 = sign_hash(env, &sk1, &batch_hash);
    let sig2 = sign_hash(env, &sk2, &batch_hash);
    PricedHarness {
        signer_pubkeys: Vec::from_array(env, [pk1, pk2]),
        signatures: Vec::from_array(env, [sig1, sig2]),
        batch_hash, batch_arr, assoc, asset_x, asset_y,
        proof: Bytes::from_array(env, &[0xabu8; 8]),
        na: BytesN::from_array(env, &[0x11u8; 32]),
        nb: BytesN::from_array(env, &[0x12u8; 32]),
        oa: BytesN::from_array(env, &[0x13u8; 32]),
        ob: BytesN::from_array(env, &[0x14u8; 32]),
        new_root: BytesN::from_array(env, &[0x15u8; 32]),
        h,
    }
}

#[allow(clippy::too_many_arguments)]
fn priced_signals(p: &PricedHarness, asset_x: [u8; 32], asset_y: [u8; 32], batch: &[u8; 32], deadline: u128) -> Bytes {
    let env = &p.h.env;
    // A gives X gets Y; B gives Y gets X. matched_a=X spent, matched_b=Y spent.
    let words: [[u8; 32]; 20] = [
        p.na.to_array(),          // [0] nullifierHashA
        p.nb.to_array(),          // [1] nullifierHashB
        p.oa.to_array(),          // [2] outputCommitmentA
        p.ob.to_array(),          // [3] outputCommitmentB
        [0u8; 32],                // [4] stateRoot (empty, known)
        p.assoc,                  // [5] associationRoot
        hash_field(batch),        // [6] batchHash
        enc_u128(1),              // [7] poolId
        enc_u128(27),             // [8] chainId
        enc_u128(deadline),       // [9] deadlineLedger
        asset_x,                  // [10] inputAssetA (X)
        asset_y,                  // [11] outputAssetA (Y)
        asset_y,                  // [12] inputAssetB (Y)
        asset_x,                  // [13] outputAssetB (X)
        enc_u128(4_000_000),      // [14] matchedAmountA (X)
        enc_u128(2_000_000),      // [15] matchedAmountB (Y)
        enc_u128(500_000_000),    // [16] priceScaled
        enc_u128(1_000_000_000),  // [17] priceScale
        enc_u128(1_900_000),      // [18] minOutputA
        enc_u128(3_900_000),      // [19] minOutputB
    ];
    build_signals(env, &words)
}

#[test]
fn mpc_settle_priced_accepts_valid_cross_asset() {
    let p = setup_priced(true);
    let env = &p.h.env;
    let signals = priced_signals(&p, p.asset_x, p.asset_y, &p.batch_arr, 999_999);
    let r = p.h.pool.try_mpc_settle_priced(
        &p.na, &p.nb, &p.oa, &p.ob, &p.new_root, &p.batch_hash,
        &p.signer_pubkeys, &p.signatures, &Some(p.proof.clone()), &Some(signals),
    );
    assert!(r.is_ok(), "valid priced cross-asset settlement must succeed: {:?}", r);
}

#[test]
fn mpc_settle_priced_rejects_same_asset() {
    let p = setup_priced(true);
    let env = &p.h.env;
    // inputAssetA == inputAssetB (X == X) -> NotCrossAsset.
    let signals = priced_signals(&p, p.asset_x, p.asset_x, &p.batch_arr, 999_999);
    let r = p.h.pool.try_mpc_settle_priced(
        &p.na, &p.nb, &p.oa, &p.ob, &p.new_root, &p.batch_hash,
        &p.signer_pubkeys, &p.signatures, &Some(p.proof.clone()), &Some(signals),
    );
    assert!(r.is_err(), "a same-asset 'priced' settlement must be rejected (use mpc_settle)");
}

#[test]
fn mpc_settle_priced_rejects_unregistered_asset() {
    let p = setup_priced(true);
    let env = &p.h.env;
    // asset_y not registered -> get_asset_token fails closed.
    let unreg = [0xEEu8; 32];
    let signals = priced_signals(&p, p.asset_x, unreg, &p.batch_arr, 999_999);
    let r = p.h.pool.try_mpc_settle_priced(
        &p.na, &p.nb, &p.oa, &p.ob, &p.new_root, &p.batch_hash,
        &p.signer_pubkeys, &p.signatures, &Some(p.proof.clone()), &Some(signals),
    );
    assert!(r.is_err(), "priced settlement with an unregistered asset must fail closed");
}

#[test]
fn mpc_settle_priced_rejects_missing_proof() {
    let p = setup_priced(true);
    let r = p.h.pool.try_mpc_settle_priced(
        &p.na, &p.nb, &p.oa, &p.ob, &p.new_root, &p.batch_hash,
        &p.signer_pubkeys, &p.signatures, &None, &None,
    );
    assert!(r.is_err(), "priced settlement without a proof must be rejected (fail closed)");
}

#[test]
fn mpc_settle_priced_rejects_invalid_proof() {
    let p = setup_priced(false); // rejecting verifier
    let env = &p.h.env;
    let signals = priced_signals(&p, p.asset_x, p.asset_y, &p.batch_arr, 999_999);
    let r = p.h.pool.try_mpc_settle_priced(
        &p.na, &p.nb, &p.oa, &p.ob, &p.new_root, &p.batch_hash,
        &p.signer_pubkeys, &p.signatures, &Some(p.proof.clone()), &Some(signals),
    );
    assert!(r.is_err(), "a verifier-rejected priced proof must not settle");
}

#[test]
fn mpc_settle_priced_rejects_wrong_association_root() {
    let p = setup_priced(true);
    let env = &p.h.env;
    let mut signals_words = priced_signals(&p, p.asset_x, p.asset_y, &p.batch_arr, 999_999);
    let _ = &mut signals_words;
    // Rebuild with a wrong association root at [5].
    let words_bad = {
        let env = &p.h.env;
        let w: [[u8; 32]; 20] = [
            p.na.to_array(), p.nb.to_array(), p.oa.to_array(), p.ob.to_array(),
            [0u8; 32], [0xAAu8; 32] /* wrong assoc */, hash_field(&p.batch_arr),
            enc_u128(1), enc_u128(27), enc_u128(999_999),
            p.asset_x, p.asset_y, p.asset_y, p.asset_x,
            enc_u128(4_000_000), enc_u128(2_000_000), enc_u128(500_000_000), enc_u128(1_000_000_000),
            enc_u128(1_900_000), enc_u128(3_900_000),
        ];
        build_signals(env, &w)
    };
    let r = p.h.pool.try_mpc_settle_priced(
        &p.na, &p.nb, &p.oa, &p.ob, &p.new_root, &p.batch_hash,
        &p.signer_pubkeys, &p.signatures, &Some(p.proof.clone()), &Some(words_bad),
    );
    assert!(r.is_err(), "priced settlement binding a non-canonical association root must be rejected");
}

#[test]
fn mpc_settle_priced_rejects_expired_deadline() {
    let p = setup_priced(true);
    let env = &p.h.env;
    env.ledger().with_mut(|li| li.sequence_number = 1000);
    let signals = priced_signals(&p, p.asset_x, p.asset_y, &p.batch_arr, 10);
    let r = p.h.pool.try_mpc_settle_priced(
        &p.na, &p.nb, &p.oa, &p.ob, &p.new_root, &p.batch_hash,
        &p.signer_pubkeys, &p.signatures, &Some(p.proof.clone()), &Some(signals),
    );
    assert!(r.is_err(), "an expired priced settlement deadline must be rejected");
}

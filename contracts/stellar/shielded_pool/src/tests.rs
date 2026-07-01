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

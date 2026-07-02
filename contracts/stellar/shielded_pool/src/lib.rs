#![no_std]
//! # ShadePool — the canonical Shade settlement contract (a.k.a. ShadeVaultV2).
//!
//! P1.1: `shielded_pool` (this contract) is the ONE canonical settlement contract
//! for Shade. It is the only contract on the active deposit/withdraw/RFQ/CCTP-exit
//! path and is what every env var (`SHIELDED_POOL_CONTRACT`), doc, API endpoint,
//! and e2e points at. The legacy `shade_vault` + `commitment_tree` contracts are
//! DEPRECATED (see their headers) and are not wired into any live flow.
//!
//! Shade shielded pool: the integrated ZK withdrawal engine.
//!
//! - Holds USDC (SAC) that arrived via CCTP (forwardRecipient = this contract).
//! - Embeds a Poseidon Lean Incremental Merkle Tree (BLS12-381), matching the
//!   `circuits/` Withdraw circuit, so on-chain roots equal in-circuit roots.
//! - `withdraw` verifies a real Groth16/BLS12-381 proof via the deployed
//!   `proof_verifiers` contract, spends the nullifier in the deployed
//!   `NullifierRegistry` (double-spend prevention), and releases USDC.
//!
//! Withdraw-family public-signal layout (P1.5, shared withdraw circuit):
//!   [0] nullifierHash [1] operationType [2] withdrawnValue [3] recipientHash
//!   [4] relayerFee    [5] deadlineLedger [6] stateRoot     [7] associationRoot
//!   [8] poolId        [9] chainId

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, token, vec, Address, Bytes,
    BytesN, Env, IntoVal, Symbol, Val, Vec,
};

// P1.5 operation types bound into the proof public input [1].
const OP_WITHDRAW_PUBLIC: i128 = 1;
const OP_WITHDRAW_CCTP: i128 = 2;
const OP_RFQ_SETTLEMENT: i128 = 3;
const OP_DEPOSIT_NOTE_MINT: i128 = 4; // P1.8 deposit circuit op type
const OP_RFQ_ATOMIC_SWAP: i128 = 5;   // Phase 3: atomic USDC->XLM RFQ settlement
const PRICE_SCALE: i128 = 1_000_000_000; // Phase 3 (spec §7.6): fixed-point price scale
const STELLAR_CCTP_DOMAIN: i128 = 27; // C6: inbound deposits must target the Stellar CCTP domain
const ARBITRUM_SEPOLIA_DOMAIN: u32 = 3; // Phase 4 (spec §8.6): the only supported outbound CCTP domain on testnet

// Off-chain-root design: the authorized registrar (admin/relayer) maintains the
// Poseidon incremental Merkle tree off-chain at native speed (the same lean-imt
// used by coinutils) and submits the resulting root with each deposit. The
// contract appends the commitment (emitted on-chain for full auditability) and
// records the root as "known". On-chain Poseidon Merkle inserts are infeasible
// here: a single depth-N insert performs N native Poseidon permutations plus
// tree-bookkeeping and exceeds the Soroban per-transaction instruction budget
// beyond the first leaf. All security-critical steps (proof verification,
// nullifier spend, fund release) remain fully on-chain; only root *computation*
// is off-chain, which is acceptable pre-MPC/TEE and documented in docs/.
const TREE_ROOT_KEY: Symbol = symbol_short!("root");
// P3 #19: leaves are NOT stored as an on-chain Vec<BytesN<32>> — that vector
// was rewritten in full on every single deposit/transfer/settle (O(n) cost
// per op) and grows without bound toward the Soroban ledger-entry size limit.
// Since root computation is off-chain anyway (see above) the vector was pure
// auditability bloat with no cryptographic role; every insertion site already
// emits the commitment via `env.events().publish(...)`, so full off-chain
// reconstruction was always possible from events. LEAF_COUNT_KEY is just a
// cheap O(1) counter for `get_leaf_count()` / computing the next leaf_index.
// NOTE: upgrading an already-deployed pool from the old Vec-based storage
// needs a one-time migration (seed LEAF_COUNT_KEY from the old vector's
// length) — not needed for a fresh deploy.
const LEAF_COUNT_KEY: Symbol = symbol_short!("leafcnt");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    Paused = 2,
    DuplicateDeposit = 3,
    UnknownRoot = 4,
    ProofInvalid = 5,
    NullifierUsed = 6,
    InsufficientBalance = 7,
    BadAmount = 8,
    WrongDomain = 9,        // #3 pool_id/chain_id in proof != this pool/chain
    WrongAssociation = 10,  // #4 association root in proof != configured ASP root
    WrongOperation = 11,    // P1.5 operation_type in proof != expected for this fn
    WrongRecipient = 12,    // P1.5 recipientHash in proof != hash(to)
    Expired = 13,           // P1.5 deadline_ledger exceeded
    WrongQuote = 14,        // P1.6 quote_hash arg != quoteHash bound in proof
    WrongIntent = 15,       // P1.6 intent_hash arg != intentHash bound in proof
    WrongFillReceipt = 16,  // P1.6 fill_receipt_hash arg != fillReceiptHash bound in proof
    WrongDestDomain = 17,   // P1.7 destination_domain arg != bound in proof
    WrongDestRecipient = 18,// P1.7 destination_recipient arg != bound in proof
    WrongMaxFee = 19,       // P1.7 max_fee arg != bound in proof
    WrongFinality = 20,     // P1.7 min_finality_threshold arg != bound in proof
    WrongCommitment = 21,   // P1.8 commitment arg != commitment bound in deposit proof
    WrongDepositField = 22, // P1.8 a deposit CCTP field arg != value bound in proof
    UnauthorizedSolver = 23,// C4 solver_pubkey is not in the authorized-solver registry
    MpcThreshold = 24,      // Phase 8: fewer than 2/3 committee signatures verified
    MpcUnknownSigner = 25,  // Phase 8: a provided signer pubkey is not in the registered committee
    MpcProofInvalid = 26,   // Phase C: mpc_settlement ZK proof failed verification
    MpcSignalMismatch = 27, // Phase C: proof public signal != provided argument
    MpcDuplicateSigner = 28,// Phase 8: the same committee pubkey appears more than once in signer_pubkeys
    UnknownAsset = 29,      // Phase 2: asset_id is not registered (never defaults to USDC)
    AssetAlreadyRegistered = 30, // Phase 2: asset_id already mapped to a token
    SameAssetSwap = 31,     // Phase 3: RFQ swap input asset == output asset
    UnderDelivered = 32,    // Phase 3: quoted output < min output
    WrongPrice = 33,        // Phase 3: quoted output != floor(input * priceScaled / PRICE_SCALE)
    UnsupportedDomain = 34, // Phase 4: outbound CCTP destination domain is not supported
    NotCrossAsset = 35,     // Phase 6: priced settlement input assets are equal (not a cross-asset)
    SupplyUnderflow = 36,   // Phase 7: a note-supply debit would drive per-asset supply negative
    ReserveBroken = 37,     // Phase 7: note_supply(asset) would exceed vault_balance(asset)
}

const ADMIN: Symbol = symbol_short!("admin");
const USDC: Symbol = symbol_short!("usdc");
const VERIFIER: Symbol = symbol_short!("verifier");
const NULLREG: Symbol = symbol_short!("nullreg");
const PAUSED: Symbol = symbol_short!("paused");
const TMM: Symbol = symbol_short!("tmm"); // Stellar CCTP TokenMessengerMinter (for outbound)
const POOLID: Symbol = symbol_short!("poolid"); // #3 domain separator bound in proofs
const CHAINID: Symbol = symbol_short!("chainid"); // #3 domain separator bound in proofs
const ASSOCROOT: Symbol = symbol_short!("assocroot"); // #4 ASP allowlist root bound in proofs
const XVERIFIER: Symbol = symbol_short!("xverifier"); // #2 PrivateTransfer verifier (separate circuit/vk)
const DEPVERIFIER: Symbol = symbol_short!("depverif"); // P1.8 DepositNoteMint verifier (separate circuit/vk)
const MPC_CMTE: Symbol = symbol_short!("mpc_cmte");   // Phase 8: Vec<BytesN<32>> committee ed25519 pubkeys
const MPC_VERIFIER: Symbol = symbol_short!("mpc_verif"); // Phase C: mpc_settlement Groth16 verifier contract
const MPC_PVERIFIER: Symbol = symbol_short!("mpc_pverf"); // Phase 6: mpc_priced_settlement Groth16 verifier

#[contracttype]
enum DataKey {
    KnownRoot(BytesN<32>),
    Deposit(BytesN<32>),
    Solver(BytesN<32>), // C4: authorized solver ed25519 pubkey -> allowed
    // Phase 2 asset registry (spec §6.5): asset_id (field-compatible BytesN<32>)
    // -> Stellar token/SAC contract. Unknown assets are rejected, never defaulted
    // to USDC.
    AssetToken(BytesN<32>),
    // Per-asset shielded note supply (spec §6.6): sum of note values (7dp) minted
    // for this asset minus those withdrawn. Must never exceed vault_balance.
    NoteSupply(BytesN<32>),
}

#[contract]
pub struct ShieldedPool;

#[contractimpl]
impl ShieldedPool {
    pub fn __constructor(
        env: Env,
        admin: Address,
        usdc_sac: Address,
        verifier: Address,
        nullifier_registry: Address,
        depth: u32,
        pool_id: u32,
        chain_id: u32,
    ) {
        env.storage().instance().set(&ADMIN, &admin);
        env.storage().instance().set(&USDC, &usdc_sac);
        env.storage().instance().set(&VERIFIER, &verifier);
        env.storage().instance().set(&NULLREG, &nullifier_registry);
        env.storage().instance().set(&PAUSED, &false);
        // #3 domain separators bound into every spend proof.
        env.storage().instance().set(&POOLID, &pool_id);
        env.storage().instance().set(&CHAINID, &chain_id);

        // Empty-tree root for the configured depth (computed off-chain, passed in
        // as `empty_root`) is recorded as a known root so an empty-pool proof is
        // possible; depth is informational on-chain.
        let _ = depth;
        let empty_root = BytesN::from_array(&env, &[0u8; 32]);
        env.storage().instance().set(&TREE_ROOT_KEY, &empty_root);
        env.storage().instance().set(&LEAF_COUNT_KEY, &0u32);
        env.storage().persistent().set(&DataKey::KnownRoot(empty_root), &true);
    }

    /// Register a note commitment funded by a prior CCTP mint into this contract.
    /// `new_root` is the post-insert Merkle root computed off-chain by the
    /// registrar (admin) using the same Poseidon lean-imt as the circuit.
    /// Admin-gated; the commitment is emitted on-chain so the root is auditable.
    ///
    /// P1.8: a DepositNoteMint proof binds the note commitment to its private
    /// opening AND to the CCTP message fields. The contract verifies the proof and
    /// checks that every binding arg equals the corresponding proof public signal,
    /// so a registrar cannot insert a commitment that does not correspond to the
    /// deposit it claims (wrong amount, wrong nonce, wrong asset, etc.).
    ///
    /// Deposit pub signals (14): [0] commitment [1] operationType [2] sourceDomain
    /// [3] destinationDomain [4] cctpNonceHash [5] burnTxHashHash [6] amount6dp
    /// [7] amount7dp [8] assetIdHash [9] recipientPool [10] encryptedNotePayloadHash
    /// [11] policyIdHash [12] poolId [13] chainId.
    pub fn receive_cctp_deposit(
        env: Env,
        source_domain: u32,
        cctp_nonce: BytesN<32>,
        asset: Address,
        amount: i128,
        commitment: BytesN<32>,
        new_root: BytesN<32>,
        encrypted_note_payload_hash: BytesN<32>,
        policy_id: BytesN<32>,
        proof_bytes: Bytes,
        pub_signals_bytes: Bytes,
    ) -> u32 {
        Self::require_not_paused(&env);
        Self::require_admin(&env);
        if amount <= 0 {
            panic_err(&env, Error::BadAmount);
        }
        if env.storage().persistent().has(&DataKey::Deposit(cctp_nonce.clone())) {
            panic_err(&env, Error::DuplicateDeposit);
        }

        // P1.8 deposit proof: verify and bind the CCTP message to the commitment.
        let signals = parse_public_signals(&env, &pub_signals_bytes);
        // [0] commitment output must equal the leaf we are inserting.
        if signals.get(0).unwrap() != commitment {
            panic_err(&env, Error::WrongCommitment);
        }
        // [1] operation type must be DEPOSIT_NOTE_MINT.
        if fr32_to_i128(&signals.get(1).unwrap()) != OP_DEPOSIT_NOTE_MINT {
            panic_err(&env, Error::WrongOperation);
        }
        // [2] source domain, [7] minted 7dp amount must match the args.
        if fr32_to_i128(&signals.get(2).unwrap()) != source_domain as i128 {
            panic_err(&env, Error::WrongDepositField);
        }
        if fr32_to_i128(&signals.get(7).unwrap()) != amount {
            panic_err(&env, Error::WrongDepositField);
        }
        // C6 [3] destination domain must be the Stellar CCTP domain (this chain).
        if fr32_to_i128(&signals.get(3).unwrap()) != STELLAR_CCTP_DOMAIN {
            panic_err(&env, Error::WrongDepositField);
        }
        // C6 [5] burn-tx hash must be bound (non-zero); it has no trusted on-chain
        // source so it is recorded for auditability rather than independently verified.
        if fr32_to_i128(&signals.get(5).unwrap()) == 0 {
            panic_err(&env, Error::WrongDepositField);
        }
        // C6 [6] amount6dp must be positive and consistent with the minted 7dp
        // amount: 7dp = 6dp * 10 minus the (non-negative) CCTP fast-transfer fee, so
        // amount6dp*10 >= amount7dp. This binds the 6dp burn amount to the mint.
        let amount6: i128 = fr32_to_i128(&signals.get(6).unwrap());
        if amount6 <= 0 || amount6 * 10 < amount {
            panic_err(&env, Error::WrongDepositField);
        }
        // [4] cctp nonce, [10] encrypted-note-payload, [11] policy id (reduced to field).
        if Self::hash_to_field(&env, &cctp_nonce) != signals.get(4).unwrap() {
            panic_err(&env, Error::WrongDepositField);
        }
        if Self::hash_to_field(&env, &encrypted_note_payload_hash) != signals.get(10).unwrap() {
            panic_err(&env, Error::WrongDepositField);
        }
        if Self::hash_to_field(&env, &policy_id) != signals.get(11).unwrap() {
            panic_err(&env, Error::WrongDepositField);
        }
        // [8] asset id = hash(asset strkey), [9] recipient pool = hash(this contract).
        if Self::recipient_hash(&env, &asset) != signals.get(8).unwrap() {
            panic_err(&env, Error::WrongDepositField);
        }
        if Self::recipient_hash(&env, &env.current_contract_address()) != signals.get(9).unwrap() {
            panic_err(&env, Error::WrongDepositField);
        }
        // [12] poolId, [13] chainId must match this pool's domain (#3).
        let pool_id: u32 = env.storage().instance().get(&POOLID).unwrap();
        let chain_id: u32 = env.storage().instance().get(&CHAINID).unwrap();
        if fr32_to_i128(&signals.get(12).unwrap()) != pool_id as i128
            || fr32_to_i128(&signals.get(13).unwrap()) != chain_id as i128 {
            panic_err(&env, Error::WrongDomain);
        }
        // Verify the DepositNoteMint Groth16 proof against its dedicated verifier.
        let dep_verifier: Address = env.storage().instance().get(&DEPVERIFIER).unwrap();
        let ok: bool = env.invoke_contract(
            &dep_verifier,
            &Symbol::new(&env, "verify"),
            vec![&env, proof_bytes.to_val(), pub_signals_bytes.to_val()],
        );
        if !ok {
            panic_err(&env, Error::ProofInvalid);
        }

        let leaf_index: u32 = env.storage().instance().get(&LEAF_COUNT_KEY).unwrap_or(0u32);
        env.storage().instance().set(&LEAF_COUNT_KEY, &(leaf_index + 1));
        env.storage().instance().set(&TREE_ROOT_KEY, &new_root);
        env.storage().persistent().set(&DataKey::KnownRoot(new_root.clone()), &true);
        env.storage().persistent().set(&DataKey::Deposit(cctp_nonce.clone()), &true);
        // Phase 2 (spec §6.6): the minted note enters the shielded set for its
        // asset. signal[8] (assetIdHash) IS the field asset id; the asset must be
        // registered (fail closed) so per-asset supply/reserves stay consistent.
        Self::adjust_note_supply(&env, &signals.get(8).unwrap(), amount);
        env.events().publish(
            (symbol_short!("deposit"), source_domain),
            (cctp_nonce, asset, amount, commitment, encrypted_note_payload_hash, policy_id, leaf_index, new_root),
        );
        leaf_index
    }

    /// Withdraw with a real Groth16/BLS12-381 proof (P1.5: recipient/fee/deadline/
    /// operation-type are bound into the proof and enforced here). Verifies,
    /// spends the nullifier once, and releases (withdrawnValue - relayerFee) to
    /// `to`, keeping the fee in the pool for relayer reimbursement.
    pub fn withdraw(env: Env, to: Address, proof_bytes: Bytes, pub_signals_bytes: Bytes) {
        Self::require_not_paused(&env);
        to.require_auth();

        let signals = parse_public_signals(&env, &pub_signals_bytes);
        let op_type: i128 = fr32_to_i128(&signals.get(1).unwrap());
        let nullifier_hash: BytesN<32> = signals.get(0).unwrap();
        let withdrawn_value: i128 = fr32_to_i128(&signals.get(2).unwrap());
        let recipient_hash: BytesN<32> = signals.get(3).unwrap();
        let relayer_fee: i128 = fr32_to_i128(&signals.get(4).unwrap());
        let deadline_ledger: i128 = fr32_to_i128(&signals.get(5).unwrap());
        let state_root: BytesN<32> = signals.get(6).unwrap();
        // Phase 2 (spec §6.4): the note's asset id is a public signal bound into
        // the commitment. The contract releases the token registered for THIS
        // asset — never a hardcoded USDC — and fails closed on an unknown asset.
        let asset_id: BytesN<32> = signals.get(17).unwrap();

        // P1.5 enforce operation type.
        if op_type != OP_WITHDRAW_PUBLIC {
            panic_err(&env, Error::WrongOperation);
        }
        if withdrawn_value <= 0 || relayer_fee < 0 || relayer_fee > withdrawn_value {
            panic_err(&env, Error::BadAmount);
        }
        // P1.5 deadline must not be expired.
        if (env.ledger().sequence() as i128) > deadline_ledger {
            panic_err(&env, Error::Expired);
        }
        // P1.5 recipient binding: proof's recipientHash must equal the hash of the
        // actual recipient `to`, so a relayer cannot redirect funds.
        if recipient_hash != Self::recipient_hash(&env, &to) {
            panic_err(&env, Error::WrongRecipient);
        }
        // #3/#4 bind pool/chain domain + ASP root.
        Self::check_domain_compliance(&env, &signals);

        if !env.storage().persistent().get(&DataKey::KnownRoot(state_root.clone())).unwrap_or(false) {
            panic_err(&env, Error::UnknownRoot);
        }

        let verifier: Address = env.storage().instance().get(&VERIFIER).unwrap();
        let ok: bool = env.invoke_contract(
            &verifier,
            &Symbol::new(&env, "verify"),
            vec![&env, proof_bytes.to_val(), pub_signals_bytes.to_val()],
        );
        if !ok {
            panic_err(&env, Error::ProofInvalid);
        }

        let nullreg: Address = env.storage().instance().get(&NULLREG).unwrap();
        let _: bool = env.invoke_contract(
            &nullreg,
            &Symbol::new(&env, "spend"),
            vec![&env, env.current_contract_address().to_val(), nullifier_hash.clone().to_val()],
        );

        // Release net (withdrawnValue - relayerFee) in the NOTE'S asset to the
        // recipient; fee stays. The token is resolved from the asset registry —
        // get_asset_token fails closed (UnknownAsset) for an unregistered asset,
        // and a USDC note can never move the XLM token or vice versa.
        let net = withdrawn_value - relayer_fee;
        let token: Address = Self::get_asset_token(env.clone(), asset_id.clone());
        let client = token::TokenClient::new(&env, &token);
        if client.balance(&env.current_contract_address()) < net {
            panic_err(&env, Error::InsufficientBalance);
        }
        client.transfer(&env.current_contract_address(), &to, &net);
        // Phase 2 (spec §6.6): the withdrawn value leaves the shielded set.
        Self::adjust_note_supply(&env, &asset_id, -withdrawn_value);

        env.events().publish((symbol_short!("withdraw"),), (to, nullifier_hash, net, relayer_fee));
    }

    /// Set the Stellar CCTP TokenMessengerMinter used for proof-bound outbound.
    pub fn set_cctp_messenger(env: Env, token_messenger_minter: Address) {
        Self::require_admin(&env);
        env.storage().instance().set(&TMM, &token_messenger_minter);
    }

    /// #2 Set the PrivateTransfer verifier contract (separate circuit/vk).
    pub fn set_transfer_verifier(env: Env, verifier: Address) {
        Self::require_admin(&env);
        env.storage().instance().set(&XVERIFIER, &verifier);
    }

    /// P1.8 Set the DepositNoteMint verifier contract (separate circuit/vk).
    pub fn set_deposit_verifier(env: Env, verifier: Address) {
        Self::require_admin(&env);
        env.storage().instance().set(&DEPVERIFIER, &verifier);
    }

    /// C4 Authorize (or revoke) a solver ed25519 public key for RFQ settlement.
    /// Admin-gated. `rfq_settle` rejects any quote signed by a non-authorized key,
    /// enforcing "solver is authorized / solver public key is registered" on-chain.
    pub fn set_authorized_solver(env: Env, solver_pubkey: BytesN<32>, allowed: bool) {
        Self::require_admin(&env);
        env.storage().persistent().set(&DataKey::Solver(solver_pubkey), &allowed);
    }

    /// C4 Read whether a solver ed25519 public key is authorized.
    pub fn is_authorized_solver(env: Env, solver_pubkey: BytesN<32>) -> bool {
        env.storage().persistent().get(&DataKey::Solver(solver_pubkey)).unwrap_or(false)
    }

    /// #2 Hidden-amount shielded transfer: spend an input note, create an output
    /// note whose value is hidden in its commitment. Verifies value conservation
    /// (inValue == outValue + fee) in-circuit; the contract sees only the output
    /// commitment and public fee, never the transferred amount. No public funds move.
    ///
    /// PrivateTransfer public signals:
    ///   [0]=nullifierHash [1]=outputCommitment [2]=feePublic [3]=stateRoot
    ///   [4]=associationRoot [5]=poolId [6]=chainId
    pub fn private_transfer_settle(env: Env, proof_bytes: Bytes, pub_signals_bytes: Bytes, new_root: BytesN<32>) {
        Self::require_not_paused(&env);
        Self::require_admin(&env); // registrar submits the off-chain-computed new_root

        let signals = parse_public_signals(&env, &pub_signals_bytes);
        let nullifier_hash: BytesN<32> = signals.get(0).unwrap();
        let output_commitment: BytesN<32> = signals.get(1).unwrap();
        let state_root: BytesN<32> = signals.get(3).unwrap();
        // P2 #14: transfers are now held to the same ASP allowlist envelope as
        // deposit/withdraw (a prior version had no association-root check at
        // all here). Deny-root non-membership is not yet enforced anywhere in
        // the protocol — see circuits/compliance_membership/README.md.
        let assoc_in: BytesN<32> = signals.get(4).unwrap();
        let assoc_expected: BytesN<32> = env.storage().instance().get(&ASSOCROOT).unwrap_or(BytesN::from_array(&env, &[0u8; 32]));
        if assoc_in != assoc_expected {
            panic_err(&env, Error::WrongAssociation);
        }
        let pool_in: i128 = fr32_to_i128(&signals.get(5).unwrap());
        let chain_in: i128 = fr32_to_i128(&signals.get(6).unwrap());
        let pool_id: u32 = env.storage().instance().get(&POOLID).unwrap();
        let chain_id: u32 = env.storage().instance().get(&CHAINID).unwrap();
        if pool_in != pool_id as i128 || chain_in != chain_id as i128 {
            panic_err(&env, Error::WrongDomain);
        }
        if !env.storage().persistent().get(&DataKey::KnownRoot(state_root.clone())).unwrap_or(false) {
            panic_err(&env, Error::UnknownRoot);
        }

        // Verify the PrivateTransfer proof (value conservation enforced in-circuit).
        let verifier: Address = env.storage().instance().get(&XVERIFIER).unwrap();
        let ok: bool = env.invoke_contract(
            &verifier,
            &Symbol::new(&env, "verify"),
            vec![&env, proof_bytes.to_val(), pub_signals_bytes.to_val()],
        );
        if !ok {
            panic_err(&env, Error::ProofInvalid);
        }

        // Spend the input note's nullifier once.
        let nullreg: Address = env.storage().instance().get(&NULLREG).unwrap();
        let _: bool = env.invoke_contract(
            &nullreg,
            &Symbol::new(&env, "spend"),
            vec![&env, env.current_contract_address().to_val(), nullifier_hash.clone().to_val()],
        );

        // Insert the output commitment (new note); registrar supplies the new root.
        let leaf_index: u32 = env.storage().instance().get(&LEAF_COUNT_KEY).unwrap_or(0u32);
        env.storage().instance().set(&LEAF_COUNT_KEY, &(leaf_index + 1));
        env.storage().instance().set(&TREE_ROOT_KEY, &new_root);
        env.storage().persistent().set(&DataKey::KnownRoot(new_root.clone()), &true);

        env.events().publish(
            (symbol_short!("xfer"),),
            (nullifier_hash, output_commitment, leaf_index, new_root),
        );
    }

    /// #4 Set the ASP allowlist (association-set) root that spend proofs must match.
    /// Admin/registrar-managed; mirrors the ComplianceRegistry active policy root.
    pub fn set_association_root(env: Env, association_root: BytesN<32>) {
        Self::require_admin(&env);
        env.storage().instance().set(&ASSOCROOT, &association_root);
    }

    pub fn get_association_root(env: Env) -> BytesN<32> {
        env.storage().instance().get(&ASSOCROOT).unwrap_or(BytesN::from_array(&env, &[0u8; 32]))
    }

    // ---- Phase 2 asset registry (spec §6.5) ----
    //
    // Every shielded asset maps a field-compatible `asset_id` (BytesN<32>) to its
    // Stellar token/SAC contract. Settlement paths look up the token by asset_id;
    // an unregistered asset is rejected (UnknownAsset), never defaulted to USDC.

    /// Admin: register (or re-point) an `asset_id` to its Stellar token contract.
    /// Registering a fresh asset initializes its note supply to 0.
    pub fn register_asset(env: Env, asset_id: BytesN<32>, token: Address) {
        Self::require_admin(&env);
        let key = DataKey::AssetToken(asset_id.clone());
        if env.storage().persistent().get::<DataKey, Address>(&key).is_some() {
            panic_err(&env, Error::AssetAlreadyRegistered);
        }
        env.storage().persistent().set(&key, &token);
        env.storage().persistent().set(&DataKey::NoteSupply(asset_id.clone()), &0i128);
        env.events().publish((symbol_short!("regasset"), asset_id), token);
    }

    /// Resolve the token contract for `asset_id`. Panics (UnknownAsset) if the
    /// asset is not registered — no silent default to USDC (spec §0.2, §6.5).
    pub fn get_asset_token(env: Env, asset_id: BytesN<32>) -> Address {
        env.storage().persistent()
            .get(&DataKey::AssetToken(asset_id))
            .unwrap_or_else(|| panic_err(&env, Error::UnknownAsset))
    }

    /// Shielded note supply (7dp) for `asset_id`.
    pub fn note_supply(env: Env, asset_id: BytesN<32>) -> i128 {
        env.storage().persistent().get(&DataKey::NoteSupply(asset_id)).unwrap_or(0i128)
    }

    /// On-chain token balance the pool custodies for `asset_id`'s token.
    pub fn vault_balance(env: Env, asset_id: BytesN<32>) -> i128 {
        let token = Self::get_asset_token(env.clone(), asset_id);
        token::TokenClient::new(&env, &token).balance(&env.current_contract_address())
    }

    /// Proof of reserves for `asset_id`: (note_supply, vault_balance). A healthy
    /// pool always has note_supply <= vault_balance.
    pub fn proof_of_reserves(env: Env, asset_id: BytesN<32>) -> (i128, i128) {
        let supply = Self::note_supply(env.clone(), asset_id.clone());
        let bal = Self::vault_balance(env, asset_id);
        (supply, bal)
    }

    /// Internal: adjust a registered asset's note supply by `delta` (may be
    /// negative). Requires the asset to be registered (fails closed otherwise).
    fn adjust_note_supply(env: &Env, asset_id: &BytesN<32>, delta: i128) {
        let token: Address = env.storage().persistent()
            .get::<DataKey, Address>(&DataKey::AssetToken(asset_id.clone()))
            .unwrap_or_else(|| panic_err(env, Error::UnknownAsset));
        let cur: i128 = env.storage().persistent().get(&DataKey::NoteSupply(asset_id.clone())).unwrap_or(0i128);
        let next = cur + delta;
        // Fail closed (spec §6.6): supply can never go negative — that would mean
        // more notes were spent than exist, i.e. a double-spend / accounting bug.
        if next < 0 {
            panic_err(env, Error::SupplyUnderflow);
        }
        // Per-asset reserve invariant: the shielded note supply must never exceed
        // the tokens the pool actually custodies for this asset.
        let bal = token::TokenClient::new(env, &token).balance(&env.current_contract_address());
        if next > bal {
            panic_err(env, Error::ReserveBroken);
        }
        env.storage().persistent().set(&DataKey::NoteSupply(asset_id.clone()), &next);
    }

    /// Proof-bound CCTP outbound (Stellar -> Arbitrum Sepolia).
    ///
    /// The user spends a private note and the pool burns `withdrawnValue` USDC via
    /// the Stellar CCTP TokenMessengerMinter to the Arbitrum recipient. `to` is the
    /// note owner: requiring its auth binds the destination so a relayer cannot
    /// mutate recipient/amount. nullifier+amount are bound by the proof.
    ///
    /// P1.7 pub signals (shared withdraw circuit, 17 signals):
    /// [0] nullifierHash [1] operationType [2] withdrawnValue [5] deadlineLedger
    /// [6] stateRoot [7] associationRoot [8] poolId [9] chainId
    /// [13] destinationDomain [14] destinationRecipient [15] maxFee [16] minFinalityThreshold.
    /// The destination_domain/recipient/max_fee/min_finality_threshold args are
    /// bound into the user's proof, so a relayer cannot redirect the burn, change
    /// the domain, or alter the fee/threshold while reusing a valid user proof.
    /// (`to.require_auth()` only binds the Stellar note owner, NOT the Arbitrum
    /// destination — hence the proof bindings below.)
    pub fn withdraw_cctp(
        env: Env,
        to: Address,
        proof_bytes: Bytes,
        pub_signals_bytes: Bytes,
        destination_domain: u32,
        destination_recipient: BytesN<32>,
        max_fee: i128,
        min_finality_threshold: u32,
    ) -> i128 {
        Self::require_not_paused(&env);
        to.require_auth(); // binds the spend to the note owner

        let signals = parse_public_signals(&env, &pub_signals_bytes);
        let op_type: i128 = fr32_to_i128(&signals.get(1).unwrap());
        let nullifier_hash: BytesN<32> = signals.get(0).unwrap();
        let amount: i128 = fr32_to_i128(&signals.get(2).unwrap()); // P1.5 layout: value@2
        let deadline_ledger: i128 = fr32_to_i128(&signals.get(5).unwrap());
        let state_root: BytesN<32> = signals.get(6).unwrap();      // P1.5 layout: stateRoot@6
        let asset_id: BytesN<32> = signals.get(17).unwrap();       // Phase 2/4: note asset
        if amount <= 0 {
            panic_err(&env, Error::BadAmount);
        }
        // P1.7 enforce operation type is WITHDRAW_CCTP.
        if op_type != OP_WITHDRAW_CCTP {
            panic_err(&env, Error::WrongOperation);
        }
        // Phase 4 asset binding (spec §8.6): CCTP exit is USDC-only. The note's
        // asset id (bound in the commitment) MUST be the registered USDC asset —
        // a non-USDC note can never be burned out via CCTP. USDC's asset id is
        // hash_to_field(sha256(usdc strkey)) == recipient_hash(usdc), matching the
        // @shade/assets derivation and the deposit proof's assetIdHash.
        let usdc_addr: Address = env.storage().instance().get(&USDC).unwrap();
        if asset_id != Self::recipient_hash(&env, &usdc_addr) {
            panic_err(&env, Error::UnknownAsset);
        }
        // P1.7 deadline must not be expired.
        if (env.ledger().sequence() as i128) > deadline_ledger {
            panic_err(&env, Error::Expired);
        }
        // Phase 4 (spec §8.6): block unsupported destination domains before the
        // burn — only Arbitrum Sepolia is a supported CCTP exit on testnet.
        if destination_domain != ARBITRUM_SEPOLIA_DOMAIN {
            panic_err(&env, Error::UnsupportedDomain);
        }
        // P1.7 destination bindings: each function arg must equal the value bound
        // into the proof, so a relayer cannot mutate the outbound burn terms.
        if fr32_to_i128(&signals.get(13).unwrap()) != destination_domain as i128 {
            panic_err(&env, Error::WrongDestDomain);
        }
        if signals.get(14).unwrap() != destination_recipient {
            panic_err(&env, Error::WrongDestRecipient);
        }
        if fr32_to_i128(&signals.get(15).unwrap()) != max_fee {
            panic_err(&env, Error::WrongMaxFee);
        }
        if fr32_to_i128(&signals.get(16).unwrap()) != min_finality_threshold as i128 {
            panic_err(&env, Error::WrongFinality);
        }
        Self::check_domain_compliance(&env, &signals);
        if !env.storage().persistent().get(&DataKey::KnownRoot(state_root.clone())).unwrap_or(false) {
            panic_err(&env, Error::UnknownRoot);
        }

        let verifier: Address = env.storage().instance().get(&VERIFIER).unwrap();
        let ok: bool = env.invoke_contract(
            &verifier,
            &Symbol::new(&env, "verify"),
            vec![&env, proof_bytes.to_val(), pub_signals_bytes.to_val()],
        );
        if !ok {
            panic_err(&env, Error::ProofInvalid);
        }

        let nullreg: Address = env.storage().instance().get(&NULLREG).unwrap();
        let _: bool = env.invoke_contract(
            &nullreg,
            &Symbol::new(&env, "spend"),
            vec![&env, env.current_contract_address().to_val(), nullifier_hash.clone().to_val()],
        );

        // Burn pool USDC outbound via Stellar CCTP. TokenMessengerMinter pulls the
        // USDC from the pool via SEP-41 `transfer_from`, so the pool must approve
        // the TMM as spender for `amount + max_fee` first. The pool is the caller;
        // its contract invocation authorizes both the approve and the burn.
        let tmm: Address = env.storage().instance().get(&TMM).unwrap();
        let usdc: Address = env.storage().instance().get(&USDC).unwrap();
        let pool = env.current_contract_address();
        let pull_amount = amount + if max_fee > 0 { max_fee } else { 0 };
        let token_client = token::TokenClient::new(&env, &usdc);
        let expiration = env.ledger().sequence() + 200;
        token_client.approve(&pool, &tmm, &pull_amount, &expiration);
        let zero_caller = BytesN::from_array(&env, &[0u8; 32]); // anyone can complete on Arbitrum
        let args: Vec<Val> = vec![
            &env,
            pool.into_val(&env),
            amount.into_val(&env),
            destination_domain.into_val(&env),
            destination_recipient.into_val(&env),
            usdc.into_val(&env),
            zero_caller.into_val(&env),
            max_fee.into_val(&env),
            min_finality_threshold.into_val(&env),
        ];
        env.invoke_contract::<()>(&tmm, &Symbol::new(&env, "deposit_for_burn"), args);

        // Phase 2 (spec §6.6): the burned note leaves the shielded set.
        Self::adjust_note_supply(&env, &asset_id, -amount);

        env.events().publish(
            (symbol_short!("cctpout"), destination_domain),
            (to, nullifier_hash, destination_recipient, amount),
        );
        amount
    }

    /// RFQ settlement (Path A: solver-fronted proof-of-fill).
    ///
    /// The solver has already delivered output funds to the user on the
    /// destination chain (real Arbitrum Sepolia fill tx, bound off-chain in the
    /// quote/fill records). This call reimburses the solver from the pool by:
    ///   1. verifying the user's note-ownership Groth16 proof,
    ///   2. verifying the solver's ed25519 signature over `quote_hash`
    ///      (binds the accepted quote to the configured solver key),
    ///   3. spending the user's nullifier exactly once,
    ///   4. crediting `withdrawnValue` USDC to the solver's account.
    ///
    /// P1.6 pub signals (shared withdraw circuit, 13 signals):
    /// [0] nullifierHash [1] operationType [2] withdrawnValue/credit [4] relayerFee/fee
    /// [5] deadlineLedger [6] stateRoot [7] associationRoot [8] poolId [9] chainId
    /// [10] quoteHash [11] intentHash [12] fillReceiptHash.
    /// The quote_hash / intent_hash / fill_receipt_hash function args are bound into
    /// the proof (field element = int(sha256(..)[:31])), so a relayer cannot settle
    /// a valid user proof against a different quote, intent, or fill.
    pub fn rfq_settle(
        env: Env,
        to_solver: Address,
        proof_bytes: Bytes,
        pub_signals_bytes: Bytes,
        quote_hash: BytesN<32>,
        intent_hash: BytesN<32>,
        fill_receipt_hash: BytesN<32>,
        solver_pubkey: BytesN<32>,
        solver_sig: BytesN<64>,
    ) {
        Self::require_not_paused(&env);

        // C4: the solver key must be in the admin-managed authorized-solver registry
        // (enforces "solver is authorized / pubkey registered" on-chain).
        if !env.storage().persistent().get(&DataKey::Solver(solver_pubkey.clone())).unwrap_or(false) {
            panic_err(&env, Error::UnauthorizedSolver);
        }
        // Verify the solver signed this exact quote (binds quote to solver key).
        let msg = Bytes::from_array(&env, &quote_hash.to_array());
        env.crypto().ed25519_verify(&solver_pubkey, &msg, &solver_sig);

        let signals = parse_public_signals(&env, &pub_signals_bytes);
        let op_type: i128 = fr32_to_i128(&signals.get(1).unwrap());
        let nullifier_hash: BytesN<32> = signals.get(0).unwrap();
        let credit: i128 = fr32_to_i128(&signals.get(2).unwrap()); // P1.5 layout: value@2
        let relayer_fee: i128 = fr32_to_i128(&signals.get(4).unwrap());
        let deadline_ledger: i128 = fr32_to_i128(&signals.get(5).unwrap());
        let state_root: BytesN<32> = signals.get(6).unwrap();      // P1.5 layout: stateRoot@6
        if credit <= 0 || relayer_fee < 0 || relayer_fee > credit {
            panic_err(&env, Error::BadAmount);
        }
        // P1.6 enforce operation type is RFQ settlement.
        if op_type != OP_RFQ_SETTLEMENT {
            panic_err(&env, Error::WrongOperation);
        }
        // P1.6 deadline must not be expired.
        if (env.ledger().sequence() as i128) > deadline_ledger {
            panic_err(&env, Error::Expired);
        }
        // P1.6 full RFQ-term binding: the quote/intent/fill args must equal the
        // values bound into the proof. quote_hash also commits (via its sha256) to
        // output asset, net_output, fee, solver_id and deadline of the accepted
        // quote, so this prevents any relayer mutation of the accepted terms.
        if Self::hash_to_field(&env, &quote_hash) != signals.get(10).unwrap() {
            panic_err(&env, Error::WrongQuote);
        }
        if Self::hash_to_field(&env, &intent_hash) != signals.get(11).unwrap() {
            panic_err(&env, Error::WrongIntent);
        }
        if Self::hash_to_field(&env, &fill_receipt_hash) != signals.get(12).unwrap() {
            panic_err(&env, Error::WrongFillReceipt);
        }
        Self::check_domain_compliance(&env, &signals);
        if !env.storage().persistent().get(&DataKey::KnownRoot(state_root.clone())).unwrap_or(false) {
            panic_err(&env, Error::UnknownRoot);
        }

        // Verify the user's note-ownership proof.
        let verifier: Address = env.storage().instance().get(&VERIFIER).unwrap();
        let ok: bool = env.invoke_contract(
            &verifier,
            &Symbol::new(&env, "verify"),
            vec![&env, proof_bytes.to_val(), pub_signals_bytes.to_val()],
        );
        if !ok {
            panic_err(&env, Error::ProofInvalid);
        }

        // Spend the user's nullifier once (note consumed; no double settle/withdraw).
        let nullreg: Address = env.storage().instance().get(&NULLREG).unwrap();
        let _: bool = env.invoke_contract(
            &nullreg,
            &Symbol::new(&env, "spend"),
            vec![&env, env.current_contract_address().to_val(), nullifier_hash.clone().to_val()],
        );

        // Reimburse the solver from the pool.
        let usdc: Address = env.storage().instance().get(&USDC).unwrap();
        let client = token::TokenClient::new(&env, &usdc);
        if client.balance(&env.current_contract_address()) < credit {
            panic_err(&env, Error::InsufficientBalance);
        }
        client.transfer(&env.current_contract_address(), &to_solver, &credit);

        env.events().publish(
            (symbol_short!("rfq"), quote_hash),
            (to_solver, nullifier_hash, credit),
        );
    }

    /// Phase 3 (spec §7): ATOMIC USDC->XLM RFQ settlement. In ONE transaction:
    ///   1. verify the solver signed the exact swap terms (accepted quote +
    ///      output asset/amount/min/recipient) — the relayer cannot mutate any;
    ///   2. verify the user's note-ownership proof (reuses the withdraw circuit,
    ///      operationType = RFQ_ATOMIC_SWAP) and bind quote/intent/fill;
    ///   3. spend the user's USDC nullifier once;
    ///   4. deliver `quoted_output` of the OUTPUT asset (XLM) to the user from pool
    ///      reserves (>= `min_output`);
    ///   5. credit the solver `withdrawnValue - relayerFee` in the INPUT asset (USDC).
    ///
    /// All-or-nothing: any failure (insufficient XLM reserves, unregistered asset,
    /// bad proof) reverts the whole tx, so the nullifier is never spent without the
    /// user receiving XLM (spec §7.3).
    pub fn rfq_settle_atomic_swap(
        env: Env,
        user_xlm_recipient: Address,
        solver_usdc_recipient: Address,
        proof_bytes: Bytes,
        pub_signals_bytes: Bytes,
        quote_hash: BytesN<32>,
        intent_hash: BytesN<32>,
        fill_receipt_hash: BytesN<32>,
        output_asset_id: BytesN<32>,
        quoted_output: i128,
        min_output: i128,
        price_scaled: i128,
        solver_pubkey: BytesN<32>,
        solver_sig: BytesN<64>,
    ) {
        Self::require_not_paused(&env);

        // Solver must be in the authorized-solver registry.
        if !env.storage().persistent().get(&DataKey::Solver(solver_pubkey.clone())).unwrap_or(false) {
            panic_err(&env, Error::UnauthorizedSolver);
        }
        // Output amounts sane and quote satisfied (spec §7.6: actual >= min).
        if quoted_output <= 0 || min_output <= 0 || quoted_output < min_output || price_scaled <= 0 {
            panic_err(&env, Error::UnderDelivered);
        }

        // Bind the solver to the EXACT swap terms: accepted quote hash + output
        // asset + quoted/min output + price + recipient. Any relayer mutation of
        // these breaks the signature (spec §7.7/§7.8).
        let recipient_h = Self::recipient_hash(&env, &user_xlm_recipient);
        let mut terms = Bytes::new(&env);
        terms.extend_from_array(&quote_hash.to_array());
        terms.extend_from_array(&output_asset_id.to_array());
        terms.extend_from_array(&quoted_output.to_be_bytes());
        terms.extend_from_array(&min_output.to_be_bytes());
        terms.extend_from_array(&price_scaled.to_be_bytes());
        terms.extend_from_array(&recipient_h.to_array());
        let swap_hash: [u8; 32] = env.crypto().sha256(&terms).to_array();
        env.crypto().ed25519_verify(&solver_pubkey, &Bytes::from_array(&env, &swap_hash), &solver_sig);

        // Parse + validate the user's note proof.
        let signals = parse_public_signals(&env, &pub_signals_bytes);
        let op_type: i128 = fr32_to_i128(&signals.get(1).unwrap());
        let nullifier_hash: BytesN<32> = signals.get(0).unwrap();
        let withdrawn_value: i128 = fr32_to_i128(&signals.get(2).unwrap());
        let relayer_fee: i128 = fr32_to_i128(&signals.get(4).unwrap());
        let deadline_ledger: i128 = fr32_to_i128(&signals.get(5).unwrap());
        let state_root: BytesN<32> = signals.get(6).unwrap();
        let input_asset_id: BytesN<32> = signals.get(17).unwrap();

        if op_type != OP_RFQ_ATOMIC_SWAP {
            panic_err(&env, Error::WrongOperation);
        }
        if withdrawn_value <= 0 || relayer_fee < 0 || relayer_fee > withdrawn_value {
            panic_err(&env, Error::BadAmount);
        }
        if (env.ledger().sequence() as i128) > deadline_ledger {
            panic_err(&env, Error::Expired);
        }
        // Fixed-point price rule (spec §7.6): quoted output must equal
        // floor(inputAmount * priceScaled / PRICE_SCALE). inputAmount is the
        // proof-bound withdrawnValue (the USDC the solver is credited against).
        let expected_output = withdrawn_value
            .checked_mul(price_scaled)
            .unwrap_or_else(|| panic_err(&env, Error::BadAmount)) / PRICE_SCALE;
        if quoted_output != expected_output {
            panic_err(&env, Error::WrongPrice);
        }
        // Cross-asset: the output asset must differ from the note's input asset.
        if output_asset_id == input_asset_id {
            panic_err(&env, Error::SameAssetSwap);
        }
        // Proof commits to quote/intent/fill so the note is bound to this quote.
        if Self::hash_to_field(&env, &quote_hash) != signals.get(10).unwrap() {
            panic_err(&env, Error::WrongQuote);
        }
        if Self::hash_to_field(&env, &intent_hash) != signals.get(11).unwrap() {
            panic_err(&env, Error::WrongIntent);
        }
        if Self::hash_to_field(&env, &fill_receipt_hash) != signals.get(12).unwrap() {
            panic_err(&env, Error::WrongFillReceipt);
        }
        Self::check_domain_compliance(&env, &signals);
        if !env.storage().persistent().get(&DataKey::KnownRoot(state_root.clone())).unwrap_or(false) {
            panic_err(&env, Error::UnknownRoot);
        }

        // Verify the note-ownership proof.
        let verifier: Address = env.storage().instance().get(&VERIFIER).unwrap();
        let ok: bool = env.invoke_contract(&verifier, &Symbol::new(&env, "verify"),
            vec![&env, proof_bytes.to_val(), pub_signals_bytes.to_val()]);
        if !ok { panic_err(&env, Error::ProofInvalid); }

        // Spend the user's USDC nullifier exactly once.
        let nullreg: Address = env.storage().instance().get(&NULLREG).unwrap();
        let _: bool = env.invoke_contract(&nullreg, &Symbol::new(&env, "spend"),
            vec![&env, env.current_contract_address().to_val(), nullifier_hash.clone().to_val()]);

        // Deliver the OUTPUT asset (XLM) to the user from pool reserves. Fails
        // closed on an unregistered asset or insufficient reserves — reverting the
        // whole tx (including the nullifier spend).
        let out_token: Address = Self::get_asset_token(env.clone(), output_asset_id.clone());
        let out_client = token::TokenClient::new(&env, &out_token);
        if out_client.balance(&env.current_contract_address()) < quoted_output {
            panic_err(&env, Error::InsufficientBalance);
        }
        out_client.transfer(&env.current_contract_address(), &user_xlm_recipient, &quoted_output);

        // Credit the solver in the INPUT asset (USDC). Solver receives funds only
        // after the user's XLM has been delivered above.
        let credit = withdrawn_value - relayer_fee;
        let in_token: Address = Self::get_asset_token(env.clone(), input_asset_id.clone());
        let in_client = token::TokenClient::new(&env, &in_token);
        if in_client.balance(&env.current_contract_address()) < credit {
            panic_err(&env, Error::InsufficientBalance);
        }
        in_client.transfer(&env.current_contract_address(), &solver_usdc_recipient, &credit);

        // The user's input note leaves the shielded set.
        Self::adjust_note_supply(&env, &input_asset_id, -withdrawn_value);

        env.events().publish((symbol_short!("rfqswap"), quote_hash),
            (user_xlm_recipient, solver_usdc_recipient, nullifier_hash, quoted_output, credit));
    }

    // ---- Phase 8: MPC committee settlement ----

    /// Store the committee's ed25519 signing pubkeys on-chain (admin-only).
    /// Must be called once after deploying the committee before any mpc_settle.
    /// pubkeys: Vec of 32-byte ed25519 public keys (one per committee node).
    pub fn set_committee(env: Env, pubkeys: Vec<BytesN<32>>) {
        Self::require_admin(&env);
        env.storage().instance().set(&MPC_CMTE, &pubkeys);
    }

    /// Return the registered committee pubkeys.
    pub fn get_committee(env: Env) -> Vec<BytesN<32>> {
        env.storage().instance().get(&MPC_CMTE).unwrap_or(Vec::new(&env))
    }

    /// Phase C: set the mpc_settlement Groth16 verifier (admin-only).
    /// Once set, mpc_settle() requires a valid ZK proof alongside the committee sigs.
    pub fn set_mpc_verifier(env: Env, verifier: Address) {
        Self::require_admin(&env);
        env.storage().instance().set(&MPC_VERIFIER, &verifier);
    }

    /// Phase C: return the mpc_settlement verifier address (None = not configured).
    pub fn get_mpc_verifier(env: Env) -> Option<Address> {
        env.storage().instance().get(&MPC_VERIFIER)
    }

    /// Phase 6: set the mpc_priced_settlement Groth16 verifier (admin-only).
    pub fn set_mpc_priced_verifier(env: Env, verifier: Address) {
        Self::require_admin(&env);
        env.storage().instance().set(&MPC_PVERIFIER, &verifier);
    }

    /// Phase 6: return the mpc_priced_settlement verifier address (None = unset).
    pub fn get_mpc_priced_verifier(env: Env) -> Option<Address> {
        env.storage().instance().get(&MPC_PVERIFIER)
    }

    /// Settle one matched pair from a committee-signed batch.
    ///
    /// Verification steps:
    ///   1. Require ≥ ceil(2n/3) valid ed25519 signatures from registered committee nodes.
    ///   2. Verify the Groth16 mpc_settlement proof (MANDATORY once a committee
    ///      exists — B1) and check its public signals match nullifier_a/b,
    ///      output_commitment_a/b, batch_hash, poolId, chainId, the canonical
    ///      associationRoot, and a non-expired deadlineLedger (B2).
    ///   3. Spend nullifier_a and nullifier_b (prevents double-settle / double-withdraw).
    ///   4. Record the new Merkle root (which now includes output_commitment_a + output_commitment_b).
    ///   5. Emit a settlement event so off-chain indexers can credit the output notes.
    ///
    /// Arguments:
    ///   nullifier_a / nullifier_b      — domain-separated nullifiers of the two input notes.
    ///   output_commitment_a / _b       — new note commitments for the two recipients.
    ///   new_root                       — Merkle root after inserting both output commitments off-chain.
    ///   batch_hash                     — sha256 of the canonical match JSON the committee signed.
    ///   signer_pubkeys / signatures    — parallel vecs; each must be a registered committee member.
    ///   proof_bytes / pub_signals_bytes — Groth16 proof (required when mpc_verifier is set).
    pub fn mpc_settle(
        env: Env,
        nullifier_a: BytesN<32>,
        nullifier_b: BytesN<32>,
        output_commitment_a: BytesN<32>,
        output_commitment_b: BytesN<32>,
        new_root: BytesN<32>,
        batch_hash: BytesN<32>,
        signer_pubkeys: Vec<BytesN<32>>,
        signatures: Vec<BytesN<64>>,
        proof_bytes: Option<Bytes>,
        pub_signals_bytes: Option<Bytes>,
    ) {
        Self::require_not_paused(&env);

        // Committee threshold over DISTINCT registered signers.
        Self::verify_committee_threshold(&env, &batch_hash, &signer_pubkeys, &signatures);

        // Phase C: ZK proof verification (required when mpc_verifier is configured).
        //
        // mpc_settlement public signal layout:
        //   [0] nullifierHashA   [1] nullifierHashB
        //   [2] outputCommitmentA [3] outputCommitmentB
        //   [4] stateRoot         [5] associationRoot
        //   [6] batchHash (= hashToField(batch_hash))
        //   [7] poolId            [8] chainId
        //   [9] matchedAmount7dp  [10] deadlineLedger
        // B1 (spec §5.1): once a committee exists (enforced above), the MPC
        // settlement proof is MANDATORY. The verifier must be configured, both the
        // proof and its public signals must be present, and verification must
        // return true. There is NO fail-open path: an unset verifier or a missing
        // proof aborts the settlement (fail closed).
        let mpc_verifier: Address = env.storage().instance()
            .get::<Symbol, Address>(&MPC_VERIFIER)
            .unwrap_or_else(|| panic_err(&env, Error::MpcProofInvalid));
        let pb = proof_bytes.unwrap_or_else(|| panic_err(&env, Error::MpcProofInvalid));
        let sb = pub_signals_bytes.unwrap_or_else(|| panic_err(&env, Error::MpcProofInvalid));

        let ok: bool = env.invoke_contract(
            &mpc_verifier,
            &Symbol::new(&env, "verify"),
            vec![&env, pb.to_val(), sb.to_val()],
        );
        if !ok {
            panic_err(&env, Error::MpcProofInvalid);
        }

        // Bind proof public signals to the provided call arguments.
        let signals = parse_public_signals(&env, &sb);
        // [0] nullifierHashA must equal nullifier_a
        if signals.get(0).unwrap() != nullifier_a {
            panic_err(&env, Error::MpcSignalMismatch);
        }
        // [1] nullifierHashB must equal nullifier_b
        if signals.get(1).unwrap() != nullifier_b {
            panic_err(&env, Error::MpcSignalMismatch);
        }
        // [2] outputCommitmentA must equal output_commitment_a
        if signals.get(2).unwrap() != output_commitment_a {
            panic_err(&env, Error::MpcSignalMismatch);
        }
        // [3] outputCommitmentB must equal output_commitment_b
        if signals.get(3).unwrap() != output_commitment_b {
            panic_err(&env, Error::MpcSignalMismatch);
        }
        // [4] stateRoot must be a known root (input notes were in this tree)
        let state_root: BytesN<32> = signals.get(4).unwrap();
        if !env.storage().persistent().get(&DataKey::KnownRoot(state_root)).unwrap_or(false) {
            panic_err(&env, Error::UnknownRoot);
        }
        // [5] associationRoot must equal the canonical ASP root (B2, spec §5.2).
        // The prover must not choose its own compliance root. A pool with no
        // configured ASP root cannot MPC-settle (fail closed).
        let assoc_root: BytesN<32> = signals.get(5).unwrap();
        let canonical_assoc: BytesN<32> = env.storage().instance()
            .get(&ASSOCROOT)
            .unwrap_or_else(|| panic_err(&env, Error::WrongAssociation));
        if assoc_root != canonical_assoc {
            panic_err(&env, Error::WrongAssociation);
        }
        // [6] batchHash field element must match hashToField(batch_hash)
        let batch_hash_field = Self::hash_to_field(&env, &batch_hash);
        if signals.get(6).unwrap() != batch_hash_field {
            panic_err(&env, Error::MpcSignalMismatch);
        }
        // [7][8] poolId and chainId match this contract's domain separators
        let pool_id: u32 = env.storage().instance().get(&POOLID).unwrap();
        let chain_id: u32 = env.storage().instance().get(&CHAINID).unwrap();
        let pool_in: i128 = fr32_to_i128(&signals.get(7).unwrap());
        let chain_in: i128 = fr32_to_i128(&signals.get(8).unwrap());
        if pool_in != pool_id as i128 || chain_in != chain_id as i128 {
            panic_err(&env, Error::WrongDomain);
        }
        // [10] deadlineLedger must not be in the past (B2, spec §5.2): stale
        // matches must not execute.
        let deadline_ledger: i128 = fr32_to_i128(&signals.get(10).unwrap());
        if (env.ledger().sequence() as i128) > deadline_ledger {
            panic_err(&env, Error::Expired);
        }

        // Spend both nullifiers atomically.  NullifierRegistry.spend panics if already used.
        let nullreg: Address = env.storage().instance().get(&NULLREG).unwrap();
        let _: bool = env.invoke_contract(
            &nullreg,
            &Symbol::new(&env, "spend"),
            vec![&env, env.current_contract_address().to_val(), nullifier_a.clone().to_val()],
        );
        let _: bool = env.invoke_contract(
            &nullreg,
            &Symbol::new(&env, "spend"),
            vec![&env, env.current_contract_address().to_val(), nullifier_b.clone().to_val()],
        );

        // P1 #9 / P3 #19: account for both output commitments (mirrors deposit
        // and private-transfer) so leaf_index/leaf_count stay in sync with the
        // off-chain tree — otherwise the lineage diverges after the first MPC
        // settlement. Commitments themselves are emitted via the event below,
        // not stored on-chain (see LEAF_COUNT_KEY note above).
        let leaf_count: u32 = env.storage().instance().get(&LEAF_COUNT_KEY).unwrap_or(0u32);
        env.storage().instance().set(&LEAF_COUNT_KEY, &(leaf_count + 2));

        // Record the new Merkle root (includes both output commitments inserted off-chain).
        env.storage().persistent().set(&DataKey::KnownRoot(new_root.clone()), &true);
        env.storage().instance().set(&TREE_ROOT_KEY, &new_root);

        // Emit event so indexers credit the two output notes to recipients.
        env.events().publish(
            (symbol_short!("mpc"), batch_hash),
            (nullifier_a, nullifier_b, output_commitment_a, output_commitment_b, new_root),
        );
    }

    /// Phase 6 (spec §10): settle a PRICED CROSS-ASSET committee match. Party A
    /// spends `matched_a` of assetX and receives `matched_b` of assetY; party B
    /// spends `matched_b` of assetY and receives `matched_a` of assetX. The
    /// mpc_priced_settlement proof enforces the fixed-point price and minOutputs
    /// in-circuit; this contract binds the committee threshold, canonical ASP
    /// root, deadline, batch hash, domain, per-asset supply conservation, and the
    /// asset-pair. Fail-closed: the priced verifier + proof are mandatory once a
    /// committee exists.
    ///
    /// Priced public signals (20): [0] nullifierHashA [1] nullifierHashB
    /// [2] outputCommitmentA [3] outputCommitmentB [4] stateRoot [5] associationRoot
    /// [6] batchHash [7] poolId [8] chainId [9] deadlineLedger [10] inputAssetA
    /// [11] outputAssetA [12] inputAssetB [13] outputAssetB [14] matchedAmountA
    /// [15] matchedAmountB [16] priceScaled [17] priceScale [18] minOutputA
    /// [19] minOutputB.
    pub fn mpc_settle_priced(
        env: Env,
        nullifier_a: BytesN<32>,
        nullifier_b: BytesN<32>,
        output_commitment_a: BytesN<32>,
        output_commitment_b: BytesN<32>,
        new_root: BytesN<32>,
        batch_hash: BytesN<32>,
        signer_pubkeys: Vec<BytesN<32>>,
        signatures: Vec<BytesN<64>>,
        proof_bytes: Option<Bytes>,
        pub_signals_bytes: Option<Bytes>,
    ) {
        Self::require_not_paused(&env);

        // Committee threshold over DISTINCT registered signers (same as mpc_settle).
        Self::verify_committee_threshold(&env, &batch_hash, &signer_pubkeys, &signatures);

        // Priced verifier + proof are mandatory (B1, fail-closed).
        let pverifier: Address = env.storage().instance()
            .get::<Symbol, Address>(&MPC_PVERIFIER)
            .unwrap_or_else(|| panic_err(&env, Error::MpcProofInvalid));
        let pb = proof_bytes.unwrap_or_else(|| panic_err(&env, Error::MpcProofInvalid));
        let sb = pub_signals_bytes.unwrap_or_else(|| panic_err(&env, Error::MpcProofInvalid));
        let ok: bool = env.invoke_contract(&pverifier, &Symbol::new(&env, "verify"),
            vec![&env, pb.to_val(), sb.to_val()]);
        if !ok { panic_err(&env, Error::MpcProofInvalid); }

        let signals = parse_public_signals(&env, &sb);
        // Bind the call args to the proof outputs.
        if signals.get(0).unwrap() != nullifier_a { panic_err(&env, Error::MpcSignalMismatch); }
        if signals.get(1).unwrap() != nullifier_b { panic_err(&env, Error::MpcSignalMismatch); }
        if signals.get(2).unwrap() != output_commitment_a { panic_err(&env, Error::MpcSignalMismatch); }
        if signals.get(3).unwrap() != output_commitment_b { panic_err(&env, Error::MpcSignalMismatch); }
        // [4] state root known.
        let state_root: BytesN<32> = signals.get(4).unwrap();
        if !env.storage().persistent().get(&DataKey::KnownRoot(state_root)).unwrap_or(false) {
            panic_err(&env, Error::UnknownRoot);
        }
        // [5] canonical association root (B2).
        let assoc_root: BytesN<32> = signals.get(5).unwrap();
        let canonical: BytesN<32> = env.storage().instance().get(&ASSOCROOT)
            .unwrap_or_else(|| panic_err(&env, Error::WrongAssociation));
        if assoc_root != canonical { panic_err(&env, Error::WrongAssociation); }
        // [6] batch hash field.
        if signals.get(6).unwrap() != Self::hash_to_field(&env, &batch_hash) {
            panic_err(&env, Error::MpcSignalMismatch);
        }
        // [7][8] domain.
        let pool_id: u32 = env.storage().instance().get(&POOLID).unwrap();
        let chain_id: u32 = env.storage().instance().get(&CHAINID).unwrap();
        if fr32_to_i128(&signals.get(7).unwrap()) != pool_id as i128
            || fr32_to_i128(&signals.get(8).unwrap()) != chain_id as i128 {
            panic_err(&env, Error::WrongDomain);
        }
        // [9] deadline (B2).
        if (env.ledger().sequence() as i128) > fr32_to_i128(&signals.get(9).unwrap()) {
            panic_err(&env, Error::Expired);
        }
        // Asset pair: A gives X gets Y, B gives Y gets X, X != Y. The circuit
        // already enforces outputAssetA==inputAssetB and outputAssetB==inputAssetA;
        // here also require both to be REGISTERED assets and a genuine cross-asset.
        let input_a: BytesN<32> = signals.get(10).unwrap();  // X
        let input_b: BytesN<32> = signals.get(12).unwrap();  // Y
        if input_a == input_b { panic_err(&env, Error::NotCrossAsset); }
        // Fail closed on an unregistered asset.
        let _ = Self::get_asset_token(env.clone(), input_a.clone());
        let _ = Self::get_asset_token(env.clone(), input_b.clone());
        let matched_a: i128 = fr32_to_i128(&signals.get(14).unwrap()); // X spent by A
        let matched_b: i128 = fr32_to_i128(&signals.get(15).unwrap()); // Y spent by B

        // Spend both nullifiers once.
        let nullreg: Address = env.storage().instance().get(&NULLREG).unwrap();
        let _: bool = env.invoke_contract(&nullreg, &Symbol::new(&env, "spend"),
            vec![&env, env.current_contract_address().to_val(), nullifier_a.clone().to_val()]);
        let _: bool = env.invoke_contract(&nullreg, &Symbol::new(&env, "spend"),
            vec![&env, env.current_contract_address().to_val(), nullifier_b.clone().to_val()]);

        // Per-asset supply is CONSERVED for a private cross-asset crossing: assetX
        // note A (matched_a) is destroyed and an assetX output note B (matched_a) is
        // created; likewise assetY. Net supply per asset is unchanged, so no
        // adjustment is needed — but assert the amounts are positive.
        if matched_a <= 0 || matched_b <= 0 { panic_err(&env, Error::BadAmount); }

        let leaf_count: u32 = env.storage().instance().get(&LEAF_COUNT_KEY).unwrap_or(0u32);
        env.storage().instance().set(&LEAF_COUNT_KEY, &(leaf_count + 2));
        env.storage().persistent().set(&DataKey::KnownRoot(new_root.clone()), &true);
        env.storage().instance().set(&TREE_ROOT_KEY, &new_root);

        env.events().publish(
            (symbol_short!("mpcprice"), batch_hash),
            (nullifier_a, nullifier_b, output_commitment_a, output_commitment_b, new_root),
        );
    }

    pub fn is_known_root(env: Env, root: BytesN<32>) -> bool {
        env.storage().persistent().get(&DataKey::KnownRoot(root)).unwrap_or(false)
    }

    pub fn get_root(env: Env) -> BytesN<32> {
        env.storage().instance().get(&TREE_ROOT_KEY).unwrap()
    }

    pub fn get_leaf_count(env: Env) -> u32 {
        env.storage().instance().get(&LEAF_COUNT_KEY).unwrap_or(0u32)
    }

    pub fn usdc_balance(env: Env) -> i128 {
        let usdc: Address = env.storage().instance().get(&USDC).unwrap();
        token::TokenClient::new(&env, &usdc).balance(&env.current_contract_address())
    }

    pub fn upgrade(env: Env, new_wasm_hash: soroban_sdk::BytesN<32>) {
        Self::require_admin(&env);
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    pub fn pause(env: Env) {
        Self::require_admin(&env);
        env.storage().instance().set(&PAUSED, &true);
    }
    pub fn unpause(env: Env) {
        Self::require_admin(&env);
        env.storage().instance().set(&PAUSED, &false);
    }

    /// P3 #20: move admin authority to a GovernanceGuardian contract so
    /// `upgrade()` (and every other admin-gated function) is bound by its
    /// quorum + timelock instead of a single key. Same-key-as-before is also
    /// valid (transferring to another plain account) — this is a generic
    /// "rotate admin" primitive, not guardian-specific.
    pub fn transfer_admin(env: Env, new_admin: Address) {
        Self::require_admin(&env);
        env.storage().instance().set(&ADMIN, &new_admin);
    }

    fn require_admin(env: &Env) {
        let admin: Address = env.storage().instance().get(&ADMIN).unwrap();
        admin.require_auth();
    }

    /// Shared committee-signature check used by mpc_settle and mpc_settle_priced.
    /// Requires >= ceil(2n/3) DISTINCT registered committee ed25519 signatures over
    /// `batch_hash`. Duplicate or unregistered signers, or too few, abort the tx.
    fn verify_committee_threshold(
        env: &Env,
        batch_hash: &BytesN<32>,
        signer_pubkeys: &Vec<BytesN<32>>,
        signatures: &Vec<BytesN<64>>,
    ) {
        let committee: Vec<BytesN<32>> = env.storage().instance()
            .get(&MPC_CMTE)
            .unwrap_or_else(|| panic_err(env, Error::NotInitialized));
        if committee.len() == 0 {
            panic_err(env, Error::NotInitialized);
        }
        let n = committee.len() as u32;
        let threshold = (n * 2 + 2) / 3; // ceil(2n/3)
        if signer_pubkeys.len() < threshold || signatures.len() < threshold {
            panic_err(env, Error::MpcThreshold);
        }
        let msg = Bytes::from_array(env, &batch_hash.to_array());
        let mut seen: Vec<BytesN<32>> = Vec::new(env);
        let mut verified: u32 = 0;
        for i in 0..signer_pubkeys.len() {
            let pk: BytesN<32> = signer_pubkeys.get(i).unwrap();
            let mut registered = false;
            for j in 0..committee.len() {
                if committee.get(j).unwrap() == pk { registered = true; break; }
            }
            if !registered { panic_err(env, Error::MpcUnknownSigner); }
            for j in 0..seen.len() {
                if seen.get(j).unwrap() == pk { panic_err(env, Error::MpcDuplicateSigner); }
            }
            seen.push_back(pk.clone());
            let sig: BytesN<64> = signatures.get(i).unwrap();
            env.crypto().ed25519_verify(&pk, &msg, &sig);
            verified += 1;
        }
        if verified < threshold {
            panic_err(env, Error::MpcThreshold);
        }
    }
    fn require_not_paused(env: &Env) {
        if env.storage().instance().get(&PAUSED).unwrap_or(false) {
            panic_err(env, Error::Paused);
        }
    }

    /// Verify the proof's public signals bind this pool's domain (#3) and the
    /// configured ASP allowlist root (#4). Withdraw-family layout (P1.5):
    /// [7]=associationRoot [8]=poolId [9]=chainId
    fn check_domain_compliance(env: &Env, signals: &Vec<BytesN<32>>) {
        let assoc_in: BytesN<32> = signals.get(7).unwrap();
        let pool_in: i128 = fr32_to_i128(&signals.get(8).unwrap());
        let chain_in: i128 = fr32_to_i128(&signals.get(9).unwrap());
        let pool_id: u32 = env.storage().instance().get(&POOLID).unwrap();
        let chain_id: u32 = env.storage().instance().get(&CHAINID).unwrap();
        if pool_in != pool_id as i128 || chain_in != chain_id as i128 {
            panic_err(env, Error::WrongDomain);
        }
        let assoc_expected: BytesN<32> = env.storage().instance().get(&ASSOCROOT).unwrap_or(BytesN::from_array(env, &[0u8; 32]));
        if assoc_in != assoc_expected {
            panic_err(env, Error::WrongAssociation);
        }
    }

    /// P1.5 recipient binding hash: sha256(recipient strkey utf8), high byte
    /// zeroed so the 32-byte value is a valid BLS12-381 field element (matches
    /// the off-chain `recipient_hash = int(sha256(strkey)[:31])`). Recipients are
    /// classic G accounts (56-char strkey) in the current flow.
    fn recipient_hash(env: &Env, to: &Address) -> BytesN<32> {
        let s = to.to_string();
        let mut buf = [0u8; 56];
        s.copy_into_slice(&mut buf);
        let sha: [u8; 32] = env.crypto().sha256(&Bytes::from_slice(env, &buf)).to_array();
        Self::hash_to_field(env, &BytesN::from_array(env, &sha))
    }

    /// Reduce a 32-byte hash to a valid BLS12-381 field element by taking the top
    /// 31 bytes (BE) with the high byte zeroed. Matches the off-chain encoding
    /// `int(sha256(..)[:31])` used for P1.5 recipient and P1.6 quote/intent/fill
    /// bindings (circom2soroban serialises a 248-bit value as `[0x00, b0..b30]`).
    fn hash_to_field(env: &Env, h: &BytesN<32>) -> BytesN<32> {
        let src = h.to_array();
        let mut out = [0u8; 32];
        for i in 0..31 {
            out[i + 1] = src[i];
        }
        BytesN::from_array(env, &out)
    }
}

fn panic_err(env: &Env, e: Error) -> ! {
    soroban_sdk::panic_with_error!(env, e)
}

/// Parse the circom2soroban public-signals layout: u32_be(len) | sig_i(32 BE)...
/// Returns each signal as a 32-byte big-endian value.
fn parse_public_signals(env: &Env, bytes: &Bytes) -> Vec<BytesN<32>> {
    let mut pos: u32 = 0;
    let len = read_u32_be(bytes, &mut pos);
    let mut out = Vec::new(env);
    for _ in 0..len {
        let mut arr = [0u8; 32];
        bytes.slice(pos..pos + 32).copy_into_slice(&mut arr);
        pos += 32;
        out.push_back(BytesN::from_array(env, &arr));
    }
    out
}

fn read_u32_be(bytes: &Bytes, pos: &mut u32) -> u32 {
    let mut arr = [0u8; 4];
    bytes.slice(*pos..*pos + 4).copy_into_slice(&mut arr);
    *pos += 4;
    u32::from_be_bytes(arr)
}

/// Interpret a 32-byte big-endian field value as i128 (low 16 bytes).
/// The circuit range-checks withdrawnValue to 128 bits, so the high 16 are zero.
fn fr32_to_i128(b: &BytesN<32>) -> i128 {
    let arr = b.to_array();
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&arr[16..32]);
    u128::from_be_bytes(lo) as i128
}

mod tests;

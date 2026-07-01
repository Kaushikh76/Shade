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
const STELLAR_CCTP_DOMAIN: i128 = 27; // C6: inbound deposits must target the Stellar CCTP domain

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
const LEAVES_KEY: Symbol = symbol_short!("leaves");

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

#[contracttype]
enum DataKey {
    KnownRoot(BytesN<32>),
    Deposit(BytesN<32>),
    Solver(BytesN<32>), // C4: authorized solver ed25519 pubkey -> allowed
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
        env.storage().instance().set(&LEAVES_KEY, &Vec::<BytesN<32>>::new(&env));
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

        let mut leaves: Vec<BytesN<32>> = env.storage().instance().get(&LEAVES_KEY).unwrap_or(Vec::new(&env));
        let leaf_index = leaves.len();
        leaves.push_back(commitment.clone());
        env.storage().instance().set(&LEAVES_KEY, &leaves);
        env.storage().instance().set(&TREE_ROOT_KEY, &new_root);
        env.storage().persistent().set(&DataKey::KnownRoot(new_root.clone()), &true);
        env.storage().persistent().set(&DataKey::Deposit(cctp_nonce.clone()), &true);
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

        // Release net (withdrawnValue - relayerFee) to the recipient; fee stays.
        let net = withdrawn_value - relayer_fee;
        let usdc: Address = env.storage().instance().get(&USDC).unwrap();
        let client = token::TokenClient::new(&env, &usdc);
        if client.balance(&env.current_contract_address()) < net {
            panic_err(&env, Error::InsufficientBalance);
        }
        client.transfer(&env.current_contract_address(), &to, &net);

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
    ///   [0]=nullifierHash [1]=outputCommitment [2]=feePublic [3]=stateRoot [4]=poolId [5]=chainId
    pub fn private_transfer_settle(env: Env, proof_bytes: Bytes, pub_signals_bytes: Bytes, new_root: BytesN<32>) {
        Self::require_not_paused(&env);
        Self::require_admin(&env); // registrar submits the off-chain-computed new_root

        let signals = parse_public_signals(&env, &pub_signals_bytes);
        let nullifier_hash: BytesN<32> = signals.get(0).unwrap();
        let output_commitment: BytesN<32> = signals.get(1).unwrap();
        let state_root: BytesN<32> = signals.get(3).unwrap();
        // #3 domain check (no ASP binding in the transfer circuit).
        let pool_in: i128 = fr32_to_i128(&signals.get(4).unwrap());
        let chain_in: i128 = fr32_to_i128(&signals.get(5).unwrap());
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
        let mut leaves: Vec<BytesN<32>> = env.storage().instance().get(&LEAVES_KEY).unwrap_or(Vec::new(&env));
        let leaf_index = leaves.len();
        leaves.push_back(output_commitment.clone());
        env.storage().instance().set(&LEAVES_KEY, &leaves);
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
        if amount <= 0 {
            panic_err(&env, Error::BadAmount);
        }
        // P1.7 enforce operation type is WITHDRAW_CCTP.
        if op_type != OP_WITHDRAW_CCTP {
            panic_err(&env, Error::WrongOperation);
        }
        // P1.7 deadline must not be expired.
        if (env.ledger().sequence() as i128) > deadline_ledger {
            panic_err(&env, Error::Expired);
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

    /// Settle one matched pair from a committee-signed batch.
    ///
    /// Verification steps:
    ///   1. Require ≥ ceil(2n/3) valid ed25519 signatures from registered committee nodes.
    ///   2. If mpc_verifier is set (Phase C): verify the Groth16 mpc_settlement proof
    ///      and check its public signals match nullifier_a/b, output_commitment_a/b,
    ///      batch_hash, poolId, and chainId. Proof is mandatory once the verifier is set.
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

        // Load registered committee from contract storage.
        let committee: Vec<BytesN<32>> = env.storage().instance()
            .get(&MPC_CMTE)
            .unwrap_or_else(|| panic_err(&env, Error::NotInitialized));
        if committee.len() == 0 {
            panic_err(&env, Error::NotInitialized);
        }

        // Threshold = ceil(2n/3).
        let n = committee.len() as u32;
        let threshold = (n * 2 + 2) / 3;

        if signer_pubkeys.len() < threshold || signatures.len() < threshold {
            panic_err(&env, Error::MpcThreshold);
        }

        // Verify each provided signature against the registered committee set.
        // ed25519_verify panics if the signature is invalid, aborting the whole tx.
        let msg = Bytes::from_array(&env, &batch_hash.to_array());
        let mut verified: u32 = 0;
        for i in 0..signer_pubkeys.len() {
            let pk: BytesN<32> = signer_pubkeys.get(i).unwrap();
            // Check pk is in the registered committee (linear scan; n ≤ 10 in practice).
            let mut registered = false;
            for j in 0..committee.len() {
                if committee.get(j).unwrap() == pk {
                    registered = true;
                    break;
                }
            }
            if !registered {
                panic_err(&env, Error::MpcUnknownSigner);
            }
            let sig: BytesN<64> = signatures.get(i).unwrap();
            env.crypto().ed25519_verify(&pk, &msg, &sig);
            verified += 1;
        }

        if verified < threshold {
            panic_err(&env, Error::MpcThreshold);
        }

        // Phase C: ZK proof verification (required when mpc_verifier is configured).
        //
        // mpc_settlement public signal layout:
        //   [0] nullifierHashA   [1] nullifierHashB
        //   [2] outputCommitmentA [3] outputCommitmentB
        //   [4] stateRoot         [5] associationRoot
        //   [6] batchHash (= hashToField(batch_hash))
        //   [7] poolId            [8] chainId
        //   [9] matchedAmount7dp  [10] deadlineLedger
        if let Some(mpc_verifier) = env.storage().instance().get::<Symbol, Address>(&MPC_VERIFIER) {
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

        // Record the new Merkle root (includes both output commitments inserted off-chain).
        env.storage().persistent().set(&DataKey::KnownRoot(new_root.clone()), &true);
        env.storage().instance().set(&TREE_ROOT_KEY, &new_root);

        // Emit event so indexers credit the two output notes to recipients.
        env.events().publish(
            (symbol_short!("mpc"), batch_hash),
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
        let leaves: Vec<BytesN<32>> = env.storage().instance().get(&LEAVES_KEY).unwrap_or(Vec::new(&env));
        leaves.len()
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

    fn require_admin(env: &Env) {
        let admin: Address = env.storage().instance().get(&ADMIN).unwrap();
        admin.require_auth();
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

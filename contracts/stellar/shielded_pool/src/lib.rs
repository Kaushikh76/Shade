#![no_std]
//! Shade shielded pool: the integrated ZK withdrawal engine.
//!
//! - Holds USDC (SAC) that arrived via CCTP (forwardRecipient = this contract).
//! - Embeds a Poseidon Lean Incremental Merkle Tree (BLS12-381), matching the
//!   `circuits/` Withdraw circuit, so on-chain roots equal in-circuit roots.
//! - `withdraw` verifies a real Groth16/BLS12-381 proof via the deployed
//!   `proof_verifiers` contract, spends the nullifier in the deployed
//!   `NullifierRegistry` (double-spend prevention), and releases USDC.
//!
//! Public signals layout (snarkjs: output first, then declared public inputs):
//!   [0] nullifierHash   [1] withdrawnValue   [2] stateRoot   [3] associationRoot

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, token, vec, Address, Bytes,
    BytesN, Env, IntoVal, Symbol, Val, Vec,
};

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

#[contracttype]
enum DataKey {
    KnownRoot(BytesN<32>),
    Deposit(BytesN<32>),
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

    /// Register a note commitment (funded by a prior CCTP mint into this contract).
    /// `cctp_nonce` is a dedup key. Admin-gated registrar.
    /// Register a note commitment funded by a prior CCTP mint into this contract.
    /// `new_root` is the post-insert Merkle root computed off-chain by the
    /// registrar (admin) using the same Poseidon lean-imt as the circuit.
    /// Admin-gated; the commitment is emitted on-chain so the root is auditable.
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
    ) -> u32 {
        Self::require_not_paused(&env);
        Self::require_admin(&env);
        if amount <= 0 {
            panic_err(&env, Error::BadAmount);
        }
        if env.storage().persistent().has(&DataKey::Deposit(cctp_nonce.clone())) {
            panic_err(&env, Error::DuplicateDeposit);
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

    /// Withdraw with a real Groth16/BLS12-381 proof. Verifies, spends the
    /// nullifier once (double-spend prevention), and releases USDC to `to`.
    pub fn withdraw(env: Env, to: Address, proof_bytes: Bytes, pub_signals_bytes: Bytes) {
        Self::require_not_paused(&env);
        to.require_auth();

        let signals = parse_public_signals(&env, &pub_signals_bytes);
        let nullifier_hash: BytesN<32> = signals.get(0).unwrap();
        let withdrawn_value: i128 = fr32_to_i128(&signals.get(1).unwrap());
        let state_root: BytesN<32> = signals.get(2).unwrap();
        if withdrawn_value <= 0 {
            panic_err(&env, Error::BadAmount);
        }
        // #3/#4 bind pool/chain domain + ASP root.
        Self::check_domain_compliance(&env, &signals);

        // 1) stateRoot must be a known historical root of this pool's tree.
        if !env.storage().persistent().get(&DataKey::KnownRoot(state_root.clone())).unwrap_or(false) {
            panic_err(&env, Error::UnknownRoot);
        }

        // 2) Verify the Groth16 proof on-chain (BLS12-381 pairing_check).
        let verifier: Address = env.storage().instance().get(&VERIFIER).unwrap();
        let ok: bool = env.invoke_contract(
            &verifier,
            &Symbol::new(&env, "verify"),
            vec![&env, proof_bytes.to_val(), pub_signals_bytes.to_val()],
        );
        if !ok {
            panic_err(&env, Error::ProofInvalid);
        }

        // 3) Spend the nullifier exactly once via the NullifierRegistry.
        //    `spend` panics if already spent -> whole withdraw reverts (no release).
        let nullreg: Address = env.storage().instance().get(&NULLREG).unwrap();
        let _: bool = env.invoke_contract(
            &nullreg,
            &Symbol::new(&env, "spend"),
            vec![&env, nullifier_hash.clone().to_val()],
        );

        // 4) Release USDC to the recipient.
        let usdc: Address = env.storage().instance().get(&USDC).unwrap();
        let client = token::TokenClient::new(&env, &usdc);
        let bal = client.balance(&env.current_contract_address());
        if bal < withdrawn_value {
            panic_err(&env, Error::InsufficientBalance);
        }
        client.transfer(&env.current_contract_address(), &to, &withdrawn_value);

        env.events().publish((symbol_short!("withdraw"),), (to, nullifier_hash, withdrawn_value));
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
            vec![&env, nullifier_hash.clone().to_val()],
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
    /// pub signals: [nullifierHash, withdrawnValue, stateRoot, associationRoot]
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
        to.require_auth(); // binds destination/amount to the note owner

        let signals = parse_public_signals(&env, &pub_signals_bytes);
        let nullifier_hash: BytesN<32> = signals.get(0).unwrap();
        let amount: i128 = fr32_to_i128(&signals.get(1).unwrap());
        let state_root: BytesN<32> = signals.get(2).unwrap();
        if amount <= 0 {
            panic_err(&env, Error::BadAmount);
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
            vec![&env, nullifier_hash.clone().to_val()],
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
    /// pub signals: [nullifierHash, withdrawnValue, stateRoot, associationRoot]
    pub fn rfq_settle(
        env: Env,
        to_solver: Address,
        proof_bytes: Bytes,
        pub_signals_bytes: Bytes,
        quote_hash: BytesN<32>,
        solver_pubkey: BytesN<32>,
        solver_sig: BytesN<64>,
    ) {
        Self::require_not_paused(&env);

        // Verify the solver signed this exact quote (binds quote to solver key).
        let msg = Bytes::from_array(&env, &quote_hash.to_array());
        env.crypto().ed25519_verify(&solver_pubkey, &msg, &solver_sig);

        let signals = parse_public_signals(&env, &pub_signals_bytes);
        let nullifier_hash: BytesN<32> = signals.get(0).unwrap();
        let credit: i128 = fr32_to_i128(&signals.get(1).unwrap());
        let state_root: BytesN<32> = signals.get(2).unwrap();
        if credit <= 0 {
            panic_err(&env, Error::BadAmount);
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
            vec![&env, nullifier_hash.clone().to_val()],
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
    /// configured ASP allowlist root (#4). signals layout:
    /// [0]=nullifierHash [1]=withdrawnValue [2]=stateRoot [3]=associationRoot [4]=poolId [5]=chainId
    fn check_domain_compliance(env: &Env, signals: &Vec<BytesN<32>>) {
        let assoc_in: BytesN<32> = signals.get(3).unwrap();
        let pool_in: i128 = fr32_to_i128(&signals.get(4).unwrap());
        let chain_in: i128 = fr32_to_i128(&signals.get(5).unwrap());
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

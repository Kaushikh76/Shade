#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, BytesN, Env, String, Symbol, Vec, symbol_short};

#[contracttype]
enum DataKey {
    Admin,
    Paused,
    UsdcSac,
    Tree,
    Nullifiers,
    Compliance,
    Deposit(BytesN<32>),
}

#[contract]
pub struct ShadeVault;

#[contractimpl]
impl ShadeVault {
    pub fn initialize(env: Env, admin: Address, usdc_sac: Address, tree: Address, nullifiers: Address, compliance_registry: Address) {
        if env.storage().instance().has(&DataKey::Admin) { panic!("already initialized"); }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().set(&DataKey::UsdcSac, &usdc_sac);
        env.storage().instance().set(&DataKey::Tree, &tree);
        env.storage().instance().set(&DataKey::Nullifiers, &nullifiers);
        env.storage().instance().set(&DataKey::Compliance, &compliance_registry);
    }

    pub fn receive_cctp_deposit(env: Env, source_domain: u32, cctp_nonce: BytesN<32>, asset: Address, amount: i128, commitment: BytesN<32>, encrypted_note_payload_hash: BytesN<32>, policy_id: BytesN<32>) -> u32 {
        Self::require_not_paused(&env);
        if amount <= 0 { panic!("amount"); }
        if env.storage().persistent().has(&DataKey::Deposit(cctp_nonce.clone())) { panic!("duplicate cctp nonce"); }
        let tree: Address = env.storage().instance().get(&DataKey::Tree).unwrap();
        let result: (u32, BytesN<32>) = env.invoke_contract(&tree, &Symbol::new(&env, "append"), Vec::from_array(&env, [commitment.to_val()]));
        env.storage().persistent().set(&DataKey::Deposit(cctp_nonce.clone()), &true);
        env.events().publish((symbol_short!("deposit"), source_domain), (cctp_nonce, asset, amount, commitment, encrypted_note_payload_hash, policy_id, result.0, result.1));
        result.0
    }

    pub fn private_transfer_settle(env: Env, verifier_id: Address, proof: Bytes, public_inputs: Bytes) -> BytesN<32> {
        Self::verify(&env, verifier_id, proof, public_inputs)
    }

    pub fn withdraw_public(env: Env, proof: Bytes, public_inputs: Bytes, recipient: Address) -> BytesN<32> {
        Self::require_not_paused(&env);
        if proof.len() == 0 || public_inputs.len() == 0 { panic!("empty proof"); }
        env.events().publish((symbol_short!("withdraw"),), recipient);
        env.crypto().sha256(&public_inputs).into()
    }

    pub fn withdraw_cctp(env: Env, proof: Bytes, public_inputs: Bytes, destination_domain: u32, destination_recipient: BytesN<32>) -> BytesN<32> {
        Self::require_not_paused(&env);
        if proof.len() == 0 || public_inputs.len() == 0 { panic!("empty proof"); }
        env.events().publish((symbol_short!("cctpexit"), destination_domain), destination_recipient);
        env.crypto().sha256(&public_inputs).into()
    }

    pub fn rfq_settle(env: Env, proof: Bytes, public_inputs: Bytes, quote_hash: BytesN<32>, solver_id: String) -> BytesN<32> {
        Self::require_not_paused(&env);
        if proof.len() == 0 || public_inputs.len() == 0 { panic!("empty proof"); }
        env.events().publish((symbol_short!("rfq"), quote_hash), solver_id);
        env.crypto().sha256(&public_inputs).into()
    }

    pub fn solver_claim_or_credit(env: Env, proof: Bytes, public_inputs: Bytes) -> BytesN<32> {
        Self::require_not_paused(&env);
        if proof.len() == 0 || public_inputs.len() == 0 { panic!("empty proof"); }
        env.crypto().sha256(&public_inputs).into()
    }

    pub fn pause(env: Env, reason_hash: BytesN<32>) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Paused, &true);
        env.events().publish((symbol_short!("pause"),), reason_hash);
    }

    pub fn unpause(env: Env) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Paused, &false);
    }

    fn verify(env: &Env, verifier_id: Address, proof: Bytes, public_inputs: Bytes) -> BytesN<32> {
        Self::require_not_paused(env);
        if proof.len() == 0 || public_inputs.len() == 0 { panic!("empty proof"); }
        let ok: bool = env.invoke_contract(&verifier_id, &Symbol::new(env, "verify"), Vec::from_array(env, [proof.to_val(), public_inputs.to_val()]));
        if !ok { panic!("proof failed"); }
        env.crypto().sha256(&public_inputs).into()
    }

    fn require_admin(env: &Env) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
    }

    fn require_not_paused(env: &Env) {
        let paused: bool = env.storage().instance().get(&DataKey::Paused).unwrap_or(false);
        if paused { panic!("paused"); }
    }
}

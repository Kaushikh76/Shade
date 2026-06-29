#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, Symbol, Vec};

#[contracttype]
enum DataKey {
    Admin,
    Guardian,
}

#[contract]
pub struct GovernanceGuardian;

#[contractimpl]
impl GovernanceGuardian {
    pub fn initialize(env: Env, admin: Address, guardian: Address) {
        if env.storage().instance().has(&DataKey::Admin) { panic!("already initialized"); }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Guardian, &guardian);
    }

    pub fn pause_contract(env: Env, contract_id: Address, reason_hash: BytesN<32>) {
        Self::require_guardian(&env);
        let _: () = env.invoke_contract(&contract_id, &Symbol::new(&env, "pause"), Vec::from_array(&env, [reason_hash.to_val()]));
    }

    pub fn unpause_contract(env: Env, contract_id: Address) {
        Self::require_guardian(&env);
        let _: () = env.invoke_contract(&contract_id, &Symbol::new(&env, "unpause"), Vec::new(&env));
    }

    fn require_guardian(env: &Env) {
        let guardian: Address = env.storage().instance().get(&DataKey::Guardian).unwrap();
        guardian.require_auth();
    }
}

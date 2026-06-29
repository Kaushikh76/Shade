#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, symbol_short};

#[contracttype]
enum DataKey {
    Admin,
    Paused,
    Spent(BytesN<32>),
}

#[contract]
pub struct NullifierRegistry;

#[contractimpl]
impl NullifierRegistry {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) { panic!("already initialized"); }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
    }

    pub fn spend(env: Env, nullifier: BytesN<32>) -> bool {
        Self::require_not_paused(&env);
        if Self::is_spent(env.clone(), nullifier.clone()) { panic!("nullifier spent"); }
        env.storage().persistent().set(&DataKey::Spent(nullifier.clone()), &true);
        env.events().publish((symbol_short!("spend"),), nullifier);
        true
    }

    pub fn is_spent(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage().persistent().get(&DataKey::Spent(nullifier)).unwrap_or(false)
    }

    pub fn pause(env: Env) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Paused, &true);
    }

    pub fn unpause(env: Env) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Paused, &false);
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

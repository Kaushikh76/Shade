#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};

#[contracttype]
#[derive(Clone)]
pub struct Policy {
    pub allow_root: BytesN<32>,
    pub deny_root: BytesN<32>,
    pub valid_from: u32,
    pub valid_until: u32,
    pub rules_hash: BytesN<32>,
}

#[contracttype]
enum DataKey {
    Admin,
    Policy(BytesN<32>),
}

#[contract]
pub struct ComplianceRegistry;

#[contractimpl]
impl ComplianceRegistry {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) { panic!("already initialized"); }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn set_policy(env: Env, policy_id: BytesN<32>, allow_root: BytesN<32>, deny_root: BytesN<32>, valid_from: u32, valid_until: u32, rules_hash: BytesN<32>) {
        Self::require_admin(&env);
        if valid_until <= valid_from { panic!("invalid validity"); }
        let policy = Policy { allow_root, deny_root, valid_from, valid_until, rules_hash };
        env.storage().persistent().set(&DataKey::Policy(policy_id), &policy);
    }

    pub fn get_policy(env: Env, policy_id: BytesN<32>) -> Policy {
        env.storage().persistent().get(&DataKey::Policy(policy_id)).unwrap()
    }

    pub fn is_policy_active(env: Env, policy_id: BytesN<32>) -> bool {
        let policy: Option<Policy> = env.storage().persistent().get(&DataKey::Policy(policy_id));
        match policy {
            Some(p) => {
                let ledger = env.ledger().sequence();
                ledger >= p.valid_from && ledger <= p.valid_until
            }
            None => false,
        }
    }

    fn require_admin(env: &Env) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
    }
}

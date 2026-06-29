#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, symbol_short};

#[contracttype]
enum DataKey {
    Admin,
    Depth,
    Paused,
    Count,
    LatestRoot,
    Leaf(u32),
    KnownRoot(BytesN<32>),
}

#[contract]
pub struct CommitmentTree;

#[contractimpl]
impl CommitmentTree {
    pub fn initialize(env: Env, admin: Address, depth: u32) {
        if env.storage().instance().has(&DataKey::Admin) { panic!("already initialized"); }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Depth, &depth);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().set(&DataKey::Count, &0u32);
        let zero = BytesN::from_array(&env, &[0u8; 32]);
        env.storage().instance().set(&DataKey::LatestRoot, &zero);
        env.storage().persistent().set(&DataKey::KnownRoot(zero), &true);
    }

    pub fn append(env: Env, commitment: BytesN<32>) -> (u32, BytesN<32>) {
        Self::require_not_paused(&env);
        let count: u32 = env.storage().instance().get(&DataKey::Count).unwrap_or(0);
        if env.storage().persistent().has(&DataKey::Leaf(count)) { panic!("leaf exists"); }
        let previous: BytesN<32> = env.storage().instance().get(&DataKey::LatestRoot).unwrap();
        let new_root: BytesN<32> = env.crypto().sha256(&Self::concat(&env, previous, commitment.clone())).into();
        env.storage().persistent().set(&DataKey::Leaf(count), &commitment);
        env.storage().persistent().set(&DataKey::KnownRoot(new_root.clone()), &true);
        env.storage().instance().set(&DataKey::LatestRoot, &new_root);
        env.storage().instance().set(&DataKey::Count, &(count + 1));
        env.events().publish((symbol_short!("append"), count), commitment);
        env.events().publish((symbol_short!("root"), count), new_root.clone());
        (count, new_root)
    }

    pub fn is_known_root(env: Env, root: BytesN<32>) -> bool {
        env.storage().persistent().get(&DataKey::KnownRoot(root)).unwrap_or(false)
    }

    pub fn get_latest_root(env: Env) -> BytesN<32> {
        env.storage().instance().get(&DataKey::LatestRoot).unwrap()
    }

    pub fn get_leaf_count(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::Count).unwrap_or(0)
    }

    pub fn get_leaf(env: Env, index: u32) -> BytesN<32> {
        env.storage().persistent().get(&DataKey::Leaf(index)).unwrap()
    }

    pub fn pause(env: Env) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Paused, &true);
    }

    pub fn unpause(env: Env) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Paused, &false);
    }

    fn concat(env: &Env, a: BytesN<32>, b: BytesN<32>) -> soroban_sdk::Bytes {
        let mut out = soroban_sdk::Bytes::new(env);
        out.append(&soroban_sdk::Bytes::from(a));
        out.append(&soroban_sdk::Bytes::from(b));
        out
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

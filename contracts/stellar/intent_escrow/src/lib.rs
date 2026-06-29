#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, BytesN, Env, String, symbol_short};

#[contracttype]
enum DataKey {
    Admin,
    Vault,
    Nullifiers,
    Intent(BytesN<32>),
    Quote(BytesN<32>),
    Accepted(BytesN<32>),
    Lock(BytesN<32>),
    Failed(BytesN<32>),
}

#[contracttype]
#[derive(Clone)]
pub struct Intent {
    expiry_ledger: u32,
    policy_id: BytesN<32>,
    intent_commitment: BytesN<32>,
}

#[contracttype]
#[derive(Clone)]
pub struct Quote {
    solver_id: String,
    valid_until_ledger: u32,
}

#[contract]
pub struct IntentEscrow;

#[contractimpl]
impl IntentEscrow {
    pub fn initialize(env: Env, admin: Address, vault: Address, nullifier_registry: Address) {
        if env.storage().instance().has(&DataKey::Admin) { panic!("already initialized"); }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Vault, &vault);
        env.storage().instance().set(&DataKey::Nullifiers, &nullifier_registry);
    }

    pub fn register_intent(env: Env, intent_hash: BytesN<32>, expiry_ledger: u32, policy_id: BytesN<32>, intent_commitment: BytesN<32>) {
        if env.storage().persistent().has(&DataKey::Intent(intent_hash.clone())) { panic!("intent exists"); }
        env.storage().persistent().set(&DataKey::Intent(intent_hash.clone()), &Intent { expiry_ledger, policy_id, intent_commitment });
        env.events().publish((symbol_short!("intent"),), intent_hash);
    }

    pub fn register_quote(env: Env, quote_hash: BytesN<32>, solver_id: String, valid_until_ledger: u32) {
        if env.ledger().sequence() > valid_until_ledger { panic!("expired"); }
        if env.storage().persistent().has(&DataKey::Quote(quote_hash.clone())) { panic!("quote exists"); }
        env.storage().persistent().set(&DataKey::Quote(quote_hash.clone()), &Quote { solver_id, valid_until_ledger });
        env.events().publish((symbol_short!("quote"),), quote_hash);
    }

    pub fn accept_quote(env: Env, intent_hash: BytesN<32>, quote_hash: BytesN<32>, user_signature_hash: BytesN<32>) {
        let intent: Intent = env.storage().persistent().get(&DataKey::Intent(intent_hash.clone())).unwrap();
        let quote: Quote = env.storage().persistent().get(&DataKey::Quote(quote_hash.clone())).unwrap();
        if env.ledger().sequence() > intent.expiry_ledger || env.ledger().sequence() > quote.valid_until_ledger { panic!("expired"); }
        if env.storage().persistent().has(&DataKey::Accepted(intent_hash.clone())) { panic!("already accepted"); }
        env.storage().persistent().set(&DataKey::Accepted(intent_hash.clone()), &(quote_hash.clone(), user_signature_hash));
        env.events().publish((symbol_short!("accept"), intent_hash), quote_hash);
    }

    pub fn lock_solver_inventory(env: Env, quote_hash: BytesN<32>, lock_hash: BytesN<32>) {
        if !env.storage().persistent().has(&DataKey::Quote(quote_hash.clone())) { panic!("quote missing"); }
        env.storage().persistent().set(&DataKey::Lock(quote_hash.clone()), &lock_hash);
        env.events().publish((symbol_short!("lock"), quote_hash), lock_hash);
    }

    pub fn settle_rfq(env: Env, proof: Bytes, public_inputs: Bytes) -> BytesN<32> {
        if proof.len() == 0 || public_inputs.len() == 0 { panic!("empty proof"); }
        env.crypto().sha256(&public_inputs).into()
    }

    pub fn mark_failed_recoverable(env: Env, intent_hash: BytesN<32>, reason_hash: BytesN<32>) {
        env.storage().persistent().set(&DataKey::Failed(intent_hash.clone()), &reason_hash);
        env.events().publish((symbol_short!("fail"), intent_hash), reason_hash);
    }
}

#![cfg(test)]
//! P0 #1 adversarial tests: the 2-of-3 committee threshold must be counted over
//! DISTINCT signer pubkeys. A single leaked/compromised key replayed twice must
//! never satisfy the threshold on its own.

use crate::*;
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::testutils::Address as _;

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

#[test]
fn mpc_settle_accepts_distinct_signers_at_threshold() {
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
    assert!(result.is_ok(), "two distinct valid committee signatures must meet the 2-of-3 threshold");
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

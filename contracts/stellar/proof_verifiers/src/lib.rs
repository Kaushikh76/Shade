#![no_std]
//! Real Groth16 verifier over BLS12-381, using Soroban's native BLS12-381 host
//! functions (env.crypto().bls12_381()). Serialization is byte-compatible with
//! arkworks `serialize_uncompressed`, matching the official Stellar
//! `circom2soroban` tool and `groth16_verifier` / `privacy-pools` examples.
//!
//! The verifying key is fixed at construction (one verifier instance per circuit).
//! `verify(proof_bytes, pub_signals_bytes) -> bool` is the integration point
//! called by ShadeVault / IntentEscrow via cross-contract invocation.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    crypto::bls12_381::{Fr, G1Affine, G2Affine, G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE},
    vec, Bytes, BytesN, Env, U256, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VerifierError {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    MalformedVerifyingKey = 3,
    MalformedProof = 4,
}

#[contracttype]
enum DataKey {
    Vk,
}

#[contract]
pub struct ProofVerifier;

struct VerificationKey {
    alpha: G1Affine,
    beta: G2Affine,
    gamma: G2Affine,
    delta: G2Affine,
    ic: Vec<G1Affine>,
}

struct Proof {
    a: G1Affine,
    b: G2Affine,
    c: G1Affine,
}

fn take<const N: usize>(bytes: &Bytes, pos: &mut u32) -> [u8; N] {
    let start = *pos;
    let end = start + N as u32;
    let mut arr = [0u8; N];
    bytes.slice(start..end).copy_into_slice(&mut arr);
    *pos = end;
    arr
}

fn vk_from_bytes(env: &Env, bytes: &Bytes) -> VerificationKey {
    let mut pos: u32 = 0;
    let alpha = G1Affine::from_array(env, &take::<G1_SERIALIZED_SIZE>(bytes, &mut pos));
    let beta = G2Affine::from_array(env, &take::<G2_SERIALIZED_SIZE>(bytes, &mut pos));
    let gamma = G2Affine::from_array(env, &take::<G2_SERIALIZED_SIZE>(bytes, &mut pos));
    let delta = G2Affine::from_array(env, &take::<G2_SERIALIZED_SIZE>(bytes, &mut pos));
    let ic_len = u32::from_be_bytes(take::<4>(bytes, &mut pos));
    let mut ic = Vec::new(env);
    for _ in 0..ic_len {
        ic.push_back(G1Affine::from_array(env, &take::<G1_SERIALIZED_SIZE>(bytes, &mut pos)));
    }
    VerificationKey { alpha, beta, gamma, delta, ic }
}

fn proof_from_bytes(env: &Env, bytes: &Bytes) -> Proof {
    let mut pos: u32 = 0;
    let a = G1Affine::from_array(env, &take::<G1_SERIALIZED_SIZE>(bytes, &mut pos));
    let b = G2Affine::from_array(env, &take::<G2_SERIALIZED_SIZE>(bytes, &mut pos));
    let c = G1Affine::from_array(env, &take::<G1_SERIALIZED_SIZE>(bytes, &mut pos));
    Proof { a, b, c }
}

fn public_from_bytes(env: &Env, bytes: &Bytes) -> Vec<Fr> {
    let mut pos: u32 = 0;
    let len = u32::from_be_bytes(take::<4>(bytes, &mut pos));
    let mut signals = Vec::new(env);
    for _ in 0..len {
        let arr = take::<32>(bytes, &mut pos);
        let u256 = U256::from_be_bytes(env, &Bytes::from_array(env, &arr));
        signals.push_back(Fr::from_u256(u256));
    }
    signals
}

#[contractimpl]
impl ProofVerifier {
    /// One verifier per circuit; vk_bytes is the circom2soroban-encoded verifying key.
    pub fn __constructor(env: Env, vk_bytes: Bytes) {
        env.storage().instance().set(&DataKey::Vk, &vk_bytes);
    }

    /// Allow re-pointing the vk (admin-less testnet helper; guard in production).
    pub fn set_vk(env: Env, vk_bytes: Bytes) {
        env.storage().instance().set(&DataKey::Vk, &vk_bytes);
    }

    pub fn vk_hash(env: Env) -> BytesN<32> {
        let vk: Bytes = env.storage().instance().get(&DataKey::Vk).unwrap();
        env.crypto().sha256(&vk).into()
    }

    /// Verifies a Groth16 proof against the stored verifying key.
    /// proof_bytes / pub_signals_bytes use the circom2soroban byte layout.
    pub fn verify(env: Env, proof: Bytes, public_inputs: Bytes) -> bool {
        if proof.len() == 0 || public_inputs.len() == 0 {
            return false;
        }
        let vk_bytes: Bytes = match env.storage().instance().get(&DataKey::Vk) {
            Some(b) => b,
            None => return false,
        };
        let vk = vk_from_bytes(&env, &vk_bytes);
        let proof = proof_from_bytes(&env, &proof);
        let pub_signals = public_from_bytes(&env, &public_inputs);

        if pub_signals.len() + 1 != vk.ic.len() {
            return false;
        }

        let bls = env.crypto().bls12_381();
        // vk_x = ic[0] + sum(pub_signals[i] * ic[i+1])
        let mut vk_x = vk.ic.get(0).unwrap();
        for (s, v) in pub_signals.iter().zip(vk.ic.iter().skip(1)) {
            let prod = bls.g1_mul(&v, &s);
            vk_x = bls.g1_add(&vk_x, &prod);
        }
        // e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
        let neg_a = -proof.a;
        let vp1 = vec![&env, neg_a, vk.alpha, vk_x, proof.c];
        let vp2 = vec![&env, proof.b, vk.beta, vk.gamma, vk.delta];
        bls.pairing_check(vp1, vp2)
    }
}

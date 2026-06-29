//! Converts snarkjs BLS12-381 Groth16 artifacts (verification_key.json /
//! proof.json / public.json) into the byte layout consumed by the Shade
//! `proof_verifiers` Soroban contract.
//!
//! Byte layout (matches arkworks `serialize_uncompressed`, i.e. the Soroban
//! BLS12-381 host `G1Affine::from_array` / `G2Affine::from_array` format):
//!   VK     = alpha(96) | beta(192) | gamma(192) | delta(192) | u32_be(ic_len) | ic[i](96)...
//!   Proof  = a(96) | b(192) | c(96)
//!   Public = u32_be(len) | signal_i(32 BE)...
//!
//! G1 = serialize_uncompressed(G1Affine(Fq(x), Fq(y)))            -> 96 bytes
//! G2 = serialize_uncompressed(G2Affine(Fq2(x_c0,x_c1), Fq2(y_c0,y_c1))) -> 192 bytes
//!
//! Vendored from the Apache-2.0 stellar/soroban-examples `circom2soroban`,
//! reduced to a dependency-free (no soroban-sdk) host tool.

use ark_bls12_381::{Fq, Fq2, G1Affine, G2Affine};
use ark_serialize::CanonicalSerialize;
use core::str::FromStr;
use num_bigint::BigUint;
use num_traits::Num;
use serde::Deserialize;
use std::env;
use std::fs;

#[derive(Deserialize)]
struct VerificationKeyJson {
    vk_alpha_1: [String; 3],
    vk_beta_2: [[String; 2]; 3],
    vk_gamma_2: [[String; 2]; 3],
    vk_delta_2: [[String; 2]; 3],
    #[serde(rename = "IC")]
    ic: Vec<[String; 3]>,
    #[serde(rename = "nPublic")]
    n_public: u32,
}

#[derive(Deserialize)]
struct ProofJson {
    pi_a: [String; 3],
    pi_b: [[String; 2]; 3],
    pi_c: [String; 3],
}

fn g1_bytes(x: &str, y: &str) -> Vec<u8> {
    let p = G1Affine::new(Fq::from_str(x).unwrap(), Fq::from_str(y).unwrap());
    let mut buf = Vec::new();
    p.serialize_uncompressed(&mut buf).unwrap();
    assert_eq!(buf.len(), 96, "G1 serialized size");
    buf
}

fn g2_bytes(x1: &str, x2: &str, y1: &str, y2: &str) -> Vec<u8> {
    let x = Fq2::new(Fq::from_str(x1).unwrap(), Fq::from_str(x2).unwrap());
    let y = Fq2::new(Fq::from_str(y1).unwrap(), Fq::from_str(y2).unwrap());
    let p = G2Affine::new(x, y);
    let mut buf = Vec::new();
    p.serialize_uncompressed(&mut buf).unwrap();
    assert_eq!(buf.len(), 192, "G2 serialized size");
    buf
}

fn vk_to_bytes(json: &str) -> Vec<u8> {
    let vk: VerificationKeyJson = serde_json::from_str(json).expect("invalid vk json");
    assert_eq!(vk.ic.len() as u32, vk.n_public + 1, "IC length must be nPublic+1");
    let mut out = Vec::new();
    out.extend(g1_bytes(&vk.vk_alpha_1[0], &vk.vk_alpha_1[1]));
    out.extend(g2_bytes(&vk.vk_beta_2[0][0], &vk.vk_beta_2[0][1], &vk.vk_beta_2[1][0], &vk.vk_beta_2[1][1]));
    out.extend(g2_bytes(&vk.vk_gamma_2[0][0], &vk.vk_gamma_2[0][1], &vk.vk_gamma_2[1][0], &vk.vk_gamma_2[1][1]));
    out.extend(g2_bytes(&vk.vk_delta_2[0][0], &vk.vk_delta_2[0][1], &vk.vk_delta_2[1][0], &vk.vk_delta_2[1][1]));
    out.extend((vk.ic.len() as u32).to_be_bytes());
    for ic in &vk.ic {
        out.extend(g1_bytes(&ic[0], &ic[1]));
    }
    out
}

fn proof_to_bytes(json: &str) -> Vec<u8> {
    let p: ProofJson = serde_json::from_str(json).expect("invalid proof json");
    let mut out = Vec::new();
    out.extend(g1_bytes(&p.pi_a[0], &p.pi_a[1]));
    out.extend(g2_bytes(&p.pi_b[0][0], &p.pi_b[0][1], &p.pi_b[1][0], &p.pi_b[1][1]));
    out.extend(g1_bytes(&p.pi_c[0], &p.pi_c[1]));
    out
}

fn public_to_bytes(json: &str) -> Vec<u8> {
    let signals: Vec<String> = serde_json::from_str(json).expect("invalid public json");
    let mut out = Vec::new();
    out.extend((signals.len() as u32).to_be_bytes());
    for s in &signals {
        let v = BigUint::from_str_radix(s, 10).unwrap();
        let mut be = v.to_bytes_be();
        assert!(be.len() <= 32, "signal exceeds 32 bytes");
        let mut padded = vec![0u8; 32 - be.len()];
        padded.append(&mut be);
        out.extend(padded);
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: circom2soroban <vk|proof|public> <file.json>");
        std::process::exit(2);
    }
    let json = fs::read_to_string(&args[2]).expect("read file");
    let bytes = match args[1].as_str() {
        "vk" => vk_to_bytes(&json),
        "proof" => proof_to_bytes(&json),
        "public" => public_to_bytes(&json),
        other => {
            eprintln!("unknown filetype: {other}");
            std::process::exit(2);
        }
    };
    println!("{}", hex::encode(&bytes));
}

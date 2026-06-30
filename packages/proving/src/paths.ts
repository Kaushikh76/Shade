import { resolve } from "node:path";
import { mkdirSync } from "node:fs";

// Central, env-overridable path resolution. Fresh clones work with no edits:
// every path defaults relative to SHADE_ROOT (the repo root = process.cwd()).
export const SHADE_ROOT = process.env.SHADE_ROOT || process.cwd();

export const SHADE_SCRATCH_DIR =
  process.env.SHADE_SCRATCH_DIR || resolve(SHADE_ROOT, ".scratch");

// The external soroban-examples clone (coinutils prover + circuit libs). Gitignored;
// see vendor-patches/. Override with SHADE_ZK_REF if cloned elsewhere.
export const ZK_REF =
  process.env.SHADE_ZK_REF || resolve(SHADE_ROOT, ".zk-ref/soroban-examples/privacy-pools");

export const COINUTILS_BIN =
  process.env.COINUTILS_BIN || resolve(ZK_REF, "target/release/stellar-coinutils");

export const CIRCOM2SOROBAN_BIN =
  process.env.CIRCOM2SOROBAN_BIN ||
  resolve(SHADE_ROOT, "tools/circom2soroban/target/release/circom2soroban");

export const CIRCUIT_BUILD_DIR =
  process.env.CIRCUIT_BUILD_DIR || resolve(SHADE_ROOT, "circuits");

export function withdrawCircuitDir(): string {
  return process.env.WITHDRAW_CIRCUIT_DIR || resolve(CIRCUIT_BUILD_DIR, "withdraw_public");
}
export function transferCircuitDir(): string {
  return process.env.TRANSFER_CIRCUIT_DIR || resolve(CIRCUIT_BUILD_DIR, "private_transfer");
}
export function depositCircuitDir(): string {
  return process.env.DEPOSIT_CIRCUIT_DIR || resolve(CIRCUIT_BUILD_DIR, "deposit_note_mint");
}
export function mpcSettlementCircuitDir(): string {
  return process.env.MPC_SETTLEMENT_CIRCUIT_DIR || resolve(CIRCUIT_BUILD_DIR, "mpc_settlement");
}

let scratchEnsured = false;
export function scratchDir(): string {
  if (!scratchEnsured) {
    mkdirSync(SHADE_SCRATCH_DIR, { recursive: true });
    scratchEnsured = true;
  }
  return SHADE_SCRATCH_DIR;
}

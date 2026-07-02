import "dotenv/config";
import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

// Phase C: deploy the mpc_settlement Groth16 verifier and wire it to the shielded pool.
//
// Prerequisites:
//   1. bash circuits/mpc_settlement/build.sh   — produces main_verification_key.json
//   2. npm run contracts:build                  — shielded_pool.wasm must include mpc_settle
//                                                 with proof_bytes + pub_signals_bytes params
//
// What this script does:
//   a) Deploys a new ProofVerifier instance initialized with the mpc_settlement VK.
//   b) Calls pool.set_mpc_verifier(verifier) — once set, mpc_settle() requires a ZK proof.
//   c) Writes MPC_VERIFIER_CONTRACT to .env.generated.
//
// Run: npm run deploy:mpc:verifier
// To skip re-deploy when already set: the script re-uses MPC_VERIFIER_CONTRACT if present.

type EnvMap = Record<string, string>;
const SHADE_ROOT = process.env.SHADE_ROOT ?? process.cwd();
const RPC = process.env.STELLAR_RPC_URL ?? "https://soroban-testnet.stellar.org";
const PASS = process.env.STELLAR_NETWORK_PASSPHRASE ?? "Test SDF Network ; September 2015";
const WASM_DIR = resolve(SHADE_ROOT, "contracts/stellar/target/wasm32v1-none/release");
const C2S_BASE = process.env.CIRCOM2SOROBAN_BIN ?? resolve(SHADE_ROOT, "tools/circom2soroban/target/release/circom2soroban");
const C2S = process.platform === "win32" && !C2S_BASE.endsWith(".exe") ? C2S_BASE + ".exe" : C2S_BASE;
const CARGO_BIN = process.platform === "win32"
  ? `${process.env.USERPROFILE ?? ""}\.cargo\bin`
  : `${process.env.HOME ?? ""}/.cargo/bin`;
const PATH_SEP = process.platform === "win32" ? ";" : ":";
const SH_PATH = `${CARGO_BIN}${PATH_SEP}${process.env.PATH ?? ""}`;

const env = loadEnv(".env.generated");
const deployer = req(env, "STELLAR_DEPLOYER_SECRET");
const deployerPub = req(env, "STELLAR_DEPLOYER_PUBLIC");
const pool = req(env, "SHIELDED_POOL_CONTRACT");

const vkPath = resolve(SHADE_ROOT, "circuits/mpc_settlement/output/main_verification_key.json");
if (!existsSync(vkPath)) {
  throw new Error(
    `mpc_settlement verification key not found: ${vkPath}\n` +
    `Run: bash circuits/mpc_settlement/build.sh`
  );
}

const vkBytes = execFileSync(C2S, ["vk", vkPath], { encoding: "utf8" }).trim();
console.log(`mpc_settlement vk: ${vkBytes.slice(0, 32)}…`);

// Deploy or reuse the MPC verifier.
if (env.MPC_VERIFIER_CONTRACT) {
  console.log(`MPC_VERIFIER_CONTRACT: reuse ${env.MPC_VERIFIER_CONTRACT}`);
} else {
  console.log("Deploying mpc_settlement verifier…");
  const verifierId = deploy(
    resolve(WASM_DIR, "proof_verifiers.wasm"),
    ["--admin", deployerPub, "--vk_bytes", vkBytes],
    deployer
  );
  env.MPC_VERIFIER_CONTRACT = verifierId;
  writeEnv();
  console.log(`MPC_VERIFIER_CONTRACT: ${verifierId}`);
}

// Upgrade the pool wasm BEFORE wiring — set_mpc_verifier only exists in the new wasm.
// Only runs when SHADE_UPGRADE_POOL=1 is explicitly set.
if (process.env.SHADE_UPGRADE_POOL === "1") {
  console.log("Upgrading pool wasm (SHADE_UPGRADE_POOL=1)…");
  const wasmPath = resolve(WASM_DIR, "shielded_pool.wasm");
  invoke(deployer, pool, ["upgrade", "--new_wasm_hash", wasmHash(deployer, wasmPath)]);
  console.log("Pool wasm upgraded.");
}

// Wire the verifier to the pool — once set, all mpc_settle calls require a ZK proof.
console.log(`Wiring pool.set_mpc_verifier(${env.MPC_VERIFIER_CONTRACT})…`);
invoke(deployer, pool, ["set_mpc_verifier", "--verifier", env.MPC_VERIFIER_CONTRACT]);
console.log("Pool wired: mpc_settle now requires a Groth16 proof alongside committee sigs.");

// Phase 6: deploy + wire the mpc_priced_settlement verifier for cross-asset MPC.
const pvkPath = resolve(SHADE_ROOT, "circuits/mpc_priced_settlement/output/main_verification_key.json");
if (existsSync(pvkPath)) {
  if (!env.MPC_PRICED_VERIFIER_CONTRACT) {
    const pvkBytes = execFileSync(C2S, ["vk", pvkPath], { encoding: "utf8" }).trim();
    console.log("Deploying mpc_priced_settlement verifier…");
    env.MPC_PRICED_VERIFIER_CONTRACT = deploy(
      resolve(WASM_DIR, "proof_verifiers.wasm"),
      ["--admin", deployerPub, "--vk_bytes", pvkBytes],
      deployer
    );
    writeEnv();
    console.log(`MPC_PRICED_VERIFIER_CONTRACT: ${env.MPC_PRICED_VERIFIER_CONTRACT}`);
  } else {
    console.log(`MPC_PRICED_VERIFIER_CONTRACT: reuse ${env.MPC_PRICED_VERIFIER_CONTRACT}`);
  }
  console.log(`Wiring pool.set_mpc_priced_verifier(${env.MPC_PRICED_VERIFIER_CONTRACT})…`);
  invoke(deployer, pool, ["set_mpc_priced_verifier", "--verifier", env.MPC_PRICED_VERIFIER_CONTRACT]);
  console.log("Pool wired: mpc_settle_priced now requires a Groth16 proof.");
} else {
  console.log(`mpc_priced_settlement vk not found (${pvkPath}); skipping priced verifier. Run npm run circuits:build.`);
}

console.log("Phase C deploy PASS");

// ---- helpers ----

function wasmHash(secret: string, wasmPath: string): string {
  if (!existsSync(wasmPath)) throw new Error(`missing ${wasmPath}; run npm run contracts:build`);
  for (let i = 0; i < 4; i++) {
    const r = spawnSync(
      "stellar",
      ["contract", "install", "--wasm", wasmPath, "--rpc-url", RPC, "--network-passphrase", PASS],
      { encoding: "utf8", env: { ...process.env, STELLAR_ACCOUNT: secret, PATH: SH_PATH } }
    );
    const hash = `${r.stdout}\n${r.stderr}`.match(/[0-9a-f]{64}/i)?.[0];
    if (hash) return hash;
    sleep(8000);
  }
  throw new Error("wasm install failed");
}

function deploy(wasm: string, ctorArgs: string[], secret: string): string {
  if (!existsSync(wasm)) throw new Error(`missing ${wasm}; run npm run contracts:build`);
  for (let i = 0; i < 4; i++) {
    const r = spawnSync(
      "stellar",
      ["contract", "deploy", "--wasm", wasm, "--rpc-url", RPC, "--network-passphrase", PASS, "--", ...ctorArgs],
      { encoding: "utf8", env: { ...process.env, STELLAR_ACCOUNT: secret, PATH: SH_PATH } }
    );
    const id = `${r.stdout}\n${r.stderr}`.match(/C[A-Z0-9]{55}/)?.[0];
    if (id) return id;
    sleep(8000);
  }
  throw new Error(`deploy failed for ${wasm}`);
}

function invoke(secret: string, contract: string, args: string[]): void {
  for (let i = 0; i < 6; i++) {
    const r = spawnSync(
      "stellar",
      ["contract", "invoke", "--id", contract, "--rpc-url", RPC, "--network-passphrase", PASS, "--send=yes", "--", ...args],
      { encoding: "utf8", env: { ...process.env, STELLAR_ACCOUNT: secret, PATH: SH_PATH } }
    );
    if (r.status === 0) { sleep(2000); return; }
    const out = `${r.stdout}${r.stderr}`;
    if (!/txBadSeq|TxBadSeq|timeout|submission failed|429|temporarily/i.test(out)) {
      throw new Error(`invoke ${args[0]} failed: ${(r.stderr ?? "").slice(0, 200)}`);
    }
    sleep(9000);
  }
  throw new Error(`invoke ${args[0]} failed after retries`);
}

function sleep(ms: number) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
function req(e: EnvMap, k: string): string { if (!e[k]) throw new Error(`${k} required in .env.generated`); return e[k]; }

function loadEnv(p: string): EnvMap {
  const e: EnvMap = { ...process.env } as EnvMap;
  if (existsSync(p)) {
    for (const raw of readFileSync(p, "utf8").split("\n")) {
      const l = raw.replace(/\r$/, "");
      if (l.includes("=") && !l.trimStart().startsWith("#")) {
        const i = l.indexOf("=");
        e[l.slice(0, i)] = l.slice(i + 1);
      }
    }
  }
  return e;
}

function writeEnv() {
  const existing: EnvMap = {};
  if (existsSync(".env.generated")) {
    for (const raw of readFileSync(".env.generated", "utf8").split("\n")) {
      const l = raw.replace(/\r$/, "");
      if (l.includes("=") && !l.trimStart().startsWith("#")) {
        const i = l.indexOf("=");
        existing[l.slice(0, i)] = l.slice(i + 1);
      }
    }
  }
  for (const k of [
    "VERIFIER_WITHDRAW_CONTRACT", "TRANSFER_VERIFIER_CONTRACT",
    "VERIFIER_DEPOSIT_NOTE_MINT_CONTRACT", "SHIELDED_POOL_CONTRACT",
    "MPC_VERIFIER_CONTRACT", "MPC_PRICED_VERIFIER_CONTRACT"
  ]) {
    if (env[k]) existing[k] = env[k];
  }
  const text = Object.entries(existing)
    .filter(([k]) => !k.includes(" "))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");
  writeFileSync(".env.generated", `${text}\n`, { mode: 0o600 });
  chmodSync(".env.generated", 0o600);
}

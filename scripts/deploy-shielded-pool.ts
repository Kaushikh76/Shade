import "dotenv/config";
import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

// C2: deploy the CANONICAL ShadePool stack (the active settlement path) and write
// its contract IDs to .env.generated. This codifies the manual P1.5–P1.8 deploy:
//   - VerifierWithdraw (proof_verifiers, withdraw_public vk, admin-gated)
//   - VerifierTransfer (proof_verifiers, private_transfer vk)
//   - VerifierDepositNoteMint (proof_verifiers, deposit_note_mint vk)
//   - ShieldedPool (constructor: admin, usdc, withdraw verifier, nullreg, depth, pool_id, chain_id)
//   - wiring: nullreg.set_authorized_spender(pool), pool.set_cctp_messenger,
//             set_transfer_verifier, set_deposit_verifier
// Re-deploys the pool when SHADE_REDEPLOY_POOL=1 (or it is absent); verifiers are
// reused if already set. The legacy shade_vault/commitment_tree stack is NOT used.

type EnvMap = Record<string, string>;
const SHADE_ROOT = process.env.SHADE_ROOT ?? process.cwd();
const RPC = process.env.STELLAR_RPC_URL ?? "https://soroban-testnet.stellar.org";
const PASS = process.env.STELLAR_NETWORK_PASSPHRASE ?? "Test SDF Network ; September 2015";
const WASM_DIR = resolve(SHADE_ROOT, "contracts/stellar/target/wasm32v1-none/release");
const C2S_BASE = process.env.CIRCOM2SOROBAN_BIN ?? resolve(SHADE_ROOT, "tools/circom2soroban/target/release/circom2soroban");
const C2S = process.platform === "win32" && !C2S_BASE.endsWith(".exe") ? C2S_BASE + ".exe" : C2S_BASE;
const POOL_ID = process.env.SHADE_POOL_ID ?? "1";
const CHAIN_ID = process.env.SHADE_CHAIN_ID ?? "148";
const TMM = process.env.STELLAR_CCTP_TOKEN_MESSENGER_MINTER ?? "CDNG7HXAPBWICI2E3AUBP3YZWZELJLYSB6F5CC7WLDTLTHVM74SLRTHP";
const CARGO_BIN = process.platform === "win32"
  ? `${process.env.USERPROFILE ?? ""}\.cargo\bin`
  : `${process.env.HOME ?? ""}/.cargo/bin`;
const PATH_SEP = process.platform === "win32" ? ";" : ":";
const SH_PATH = `${CARGO_BIN}${PATH_SEP}${process.env.PATH ?? ""}`;

const env = loadEnv(".env.generated");
const deployer = req(env, "STELLAR_DEPLOYER_SECRET");
const deployerPub = req(env, "STELLAR_DEPLOYER_PUBLIC");
const relayer = req(env, "STELLAR_RELAYER_SECRET");
const relayerPub = req(env, "STELLAR_RELAYER_PUBLIC");
const usdc = req(env, "STELLAR_TESTNET_USDC_SAC_CONTRACT");
const nullreg = req(env, "NULLIFIER_REGISTRY_CONTRACT");

function vkBytes(circuit: string): string {
  const vk = resolve(SHADE_ROOT, `circuits/${circuit}/output/main_verification_key.json`);
  if (!existsSync(vk)) throw new Error(`missing vk ${vk}; run npm run circuits:build`);
  return execFileSync(C2S, ["vk", vk], { encoding: "utf8" }).trim();
}

function deployVerifier(envKey: string, circuit: string): string {
  if (env[envKey]) { console.log(`${envKey}: reuse ${env[envKey]}`); return env[envKey]; }
  const id = deploy(resolve(WASM_DIR, "proof_verifiers.wasm"), ["--admin", deployerPub, "--vk_bytes", vkBytes(circuit)], deployer);
  env[envKey] = id; writeEnv(); console.log(`${envKey}: ${id}`); return id;
}

const withdrawV = deployVerifier("VERIFIER_WITHDRAW_CONTRACT", "withdraw_public");
const transferV = deployVerifier("TRANSFER_VERIFIER_CONTRACT", "private_transfer");
const depositV = deployVerifier("VERIFIER_DEPOSIT_NOTE_MINT_CONTRACT", "deposit_note_mint");

const redeployPool = process.env.SHADE_REDEPLOY_POOL === "1" || !env.SHIELDED_POOL_CONTRACT;
if (redeployPool) {
  const pool = deploy(resolve(WASM_DIR, "shielded_pool.wasm"),
    ["--admin", deployerPub, "--usdc_sac", usdc, "--verifier", withdrawV, "--nullifier_registry", nullreg,
     "--depth", "12", "--pool_id", POOL_ID, "--chain_id", CHAIN_ID], deployer);
  env.SHIELDED_POOL_CONTRACT = pool; writeEnv(); console.log(`SHIELDED_POOL_CONTRACT: ${pool}`);
  // Wire the pool.
  invoke(deployer, nullreg, ["set_authorized_spender", "--spender", pool, "--allowed", "true"]);
  invoke(deployer, pool, ["set_cctp_messenger", "--token_messenger_minter", TMM]);
  invoke(deployer, pool, ["set_transfer_verifier", "--verifier", transferV]);
  invoke(deployer, pool, ["set_deposit_verifier", "--verifier", depositV]);
  console.log("pool wired: spender, cctp_messenger, transfer_verifier, deposit_verifier");
} else {
  console.log(`SHIELDED_POOL_CONTRACT: reuse ${env.SHIELDED_POOL_CONTRACT} (set SHADE_REDEPLOY_POOL=1 to redeploy)`);
}
console.log("Canonical ShadePool deploy PASS");

// ---- helpers ----
function deploy(wasm: string, ctorArgs: string[], secret: string): string {
  if (!existsSync(wasm)) throw new Error(`missing ${wasm}; run npm run contracts:build`);
  for (let i = 0; i < 4; i++) {
    const r = spawnSync("stellar", ["contract", "deploy", "--wasm", wasm, "--rpc-url", RPC, "--network-passphrase", PASS, "--", ...ctorArgs],
      { encoding: "utf8", env: { ...process.env, STELLAR_ACCOUNT: secret, PATH: SH_PATH } });
    const id = `${r.stdout}\n${r.stderr}`.match(/C[A-Z0-9]{55}/)?.[0];
    if (id) return id;
    sleep(8000);
  }
  throw new Error(`deploy failed for ${wasm}`);
}
function invoke(secret: string, contract: string, args: string[]): void {
  for (let i = 0; i < 6; i++) {
    const r = spawnSync("stellar", ["contract", "invoke", "--id", contract, "--rpc-url", RPC, "--network-passphrase", PASS, "--send=yes", "--", ...args],
      { encoding: "utf8", env: { ...process.env, STELLAR_ACCOUNT: secret, PATH: SH_PATH } });
    if (r.status === 0) { sleep(2000); return; } // small gap so the next tx gets a fresh sequence
    const out = `${r.stdout}${r.stderr}`;
    // Sequence collisions (rapid same-account txs) and transient RPC errors are retryable.
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
  if (existsSync(p)) for (const raw of readFileSync(p, "utf8").split("\n")) { const l = raw.replace(/\r$/, ""); if (l.includes("=") && !l.trimStart().startsWith("#")) { const i = l.indexOf("="); e[l.slice(0, i)] = l.slice(i + 1); } }
  return e;
}
function writeEnv() {
  const onlyGenerated: EnvMap = {};
  if (existsSync(".env.generated")) for (const raw of readFileSync(".env.generated", "utf8").split("\n")) { const l = raw.replace(/\r$/, ""); if (l.includes("=") && !l.trimStart().startsWith("#")) { const i = l.indexOf("="); onlyGenerated[l.slice(0, i)] = l.slice(i + 1); } }
  for (const k of ["VERIFIER_WITHDRAW_CONTRACT", "TRANSFER_VERIFIER_CONTRACT", "VERIFIER_DEPOSIT_NOTE_MINT_CONTRACT", "SHIELDED_POOL_CONTRACT"]) if (env[k]) onlyGenerated[k] = env[k];
  const text = Object.entries(onlyGenerated).filter(([k]) => !k.includes(" ")).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join("\n");
  writeFileSync(".env.generated", `${text}\n`, { mode: 0o600 }); chmodSync(".env.generated", 0o600);
}

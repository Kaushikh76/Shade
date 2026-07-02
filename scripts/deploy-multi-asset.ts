import "dotenv/config";
import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

// Multi-asset redeploy: the asset-bound commitment scheme (assetId folded into
// the note commitment) is a breaking change to every circuit's VK, so this
// deploys a FRESH stack (new verifiers, new nullifier registry, new pool) —
// existing testnet notes under the old commitment scheme become unspendable
// against this deployment, by design (see conversation: "full change + deploy
// + e2e now").
//
// Deploys:
//   - 4 verifiers (withdraw_public, private_transfer, deposit_note_mint, mpc_settlement)
//   - fresh NullifierRegistry
//   - fresh ShieldedPool (multi-asset: USDC + XLM)
// Wires: nullreg.set_authorized_spender, cctp_messenger, transfer/deposit/mpc
// verifiers, register_asset(USDC), register_asset(XLM), set_reflector_oracle,
// set_committee.

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
// Live testnet Reflector "External CEXs & DEXs" oracle — verified via direct
// `stellar contract invoke ... lastprice` simulate calls (see conversation):
// decimals()=14 (matches RATE_SCALE), assets() lists Other("XLM")/Other("USDC")
// among others, lastprice returns plausible current USD prices for both.
const REFLECTOR_ORACLE = process.env.REFLECTOR_ORACLE_CONTRACT ?? "CCYOZJCOPG34LLQQ7N24YXBM7LL62R7ONMZ3G6WZAAYPB5OYKOMJRN63";
// Testnet native XLM SAC, derived via `stellar contract id asset --asset native --network testnet`.
const XLM_SAC = process.env.STELLAR_TESTNET_XLM_SAC_CONTRACT ?? "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

const CARGO_BIN = process.platform === "win32"
  ? `${process.env.USERPROFILE ?? ""}\\.cargo\\bin`
  : `${process.env.HOME ?? ""}/.cargo/bin`;
const PATH_SEP = process.platform === "win32" ? ";" : ":";
const SH_PATH = `${CARGO_BIN}${PATH_SEP}${process.env.PATH ?? ""}`;

const env = loadEnv(".env.generated");
const deployer = req(env, "STELLAR_DEPLOYER_SECRET");
const deployerPub = req(env, "STELLAR_DEPLOYER_PUBLIC");
const usdc = req(env, "STELLAR_TESTNET_USDC_SAC_CONTRACT");

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

console.log("=== Deploying multi-asset verifiers (new VKs, asset-bound commitment) ===");
const withdrawV = deployVerifier("MA_VERIFIER_WITHDRAW_CONTRACT", "withdraw_public");
const transferV = deployVerifier("MA_TRANSFER_VERIFIER_CONTRACT", "private_transfer");
const depositV = deployVerifier("MA_VERIFIER_DEPOSIT_NOTE_MINT_CONTRACT", "deposit_note_mint");
const mpcV = deployVerifier("MA_MPC_VERIFIER_CONTRACT", "mpc_settlement");

console.log("\n=== Deploying fresh NullifierRegistry ===");
const nullreg = env.MA_NULLIFIER_REGISTRY_CONTRACT || deploy(resolve(WASM_DIR, "nullifier_registry.wasm"), [], deployer);
env.MA_NULLIFIER_REGISTRY_CONTRACT = nullreg; writeEnv();
console.log(`MA_NULLIFIER_REGISTRY_CONTRACT: ${nullreg}`);
// nullifier_registry has no __constructor — initialize() is a separate first call.
if (!env.MA_NULLREG_INITIALIZED) {
  invoke(deployer, nullreg, ["initialize", "--admin", deployerPub]);
  env.MA_NULLREG_INITIALIZED = "true"; writeEnv();
  console.log("  nullreg.initialize(admin) OK");
}

console.log("\n=== Deploying fresh ShieldedPool (multi-asset) ===");
const pool = env.MA_SHIELDED_POOL_CONTRACT || deploy(resolve(WASM_DIR, "shielded_pool.wasm"),
  ["--admin", deployerPub, "--usdc_sac", usdc, "--verifier", withdrawV, "--nullifier_registry", nullreg,
   "--depth", "12", "--pool_id", POOL_ID, "--chain_id", CHAIN_ID], deployer);
env.MA_SHIELDED_POOL_CONTRACT = pool; writeEnv();
console.log(`MA_SHIELDED_POOL_CONTRACT: ${pool}`);

console.log("\n=== Wiring pool ===");
function wireOnce(stepKey: string, fn: () => void, label: string) {
  if (env[stepKey]) { console.log(`  ${label}: already done`); return; }
  fn();
  env[stepKey] = "true"; writeEnv();
  console.log(`  ${label} OK`);
}
wireOnce("MA_WIRED_SPENDER", () => invoke(deployer, nullreg, ["set_authorized_spender", "--spender", pool, "--allowed", "true"]), "nullreg.set_authorized_spender(pool)");
wireOnce("MA_WIRED_CCTP", () => invoke(deployer, pool, ["set_cctp_messenger", "--token_messenger_minter", TMM]), "pool.set_cctp_messenger");
wireOnce("MA_WIRED_XVERIFIER", () => invoke(deployer, pool, ["set_transfer_verifier", "--verifier", transferV]), "pool.set_transfer_verifier");
wireOnce("MA_WIRED_DEPVERIFIER", () => invoke(deployer, pool, ["set_deposit_verifier", "--verifier", depositV]), "pool.set_deposit_verifier");
wireOnce("MA_WIRED_MPCVERIFIER", () => invoke(deployer, pool, ["set_mpc_verifier", "--verifier", mpcV]), "pool.set_mpc_verifier");

console.log("\n=== Registering assets ===");
wireOnce("MA_WIRED_ASSET_USDC", () => invoke(deployer, pool, ["register_asset", "--sac", usdc, "--reflector_symbol", "USDC"]), `register_asset(USDC=${usdc})`);
wireOnce("MA_WIRED_ASSET_XLM", () => invoke(deployer, pool, ["register_asset", "--sac", XLM_SAC, "--reflector_symbol", "XLM"]), `register_asset(XLM=${XLM_SAC})`);

console.log("\n=== Configuring Reflector oracle ===");
wireOnce("MA_WIRED_REFLECTOR", () => invoke(deployer, pool, ["set_reflector_oracle", "--oracle", REFLECTOR_ORACLE]), `set_reflector_oracle(${REFLECTOR_ORACLE})`);

env.MA_XLM_SAC_CONTRACT = XLM_SAC;
env.MA_REFLECTOR_ORACLE_CONTRACT = REFLECTOR_ORACLE;
writeEnv();

console.log("\nMulti-asset deploy PASS");
console.log(JSON.stringify({
  pool, nullreg, withdrawV, transferV, depositV, mpcV,
  usdc, xlm: XLM_SAC, reflector: REFLECTOR_ORACLE
}, null, 2));

// ---- helpers ----
function deploy(wasm: string, ctorArgs: string[], secret: string): string {
  if (!existsSync(wasm)) throw new Error(`missing ${wasm}; run npm run contracts:build`);
  for (let i = 0; i < 4; i++) {
    const r = spawnSync("stellar", ["contract", "deploy", "--wasm", wasm, "--rpc-url", RPC, "--network-passphrase", PASS, "--", ...ctorArgs],
      { encoding: "utf8", env: { ...process.env, STELLAR_ACCOUNT: secret, PATH: SH_PATH } });
    const id = `${r.stdout}\n${r.stderr}`.match(/C[A-Z0-9]{55}/)?.[0];
    if (id) return id;
    console.error(`deploy attempt ${i + 1} failed:`, (r.stderr ?? "").slice(0, 500));
    sleep(8000);
  }
  throw new Error(`deploy failed for ${wasm}`);
}
function invoke(secret: string, contract: string, args: string[]): void {
  for (let i = 0; i < 6; i++) {
    const r = spawnSync("stellar", ["contract", "invoke", "--id", contract, "--rpc-url", RPC, "--network-passphrase", PASS, "--send=yes", "--", ...args],
      { encoding: "utf8", env: { ...process.env, STELLAR_ACCOUNT: secret, PATH: SH_PATH } });
    if (r.status === 0) { sleep(2000); return; }
    const out = `${r.stdout}${r.stderr}`;
    if (!/txBadSeq|TxBadSeq|timeout|submission failed|429|temporarily/i.test(out)) {
      throw new Error(`invoke ${args[0]} failed: ${out.slice(0, 500)}`);
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
  for (const k of ["MA_VERIFIER_WITHDRAW_CONTRACT", "MA_TRANSFER_VERIFIER_CONTRACT", "MA_VERIFIER_DEPOSIT_NOTE_MINT_CONTRACT", "MA_MPC_VERIFIER_CONTRACT", "MA_NULLIFIER_REGISTRY_CONTRACT", "MA_SHIELDED_POOL_CONTRACT", "MA_XLM_SAC_CONTRACT", "MA_REFLECTOR_ORACLE_CONTRACT", "MA_NULLREG_INITIALIZED", "MA_WIRED_SPENDER", "MA_WIRED_CCTP", "MA_WIRED_XVERIFIER", "MA_WIRED_DEPVERIFIER", "MA_WIRED_MPCVERIFIER", "MA_WIRED_ASSET_USDC", "MA_WIRED_ASSET_XLM", "MA_WIRED_REFLECTOR"]) if (env[k]) onlyGenerated[k] = env[k];
  const text = Object.entries(onlyGenerated).filter(([k]) => !k.includes(" ")).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join("\n");
  writeFileSync(".env.generated", `${text}\n`, { mode: 0o600 }); chmodSync(".env.generated", 0o600);
}

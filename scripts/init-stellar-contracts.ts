import { existsSync } from "node:fs";
import { readFile, writeFile, chmod, appendFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

type EnvMap = Record<string, string>;

const env = await loadEnv(".env.generated");
const deployerSecret = env.STELLAR_DEPLOYER_SECRET;
if (!deployerSecret) throw new Error("STELLAR_DEPLOYER_SECRET missing; run npm run setup:testnet");

const rpcUrl = env.STELLAR_RPC_URL ?? "https://soroban-testnet.stellar.org";
const passphrase = env.STELLAR_NETWORK_PASSPHRASE ?? "Test SDF Network ; September 2015";
const usdcAsset = `${env.STELLAR_TESTNET_USDC_ASSET_CODE ?? "USDC"}:${env.STELLAR_TESTNET_USDC_ISSUER ?? "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"}`;

if (!env.STELLAR_TESTNET_USDC_SAC_CONTRACT) {
  const id = run("stellar", ["contract", "id", "asset", "--asset", usdcAsset, "--rpc-url", rpcUrl, "--network-passphrase", passphrase], { secret: deployerSecret }).stdout.trim();
  env.STELLAR_TESTNET_USDC_ASSET_CODE = "USDC";
  env.STELLAR_TESTNET_USDC_ISSUER = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
  env.STELLAR_TESTNET_USDC_SAC_CONTRACT = id;
  await writeEnv(".env.generated", env);
}

const admin = env.STELLAR_DEPLOYER_PUBLIC;
const guardian = env.STELLAR_RELAYER_PUBLIC;
if (!admin || !guardian) throw new Error("STELLAR_DEPLOYER_PUBLIC and STELLAR_RELAYER_PUBLIC required");

await invokeOnce("COMMITMENT_TREE_INITIALIZED", env.COMMITMENT_TREE_CONTRACT, ["initialize", "--admin", admin, "--depth", "32"]);
await invokeOnce("NULLIFIER_REGISTRY_INITIALIZED", env.NULLIFIER_REGISTRY_CONTRACT, ["initialize", "--admin", admin]);
await invokeOnce("COMPLIANCE_REGISTRY_INITIALIZED", env.COMPLIANCE_REGISTRY_CONTRACT, ["initialize", "--admin", admin]);
await invokeOnce("SHADE_VAULT_INITIALIZED", env.SHADE_VAULT_CONTRACT, [
  "initialize",
  "--admin", admin,
  "--usdc_sac", env.STELLAR_TESTNET_USDC_SAC_CONTRACT,
  "--tree", env.COMMITMENT_TREE_CONTRACT,
  "--nullifiers", env.NULLIFIER_REGISTRY_CONTRACT,
  "--compliance_registry", env.COMPLIANCE_REGISTRY_CONTRACT
]);
await invokeOnce("INTENT_ESCROW_INITIALIZED", env.INTENT_ESCROW_CONTRACT, [
  "initialize",
  "--admin", admin,
  "--vault", env.SHADE_VAULT_CONTRACT,
  "--nullifier_registry", env.NULLIFIER_REGISTRY_CONTRACT
]);
await invokeOnce("GOVERNANCE_GUARDIAN_INITIALIZED", env.GOVERNANCE_GUARDIAN_CONTRACT, ["initialize", "--admin", admin, "--guardian", guardian]);

console.log("Stellar contract initialization PASS");

async function invokeOnce(flag: string, contractId: string | undefined, args: string[]) {
  if (!contractId) throw new Error(`${flag} contract ID missing`);
  if (env[flag] === "true") {
    console.log(`${flag}: already true`);
    return;
  }
  const result = run("stellar", [
    "contract",
    "invoke",
    "--id", contractId,
    "--rpc-url", rpcUrl,
    "--network-passphrase", passphrase,
    "--",
    ...args
  ], { secret: deployerSecret });
  env[flag] = "true";
  env[`${flag}_TX`] = parseTx(result.stderr + "\n" + result.stdout);
  await writeEnv(".env.generated", env);
  await appendFile("docs/test-report.md", `\n- ${flag}: PASS ${env[`${flag}_TX`] ?? ""}\n`);
  console.log(`${flag}: PASS`);
}

function run(command: string, args: string[], opts: { secret: string }) {
  let last = "";
  for (let attempt = 1; attempt <= 4; attempt++) {
    const result = spawnSync(command, args, {
      encoding: "utf8",
      env: {
        ...process.env,
        STELLAR_ACCOUNT: opts.secret,
        PATH: `${process.env.HOME}/.cargo/bin:${process.env.PATH ?? ""}`
      }
    });
    if (result.status === 0) return result;
    last = `${result.stderr}\n${result.stdout}`.replaceAll(opts.secret, "[REDACTED_STELLAR_SECRET]");
    if (last.includes("already initialized")) return result;
    const retryable = last.includes("TxBadSeq") || last.includes("transaction submission timeout");
    if (!retryable) break;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5000);
  }
  throw new Error(`${command} ${args.slice(0, 4).join(" ")} failed: ${last}`);
}

function parseTx(output: string): string {
  const direct = output.match(/transaction:\s*([a-fA-F0-9]{64})/);
  if (direct) return direct[1];
  const expert = output.match(/tx\/([a-fA-F0-9]{64})/);
  if (expert) return expert[1];
  return createHash("sha256").update(output).digest("hex");
}

async function loadEnv(path: string): Promise<EnvMap> {
  if (!existsSync(path)) return {};
  const text = await readFile(path, "utf8");
  const values: EnvMap = {};
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!line.includes("=") || line.trimStart().startsWith("#")) continue;
    const index = line.indexOf("=");
    values[line.slice(0, index)] = line.slice(index + 1);
  }
  return values;
}

async function writeEnv(path: string, values: EnvMap) {
  const text = Object.entries(values).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join("\n");
  await writeFile(path, `${text}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}

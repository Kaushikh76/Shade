import { existsSync } from "node:fs";
import { appendFile, chmod, readFile, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";

type EnvMap = Record<string, string>;

const contracts = [
  ["COMMITMENT_TREE_CONTRACT", "commitment_tree"],
  ["NULLIFIER_REGISTRY_CONTRACT", "nullifier_registry"],
  ["COMPLIANCE_REGISTRY_CONTRACT", "compliance_registry"],
  ["SHADE_VAULT_CONTRACT", "shade_vault"],
  ["INTENT_ESCROW_CONTRACT", "intent_escrow"],
  ["GOVERNANCE_GUARDIAN_CONTRACT", "governance_guardian"],
  ["VERIFIER_DEPOSIT_CONTRACT", "proof_verifiers"],
  ["VERIFIER_WITHDRAW_CONTRACT", "proof_verifiers"],
  ["VERIFIER_RFQ_CONTRACT", "proof_verifiers"],
  ["VERIFIER_FILL_CLAIM_CONTRACT", "proof_verifiers"]
] as const;

const generated = await loadEnv(".env.generated");
const deployerSecret = generated.STELLAR_DEPLOYER_SECRET;
const rpcUrl = generated.STELLAR_RPC_URL ?? process.env.STELLAR_RPC_URL ?? "https://soroban-testnet.stellar.org";
const passphrase = generated.STELLAR_NETWORK_PASSPHRASE ?? process.env.STELLAR_NETWORK_PASSPHRASE ?? "Test SDF Network ; September 2015";

if (!deployerSecret) throw new Error("STELLAR_DEPLOYER_SECRET is required in .env.generated; run npm run setup:testnet first");

for (const [envKey, crate] of contracts) {
  if (generated[envKey]) {
    console.log(`${envKey}: already deployed ${generated[envKey]}`);
    continue;
  }
  const wasm = `contracts/stellar/target/wasm32v1-none/release/${crate}.wasm`;
  if (!existsSync(wasm)) throw new Error(`Missing ${wasm}; run npm run contracts:build first`);
  const alias = `shade-${envKey.toLowerCase().replaceAll("_", "-")}`;
  const result = deployWithRetry(wasm, alias, deployerSecret, rpcUrl, passphrase);
  const contractId = result.stdout.trim().split(/\s+/).find((part) => part.startsWith("C"));
  if (!contractId) throw new Error(`Could not parse contract ID for ${crate}: ${result.stdout}`);
  generated[envKey] = contractId;
  await writeEnv(".env.generated", generated);
  console.log(`${envKey}: ${contractId}`);
}

await writeEnv(".env.generated", generated);
await appendContractsToReport(generated);

async function loadEnv(path: string): Promise<EnvMap> {
  if (!existsSync(path)) return {};
  const text = await readFile(path, "utf8");
  const env: EnvMap = {};
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!line.includes("=") || line.trimStart().startsWith("#")) continue;
    const index = line.indexOf("=");
    env[line.slice(0, index)] = line.slice(index + 1);
  }
  return env;
}

async function writeEnv(path: string, values: EnvMap): Promise<void> {
  const text = Object.entries(values)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");
  await writeFile(path, `${text}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function appendContractsToReport(values: EnvMap): Promise<void> {
  const lines = [
    "",
    "## Stellar Deploy Results",
    "",
    `- ShadeVault: ${values.SHADE_VAULT_CONTRACT ?? "pending"}`,
    `- CommitmentTree: ${values.COMMITMENT_TREE_CONTRACT ?? "pending"}`,
    `- NullifierRegistry: ${values.NULLIFIER_REGISTRY_CONTRACT ?? "pending"}`,
    `- ComplianceRegistry: ${values.COMPLIANCE_REGISTRY_CONTRACT ?? "pending"}`,
    `- IntentEscrow: ${values.INTENT_ESCROW_CONTRACT ?? "pending"}`,
    `- GovernanceGuardian: ${values.GOVERNANCE_GUARDIAN_CONTRACT ?? "pending"}`,
    `- VerifierDeposit: ${values.VERIFIER_DEPOSIT_CONTRACT ?? "pending"}`,
    `- VerifierWithdraw: ${values.VERIFIER_WITHDRAW_CONTRACT ?? "pending"}`,
    `- VerifierRFQ: ${values.VERIFIER_RFQ_CONTRACT ?? "pending"}`,
    `- VerifierFillClaim: ${values.VERIFIER_FILL_CLAIM_CONTRACT ?? "pending"}`
  ];
  await appendFile("docs/test-report.md", `${lines.join("\n")}\n`);
}

function deployWithRetry(wasm: string, alias: string, deployerSecret: string, rpcUrl: string, passphrase: string) {
  let lastOutput = "";
  for (let attempt = 1; attempt <= 3; attempt++) {
    const result = spawnSync(
      "stellar",
      [
        "contract",
        "deploy",
        "--wasm",
        wasm,
        "--rpc-url",
        rpcUrl,
        "--network-passphrase",
        passphrase,
        "--alias",
        alias
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          STELLAR_ACCOUNT: deployerSecret,
          PATH: `${process.env.HOME}/.cargo/bin:${process.env.PATH ?? ""}`
        }
      }
    );
    if (result.status === 0) return result;
    lastOutput = `${result.stderr}\n${result.stdout}`.replaceAll(deployerSecret, "[REDACTED_STELLAR_SECRET]");
    const retryable = lastOutput.includes("TxBadSeq") || lastOutput.includes("Wasm does not exist") || lastOutput.includes("transaction submission timeout");
    if (!retryable || attempt === 3) {
      throw new Error(`Deploy failed for ${wasm} (status ${result.status}, signal ${result.signal ?? "none"}): ${lastOutput}`);
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 8000);
  }
  throw new Error(`Deploy failed for ${wasm}: ${lastOutput}`);
}

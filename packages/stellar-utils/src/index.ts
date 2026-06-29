import { Horizon, Keypair, Networks, TransactionBuilder, Operation, Asset, BASE_FEE } from "@stellar/stellar-sdk";
import { spawnSync } from "node:child_process";

export const TESTNET = {
  rpcUrl: "https://soroban-testnet.stellar.org",
  horizonUrl: "https://horizon-testnet.stellar.org",
  passphrase: Networks.TESTNET,
  friendbotUrl: "https://friendbot.stellar.org"
} as const;

export type StellarWallet = {
  role: string;
  publicKey: string;
  secret: string;
};

export function generateStellarWallet(role: string): StellarWallet {
  const keypair = Keypair.random();
  return { role, publicKey: keypair.publicKey(), secret: keypair.secret() };
}

export async function fundWithFriendbot(publicKey: string): Promise<void> {
  const url = `${TESTNET.friendbotUrl}?addr=${encodeURIComponent(publicKey)}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Friendbot failed for ${publicKey}: ${response.status} ${await response.text()}`);
  }
}

export async function accountExists(publicKey: string, horizonUrl = TESTNET.horizonUrl): Promise<boolean> {
  const server = new Horizon.Server(horizonUrl);
  try {
    await server.loadAccount(publicKey);
    return true;
  } catch (error: unknown) {
    if (typeof error === "object" && error && "response" in error) return false;
    throw error;
  }
}

export type SorobanInvokeResult = {
  txHash: string;
  returnValue: string;
  raw: string;
};

// Invoke a Soroban contract via the installed `stellar` CLI.
// Secret is passed through STELLAR_ACCOUNT env (never argv) so it stays out of `ps`.
// Throws (never fabricates) if no real on-chain tx hash can be parsed.
export function sorobanInvoke(opts: {
  contractId: string;
  secret: string;
  method: string;
  args?: string[];
  rpcUrl?: string;
  passphrase?: string;
  retries?: number;
  readOnly?: boolean;
}): SorobanInvokeResult {
  const rpcUrl = opts.rpcUrl ?? TESTNET.rpcUrl;
  const passphrase = opts.passphrase ?? TESTNET.passphrase;
  const args = [
    "contract",
    "invoke",
    "--id",
    opts.contractId,
    "--rpc-url",
    rpcUrl,
    "--network-passphrase",
    passphrase,
    "--",
    opts.method,
    ...(opts.args ?? [])
  ];
  let last = "";
  const retries = opts.retries ?? 4;
  for (let attempt = 1; attempt <= retries; attempt++) {
    const result = spawnSync("stellar", args, {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      env: {
        ...process.env,
        STELLAR_ACCOUNT: opts.secret,
        PATH: `${process.env.HOME}/.cargo/bin:${process.env.PATH ?? ""}`
      }
    });
    const raw = `${result.stderr ?? ""}\n${result.stdout ?? ""}`;
    if (result.status === 0) {
      const txHash = parseSorobanTx(raw);
      if (!txHash && !opts.readOnly) {
        throw new Error(`Soroban ${opts.method} succeeded but no tx hash found in output:\n${redact(raw, opts.secret)}`);
      }
      return { txHash: txHash ?? "", returnValue: (result.stdout ?? "").trim(), raw: redact(raw, opts.secret) };
    }
    last = redact(raw, opts.secret);
    const retryable = last.includes("TxBadSeq") || last.includes("timeout") || last.includes("429") || last.includes("temporarily");
    if (!retryable) break;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5000);
  }
  throw new Error(`stellar contract invoke ${opts.method} failed: ${last}`);
}

function parseSorobanTx(output: string): string | null {
  // Newer CLI prints e.g. "Transaction hash is <64hex>" or a stellar.expert link.
  const patterns = [
    /[Tt]ransaction hash(?:\s+is)?:?\s*([a-fA-F0-9]{64})/,
    /tx\/([a-fA-F0-9]{64})/,
    /transaction:\s*([a-fA-F0-9]{64})/
  ];
  for (const p of patterns) {
    const m = output.match(p);
    if (m) return m[1];
  }
  return null;
}

function redact(text: string, secret: string): string {
  return secret ? text.replaceAll(secret, "[REDACTED_STELLAR_SECRET]") : text;
}

export function bytesToCliHex(hex: string): string {
  return hex.startsWith("0x") ? hex.slice(2) : hex;
}

export async function createTrustline(secret: string, issuer: string, code = "USDC", horizonUrl = TESTNET.horizonUrl): Promise<string> {
  const server = new Horizon.Server(horizonUrl);
  const keypair = Keypair.fromSecret(secret);
  const account = await server.loadAccount(keypair.publicKey());
  const tx = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: TESTNET.passphrase
  })
    .addOperation(Operation.changeTrust({ asset: new Asset(code, issuer) }))
    .setTimeout(60)
    .build();
  tx.sign(keypair);
  const result = await server.submitTransaction(tx);
  return result.hash;
}

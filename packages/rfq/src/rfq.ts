import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { Keypair, StrKey } from "@stellar/stellar-sdk";

// ---- RFQ state machine ------------------------------------------------------
export const RFQ_STATES = [
  "INTENT_CREATED",
  "INTENT_ENCRYPTED",
  "INTENT_PUBLISHED_TO_ALLOWED_SOLVERS",
  "QUOTE_RECEIVED",
  "QUOTE_VALIDATED",
  "QUOTE_ACCEPTED",
  "SOLVER_INVENTORY_LOCKED",
  "FILL_CREATED",
  "FILL_EXECUTED_IF_REQUIRED",
  "PROOF_REQUESTED",
  "PROOF_GENERATED",
  "PROOF_VERIFIED_LOCALLY",
  "SETTLEMENT_SUBMITTED",
  "SETTLED",
  "FAILED_RECOVERABLE",
  "EXPIRED",
  "CANCELLED"
] as const;
export type RfqState = (typeof RFQ_STATES)[number];

export type Intent = {
  intent_type: "PRIVATE_RFQ";
  version: "1.0";
  user_pubkey_commitment: string;
  input_asset: string;
  output_asset: string;
  amount_mode: "exact_in" | "exact_out" | "max_in";
  amount: string; // gross input (7dp USDC), testnet-visible for solver pricing
  min_output: string;
  expiry_ledger: number;
  allowed_solvers_root: string;
  compliance_policy_id: string;
  destination: string; // Arbitrum recipient (0x...) for Path A
  replay_domain: "shade:stellar:testnet:rfq:v1";
};

export type Quote = {
  quote_id: string;
  intent_hash: string;
  solver_id: string;
  input_asset: string;
  output_asset: string;
  gross_input: string;
  net_output: string;
  fee: string;
  valid_until_ledger: number;
  solver_inventory_commitment: string;
  settlement_method: "proof_of_fill";
};

export function intentHash(intent: Intent): string {
  return "0x" + sha256(stable(intent));
}

// 32-byte quote hash the solver signs and the contract binds.
export function quoteHash(q: Quote): string {
  return "0x" + sha256(stable(q));
}

// Solver signs the quote hash with its Stellar (ed25519) key.
export function signQuoteStellar(quoteHashHex: string, stellarSecret: string): { sig: string; pubkey: string } {
  const kp = Keypair.fromSecret(stellarSecret);
  const msg = Buffer.from(strip0x(quoteHashHex), "hex");
  const sig = kp.sign(msg); // 64 bytes
  return { sig: sig.toString("hex"), pubkey: Buffer.from(StrKey.decodeEd25519PublicKey(kp.publicKey())).toString("hex") };
}

// AES-256-GCM encryption of the intent plaintext at rest.
export function encryptIntent(intent: Intent, masterKeyHex: string): { ciphertext: string; iv: string; tag: string } {
  const key = Buffer.from(strip0x(masterKeyHex).padEnd(64, "0").slice(0, 64), "hex");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(stable(intent), "utf8")), cipher.final()]);
  return { ciphertext: ct.toString("hex"), iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex") };
}

// Deterministic pricing: net = gross * (1 - feeBps), fee = gross - net. Testnet-only.
export function priceQuote(grossInput7dp: bigint, feeBps: number): { net: bigint; fee: bigint } {
  const fee = (grossInput7dp * BigInt(feeBps)) / 10000n;
  return { net: grossInput7dp - fee, fee };
}

export function usdc7ToDecimal(v: bigint): string {
  const s = v.toString().padStart(8, "0");
  return `${s.slice(0, -7)}.${s.slice(-7)}`.replace(/^0+(\d)/, "$1");
}

function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}
function strip0x(s: string): string {
  return s.startsWith("0x") ? s.slice(2) : s;
}
function stable(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  const e = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
  return `{${e.map(([k, v]) => `${JSON.stringify(k)}:${stable(v)}`).join(",")}}`;
}

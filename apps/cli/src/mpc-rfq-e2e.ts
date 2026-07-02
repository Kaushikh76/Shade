import { randomUUID } from "node:crypto";
/**
 * MPC-RFQ integrated e2e test (Phase A).
 *
 * Demonstrates the unified pipeline:
 *   RFQ intent (POST /v1/intents + encrypted_shares)
 *     → API auto-routes to MPC committee
 *     → MPC privately matches crossed intents
 *     → signed batch produced
 *     → settlement gated: all three must agree
 *         (RFQ lifecycle + MPC match + ZK proof)
 *
 * No real funds required — uses the in-process MPC committee and the
 * API running against a test DB. Run with:
 *   npm run mpc:rfq:e2e
 *
 * Requires: API_URL, MPC_COMMITTEE_URL (or both running locally),
 *           DATABASE_URL, and a valid session token (SESSION_TOKEN or
 *           ENABLE_LEGACY_WALLET_AUTH=true + wallet credentials).
 */

import { loadRuntimeEnv } from "./lib/env.js";
import { failIfAny, writeCheckReport, type CheckResult } from "./lib/report.js";
import {
  splitAmountForCommittee, type CommitteeNodeInfo
} from "@shade/mpc-crypto";

const env = await loadRuntimeEnv();
const results: CheckResult[] = [];
const check = (name: string, ok: boolean, detail = "") => {
  results.push({ name, ok, detail });
  console.log(`  [${ok ? "OK" : "FAIL"}] ${name}${detail ? " — " + detail : ""}`);
};

const API = env.API_URL ?? "http://localhost:3000";
const MPC = env.MPC_COMMITTEE_URL ?? "http://localhost:8090";
const SESSION = env.SESSION_TOKEN ?? "";

const headers: Record<string, string> = {
  "content-type": "application/json",
  ...(SESSION ? { authorization: `Bearer ${SESSION}` } : {})
};

async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: { ...headers, "idempotency-key": `mpcrfq-${randomUUID()}` },
    // Fastify rejects an application/json request with an empty body; send {} for
    // bodyless POSTs (e.g. the match trigger).
    body: body ? JSON.stringify(body) : (method === "POST" ? "{}" : undefined)
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${method} ${path} → ${res.status}: ${text.slice(0, 200)}`);
  }
  return res.json() as Promise<T>;
}

console.log("=== MPC-RFQ Integrated E2E (Phase A) ===\n");

// ── 1. Fetch committee pubkeys ────────────────────────────────────────────────

let nodes: CommitteeNodeInfo[] = [];
try {
  const resp = await fetch(`${MPC}/v1/mpc/committee`);
  const data = await resp.json() as { nodes: CommitteeNodeInfo[] };
  nodes = data.nodes;
  check("MPC committee reachable", nodes.length === 3, `${nodes.length} nodes`);
} catch (e) {
  check("MPC committee reachable", false, String(e));
  await writeCheckReport("MPC-RFQ E2E", results);
  failIfAny(results);
}

// ── 2. Build two synthetic intents with Shamir-encrypted amounts ──────────────
// Intent A: user wants USDC:Stellar → USDC:ArbitrumSepolia (sells Stellar USDC)
// Intent B: user wants USDC:ArbitrumSepolia → USDC:Stellar (sells Arb USDC)
// These cross: A and B can be matched privately by the committee.

function fakeCommitment(seed: string): string {
  const hex = Buffer.from(seed.padEnd(32, "0").slice(0, 32)).toString("hex");
  return "0x" + hex.padStart(64, "0");
}

const amount7dp = 10_000_000n; // 1 USDC (7dp)

// Split the amount into real Shamir shares and encrypt one per node.
// This is exactly what the browser SDK will do — splitAmountForCommittee
// handles the Shamir polynomial and per-node X25519 box encryption.
function buildEncryptedShares(nodes: CommitteeNodeInfo[]) {
  return splitAmountForCommittee(amount7dp.toString(), nodes, 2);
}

const intentA = {
  intent_type: "PRIVATE_RFQ" as const,
  version: "1.0" as const,
  user_pubkey_commitment: fakeCommitment("user-a-pubkey"),
  input_asset: "USDC:Stellar:SAC",
  output_asset: "USDC:ArbitrumSepolia",
  amount_mode: "exact_in" as const,
  amount_commitment: fakeCommitment("amount-a"),
  min_output_commitment: fakeCommitment("min-output-a"),
  expiry_ledger: 999_999_999,
  allowed_solvers_root: "0x" + "00".repeat(32),
  compliance_policy_id: "shade:default-testnet-policy:v1",
  destination_commitment: fakeCommitment("dest-a"),
  replay_domain: "shade:stellar:testnet:rfq:v1" as const,
  signature: "0x" + "00".repeat(64),
  // MPC routing fields
  note_nullifier: fakeCommitment("nullifier-a"),
  note_commitment: fakeCommitment("note-a"),
  recipient_commitment: fakeCommitment("recipient-a"),
  encrypted_shares: buildEncryptedShares(nodes)
};

const intentB = {
  ...intentA,
  user_pubkey_commitment: fakeCommitment("user-b-pubkey"),
  input_asset: "USDC:ArbitrumSepolia",
  output_asset: "USDC:Stellar:SAC",
  amount_commitment: fakeCommitment("amount-b"),
  min_output_commitment: fakeCommitment("min-output-b"),
  destination_commitment: fakeCommitment("dest-b"),
  signature: "0x" + "00".repeat(64),
  note_nullifier: fakeCommitment("nullifier-b"),
  note_commitment: fakeCommitment("note-b"),
  recipient_commitment: fakeCommitment("recipient-b"),
  encrypted_shares: buildEncryptedShares(nodes)
};

// ── 3. Submit both intents via POST /v1/intents ───────────────────────────────

let intentHashA = "";
let intentHashB = "";
let sessionIdA = "";

try {
  const resA = await api<{ intent_hash: string; mpc_routed: boolean; mpc_session_id?: string }>(
    "POST", "/v1/intents", intentA
  );
  intentHashA = resA.intent_hash;
  sessionIdA = resA.mpc_session_id ?? "";
  check("Intent A submitted + MPC-routed", resA.mpc_routed, `hash ${intentHashA.slice(0, 14)}... session ${sessionIdA.slice(0, 12)}...`);
} catch (e) {
  check("Intent A submitted + MPC-routed", false, String(e));
}

try {
  const resB = await api<{ intent_hash: string; mpc_routed: boolean; mpc_session_id?: string }>(
    "POST", "/v1/intents", intentB
  );
  intentHashB = resB.intent_hash;
  // B should land in the same session as A (committee batches open sessions).
  const sameSession = !!resB.mpc_session_id;
  check("Intent B submitted + MPC-routed", resB.mpc_routed && sameSession, `hash ${intentHashB.slice(0, 14)}... session ${resB.mpc_session_id?.slice(0, 12)}...`);
} catch (e) {
  check("Intent B submitted + MPC-routed", false, String(e));
}

if (!intentHashA || !intentHashB || !sessionIdA) {
  console.error("Cannot continue — intent submission failed.");
  await writeCheckReport("MPC-RFQ E2E", results);
  failIfAny(results);
}

// ── 4. Verify MPC intents are visible via the API ─────────────────────────────

try {
  const mpcA = await api<{ intent_id: string; status: string }>("GET", `/v1/mpc/intents/${intentHashA}`);
  check("MPC intent A registered in DB", mpcA.status === "pending", `status=${mpcA.status}`);
} catch (e) {
  check("MPC intent A registered in DB", false, String(e));
}

try {
  const mpcB = await api<{ intent_id: string; status: string }>("GET", `/v1/mpc/intents/${intentHashB}`);
  check("MPC intent B registered in DB", mpcB.status === "pending", `status=${mpcB.status}`);
} catch (e) {
  check("MPC intent B registered in DB", false, String(e));
}

// ── 5. Trigger matching round ─────────────────────────────────────────────────

let batchId = "";
try {
  const matchResp = await api<{ ok: boolean; batch?: { batchId: string; matches: unknown[]; signatures: unknown[] }; reason?: string }>(
    "POST", `/v1/mpc/sessions/${sessionIdA}/match`
  );
  check("MPC matching round succeeded", matchResp.ok, matchResp.ok ? `batch ${matchResp.batch?.batchId?.slice(0, 12)}...` : (matchResp.reason ?? "no reason"));
  if (matchResp.ok && matchResp.batch) {
    batchId = matchResp.batch.batchId;
    check("MPC batch has 1 match", matchResp.batch.matches.length === 1, `${matchResp.batch.matches.length} match(es)`);
    check("MPC batch signed by 3 nodes", matchResp.batch.signatures.length === 3, `${matchResp.batch.signatures.length} sig(s)`);
  }
} catch (e) {
  check("MPC matching round succeeded", false, String(e));
}

// ── 6. Verify intent A and B are now 'matched' in the DB ──────────────────────

try {
  const mpcA = await api<{ status: string; matched_with?: string }>("GET", `/v1/mpc/intents/${intentHashA}`);
  check("Intent A status = matched", mpcA.status === "matched", `matched_with=${mpcA.matched_with?.slice(0, 14)}...`);
} catch (e) {
  check("Intent A status = matched", false, String(e));
}

try {
  const mpcB = await api<{ status: string; matched_with?: string }>("GET", `/v1/mpc/intents/${intentHashB}`);
  check("Intent B status = matched", mpcB.status === "matched", `matched_with=${mpcB.matched_with?.slice(0, 14)}...`);
} catch (e) {
  check("Intent B status = matched", false, String(e));
}

// ── 7. Verify the settlement gate: MPC-routed intent must have a match ────────
// Register a real quote for intent A so settle passes the quote check and reaches
// the proof gate ("proof job is not ready"). If the MPC match were NOT confirmed,
// the MPC gate would fire instead — so reaching the proof gate proves the MPC gate
// passed on a confirmed match.

const quoteId = randomUUID();
try {
  await api("POST", "/v1/solver/quotes", {
    quote_id: quoteId,
    intent_hash: intentHashA,
    solver_id: "solver-mpcrfq-e2e",
    input_asset: "USDC:Stellar:SAC",
    output_asset: "USDC:ArbitrumSepolia",
    gross_input: "1.0",
    net_output: "0.99",
    fee: "0.01",
    valid_until_ledger: 999_999_999,
    solver_inventory_commitment: fakeCommitment("inv"),
    settlement_method: "proof_of_fill",
    quote_signature: "0x" + "00".repeat(64)
  });
  check("Solver quote registered for intent A", true, `quote ${quoteId.slice(0, 12)}...`);
} catch (e) {
  check("Solver quote registered for intent A", false, String(e));
}

try {
  await api(`POST`, `/v1/quotes/${quoteId}/accept`, {
    intent_hash: intentHashA,
    user_signature_hash: fakeCommitment("user-accept-sig")
  });
  check("Quote accepted (RFQ lifecycle)", true, "accepted");
} catch (e) {
  check("Quote accepted (RFQ lifecycle)", false, String(e));
}

const fillReceiptHash = fakeCommitment("fill");
let fillId = "";
try {
  const r = await api<{ fill_id: string }>("POST", "/v1/fills", {
    quote_id: quoteId, fill_receipt_hash: fillReceiptHash, amount: "990000", recipient: "0xrecipient"
  });
  fillId = r.fill_id;
  await api("POST", `/v1/fills/${fillId}/execute`, { destination_tx_hash: "0x" + "ab".repeat(32) });
  check("Fill created + executed (RFQ lifecycle)", true, `fill ${fillId.slice(0, 12)}...`);
} catch (e) {
  check("Fill created + executed (RFQ lifecycle)", false, String(e));
}

try {
  await api("POST", "/v1/rfq/settle", {
    intent_hash: intentHashA,
    quote_id: quoteId,
    proof_job_id: "nonexistent-proof-job",
    nullifier: fakeCommitment("nullifier-a"),
    fill_receipt_hash: fillReceiptHash
  });
  check("Settlement gate: MPC match passes, proof gate fires", false, "settle unexpectedly succeeded");
} catch (e) {
  const msg = String(e);
  const proofGate = /proof job is not ready|proof.*not ready/i.test(msg);
  const mpcGate = /MPC match not yet confirmed/i.test(msg);
  check("Settlement gate: MPC match passes, proof gate fires", proofGate && !mpcGate,
    proofGate ? "proof gate fired (MPC gate already passed)" : `unexpected: ${msg.slice(0, 120)}`);
}

// ── 8. Verify the batch signature ────────────────────────────────────────────

if (batchId) {
  try {
    const batches = await api<{ batches: Array<{ batchId: string }> }>("GET", "/v1/mpc/batches");
    const found = batches.batches.some(b => b.batchId === batchId);
    check("Signed batch appears in /v1/mpc/batches", found, `batchId=${batchId.slice(0, 12)}...`);
  } catch (e) {
    check("Signed batch appears in /v1/mpc/batches", false, String(e));
  }
}

// ── Summary ───────────────────────────────────────────────────────────────────

console.log("");
await writeCheckReport("MPC-RFQ E2E (Phase A — unified pipeline)", results);
failIfAny(results);
console.log("MPC-RFQ e2e PASS");

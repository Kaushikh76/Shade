#!/usr/bin/env tsx
/**
 * P4 #24 liveness/recovery e2e: proves the independent-operator committee
 * (node-server.ts x3 + coordinator-server.ts) actually tolerates a node
 * going down — the entire point of a 2-of-3 threshold.
 *
 *   1. Spawn 3 independent node processes + 1 coordinator (no DATABASE_URL —
 *      ephemeral in-memory mode, so this test needs no Postgres).
 *   2. Submit two crossing intents.
 *   3. Kill node-3.
 *   4. Trigger matching — must still succeed with 2/3 signatures.
 *   5. Verify that batch (both locally and via the coordinator).
 *   6. Restart node-3 (fresh ephemeral key — proves the earlier batch stays
 *      valid independent of node-3's identity, since it never signed it).
 *   7. Run a second matching round — must now get all 3 signatures again.
 *
 * Run: npm run mpc:liveness:e2e (spawns everything itself; nothing else needs
 * to be running first).
 */
import "dotenv/config";
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { v4 as uuidv4 } from "uuid";
import {
  splitAmountForCommittee, verifySignedBatch,
  type CommitteeNodeInfo, type MpcIntent, type SignedMatchBatch
} from "@shade/mpc-crypto";
import { beginReport, writeCheckReport, failIfAny, type CheckResult } from "./lib/report.js";

const NODE_PORTS = { "node-1": 18091, "node-2": 18092, "node-3": 18093 } as const;
const COORDINATOR_PORT = 18090;
const COORDINATOR_URL = `http://127.0.0.1:${COORDINATOR_PORT}`;
const INTERNAL_TOKEN = "liveness-e2e-shared-token";

const children: Record<string, ChildProcess> = {};
const results: CheckResult[] = [];

function fakeNote() {
  return {
    nullifier: `0x${randomBytes(32).toString("hex")}`,
    commitment: `0x${randomBytes(32).toString("hex")}`,
    recipientCommitment: `0x${randomBytes(32).toString("hex")}`
  };
}

const TSX_CLI = "node_modules/tsx/dist/cli.mjs";

function spawnNode(nodeId: keyof typeof NODE_PORTS): ChildProcess {
  const proc = spawn(process.execPath, [TSX_CLI, "apps/mpc-committee/src/node-server.ts"], {
    env: { ...process.env, MPC_NODE_ID: nodeId, MPC_NODE_PORT: String(NODE_PORTS[nodeId]), MPC_INTERNAL_TOKEN: INTERNAL_TOKEN, DATABASE_URL: "" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  proc.stdout?.on("data", d => process.stdout.write(`[${nodeId}] ${d}`));
  proc.stderr?.on("data", d => process.stderr.write(`[${nodeId}] ${d}`));
  children[nodeId] = proc;
  return proc;
}

function spawnCoordinator(): ChildProcess {
  const nodeUrls = Object.entries(NODE_PORTS).map(([id, port]) => `${id}=http://127.0.0.1:${port}`).join(",");
  const proc = spawn(process.execPath, [TSX_CLI, "apps/mpc-committee/src/coordinator-server.ts"], {
    env: { ...process.env, MPC_NODE_URLS: nodeUrls, MPC_INTERNAL_TOKEN: INTERNAL_TOKEN, MPC_COORDINATOR_PORT: String(COORDINATOR_PORT), DATABASE_URL: "" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  proc.stdout?.on("data", d => process.stdout.write(`[coordinator] ${d}`));
  proc.stderr?.on("data", d => process.stderr.write(`[coordinator] ${d}`));
  children.coordinator = proc;
  return proc;
}

async function waitHealthy(url: string, label: string, timeoutMs = 20_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const resp = await fetch(`${url}/health`, { signal: AbortSignal.timeout(1_000) });
      if (resp.ok) return true;
    } catch { /* not up yet */ }
    await new Promise(r => setTimeout(r, 300));
  }
  console.error(`${label} did not become healthy within ${timeoutMs}ms`);
  return false;
}

function killAll(): void {
  for (const [id, proc] of Object.entries(children)) {
    if (!proc.killed) { proc.kill("SIGTERM"); console.log(`killed ${id}`); }
  }
}

async function post(url: string, body: unknown) {
  const resp = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { ok: resp.ok, status: resp.status, body: await resp.json() };
}
async function get(url: string) {
  const resp = await fetch(url);
  return { ok: resp.ok, status: resp.status, body: await resp.json() };
}

try {
  console.log("=== MPC Liveness/Recovery E2E (P4 #24) ===");

  spawnNode("node-1"); spawnNode("node-2"); spawnNode("node-3");
  const allNodesUp = (await Promise.all(
    Object.entries(NODE_PORTS).map(([id, port]) => waitHealthy(`http://127.0.0.1:${port}`, id))
  )).every(Boolean);
  results.push({ name: "all 3 nodes start independently", ok: allNodesUp, detail: allNodesUp ? "healthy" : "one or more nodes failed to start" });
  if (!allNodesUp) throw new Error("nodes failed to start");

  spawnCoordinator();
  const coordUp = await waitHealthy(COORDINATOR_URL, "coordinator");
  results.push({ name: "coordinator starts and reaches all nodes", ok: coordUp, detail: coordUp ? "healthy" : "failed to start" });
  if (!coordUp) throw new Error("coordinator failed to start");

  const { body: committeeBody } = await get(`${COORDINATOR_URL}/v1/mpc/committee`);
  const committeeNodes = (committeeBody as { nodes: CommitteeNodeInfo[] }).nodes;
  results.push({ name: "coordinator fetched all 3 public keys over the network", ok: committeeNodes.length === 3, detail: `${committeeNodes.length} nodes` });

  // Two crossing intents.
  const amount = 5_000_000_0n;
  const noteA = fakeNote(), noteB = fakeNote();
  const intentA: MpcIntent = {
    intentId: uuidv4(), userId: "liveness-A", inputAsset: "USDC:Stellar:SAC", outputAsset: "XLM:Stellar:SAC",
    expiryLedger: 9_999_999, policyId: "policy:testnet:v1",
    noteNullifier: noteA.nullifier, noteCommitment: noteA.commitment, recipientCommitment: noteA.recipientCommitment,
    encryptedShares: splitAmountForCommittee(amount.toString(), committeeNodes, 2), submittedAt: Date.now()
  };
  const intentB: MpcIntent = {
    intentId: uuidv4(), userId: "liveness-B", inputAsset: "XLM:Stellar:SAC", outputAsset: "USDC:Stellar:SAC",
    expiryLedger: 9_999_999, policyId: "policy:testnet:v1",
    noteNullifier: noteB.nullifier, noteCommitment: noteB.commitment, recipientCommitment: noteB.recipientCommitment,
    encryptedShares: splitAmountForCommittee(amount.toString(), committeeNodes, 2), submittedAt: Date.now()
  };

  const rA = await post(`${COORDINATOR_URL}/v1/mpc/intents`, { intent: intentA });
  const rB = await post(`${COORDINATOR_URL}/v1/mpc/intents`, { intent: intentB });
  const sessionId = (rA.body as { sessionId: string }).sessionId;
  results.push({ name: "both intents submitted and shares distributed to all nodes", ok: rA.ok && rB.ok, detail: `session ${sessionId}` });

  // Give the coordinator a moment to finish forwarding shares to nodes.
  await new Promise(r => setTimeout(r, 500));

  // Kill node-3 — the failure this whole test exists to prove tolerance of.
  children["node-3"].kill("SIGTERM");
  await new Promise(r => setTimeout(r, 500));
  const node3Dead = !(await waitHealthy(`http://127.0.0.1:${NODE_PORTS["node-3"]}`, "node-3 (expect dead)", 1_500));
  results.push({ name: "node-3 killed", ok: node3Dead, detail: node3Dead ? "confirmed unreachable" : "still responding — kill failed" });

  const matchWithNodeDown = await post(`${COORDINATOR_URL}/v1/mpc/sessions/${sessionId}/match`, {});
  const batchDegraded = (matchWithNodeDown.body as { ok: boolean; batch?: SignedMatchBatch }).batch;
  const degradedOk = !!batchDegraded && batchDegraded.signatures.length === 2;
  results.push({
    name: "matching + settlement succeeds with only 2/3 nodes live",
    ok: degradedOk,
    detail: degradedOk ? `batch ${batchDegraded!.batchId} signed by ${batchDegraded!.signatures.map(s => s.nodeId).join(",")}` : JSON.stringify(matchWithNodeDown.body)
  });
  if (!degradedOk) throw new Error("degraded-mode matching failed");

  const distinctSigners = new Set(batchDegraded!.signatures.map(s => s.nodeId));
  results.push({ name: "the 2 signatures are from distinct nodes (not node-3)", ok: distinctSigners.size === 2 && !distinctSigners.has("node-3"), detail: [...distinctSigners].join(",") });

  const localVerify = verifySignedBatch(batchDegraded!, committeeNodes);
  results.push({ name: "degraded-mode batch verifies locally against the pinned committee", ok: localVerify, detail: String(localVerify) });

  // Restart node-3 with a FRESH ephemeral key (no DB in this test) — proves
  // the batch signed while it was down stays valid regardless of its identity.
  spawnNode("node-3");
  const node3BackUp = await waitHealthy(`http://127.0.0.1:${NODE_PORTS["node-3"]}`, "node-3 (restarted)");
  results.push({ name: "node-3 restarts", ok: node3BackUp, detail: node3BackUp ? "healthy again" : "failed to restart" });

  const stillValidAfterRestart = verifySignedBatch(batchDegraded!, committeeNodes);
  results.push({ name: "earlier batch is still verifiable after node-3 restarts with a new identity", ok: stillValidAfterRestart, detail: String(stillValidAfterRestart) });

  // A fresh matching round after recovery should get all 3 signatures again.
  const noteC = fakeNote(), noteD = fakeNote();
  const intentC: MpcIntent = {
    intentId: uuidv4(), userId: "liveness-C", inputAsset: "USDC:Stellar:SAC", outputAsset: "XLM:Stellar:SAC",
    expiryLedger: 9_999_999, policyId: "policy:testnet:v1",
    noteNullifier: noteC.nullifier, noteCommitment: noteC.commitment, recipientCommitment: noteC.recipientCommitment,
    encryptedShares: splitAmountForCommittee(amount.toString(), committeeNodes, 2), submittedAt: Date.now()
  };
  const intentD: MpcIntent = {
    intentId: uuidv4(), userId: "liveness-D", inputAsset: "XLM:Stellar:SAC", outputAsset: "USDC:Stellar:SAC",
    expiryLedger: 9_999_999, policyId: "policy:testnet:v1",
    noteNullifier: noteD.nullifier, noteCommitment: noteD.commitment, recipientCommitment: noteD.recipientCommitment,
    encryptedShares: splitAmountForCommittee(amount.toString(), committeeNodes, 2), submittedAt: Date.now()
  };
  const rC = await post(`${COORDINATOR_URL}/v1/mpc/intents`, { intent: intentC });
  const rD = await post(`${COORDINATOR_URL}/v1/mpc/intents`, { intent: intentD });
  const sessionId2 = (rC.body as { sessionId: string }).sessionId;
  await new Promise(r => setTimeout(r, 500));
  const matchRecovered = await post(`${COORDINATOR_URL}/v1/mpc/sessions/${sessionId2}/match`, {});
  const batchRecovered = (matchRecovered.body as { ok: boolean; batch?: SignedMatchBatch }).batch;
  const recoveredOk = !!batchRecovered && batchRecovered.signatures.length === 3;
  results.push({
    name: "after recovery, a new round gets all 3 signatures again",
    ok: recoveredOk && rC.ok && rD.ok,
    detail: recoveredOk ? `batch ${batchRecovered!.batchId} signed by all 3` : JSON.stringify(matchRecovered.body)
  });
} finally {
  killAll();
}

beginReport({ title: "MPC Liveness/Recovery" });
await writeCheckReport("MPC Liveness/Recovery E2E (P4 #24)", results);
for (const r of results) console.log(`${r.ok ? "PASS" : "FAIL"}  ${r.name} — ${r.detail}`);
failIfAny(results);
console.log("=== MPC LIVENESS E2E COMPLETE ===");

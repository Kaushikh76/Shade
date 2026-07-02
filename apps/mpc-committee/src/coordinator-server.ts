import "dotenv/config";
import Fastify from "fastify";
import pg from "pg";
import { verifySignedBatch, type MpcIntent, type EncryptedShare, type CommitteeNodeInfo } from "@shade/mpc-crypto";
import { CommitteeState } from "./state.js";
import { runMatchingRoundRemote, type NodeEndpoint } from "./remote-coordinator.js";
import { runSettlerLoop } from "./settler.js";
import { persistSignedBatch } from "./persist.js";
import { getRateProvider } from "./reflector-rate.js";

const rateProvider = getRateProvider();

// P4 #24: standalone coordinator — pairs with node-server.ts. Holds NO node
// secret keys (unlike server.ts's combined dev/demo mode); every node
// interaction is an authenticated HTTP call. Configure with:
//   MPC_NODE_URLS        comma-separated node-id=url pairs, e.g.
//                         "node-1=http://mpc-node-1:8091,node-2=http://mpc-node-2:8091,node-3=http://mpc-node-3:8091"
//   MPC_INTERNAL_TOKEN    shared bearer token, must match every node's own
//   MPC_BATCH_WINDOW_MS   auto-match timer interval (default 30s)
//   DATABASE_URL          optional; enables batch persistence + the settler

function parseNodeUrls(spec: string): NodeEndpoint[] {
  return spec.split(",").map(pair => {
    const [nodeId, url] = pair.split("=");
    if (!nodeId || !url) throw new Error(`invalid MPC_NODE_URLS entry: "${pair}" (expected nodeId=url)`);
    return { nodeId: nodeId.trim(), url: url.trim() };
  });
}

const nodeUrlsSpec = process.env.MPC_NODE_URLS;
if (!nodeUrlsSpec) throw new Error("MPC_NODE_URLS is required, e.g. node-1=http://localhost:8091,node-2=...,node-3=...");
const NODE_ENDPOINTS = parseNodeUrls(nodeUrlsSpec);

const internalTokenEnv = process.env.MPC_INTERNAL_TOKEN;
if (!internalTokenEnv) throw new Error("MPC_INTERNAL_TOKEN is required — authenticates this coordinator to every node");
const INTERNAL_TOKEN: string = internalTokenEnv;

const COORDINATOR_PORT = Number(process.env.MPC_COORDINATOR_PORT ?? 8090);
const BATCH_WINDOW_MS = Number(process.env.MPC_BATCH_WINDOW_MS ?? 30_000);
const dbUrl = process.env.DATABASE_URL;
const dbPool = dbUrl ? new pg.Pool({ connectionString: dbUrl }) : null;

const state = new CommitteeState();

// Fetch each node's public identity at boot — the only "key material" this
// process ever holds is public keys.
async function fetchCommitteeInfo(): Promise<CommitteeNodeInfo[]> {
  const infos = await Promise.all(NODE_ENDPOINTS.map(async n => {
    const resp = await fetch(`${n.url}/info`, { signal: AbortSignal.timeout(8_000) });
    if (!resp.ok) throw new Error(`node ${n.nodeId} /info failed: ${resp.status}`);
    return (await resp.json()) as CommitteeNodeInfo;
  }));
  return infos;
}
const committeeInfo = await fetchCommitteeInfo();

// Forward each node's own slice of a submitted intent's shares to that node.
async function distributeShares(intentId: string, encryptedShares: EncryptedShare[]): Promise<void> {
  await Promise.all(encryptedShares.map(async share => {
    const node = NODE_ENDPOINTS.find(n => n.nodeId === share.nodeId);
    if (!node) { console.warn(`[mpc-coordinator] no endpoint configured for node ${share.nodeId}`); return; }
    try {
      const resp = await fetch(`${node.url}/shares/${intentId}`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-mpc-internal-token": INTERNAL_TOKEN },
        body: JSON.stringify(share),
        signal: AbortSignal.timeout(8_000)
      });
      if (!resp.ok) console.warn(`[mpc-coordinator] node ${share.nodeId} rejected share for ${intentId}: ${resp.status}`);
    } catch (err) {
      console.warn(`[mpc-coordinator] failed to forward share to ${share.nodeId} for ${intentId}: ${err}`);
    }
  }));
}

const app = Fastify({ logger: { level: "info" } });

app.get("/v1/mpc/committee", async () => ({ nodes: committeeInfo }));

app.post<{ Body: { intent: MpcIntent } }>("/v1/mpc/intents", async (request, reply) => {
  const { intent } = request.body;
  if (!intent?.intentId) { reply.code(400); return { error: "intentId required" }; }
  if (intent.encryptedShares.length !== NODE_ENDPOINTS.length) {
    reply.code(400);
    return { error: `must supply ${NODE_ENDPOINTS.length} encrypted shares, one per committee node` };
  }
  const sessionId = state.addIntent(intent);
  await distributeShares(intent.intentId, intent.encryptedShares);
  return { ok: true, intentId: intent.intentId, sessionId };
});

app.get<{ Params: { sessionId: string } }>("/v1/mpc/sessions/:sessionId", async (request, reply) => {
  const session = state.getSession(request.params.sessionId);
  if (!session) { reply.code(404); return { error: "session not found" }; }
  return {
    sessionId: session.sessionId, status: session.status, intentCount: session.intents.size,
    startedAt: session.startedAt, signedBatch: session.signedBatch ?? null
  };
});

app.post<{ Params: { sessionId: string } }>("/v1/mpc/sessions/:sessionId/match", async (request, reply) => {
  const session = state.getSession(request.params.sessionId);
  if (!session) { reply.code(404); return { error: "session not found" }; }
  if (session.status !== "open") return { ok: false, reason: `session already in status '${session.status}'` };
  const result = await runMatchingRoundRemote(session, NODE_ENDPOINTS, INTERNAL_TOKEN, rateProvider);
  if (result.ok && dbPool) await persistSignedBatch(dbPool, session.sessionId, result.batch);
  return result.ok ? { ok: true, batch: result.batch } : { ok: false, reason: result.reason };
});

app.get("/v1/mpc/batches", async () => {
  const signed = state.allSessions().filter(s => s.status === "signed" && s.signedBatch).map(s => s.signedBatch!);
  return { batches: signed };
});

app.post<{ Body: { batch: import("@shade/mpc-crypto").SignedMatchBatch } }>("/v1/mpc/verify", async (request, reply) => {
  const { batch } = request.body;
  if (!batch) { reply.code(400); return { error: "batch required" }; }
  const valid = verifySignedBatch(batch, committeeInfo);
  return { valid, nodeCount: committeeInfo.length, sigCount: batch.signatures.length };
});

app.get("/health", async () => ({ ok: true, service: "mpc-coordinator", nodes: NODE_ENDPOINTS.map(n => n.nodeId), batchWindowMs: BATCH_WINDOW_MS }));

await app.listen({ port: COORDINATOR_PORT, host: "0.0.0.0" });
console.log(`[mpc-coordinator] listening on :${COORDINATOR_PORT}, nodes: ${NODE_ENDPOINTS.map(n => `${n.nodeId}@${n.url}`).join(", ")}`);

setInterval(async () => {
  for (const session of state.getOpenSessions()) {
    if (session.intents.size < 2) continue;
    console.log(`[mpc-coordinator] auto-matching session ${session.sessionId} with ${session.intents.size} intents`);
    const result = await runMatchingRoundRemote(session, NODE_ENDPOINTS, INTERNAL_TOKEN, rateProvider);
    if (result.ok) {
      if (dbPool) await persistSignedBatch(dbPool, session.sessionId, result.batch);
      console.log(`[mpc-coordinator] batch ${result.batch.batchId}: ${result.batch.matches.length} matches, signed by ${result.batch.signatures.length}/${NODE_ENDPOINTS.length} nodes`);
    } else {
      console.warn(`[mpc-coordinator] matching failed for ${session.sessionId}: ${result.reason}`);
    }
  }
}, BATCH_WINDOW_MS);

if (dbUrl) {
  const SETTLER_INTERVAL_MS = Number(process.env.MPC_SETTLER_INTERVAL_MS ?? 10_000);
  runSettlerLoop(dbUrl, SETTLER_INTERVAL_MS).catch(err => console.error("[mpc-coordinator] settler crashed:", err));
} else {
  console.log("[mpc-coordinator] DATABASE_URL not set — settler disabled");
}

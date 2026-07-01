import "dotenv/config";
import Fastify from "fastify";
import { timingSafeEqual } from "node:crypto";
import {
  generateNodeKeyPair, nodePublicInfo, decryptShare, signBatch,
  type EncryptedShare, type MatchResult
} from "@shade/mpc-crypto";
import { loadOrGenerateKeys } from "./keys.js";

// P4 #24: standalone entrypoint for ONE committee node — the actual
// independent-operator deployment target. Run three of these (different
// hosts/containers, different DATABASE_URL if each operator runs their own
// Postgres, different MPC_INTERNAL_TOKEN per node in production) alongside
// one coordinator-server.ts. This process holds ONE node's secret keys —
// never all three, unlike the combined server.ts dev/demo mode.
//
// The coordinator never sees this node's secret key. It calls:
//   POST /shares/:intentId    — receives this node's slice of a user's
//                                encrypted shares (forwarded by the coordinator)
//   POST /internal/decrypt    — decrypts THIS node's shares for the given
//                                intentIds and returns the decrypted (x,y)
//                                pairs (still just one share of a t-of-n
//                                secret, not the secret key itself)
//   POST /internal/sign-batch — signs a batch hash with this node's key
// All three are gated on a shared bearer token (MPC_INTERNAL_TOKEN). This is
// an interim authentication scheme — production should use mTLS between the
// coordinator and each node (see P0 #5's note on the same trade-off).

const NODE_ID = process.env.MPC_NODE_ID;
if (!NODE_ID) throw new Error("MPC_NODE_ID is required (e.g. node-1)");
const PORT = Number(process.env.MPC_NODE_PORT ?? 8091);
const internalTokenEnv = process.env.MPC_INTERNAL_TOKEN;
if (!internalTokenEnv) throw new Error("MPC_INTERNAL_TOKEN is required — authenticates the coordinator to this node");
const INTERNAL_TOKEN: string = internalTokenEnv;

const dbUrl = process.env.DATABASE_URL;
const [node] = dbUrl ? await loadOrGenerateKeys(dbUrl, [NODE_ID]) : [generateNodeKeyPair(NODE_ID)];

// This node's own slice of encrypted shares — intentId -> ciphertext.
// Never holds decrypted values outside the lifetime of a single request.
const shares = new Map<string, EncryptedShare>();

function requireInternalAuth(headers: Record<string, unknown>): boolean {
  const provided = headers["x-mpc-internal-token"];
  if (typeof provided !== "string" || provided.length !== INTERNAL_TOKEN.length) return false;
  return timingSafeEqual(Buffer.from(provided), Buffer.from(INTERNAL_TOKEN));
}

const app = Fastify({ logger: false });

app.get("/health", async () => ({ ok: true, nodeId: NODE_ID }));
app.get("/info", async () => nodePublicInfo(node));

app.post<{ Params: { intentId: string }; Body: EncryptedShare }>(
  "/shares/:intentId",
  async (request, reply) => {
    if (!requireInternalAuth(request.headers as Record<string, unknown>)) { reply.code(401); return { error: "unauthorized" }; }
    const { intentId } = request.params;
    const encShare = request.body;
    if (encShare.nodeId !== NODE_ID) { reply.code(400); return { error: "share addressed to wrong node" }; }
    shares.set(intentId, encShare);
    return { ok: true, nodeId: NODE_ID, intentId };
  }
);

app.post<{ Body: { intentIds: string[] } }>(
  "/internal/decrypt",
  async (request, reply) => {
    if (!requireInternalAuth(request.headers as Record<string, unknown>)) { reply.code(401); return { error: "unauthorized" }; }
    const results: Record<string, { x: string; y: string } | null> = {};
    for (const intentId of request.body.intentIds) {
      const enc = shares.get(intentId);
      if (!enc) { results[intentId] = null; continue; }
      try {
        results[intentId] = decryptShare(enc, node.encryptionKeyPair.secretKey);
      } catch {
        results[intentId] = null;
      }
    }
    return { nodeId: NODE_ID, shares: results };
  }
);

app.post<{ Body: { batchId: string; matches: MatchResult[] } }>(
  "/internal/sign-batch",
  async (request, reply) => {
    if (!requireInternalAuth(request.headers as Record<string, unknown>)) { reply.code(401); return { error: "unauthorized" }; }
    return signBatch(request.body.batchId, request.body.matches, node);
  }
);

await app.listen({ port: PORT, host: "0.0.0.0" });
console.log(`[mpc-node] ${NODE_ID} listening on :${PORT}`);

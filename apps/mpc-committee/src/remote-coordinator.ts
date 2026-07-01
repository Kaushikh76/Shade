import { v4 as uuidv4 } from "uuid";
import {
  reconstructAmount, computeBatchHash,
  type SignedMatchBatch, type NodeSignature
} from "@shade/mpc-crypto";
import type { SessionState } from "./state.js";
import { matchIntents, type CoordinatorResult } from "./coordinator.js";

// P4 #24: the network-only counterpart to coordinator.ts::runMatchingRound.
// This coordinator holds NO node secret keys — it only ever talks to nodes
// over HTTP (POST /internal/decrypt, POST /internal/sign-batch), each
// authenticated with a shared bearer token. A single compromised coordinator
// process can no longer leak any node's signing/encryption key, only
// whatever it legitimately reconstructs during an active matching round
// (the P2 #16 trusted-matcher limitation, unchanged and separately tracked).
//
// Fault-tolerant by design: with threshold = ceil(2n/3), losing ONE of three
// nodes must not stop settlement. Every node call below is best-effort
// (timeout + catch -> null) and the round only fails if fewer than
// `threshold` nodes respond to decrypt AND sign.

export type NodeEndpoint = {
  nodeId: string;
  url: string; // e.g. http://mpc-node-1:8091
};

const REQUEST_TIMEOUT_MS = 8_000;

async function postJson<T>(url: string, token: string, body: unknown): Promise<T | null> {
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mpc-internal-token": token },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    });
    if (!resp.ok) return null;
    return (await resp.json()) as T;
  } catch {
    return null;
  }
}

function threshold(n: number): number {
  return Math.ceil((n * 2) / 3);
}

export async function runMatchingRoundRemote(
  session: SessionState,
  nodeEndpoints: NodeEndpoint[],
  internalToken: string
): Promise<CoordinatorResult> {
  if (session.intents.size < 2) {
    return { ok: false, reason: "need at least 2 intents to match" };
  }
  const need = threshold(nodeEndpoints.length);
  session.status = "matching";

  const intentIds = [...session.intents.keys()];

  // Step 1: ask every node to decrypt its own shares for these intents.
  // Best-effort per node — a down/unreachable node just contributes nothing.
  const decryptResults = await Promise.all(
    nodeEndpoints.map(n =>
      postJson<{ nodeId: string; shares: Record<string, { x: string; y: string } | null> }>(
        `${n.url}/internal/decrypt`, internalToken, { intentIds }
      )
    )
  );
  const respondingDecrypt = decryptResults.filter((r): r is NonNullable<typeof r> => r !== null);
  if (respondingDecrypt.length < need) {
    session.status = "failed";
    return { ok: false, reason: `only ${respondingDecrypt.length}/${nodeEndpoints.length} nodes responded to decrypt (need ${need})` };
  }
  for (const result of respondingDecrypt) {
    const nodeShares = session.shares.get(result.nodeId);
    if (!nodeShares) continue;
    for (const [intentId, share] of Object.entries(result.shares)) {
      const entry = nodeShares.get(intentId);
      if (entry) entry.decryptedShare = share;
    }
  }

  // Step 2: reconstruct amounts from >=2 decrypted shares per intent —
  // identical logic/threshold to the in-process path.
  const reconstructed: Array<{ intentId: string; amount7dp: bigint; inputAsset: string; outputAsset: string }> = [];
  for (const [intentId, intent] of session.intents.entries()) {
    const availableShares: Array<{ x: string; y: string }> = [];
    for (const n of nodeEndpoints) {
      const share = session.shares.get(n.nodeId)?.get(intentId)?.decryptedShare;
      if (share) availableShares.push(share);
      if (availableShares.length >= 2) break;
    }
    if (availableShares.length < 2) {
      session.status = "failed";
      return { ok: false, reason: `not enough shares for intent ${intentId}` };
    }
    reconstructed.push({ intentId, amount7dp: reconstructAmount(availableShares), inputAsset: intent.inputAsset, outputAsset: intent.outputAsset });
  }

  // Privacy hygiene: clear decrypted shares from coordinator memory immediately.
  for (const n of nodeEndpoints) {
    const nodeShares = session.shares.get(n.nodeId);
    if (!nodeShares) continue;
    for (const entry of nodeShares.values()) entry.decryptedShare = null;
  }

  // Step 3: matching.
  const matches = matchIntents(reconstructed);

  // Step 4: ask every node to sign — again best-effort, threshold-gated.
  const batchId = uuidv4();
  const batchHash = computeBatchHash(batchId, matches);
  const sigResults = await Promise.all(
    nodeEndpoints.map(n => postJson<NodeSignature>(`${n.url}/internal/sign-batch`, internalToken, { batchId, matches }))
  );
  const signatures = sigResults.filter((s): s is NodeSignature => s !== null);
  if (signatures.length < need) {
    session.status = "failed";
    return { ok: false, reason: `only ${signatures.length}/${nodeEndpoints.length} nodes signed (need ${need})` };
  }

  const signedBatch: SignedMatchBatch = { batchId, sessionId: session.sessionId, matches, batchHash, signatures };
  session.signedBatch = signedBatch;
  session.status = "signed";
  return { ok: true, batch: signedBatch };
}

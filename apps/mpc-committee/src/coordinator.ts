import { createHash } from "node:crypto";
import { v4 as uuidv4 } from "uuid";
import {
  decryptShare, reconstructAmount, signBatch, computeBatchHash,
  RATE_SCALE,
  type CommitteeNodeKeyPair, type MatchResult, type SignedMatchBatch, type RateProvider
} from "@shade/mpc-crypto";
import type { CommitteeState, SessionState } from "./state.js";

// ---------- Matching algorithm ----------
// Netting: pair intents with complementary amounts (same asset pair). Amounts
// are NOT assumed interchangeable 1:1 across different assets — `rateProvider`
// supplies the real price of one unit of the input asset denominated in the
// output asset (RATE_SCALE-scaled), and the match amount + the counterparty's
// leg are derived from that rate. Same-asset pairs (e.g. splitting/merging
// notes of one asset) are still exactly 1:1 by definition.
// In production this would additionally be a full price-time priority order
// book (partial fills, resting orders) — this is still one-shot full-consumption
// netting per round, unchanged from before; only the RATE math was wrong.

export async function matchIntents(
  intents: Array<{ intentId: string; amount7dp: bigint; inputAsset: string; outputAsset: string }>,
  rateProvider: RateProvider
): Promise<MatchResult[]> {
  const matches: MatchResult[] = [];
  const used = new Set<string>();

  // Group by (inputAsset, outputAsset) pair.
  const groups = new Map<string, typeof intents>();
  for (const intent of intents) {
    const key = `${intent.inputAsset}|${intent.outputAsset}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(intent);
  }

  // Within each group, sort by amount ascending and try to match complementary pairs.
  // "Complementary" means: intent A wants to send X of assetA for assetB,
  //  intent B wants to send X of assetB for assetA.
  for (const [key, group] of groups.entries()) {
    const [inAsset, outAsset] = key.split("|");
    const reverseKey = `${outAsset}|${inAsset}`;
    const reverseGroup = groups.get(reverseKey);
    if (!reverseGroup) continue;

    // rate = price of 1 unit of inAsset in outAsset, scaled RATE_SCALE.
    // Same-asset groups (inAsset === outAsset, e.g. a pure note split/merge)
    // are 1:1 by definition — no oracle lookup needed or possible.
    const rate = inAsset === outAsset ? RATE_SCALE : BigInt(await rateProvider(inAsset, outAsset));
    if (rate <= 0n) continue; // no usable rate for this pair this round — skip, don't guess

    // Sort both groups by amount.
    const sorted = [...group].sort((a, b) => (a.amount7dp < b.amount7dp ? -1 : 1));
    const reverseSorted = [...reverseGroup].sort((a, b) => (a.amount7dp < b.amount7dp ? -1 : 1));

    let ai = 0;
    let bi = 0;
    while (ai < sorted.length && bi < reverseSorted.length) {
      const a = sorted[ai];
      const b = reverseSorted[bi];
      // Only advance the side that's actually already used — advancing both
      // unconditionally can skip a still-unused, otherwise-valid counterparty.
      if (used.has(a.intentId)) { ai++; continue; }
      if (used.has(b.intentId)) { bi++; continue; }

      // b.amount7dp is denominated in outAsset; convert to inAsset terms
      // (b's offer, valued in what a is giving) so both offers compare in the
      // same unit: bInAssetEquivalent = b.amount7dp / rate (inverse of rate,
      // since rate converts inAsset -> outAsset).
      const bInAssetEquivalent = (b.amount7dp * RATE_SCALE) / rate;
      const matchAmt = a.amount7dp < bInAssetEquivalent ? a.amount7dp : bInAssetEquivalent;
      matches.push({
        intentAId: a.intentId,
        intentBId: b.intentId,
        matchedAmount7dp: matchAmt.toString(),
        inputAsset: inAsset,
        outputAsset: outAsset,
        rate: rate.toString()
      });
      used.add(a.intentId);
      used.add(b.intentId);
      ai++;
      bi++;
    }
  }

  return matches;
}

// ---------- Coordinator ----------

export type CoordinatorResult =
  | { ok: true; batch: SignedMatchBatch }
  | { ok: false; reason: string };

/**
 * Run one matching batch for a session.
 * Steps:
 *   1. Each node decrypts its shares for all intents in the session.
 *   2. Coordinator reconstructs amounts from ≥2 shares per intent.
 *   3. Matching algorithm finds crossed pairs.
 *   4. All nodes sign the match batch.
 *   5. Return the signed batch.
 *
 * P2 #16 — NOT privacy-preserving MPC: step 2 reconstructs every intent's
 * plaintext amount in THIS process before matching (see the reconstructed[]
 * loop below). Whether the 3 "nodes" run in one process or three separate
 * ones, the matcher itself is fully trusted with every amount for the
 * duration of this function. Shares are re-nulled immediately after (privacy
 * hygiene, not a privacy guarantee). Real private matching needs a TEE (V2,
 * not started) or secure multi-party comparison (V3/V4) — see docs/PENDING.md.
 */
export async function runMatchingRound(
  session: SessionState,
  nodes: CommitteeNodeKeyPair[],
  rateProvider: RateProvider
): Promise<CoordinatorResult> {
  if (session.intents.size < 2) {
    return { ok: false, reason: "need at least 2 intents to match" };
  }

  session.status = "matching";

  // Step 1: each node decrypts its shares.
  for (const node of nodes) {
    const nodeShares = session.shares.get(node.nodeId);
    if (!nodeShares) continue;
    for (const entry of nodeShares.values()) {
      try {
        entry.decryptedShare = decryptShare(
          { ...entry.encryptedShare, nodeId: node.nodeId },
          node.encryptionKeyPair.secretKey
        );
      } catch (err) {
        session.status = "failed";
        return { ok: false, reason: `node ${node.nodeId} failed to decrypt share for ${entry.intentId}: ${err}` };
      }
    }
  }

  // Step 2: reconstruct amounts from first 2 nodes' decrypted shares.
  const reconstructed: Array<{ intentId: string; amount7dp: bigint; inputAsset: string; outputAsset: string }> = [];
  for (const [intentId, intent] of session.intents.entries()) {
    const availableShares: Array<{ x: string; y: string }> = [];
    for (const node of nodes) {
      const share = session.shares.get(node.nodeId)?.get(intentId)?.decryptedShare;
      if (share) availableShares.push(share);
      if (availableShares.length >= 2) break; // 2-of-N threshold
    }
    if (availableShares.length < 2) {
      session.status = "failed";
      return { ok: false, reason: `not enough shares for intent ${intentId}` };
    }
    const amount = reconstructAmount(availableShares);
    reconstructed.push({ intentId, amount7dp: amount, inputAsset: intent.inputAsset, outputAsset: intent.outputAsset });
  }

  // Immediately clear decrypted share data (privacy hygiene).
  for (const node of nodes) {
    const nodeShares = session.shares.get(node.nodeId);
    if (!nodeShares) continue;
    for (const entry of nodeShares.values()) {
      entry.decryptedShare = null;
    }
  }

  // Step 3: run matching.
  const matches = await matchIntents(reconstructed, rateProvider);

  // Step 4: all nodes sign the batch.
  const batchId = uuidv4();
  const batchHash = computeBatchHash(batchId, matches);
  const signatures = nodes.map(n => signBatch(batchId, matches, n));

  const signedBatch: SignedMatchBatch = {
    batchId,
    sessionId: session.sessionId,
    matches,
    batchHash,
    signatures
  };

  session.signedBatch = signedBatch;
  session.status = "signed";

  return { ok: true, batch: signedBatch };
}

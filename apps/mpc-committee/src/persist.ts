import type pg from "pg";
import type { SignedMatchBatch } from "@shade/mpc-crypto";

// P1 #12: a signed batch must be persisted to mpc_batches regardless of what
// triggered the matching round (the 30s auto-timer or a manual API call) —
// the settler only ever reads from mpc_batches, so an unpersisted batch is a
// dead end that silently never settles. This is the single persistence path
// both callers in server.ts use.
export async function persistSignedBatch(
  pool: pg.Pool,
  sessionId: string,
  batch: SignedMatchBatch
): Promise<void> {
  await pool.query(
    `INSERT INTO mpc_batches (batch_id, session_id, batch_hash, match_count, matches_json, signatures_json)
     VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
    [batch.batchId, sessionId, batch.batchHash, batch.matches.length, JSON.stringify(batch.matches), JSON.stringify(batch.signatures)]
  );

  // Denormalized per-node signature rows.
  for (const sig of batch.signatures) {
    await pool.query(
      `INSERT INTO mpc_batch_signatures (batch_id, node_id, signing_pubkey, signature)
       VALUES ($1,$2,$3,$4) ON CONFLICT (batch_id, node_id) DO NOTHING`,
      [batch.batchId, sig.nodeId, sig.signingPubkey, sig.signature]
    );
  }

  await pool.query(
    "UPDATE mpc_sessions SET status='signed', match_count=$1, closed_at=now(), updated_at=now() WHERE session_id=$2",
    [batch.matches.length, sessionId]
  );

  // P1 #17: do not persist the plaintext matched amount to mpc_intents. It
  // already lives, where operationally necessary, in mpc_batches.matches_json
  // (the committee-signed artifact the relayer/prover need to build the
  // settlement proof and on-chain call). mpc_intents only needs to record
  // that a match happened and with whom.
  for (const m of batch.matches) {
    await pool.query(
      "UPDATE mpc_intents SET status='matched', matched_with=$2, updated_at=now() WHERE intent_id=$1",
      [m.intentAId, m.intentBId]
    );
    await pool.query(
      "UPDATE mpc_intents SET status='matched', matched_with=$2, updated_at=now() WHERE intent_id=$1",
      [m.intentBId, m.intentAId]
    );
  }
}

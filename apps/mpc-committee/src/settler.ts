import pg from "pg";
import { JobQueue } from "@shade/queue";

// MPC Settler: polls mpc_batches for signed matches that haven't been submitted
// to the settlement layer yet, queues MPC_SETTLE_SUBMIT relayer jobs with full
// note data (nullifiers + output commitments) fetched from mpc_intents.

type MatchRow = {
  intentAId: string;
  intentBId: string;
  matchedAmount7dp: string;
  inputAsset: string;
  outputAsset: string;
};

type BatchRow = {
  batch_id: string;
  session_id: string;
  batch_hash: string;
  matches_json: MatchRow[];
  signatures_json: Array<{ nodeId: string; signingPubkey: string; signature: string }>;
  settlement_status: string;
};

type IntentRow = {
  intent_id: string;
  note_nullifier: string;
  note_commitment: string;
  recipient_commitment: string;
};

// Fetch nullifier + commitments for an intent from the DB.
async function fetchIntentNote(pool: pg.Pool, intentId: string): Promise<IntentRow | null> {
  const { rows } = await pool.query<IntentRow>(
    `SELECT intent_id, note_nullifier, note_commitment, recipient_commitment
     FROM mpc_intents WHERE intent_id = $1`,
    [intentId]
  );
  return rows[0] ?? null;
}

// P0 #4: an MPC-matched intent is reachable by two settlement paths — the
// proof-backed POST /v1/rfq/settle lifecycle, and this settler's mpc_settle
// path. Both spend the same nullifiers, so they must be mutually exclusive
// per intent. Phase A routes every RFQ intent through the committee by giving
// it a row in `intents` (intent_hash = mpc_intents.intent_id, see migration
// 011); those intents settle ONLY via rfq_settle, driven by the RFQ lifecycle
// (accept -> lock -> fill -> settle), never by this settler. Only intents
// submitted directly to POST /v1/mpc/intents (no `intents` row — pure
// crossing-settlement, no RFQ wrapper) are this settler's to settle.
async function isRfqRouted(pool: pg.Pool, intentId: string): Promise<boolean> {
  const { rows } = await pool.query(
    "SELECT 1 FROM intents WHERE intent_hash = $1",
    [intentId]
  );
  return rows.length > 0;
}

// One MPC_SETTLE_SUBMIT job per non-RFQ-routed match in a batch.
// Includes full note data so the relayer can construct the on-chain call.
async function queueSettlementJobs(queue: JobQueue, pool: pg.Pool, batch: BatchRow): Promise<void> {
  const matches: MatchRow[] = Array.isArray(batch.matches_json)
    ? batch.matches_json
    : (batch.matches_json as unknown as string[]).map(s => JSON.parse(String(s)));

  const sigs = Array.isArray(batch.signatures_json)
    ? batch.signatures_json
    : (batch.signatures_json as unknown as string[]).map(s => JSON.parse(String(s)));

  let queued = 0;
  let skipped = 0;

  for (let i = 0; i < matches.length; i++) {
    const m = matches[i];
    const idempotencyKey = `mpc_settle:${batch.batch_id}:${i}`;

    // Skip any match where either side belongs to the RFQ lifecycle — it
    // settles exclusively via rfq_settle, never via this path.
    const [aRfqRouted, bRfqRouted] = await Promise.all([
      isRfqRouted(pool, m.intentAId),
      isRfqRouted(pool, m.intentBId)
    ]);
    if (aRfqRouted || bRfqRouted) {
      skipped++;
      continue;
    }

    // Fetch note data for both sides of the match.
    const [noteA, noteB] = await Promise.all([
      fetchIntentNote(pool, m.intentAId),
      fetchIntentNote(pool, m.intentBId)
    ]);

    await queue.enqueue(
      "relayer",
      "MPC_SETTLE_SUBMIT",
      {
        batchId: batch.batch_id,
        batchHash: batch.batch_hash,
        signatures: sigs,
        matchIndex: i,
        sessionId: batch.session_id,
        intentAId: m.intentAId,
        intentBId: m.intentBId,
        matchedAmount7dp: m.matchedAmount7dp,
        inputAsset: m.inputAsset,
        outputAsset: m.outputAsset,
        // Note data for on-chain settlement call
        nullifierA: noteA?.note_nullifier ?? null,
        nullifierB: noteB?.note_nullifier ?? null,
        // recipientCommitment = the new output note the counterparty will own
        outputCommitmentA: noteA?.recipient_commitment ?? null,
        outputCommitmentB: noteB?.recipient_commitment ?? null,
      },
      idempotencyKey
    );
    queued++;
  }

  // A batch settles fully via mpc_settle (all matches queued), fully via the
  // RFQ lifecycle (all matches skipped), or — if a session ever mixes both
  // kinds of intents — partially. Only mark 'queued' if this settler actually
  // has work left to do; an all-RFQ batch is marked 'rfq_routed' so it stops
  // showing up in the 'pending' poll.
  const newStatus = queued > 0 ? "queued" : "rfq_routed";
  await pool.query(
    "UPDATE mpc_batches SET settlement_status=$2, updated_at=now() WHERE batch_id=$1",
    [batch.batch_id, newStatus]
  );
  console.log(`[settler] batch ${batch.batch_id}: ${queued} match(es) queued for mpc_settle, ${skipped} skipped (RFQ-routed)`);
}

// Poll once for pending signed batches and dispatch settlement jobs.
export async function settleOnce(queue: JobQueue, pool: pg.Pool): Promise<number> {
  const { rows } = await pool.query<BatchRow>(
    `SELECT batch_id, session_id, batch_hash, matches_json, signatures_json, settlement_status
     FROM mpc_batches
     WHERE settlement_status = 'pending'
     ORDER BY created_at ASC
     LIMIT 50`
  );
  for (const batch of rows) {
    await queueSettlementJobs(queue, pool, batch);
  }
  return rows.length;
}

// Long-running settler loop. Runs alongside the committee service.
export async function runSettlerLoop(
  dbUrl: string,
  intervalMs = 10_000
): Promise<void> {
  const { Pool } = pg;
  const pool = new Pool({ connectionString: dbUrl });
  const queue = new JobQueue(dbUrl);

  console.log(`[settler] starting — polling every ${intervalMs}ms for signed MPC batches`);
  for (;;) {
    try {
      const n = await settleOnce(queue, pool);
      if (n > 0) console.log(`[settler] dispatched settlement jobs for ${n} batch(es)`);
    } catch (err) {
      console.error("[settler] error in settle loop:", err);
    }
    await new Promise(r => setTimeout(r, intervalMs));
  }
}

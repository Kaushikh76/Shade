import { rmSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { JobQueue, type ServiceJob } from "@shade/queue";
import {
  buildNoteProof, buildTransferProof, buildDepositProof,
  type GeneratedCoin, type WithdrawBinding, type DepositBinding
} from "@shade/proving";

// PHASE 2 prover worker. Consumes proof jobs from the durable queue and runs the
// REAL Groth16/BLS12-381 pipeline (the same prove.ts builders the CLI uses):
// build witness -> prove -> verify locally -> convert to Soroban bytes. It stores
// only PUBLIC proof outputs (proof/public hex) in the job result, deletes the raw
// witness, and never logs note secrets.

export const PROOF_JOB_TYPES = ["withdraw_public", "withdraw_cctp", "rfq_settlement", "private_transfer", "deposit_note_mint"] as const;
export type ProofJobType = (typeof PROOF_JOB_TYPES)[number];

const SCRATCH = process.env.SHADE_SCRATCH_DIR ?? resolve(process.env.SHADE_ROOT ?? process.cwd(), ".scratch");

// A proof job's payload references a coin file (the note opening, kept in scratch)
// plus the builder inputs. The client/relayer writes the coin; the prover reads it.
type ProofPayload = {
  coinPath: string;
  scope?: string;
  commitmentsDecimal?: string[];
  assocPath?: string;
  binding?: WithdrawBinding;          // withdraw_public / withdraw_cctp / rfq_settlement
  fee7dp?: string;                    // private_transfer
  depositBinding?: DepositBinding;    // deposit_note_mint
  tag?: string;
};

function coinFromPath(path: string): GeneratedCoin {
  // The coin file already exists (written by the client/relayer into scratch). Read
  // the same JSON contract generateCoin produces — only the public fields are used
  // here; the private opening is read inside the builder when it shells coinutils.
  const c = JSON.parse(readFileSync(path, "utf8"));
  return { path, commitmentHex: c.commitment_hex, commitmentDecimal: c.coin.commitment, value7dp: c.coin.value };
}

// Process one claimed proof job through the documented status lifecycle.
export async function processProofJob(queue: JobQueue, job: ServiceJob): Promise<Record<string, unknown>> {
  const p = job.payload as ProofPayload;
  const tag = p.tag ?? `job_${job.job_id.slice(0, 8)}`;
  const coin = coinFromPath(p.coinPath);

  await queue.setStatus(job.job_id, "building_witness", `${job.job_type} witness`);
  await queue.setStatus(job.job_id, "proving", "groth16 prove");

  let result: Record<string, unknown>;
  if (job.job_type === "private_transfer") {
    // P2 #14: private_transfer now carries an ASP allow-set binding — require
    // assocPath the same way withdraw does, so a proof can't silently skip
    // the compliance envelope by omitting it.
    if (!p.assocPath) throw new Error(`${job.job_type} requires assocPath`);
    const pr = buildTransferProof(coin, p.commitmentsDecimal ?? [coin.commitmentDecimal], p.scope ?? "shade", p.fee7dp ?? "0", SCRATCH, tag, p.assocPath);
    await assertVerified(queue, job, pr.locallyVerified);
    result = { proofHex: pr.proofHex, publicHex: pr.publicHex, stateRootHex: pr.stateRootHex, associationRootHex: pr.associationRootHex, outputCommitmentHex: pr.outputCommitmentHex };
  } else if (job.job_type === "deposit_note_mint") {
    if (!p.depositBinding) throw new Error("deposit_note_mint requires depositBinding");
    const pr = buildDepositProof(coin, p.depositBinding, SCRATCH, tag);
    await assertVerified(queue, job, pr.locallyVerified);
    result = { proofHex: pr.proofHex, publicHex: pr.publicHex, commitmentHex: pr.commitmentHex };
  } else {
    // withdraw_public / withdraw_cctp / rfq_settlement share the withdraw circuit.
    if (!p.assocPath) throw new Error(`${job.job_type} requires assocPath`);
    const pr = buildNoteProof(coin, p.commitmentsDecimal ?? [coin.commitmentDecimal], p.scope ?? "shade", SCRATCH, tag, p.assocPath, p.binding);
    await assertVerified(queue, job, pr.locallyVerified);
    result = { proofHex: pr.proofHex, publicHex: pr.publicHex, stateRootHex: pr.stateRootHex };
  }

  await queue.setStatus(job.job_id, "converting_for_soroban", "circom2soroban bytes ready");
  // Delete the raw witness (contains intermediate values); keep only public hex.
  for (const f of [`${tag}_witness.wtns`, `${tag}_x.wtns`, `${tag}_dep.wtns`]) {
    try { rmSync(`${SCRATCH}/${f}`, { force: true }); } catch { /* best effort */ }
  }
  await queue.complete(job.job_id, result, "ready");
  return result;
}

async function assertVerified(queue: JobQueue, job: ServiceJob, ok: boolean): Promise<void> {
  await queue.setStatus(job.job_id, "verifying_locally", ok ? "snarkjs verify OK" : "snarkjs verify FAILED");
  if (!ok) throw new Error("local proof verification failed");
}

// Claim and process one proof job. Returns false if the queue is empty.
export async function runProverOnce(queue: JobQueue): Promise<boolean> {
  const job = await queue.claimNext("prover", [...PROOF_JOB_TYPES]);
  if (!job) return false;
  try {
    await processProofJob(queue, job);
  } catch (e) {
    await queue.fail(job.job_id, (e as Error).message);
  }
  return true;
}

// Long-running worker loop (used by the prover service).
export async function runProverLoop(queue: JobQueue, intervalMs = 2000): Promise<void> {
  for (;;) {
    const did = await runProverOnce(queue);
    if (!did) await new Promise((r) => setTimeout(r, intervalMs));
  }
}

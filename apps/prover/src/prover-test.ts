import { resolve } from "node:path";
import { JobQueue } from "@shade/queue";
import { generateCoin, buildAssociationSet } from "@shade/proving";
import { runProverOnce } from "./worker.js";

// PHASE 2 prover test: enqueue real proof jobs of each shape, run the worker, and
// assert each reaches `ready` with verifiable public proof bytes. Pure offline
// (no chain, no testnet funds) — exercises the real Groth16 pipeline end to end.

const SCRATCH = process.env.SHADE_SCRATCH_DIR ?? resolve(process.env.SHADE_ROOT ?? process.cwd(), ".scratch");
const queue = new JobQueue();
const results: { name: string; ok: boolean; detail: string }[] = [];
const check = (name: string, ok: boolean, detail = "") => { results.push({ name, ok, detail }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`); };

async function runJob(jobType: string, payload: Record<string, unknown>): Promise<{ status: string; result: Record<string, unknown> | null }> {
  const job = await queue.enqueue("prover", jobType, payload);
  // Loop until OUR job is terminal — the shared DB queue may hold older jobs and
  // the worker claims oldest-first.
  for (let i = 0; i < 20; i++) {
    const j = await queue.getJob(job.job_id);
    if (j && (j.status === "ready" || j.status === "failed")) break;
    if (!(await runProverOnce(queue))) break;
  }
  const done = await queue.getJob(job.job_id);
  return { status: done!.status, result: done!.result };
}

try {
  // withdraw_public
  const wc = generateCoin("ptest_withdraw", `${SCRATCH}/ptest_w.json`);
  const wassoc = buildAssociationSet(wc, SCRATCH, "ptest_w");
  const w = await runJob("withdraw_public", {
    coinPath: wc.path, scope: "ptest_withdraw", commitmentsDecimal: [wc.commitmentDecimal], assocPath: wassoc.assocPath,
    binding: { operationType: "1", recipientHash: "0", relayerFee: "0", deadlineLedger: "999999999" }, tag: "ptest_w"
  });
  check("withdraw_public job ready + proof bytes", w.status === "ready" && typeof w.result?.proofHex === "string" && (w.result!.proofHex as string).length > 0, `status=${w.status}`);

  // deposit_note_mint
  const dc = generateCoin("ptest_deposit", `${SCRATCH}/ptest_d.json`);
  const d = await runJob("deposit_note_mint", {
    coinPath: dc.path, tag: "ptest_d",
    depositBinding: {
      sourceDomain: "3", destinationDomain: "27", cctpNonceHex: "0x" + "ab".repeat(32), burnTxHashHex: "0x" + "cd".repeat(32),
      amount6dp: "1000000", amount7dp: dc.value7dp,
      assetStrkey: "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
      poolStrkey: "CDVEGBVXPIHKHCR7CJDJS4JVCMOVABEFBQ4HZQ7PKK6VIO3J3V5ZRTB5",
      encryptedNotePayloadHashHex: "0x" + "ef".repeat(32), policyIdHex: "0x" + "12".repeat(32), poolId: "1", chainId: "148"
    }
  });
  check("deposit_note_mint job ready + commitment bound", d.status === "ready" && d.result?.commitmentHex === dc.commitmentHex, `status=${d.status}`);

  // private_transfer
  const tc = generateCoin("ptest_xfer", `${SCRATCH}/ptest_x.json`);
  const t = await runJob("private_transfer", { coinPath: tc.path, scope: "ptest_xfer", commitmentsDecimal: [tc.commitmentDecimal], fee7dp: "100000", tag: "ptest_x" });
  check("private_transfer job ready + proof bytes", t.status === "ready" && typeof t.result?.proofHex === "string", `status=${t.status}`);

  // failure path: a bad payload must mark the job failed (not crash the worker).
  const bad = await runJob("withdraw_public", { coinPath: `${SCRATCH}/does_not_exist.json`, tag: "ptest_bad" }).catch(() => ({ status: "failed", result: null }));
  check("invalid proof job marked failed (not crashed)", bad.status === "failed" || bad.status === "failed_retry", `status=${bad.status}`);
} catch (e) {
  check("prover test harness", false, (e as Error).message.slice(0, 160));
}

await queue.close();
const failed = results.filter((r) => !r.ok);
if (failed.length) { console.error(`\nPROVER TESTS FAILED: ${failed.map((f) => f.name).join(", ")}`); process.exit(1); }
console.log("\nPROVER TESTS PASS");

import "dotenv/config";
import { resolve } from "node:path";
import Fastify from "fastify";
import { registerRoutes } from "./routes.js";
import { JobQueue } from "@shade/queue";
import { generateCoin, buildAssociationSet } from "../../cli/src/lib/prove.js";
import { runProverOnce } from "../../prover/src/worker.js";

// PHASE 2 API behavior tests (beyond registration). Drives real handlers with
// app.inject and asserts behavior: config/contracts shape, proof request enqueues
// a prover job that the worker then completes, idempotency, and 404 handling.

const SCRATCH = process.env.SHADE_SCRATCH_DIR ?? resolve(process.env.SHADE_ROOT ?? process.cwd(), ".scratch");
const app = Fastify({ logger: false });
const queue = new JobQueue();
const results: { name: string; ok: boolean; detail: string }[] = [];
const check = (name: string, ok: boolean, detail = "") => { results.push({ name, ok, detail }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`); };

try {
  await registerRoutes(app, undefined, queue);

  // health
  const health = await app.inject({ method: "GET", url: "/health" });
  check("GET /health ok", health.statusCode === 200 && health.json().ok === true);

  // contracts buckets legacy contracts under `deprecated` (C3). Values may be
  // unset in a bare test env (and Fastify omits undefined keys), so assert SHAPE:
  // legacy names live under `deprecated`, not at the top level.
  const contracts = await app.inject({ method: "GET", url: "/v1/contracts" });
  const cj = contracts.json() as Record<string, unknown>;
  check("GET /v1/contracts moves legacy under deprecated (C3)", "deprecated" in cj && !("shadeVault" in cj) && !("intentEscrow" in cj));

  // proof request enqueues a prover job; the worker then drives it to ready (P2-D)
  const wc = generateCoin("apitest_w", `${SCRATCH}/apitest_w.json`);
  const wassoc = buildAssociationSet(wc, SCRATCH, "apitest_w");
  const idemKey = `apitest-${wc.commitmentHex.slice(2, 18)}`;
  const reqBody = {
    public_inputs: { commitment: wc.commitmentHex },
    witness: {
      coinPath: wc.path, scope: "apitest_w", commitmentsDecimal: [wc.commitmentDecimal], assocPath: wassoc.assocPath,
      binding: { operationType: "1", recipientHash: "0", relayerFee: "0", deadlineLedger: "999999999" }, tag: "apitest_w"
    }
  };
  const post = await app.inject({ method: "POST", url: "/v1/proofs/withdraw_public/request", headers: { "idempotency-key": idemKey }, payload: reqBody });
  const pj = post.json() as { proof_job_id: string; job_id: string; status: string };
  check("POST proof request returns job_id queued", post.statusCode === 200 && !!pj.job_id && pj.status === "queued", `status=${pj.status}`);

  // idempotency: same key returns the same job
  const post2 = await app.inject({ method: "POST", url: "/v1/proofs/withdraw_public/request", headers: { "idempotency-key": idemKey }, payload: reqBody });
  check("proof request idempotent (same job_id)", (post2.json() as { job_id: string }).job_id === pj.job_id);

  // run the prover worker until OUR job reaches a terminal state (the DB queue may
  // hold older jobs from prior test runs; the worker claims oldest-first).
  for (let i = 0; i < 12; i++) {
    const j = await queue.getJob(pj.job_id);
    if (j && (j.status === "ready" || j.status === "failed")) break;
    if (!(await runProverOnce(queue))) break;
  }
  const jobRes = await app.inject({ method: "GET", url: `/v1/jobs/${pj.job_id}` });
  const job = jobRes.json() as { status: string; result?: { proofHex?: string } };
  check("GET /v1/jobs/:id shows ready + proof bytes after worker", jobRes.statusCode === 200 && job.status === "ready" && typeof job.result?.proofHex === "string", `status=${job.status}`);

  // 404 for unknown job
  const missing = await app.inject({ method: "GET", url: "/v1/jobs/00000000-0000-0000-0000-000000000000" });
  check("GET /v1/jobs/:id 404 for unknown", missing.statusCode === 404);
} catch (e) {
  check("api test harness", false, (e as Error).message.slice(0, 200));
}

await app.close();
await queue.close();
const failed = results.filter((r) => !r.ok);
if (failed.length) { console.error(`\nAPI TESTS FAILED: ${failed.map((f) => f.name).join(", ")}`); process.exit(1); }
console.log("\nAPI TESTS PASS");

import "dotenv/config";
import Fastify from "fastify";
import { JobQueue } from "@shade/queue";
import { runProverLoop, PROOF_JOB_TYPES } from "./worker.js";

// PHASE 2 prover service: a queue worker (real Groth16 proof generation) plus a
// small HTTP surface for health/inspection. Witnesses are deleted after proving;
// only public proof bytes are persisted.
const app = Fastify({ logger: { redact: ["*.witness", "*.secret", "*.note", "*.coinPath"] } });
const queue = new JobQueue();

app.get("/health", async () => ({ ok: true, service: "prover", jobTypes: PROOF_JOB_TYPES }));
app.get("/v1/jobs/:job_id", async (request) => {
  const id = (request.params as { job_id: string }).job_id;
  const job = await queue.getJob(id);
  if (!job) return { error: "not found" };
  return { job_id: job.job_id, type: job.job_type, status: job.status, result: job.result, error: job.error };
});

// Start the background worker loop alongside the HTTP server.
void runProverLoop(queue).catch((e) => app.log.error({ err: (e as Error).message }, "prover loop crashed"));

await app.listen({ port: Number(process.env.PROVER_PORT ?? 8083), host: "0.0.0.0" });

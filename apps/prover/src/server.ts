import "dotenv/config";
import Fastify from "fastify";
import { requireProofStack } from "@shade/proof-utils";

const app = Fastify({ logger: { redact: ["*.witness", "*.secret", "*.note"] } });
app.get("/health", async () => ({ ok: true, service: "prover" }));
app.post("/v1/proofs/generate", async () => {
  await requireProofStack();
  throw Object.assign(new Error("proof generation requires circuit-specific witness builders"), { statusCode: 501 });
});

await app.listen({ port: Number(process.env.PROVER_PORT ?? 8083), host: "0.0.0.0" });

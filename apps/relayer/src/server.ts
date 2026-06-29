import "dotenv/config";
import Fastify from "fastify";
import { LOCKED_CCTP } from "@shade/cctp-utils";

const app = Fastify({ logger: true });
app.get("/health", async () => ({ ok: true, service: "relayer" }));
app.get("/v1/cctp/route", async () => LOCKED_CCTP);
app.post("/v1/cctp/inbound/mint-forward", async () => {
  throw Object.assign(new Error("requires real CCTP message, attestation, Stellar CLI, and deployed ShadeVault"), { statusCode: 501 });
});

await app.listen({ port: Number(process.env.RELAYER_PORT ?? 8082), host: "0.0.0.0" });

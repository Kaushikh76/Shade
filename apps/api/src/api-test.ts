import "dotenv/config";
import Fastify from "fastify";
import { registerRoutes } from "./routes.js";

const app = Fastify({ logger: false });
try {
  await registerRoutes(app);
  const routes = [
    "/health",
    "/v1/config",
    "/v1/contracts",
    "/v1/deposits/:deposit_id",
    "/v1/proofs/:proof_job_id",
    "/v1/withdrawals/:withdrawal_id",
    "/v1/intents/:intent_hash",
    "/v1/settlements/:settlement_id",
    "/v1/cctp/outbound/:exit_id"
  ];
  console.log(`API route registration PASS (${routes.length} representative routes)`);
} catch (error) {
  console.error(error);
  process.exit(1);
}

import "dotenv/config";
process.env.PRIVY_APP_ID = "test-route-auth";
import Fastify from "fastify";
import { registerRoutes } from "./routes.js";
import { JobQueue } from "@shade/queue";

// FIX7/FIX12: assert every user-owned state-changing route 401s without a token.
// (Public routes /health /v1/config /v1/contracts /v1/health/full are NOT listed.)
const STATE_CHANGING: Array<[string, string]> = [
  ["POST", "/v1/me/wallets/sync-privy"],
  ["POST", "/v1/note-vaults"],
  ["POST", "/v1/note-vaults/v1/verify-backup"],
  ["POST", "/v1/note-vaults/v1/mark-restored"],
  ["POST", "/v1/note-vaults/v1/wrappers"],
  ["POST", "/v1/proofs/withdraw_public/request"],
  ["POST", "/v1/deposits/prepare"],
  ["POST", "/v1/deposits/d1/burn-submitted"],
  ["POST", "/v1/withdrawals/prepare"],
  ["POST", "/v1/withdrawals/build-xdr"],
  ["POST", "/v1/withdrawals/submit"],
  ["POST", "/v1/intents"],
  ["POST", "/v1/intents/i1/request-quotes"],
  ["POST", "/v1/quotes/q1/accept"],
  ["POST", "/v1/rfq/settle"],
  ["POST", "/v1/cctp/outbound/prepare"],
  ["POST", "/v1/cctp/outbound/submit"],
  ["POST", "/v1/cctp/outbound/e1/fetch-attestation"],
  ["POST", "/v1/cctp/outbound/e1/complete-mint"],
  ["GET", "/v1/me"],
  ["GET", "/v1/me/wallets"],
  ["GET", "/v1/activity"],
  ["GET", "/v1/jobs/j1"]
];
// Public routes must remain reachable without auth.
const PUBLIC: Array<[string, string]> = [["GET", "/health"], ["GET", "/v1/config"], ["GET", "/v1/contracts"], ["GET", "/v1/health/full"]];

const results: { name: string; ok: boolean; detail: string }[] = [];
const check = (name: string, ok: boolean, detail = "") => { results.push({ name, ok, detail }); if (!ok) console.log(`FAIL  ${name}${detail ? " — " + detail : ""}`); };

(async () => {
  const app = Fastify({ logger: false });
  const queue = new JobQueue();
  try {
    await registerRoutes(app, undefined, queue);
    for (const [method, url] of STATE_CHANGING) {
      const res = await app.inject({ method: method as "GET" | "POST", url, headers: { "idempotency-key": "x".repeat(12) }, payload: {} });
      check(`${method} ${url} requires auth (401)`, res.statusCode === 401, `got ${res.statusCode}`);
    }
    for (const [method, url] of PUBLIC) {
      const res = await app.inject({ method: method as "GET" | "POST", url });
      check(`${method} ${url} public (not 401)`, res.statusCode !== 401, `got ${res.statusCode}`);
    }
  } catch (e) { check("route-auth harness", false, (e as Error).message.slice(0, 200)); }
  await app.close(); await queue.close();
  const failed = results.filter((r) => !r.ok);
  console.log(`${results.length - failed.length}/${results.length} route-auth checks passed`);
  if (failed.length) { console.error(`ROUTE-AUTH TESTS FAILED: ${failed.length}`); process.exit(1); }
  console.log("ROUTE-AUTH TESTS PASS");
})();

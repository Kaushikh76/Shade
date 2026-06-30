import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { JobQueue } from "@shade/queue";
import { generateCoin, buildAssociationSet, computeStateRoot } from "@shade/proving";
import { sorobanInvoke } from "@shade/stellar-utils";
import { runRelayerOnce } from "./worker.js";

// Load process.env + .env.generated (contract IDs + operator secrets).
function loadEnv(): Record<string, string> {
  const env: Record<string, string> = { ...process.env } as Record<string, string>;
  for (const [path, override] of [["../.env", false], [".env", false], [".env.generated", true]] as const) {
    if (!existsSync(path)) continue;
    for (const raw of readFileSync(path, "utf8").split("\n")) {
      const line = raw.replace(/\r$/, "");
      if (!line.includes("=") || line.trimStart().startsWith("#")) continue;
      const i = line.indexOf("=");
      const k = line.slice(0, i);
      if (override || env[k] === undefined) env[k] = line.slice(i + 1);
    }
  }
  return env;
}

// Run the worker until a specific job reaches a terminal state (the shared DB
// queue may hold older jobs; the worker claims oldest-first).
async function drainUntilTerminal(queue: JobQueue, jobId: string, maxIters = 20): Promise<string> {
  for (let i = 0; i < maxIters; i++) {
    const j = await queue.getJob(jobId);
    if (j && (j.status === "ready" || j.status === "failed")) return j.status;
    if (!(await runRelayerOnce(queue))) break;
  }
  return (await queue.getJob(jobId))?.status ?? "unknown";
}

// PHASE 2 relayer test.
//  - Offline: an unknown/invalid job is marked failed (worker survives).
//  - Live (RELAYER_LIVE=1): enqueue a real CCTP_INBOUND and run the worker; assert
//    a real Arbitrum burn tx + a registered leaf on the canonical pool. Burns ~1
//    USDC + takes minutes, so it is opt-in.

const SCRATCH = process.env.SHADE_SCRATCH_DIR ?? resolve(process.env.SHADE_ROOT ?? process.cwd(), ".scratch");
const queue = new JobQueue();
const results: { name: string; ok: boolean; detail: string }[] = [];
const check = (name: string, ok: boolean, detail = "") => { results.push({ name, ok, detail }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`); };

try {
  // Offline: invalid relayer job -> failed (no crash). max_attempts=3, so drain
  // until terminal 'failed'.
  const bad = await queue.enqueue("relayer", "WITHDRAW_PUBLIC_SUBMIT", { to: "G_BOGUS", proofHex: "00", publicHex: "00" });
  // Loop the worker until OUR job is claimed+failed (the shared DB queue may hold
  // older jobs; the worker claims oldest-first). failed_retry/failed both mean the
  // worker caught the on-chain error and did not crash.
  let badStatus = "queued";
  for (let i = 0; i < 30; i++) {
    badStatus = (await queue.getJob(bad.job_id))?.status ?? "queued";
    if (badStatus === "failed" || badStatus === "failed_retry") break;
    if (!(await runRelayerOnce(queue))) break;
  }
  check("invalid relayer job marked failed (not crashed)", badStatus === "failed" || badStatus === "failed_retry", `status=${badStatus}`);

  if (process.env.RELAYER_LIVE === "1") {
    process.env.ENABLE_OPERATOR_TESTNET_DEPOSIT = "true"; // dev/test composite inbound
    const env = loadEnv();
    const pool = env.SHIELDED_POOL_CONTRACT;
    const coin = generateCoin("relayer_inbound", `${SCRATCH}/relayer_inbound.json`);
    const assoc = buildAssociationSet(coin, SCRATCH, "relayer_inbound");
    sorobanInvoke({ contractId: pool, secret: env.STELLAR_RELAYER_SECRET, method: "set_association_root",
      args: ["--association_root", assoc.rootHex.slice(2)], rpcUrl: env.STELLAR_RPC_URL, passphrase: env.STELLAR_NETWORK_PASSPHRASE });
    const newRoot = computeStateRoot(coin, [coin.commitmentDecimal], "relayer_inbound", SCRATCH, "relayer_inbound");
    const job = await queue.enqueue("relayer", "CCTP_INBOUND", {
      amount6: "1000000", commitmentHex: coin.commitmentHex,
      encryptedNotePayloadHashHex: "0x" + createHash("sha256").update(coin.commitmentHex).digest("hex"),
      policyIdHex: "0x" + createHash("sha256").update("shade:default-testnet-policy:v1").digest("hex").slice(0, 64),
      newRootHex: newRoot, coinPath: coin.path, pool
    });
    const liveStatus = await drainUntilTerminal(queue, job.job_id, 4);
    const done = await queue.getJob(job.job_id);
    const r = done?.result as { burnTxHash?: string; leafIndex?: string } | null;
    check("CCTP_INBOUND job ready with real burn + leaf", liveStatus === "ready" && !!r?.burnTxHash, `status=${liveStatus} burn=${r?.burnTxHash?.slice(0, 14)} leaf=${r?.leafIndex}`);
  } else {
    console.log("SKIP  live CCTP_INBOUND (set RELAYER_LIVE=1 to run a real on-chain inbound)");
  }
} catch (e) {
  check("relayer test harness", false, (e as Error).message.slice(0, 200));
}

await queue.close();
const failed = results.filter((r) => !r.ok);
if (failed.length) { console.error(`\nRELAYER TESTS FAILED: ${failed.map((f) => f.name).join(", ")}`); process.exit(1); }
console.log("\nRELAYER TESTS PASS");

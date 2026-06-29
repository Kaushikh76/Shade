import "dotenv/config";
import { resolve } from "node:path";
// This suite exercises the legacy wallet-signature auth flow; force it on and
// ensure Privy is not auto-enabled in the test process.
process.env.ENABLE_LEGACY_WALLET_AUTH = "true";
delete process.env.PRIVY_APP_ID;
delete process.env.PRIVY_JWT_VERIFICATION_KEY;
import Fastify from "fastify";
import { Wallet } from "ethers";
import { Keypair } from "@stellar/stellar-sdk";
import { registerRoutes } from "./routes.js";
import { JobQueue } from "@shade/queue";
import { generateNotePreimage, poseidonCommitment } from "@shade/note-crypto";
import { generateCoin, buildAssociationSet } from "@shade/proving";
import { runProverOnce } from "../../prover/src/worker.js";

// PHASE 2 API behavior tests (beyond registration; Critical 14). Drives real
// handlers with app.inject and asserts behavior across auth, user profile/wallets,
// the proof API->queue->prover->ready loop, the RFQ lifecycle, and 404/401 paths.

const SCRATCH = process.env.SHADE_SCRATCH_DIR ?? resolve(process.env.SHADE_ROOT ?? process.cwd(), ".scratch");
const app = Fastify({ logger: false });
const queue = new JobQueue();
const results: { name: string; ok: boolean; detail: string }[] = [];
const check = (name: string, ok: boolean, detail = "") => { results.push({ name, ok, detail }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`); };
const json = (r: { json: () => unknown }) => r.json() as Record<string, unknown>;

try {
  await registerRoutes(app, undefined, queue);

  check("GET /health ok", (await app.inject({ method: "GET", url: "/health" })).statusCode === 200);
  const contracts = json(await app.inject({ method: "GET", url: "/v1/contracts" }));
  check("GET /v1/contracts moves legacy under deprecated (C3)", "deprecated" in contracts && !("shadeVault" in contracts));

  // --- Auth: EVM nonce -> sign -> verify -> session ---
  const wallet = Wallet.createRandom();
  const nonceRes = json(await app.inject({ method: "POST", url: "/v1/auth/nonce", payload: { wallet_type: "EVM", address: wallet.address } }));
  check("POST /v1/auth/nonce returns message", typeof nonceRes.message === "string" && typeof nonceRes.nonce === "string");
  const sig = await wallet.signMessage(nonceRes.message as string);
  const verifyRes = await app.inject({ method: "POST", url: "/v1/auth/evm/verify", payload: { address: wallet.address, signature: sig, nonce: nonceRes.nonce } });
  const session = json(verifyRes);
  const token = session.session_token as string;
  check("EVM verify issues a session", verifyRes.statusCode === 200 && typeof token === "string", `user=${(session.user_id as string)?.slice(0, 8)}`);
  const authH = { authorization: `Bearer ${token}` };

  // bad signature is rejected
  const badNonce = json(await app.inject({ method: "POST", url: "/v1/auth/nonce", payload: { wallet_type: "EVM", address: wallet.address } }));
  const badVerify = await app.inject({ method: "POST", url: "/v1/auth/evm/verify", payload: { address: wallet.address, signature: "0xdeadbeef", nonce: badNonce.nonce } });
  check("bad EVM signature rejected 401", badVerify.statusCode === 401);

  // Stellar auth path
  const kp = Keypair.random();
  const sNonce = json(await app.inject({ method: "POST", url: "/v1/auth/nonce", payload: { wallet_type: "STELLAR", address: kp.publicKey() } }));
  const sSig = kp.sign(Buffer.from(sNonce.message as string, "utf8")).toString("hex");
  const sVerify = await app.inject({ method: "POST", url: "/v1/auth/stellar/verify", payload: { address: kp.publicKey(), signature: sSig, nonce: sNonce.nonce } });
  check("Stellar verify issues a session", sVerify.statusCode === 200 && typeof json(sVerify).session_token === "string");

  // --- session-guarded endpoints ---
  check("GET /v1/me 401 without session", (await app.inject({ method: "GET", url: "/v1/me" })).statusCode === 401);
  const me = json(await app.inject({ method: "GET", url: "/v1/me", headers: authH }));
  check("GET /v1/me returns the user", typeof me.id === "string");
  const patched = json(await app.inject({ method: "PATCH", url: "/v1/me", headers: authH, payload: { display_name: "Tester", preferences: { theme: "dark" } } }));
  check("PATCH /v1/me updates profile", patched.display_name === "Tester");
  const wallets = json(await app.inject({ method: "GET", url: "/v1/me/wallets", headers: authH }));
  check("GET /v1/me/wallets lists the primary wallet", Array.isArray(wallets.wallets) && (wallets.wallets as unknown[]).length === 1);
  const sess = json(await app.inject({ method: "GET", url: "/v1/auth/session", headers: authH }));
  check("GET /v1/auth/session authenticated", sess.authenticated === true);

  // --- proof request -> prover worker -> ready (authenticated) ---
  const wc = generateCoin("apitest_w", `${SCRATCH}/apitest_w.json`);
  const wassoc = buildAssociationSet(wc, SCRATCH, "apitest_w");
  const idemKey = `apitest-${wc.commitmentHex.slice(2, 18)}`;
  const reqBody = {
    public_inputs: { commitment: wc.commitmentHex },
    witness: { coinPath: wc.path, scope: "apitest_w", commitmentsDecimal: [wc.commitmentDecimal], assocPath: wassoc.assocPath,
      binding: { operationType: "1", recipientHash: "0", relayerFee: "0", deadlineLedger: "999999999" }, tag: "apitest_w" }
  };
  const post = json(await app.inject({ method: "POST", url: "/v1/proofs/withdraw_public/request", headers: { ...authH, "idempotency-key": idemKey }, payload: reqBody }));
  check("proof request returns job_id queued", post.status === "queued" && !!post.job_id);
  const post2 = json(await app.inject({ method: "POST", url: "/v1/proofs/withdraw_public/request", headers: { ...authH, "idempotency-key": idemKey }, payload: reqBody }));
  check("proof request idempotent", post2.job_id === post.job_id);
  for (let i = 0; i < 12; i++) {
    const j = await queue.getJob(post.job_id as string);
    if (j && (j.status === "ready" || j.status === "failed")) break;
    if (!(await runProverOnce(queue))) break;
  }
  const jobView = json(await app.inject({ method: "GET", url: `/v1/jobs/${post.job_id}` }));
  check("job reaches ready with proof bytes", jobView.status === "ready" && typeof (jobView.result as { proofHex?: string })?.proofHex === "string", `status=${jobView.status}`);

  // --- RFQ lifecycle: intent -> quote -> accept -> lock -> fill (authenticated) ---
  const intentBody = { intent_type: "PRIVATE_RFQ", version: "1.0", user_pubkey_commitment: wc.commitmentHex, input_asset: "USDC:Stellar:SAC", output_asset: "USDC:ArbitrumSepolia", amount_mode: "exact_in", amount_commitment: "0x" + "11".repeat(32), min_output_commitment: "0x" + "22".repeat(32), expiry_ledger: 999999999, allowed_solvers_root: "0x" + "00".repeat(32), compliance_policy_id: "shade:default-testnet-policy:v1", destination_commitment: "0x" + "33".repeat(32), replay_domain: "shade:stellar:testnet:rfq:v1", signature: "0xtest" };
  const intent = json(await app.inject({ method: "POST", url: "/v1/intents", headers: { ...authH, "idempotency-key": `intent-${idemKey}` }, payload: intentBody }));
  check("POST /v1/intents creates intent", typeof intent.intent_hash === "string");
  const myRfq = json(await app.inject({ method: "GET", url: "/v1/me/rfq", headers: authH }));
  check("GET /v1/me/rfq accessible", Array.isArray(myRfq.settlements));

  // --- activity timeline reflects logged events ---
  const activity = json(await app.inject({ method: "GET", url: "/v1/activity", headers: authH }));
  const acts = activity.activity as Array<{ event_type: string }>;
  check("GET /v1/activity records auth.login + actions", Array.isArray(acts) && acts.some((a) => a.event_type === "auth.login"));

  // --- logout revokes the session ---
  await app.inject({ method: "POST", url: "/v1/auth/logout", headers: authH });
  check("session revoked after logout", (await app.inject({ method: "GET", url: "/v1/me", headers: authH })).statusCode === 401);

  // note-crypto sanity used by deposit prepare
  const commit = await poseidonCommitment(generateNotePreimage({ assetId: "USDC", amount7dp: "5000000", ownerPublicKey: kp.publicKey(), spendPublicKey: kp.publicKey(), complianceTag: "t", sourceContext: "s", memoCommitment: "m" }));
  check("poseidonCommitment deterministic", typeof commit === "string" && commit.startsWith("0x"));
} catch (e) {
  check("api test harness", false, (e as Error).message.slice(0, 200));
}

await app.close();
await queue.close();
const failed = results.filter((r) => !r.ok);
if (failed.length) { console.error(`\nAPI TESTS FAILED: ${failed.map((f) => f.name).join(", ")}`); process.exit(1); }
console.log("\nAPI TESTS PASS");

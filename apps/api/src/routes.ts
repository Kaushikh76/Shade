import { randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { LOCKED_CCTP, usdc6ToStellar7, validateInboundRoute } from "@shade/cctp-utils";
import { generateNotePreimage, poseidonCommitment } from "@shade/note-crypto";
import { hashJson, deterministicId } from "@shade/shared-types/ids";
import { intentSchema, quoteSchema } from "@shade/rfq-types";
import { Store } from "./db.js";
import {
  cctpExitSchema,
  fillSchema,
  idempotencyHeader,
  lockSchema,
  prepareDepositSchema,
  proofRequestSchema,
  quoteAcceptanceSchema,
  settlementSchema,
  withdrawalSchema
} from "./schemas.js";

function idem(request: FastifyRequest): string {
  return idempotencyHeader.parse(request.headers)["idempotency-key"];
}

export async function registerRoutes(app: FastifyInstance, store = new Store()): Promise<void> {
  app.get("/health", async () => {
    await store.health();
    return { ok: true };
  });

  app.get("/v1/config", async () => LOCKED_CCTP);
  app.get("/v1/contracts", async () => ({
    shadeVault: process.env.SHADE_VAULT_CONTRACT,
    commitmentTree: process.env.COMMITMENT_TREE_CONTRACT,
    nullifierRegistry: process.env.NULLIFIER_REGISTRY_CONTRACT,
    complianceRegistry: process.env.COMPLIANCE_REGISTRY_CONTRACT,
    intentEscrow: process.env.INTENT_ESCROW_CONTRACT
  }));
  app.get("/v1/balances/testnet", async () => ({ status: "requires setup:testnet for live balances" }));
  app.post("/v1/setup/validate", async () => ({ status: "run npm run setup:testnet" }));

  app.post("/v1/deposits/prepare", async (request) => {
    const body = prepareDepositSchema.parse(request.body);
    const idempotencyKey = idem(request);
    validateInboundRoute({
      destinationDomain: LOCKED_CCTP.stellarDomain,
      mintRecipient: LOCKED_CCTP.stellarCctpForwarder,
      destinationCaller: LOCKED_CCTP.stellarCctpForwarder,
      forwardRecipient: body.shade_vault_contract
    });
    const amount6 = BigInt(body.amount_usdc_6dp);
    const amount7 = usdc6ToStellar7(amount6);
    const note = generateNotePreimage({
      assetId: body.asset_id,
      amount7dp: amount7.toString(),
      ownerPublicKey: body.owner_public_key,
      spendPublicKey: body.spend_public_key,
      complianceTag: body.compliance_tag,
      sourceContext: body.source_context,
      memoCommitment: body.memo_commitment
    });
    const commitment = await poseidonCommitment(note);
    const depositId = deterministicId({ namespace: "dep", parts: [idempotencyKey, commitment] });
    await store.upsertDeposit({
      depositId,
      idempotencyKey,
      sourceDomain: LOCKED_CCTP.arbitrumSepoliaDomain,
      destinationDomain: LOCKED_CCTP.stellarDomain,
      assetId: body.asset_id,
      amount6: amount6.toString(),
      amount7: amount7.toString(),
      commitment,
      encryptedNotePayloadHash: body.encrypted_note_payload_hash,
      policyId: body.policy_id,
      state: "prepared"
    });
    await store.transition({ entityType: "cctp_deposit", entityId: depositId, toState: "prepared" });
    return { deposit_id: depositId, commitment, amount_usdc_7dp: amount7.toString() };
  });

  app.get("/v1/deposits/:deposit_id", async (request) => store.getById("cctp_deposits", "deposit_id", (request.params as { deposit_id: string }).deposit_id));
  app.post("/v1/deposits/:deposit_id/submit-burn", async () => failLive("submit-burn requires funded .env and EVM transaction submission"));
  app.post("/v1/deposits/:deposit_id/fetch-attestation", async () => failLive("fetch-attestation requires a real Circle message hash"));
  app.post("/v1/deposits/:deposit_id/mint-forward", async () => failLive("mint-forward requires deployed Stellar contracts and stellar CLI"));
  app.post("/v1/deposits/:deposit_id/register-note", async () => failLive("register-note requires live ShadeVault and CommitmentTree"));

  app.post("/v1/notes/local/derive", async (request) => {
    const note = generateNotePreimage(request.body as never);
    return { note_secret: "redacted", commitment: await poseidonCommitment(note) };
  });
  app.post("/v1/notes/commitment", async (request) => ({ commitment: await poseidonCommitment(request.body as never) }));
  app.get("/v1/notes/:commitment/status", async (request) => store.getById("note_commitments", "commitment", (request.params as { commitment: string }).commitment));

  app.post("/v1/proofs/:kind/request", async (request) => {
    const body = proofRequestSchema.parse({ ...(request.body as object), proof_type: (request.params as { kind: string }).kind });
    const idempotencyKey = idem(request);
    const proofJobId = deterministicId({ namespace: "proof", parts: [idempotencyKey, body.proof_type, hashJson(body.public_inputs)] });
    await store.insertGeneric("proof_jobs", {
      proof_job_id: proofJobId,
      idempotency_key: idempotencyKey,
      proof_type: body.proof_type,
      public_inputs_hash: hashJson(body.public_inputs),
      status: "queued"
    });
    await store.transition({ entityType: "proof_job", entityId: proofJobId, toState: "queued" });
    return { proof_job_id: proofJobId, status: "queued" };
  });
  app.get("/v1/proofs/:proof_job_id", async (request) => store.getById("proof_jobs", "proof_job_id", (request.params as { proof_job_id: string }).proof_job_id));

  app.post("/v1/withdrawals/prepare", async (request) => createWithdrawal(request, store));
  app.post("/v1/withdrawals/submit", async () => failLive("withdraw submit requires proof and Stellar transaction"));
  app.get("/v1/withdrawals/:withdrawal_id", async (request) => store.getById("withdrawals", "withdrawal_id", (request.params as { withdrawal_id: string }).withdrawal_id));

  app.post("/v1/intents", async (request) => {
    const body = intentSchema.parse(request.body);
    const idempotencyKey = idem(request);
    const intentHash = hashJson(body);
    await store.insertGeneric("intents", {
      intent_hash: intentHash,
      idempotency_key: idempotencyKey,
      encrypted_payload: JSON.stringify({ ciphertext: "client-encrypted-payload-required" }),
      public_commitment: body,
      expiry_ledger: body.expiry_ledger,
      policy_id: body.compliance_policy_id,
      user_signature: body.signature,
      state: "INTENT_CREATED"
    });
    await store.transition({ entityType: "intent", entityId: intentHash, toState: "INTENT_CREATED" });
    return { intent_hash: intentHash };
  });
  app.get("/v1/intents/:intent_hash", async (request) => store.getById("intents", "intent_hash", (request.params as { intent_hash: string }).intent_hash));
  app.get("/v1/intents/:intent_hash/quotes", async () => ({ status: "query quotes by intent_hash via database view" }));
  app.post("/v1/solver/quotes", async (request) => {
    const body = quoteSchema.parse(request.body);
    const quoteHash = hashJson(body);
    await store.insertGeneric("quotes", {
      quote_id: body.quote_id,
      intent_hash: body.intent_hash,
      quote_hash: quoteHash,
      solver_id: body.solver_id,
      payload: body,
      quote_signature: body.quote_signature,
      valid_until_ledger: body.valid_until_ledger,
      state: "QUOTE_RECEIVED"
    });
    await store.transition({ entityType: "quote", entityId: body.quote_id, toState: "QUOTE_RECEIVED" });
    return { quote_id: body.quote_id, quote_hash: quoteHash };
  });
  app.post("/v1/quotes/:quote_id/accept", async (request) => {
    const body = quoteAcceptanceSchema.parse(request.body);
    const quoteId = (request.params as { quote_id: string }).quote_id;
    const acceptanceId = deterministicId({ namespace: "accept", parts: [quoteId, body.user_signature_hash] });
    await store.insertGeneric("quote_acceptances", { acceptance_id: acceptanceId, quote_id: quoteId, intent_hash: body.intent_hash, user_signature_hash: body.user_signature_hash });
    await store.transition({ entityType: "quote", entityId: quoteId, toState: "QUOTE_ACCEPTED" });
    return { acceptance_id: acceptanceId };
  });
  app.post("/v1/quotes/:quote_id/lock", async (request) => {
    const body = lockSchema.parse(request.body);
    const quoteId = (request.params as { quote_id: string }).quote_id;
    const lockId = deterministicId({ namespace: "lock", parts: [quoteId, body.lock_hash] });
    await store.insertGeneric("solver_inventory_locks", { lock_id: lockId, quote_id: quoteId, ...body, state: "SOLVER_INVENTORY_LOCKED" });
    await store.transition({ entityType: "quote", entityId: quoteId, toState: "SOLVER_INVENTORY_LOCKED" });
    return { lock_id: lockId };
  });
  app.post("/v1/fills", async (request) => {
    const body = fillSchema.parse(request.body);
    const fillId = deterministicId({ namespace: "fill", parts: [body.quote_id, body.fill_receipt_hash] });
    await store.insertGeneric("fills", { fill_id: fillId, ...body, state: "FILL_CREATED" });
    await store.transition({ entityType: "fill", entityId: fillId, toState: "FILL_CREATED" });
    return { fill_id: fillId };
  });
  app.post("/v1/rfq/settle", async (request) => {
    const body = settlementSchema.parse(request.body);
    const settlementId = deterministicId({ namespace: "settle", parts: [body.intent_hash, body.quote_id, body.nullifier] });
    await store.insertGeneric("settlements", { settlement_id: settlementId, ...body, state: "SETTLEMENT_SUBMITTED" });
    await store.transition({ entityType: "settlement", entityId: settlementId, toState: "SETTLEMENT_SUBMITTED" });
    return { settlement_id: settlementId };
  });
  app.get("/v1/settlements/:settlement_id", async (request) => store.getById("settlements", "settlement_id", (request.params as { settlement_id: string }).settlement_id));

  app.post("/v1/cctp/outbound/prepare", async (request) => {
    const body = cctpExitSchema.parse(request.body);
    const idempotencyKey = idem(request);
    const exitId = deterministicId({ namespace: "exit", parts: [idempotencyKey, body.nullifier] });
    await store.insertGeneric("cctp_exits", { exit_id: exitId, idempotency_key: idempotencyKey, ...body, state: "prepared" });
    await store.transition({ entityType: "cctp_exit", entityId: exitId, toState: "prepared" });
    return { exit_id: exitId };
  });
  app.post("/v1/cctp/outbound/submit", async () => failLive("outbound submit requires live Stellar CCTP burn and Arbitrum mint"));
  app.get("/v1/cctp/outbound/:exit_id", async (request) => store.getById("cctp_exits", "exit_id", (request.params as { exit_id: string }).exit_id));
  app.get("/v1/test-report/latest", async () => ({ path: "docs/test-report.md" }));
}

async function createWithdrawal(request: FastifyRequest, store: Store) {
  const body = withdrawalSchema.parse(request.body);
  const idempotencyKey = idem(request);
  const withdrawalId = deterministicId({ namespace: "wd", parts: [idempotencyKey, body.nullifier] });
  await store.insertGeneric("withdrawals", {
    withdrawal_id: withdrawalId,
    idempotency_key: idempotencyKey,
    nullifier: body.nullifier,
    amount_usdc_7dp: body.amount_public,
    recipient: body.recipient,
    relayer_fee: body.relayer_fee,
    deadline_ledger: body.deadline_ledger,
    state: "prepared"
  });
  await store.transition({ entityType: "withdrawal", entityId: withdrawalId, toState: "prepared" });
  return { withdrawal_id: withdrawalId };
}

function failLive(message: string) {
  const error = new Error(message);
  (error as Error & { statusCode: number }).statusCode = 501;
  throw error;
}

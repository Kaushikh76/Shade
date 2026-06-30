import { randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { LOCKED_CCTP, usdc6ToStellar7, validateInboundRoute, stellarContractToBytes32, encodeStellarForwardHook, FINALITY_THRESHOLD_CONFIRMED } from "@shade/cctp-utils";
import { generateNotePreimage, poseidonCommitment } from "@shade/note-crypto";
import { hashJson, deterministicId } from "@shade/shared-types/ids";
import { intentSchema, quoteSchema } from "@shade/rfq-types";
import { JobQueue } from "@shade/queue";
import { requirePrivyUser, optionalPrivyUser } from "@shade/auth-privy";
import { validateVaultEnvelope, assertNoPlaintextNoteFields, evaluateRecoveryPolicy, type VaultWrapper, type EncryptedVaultEnvelope } from "@shade/note-vault";
import { Store } from "./db.js";

// Recovery policy from the env-configured minimums (audit.md PHASE 4).
function recoveryPolicyFor(wrappers: VaultWrapper[]): "insufficient" | "sufficient" | "strong" {
  const mainnet = (process.env.SHADE_NETWORK_MODE ?? "testnet") === "mainnet";
  const min = Number(mainnet ? (process.env.SHADE_MIN_RECOVERY_WRAPPERS_MAINNET ?? "2") : (process.env.SHADE_MIN_RECOVERY_WRAPPERS_TESTNET ?? "1"));
  const allowEvmOnly = process.env.ALLOW_EVM_SIGNATURE_ONLY_RECOVERY === "true";
  return evaluateRecoveryPolicy(wrappers, { mainnet, min, allowEvmOnly });
}

// Privy is the canonical identity by default. The legacy custom wallet-nonce auth
// is dev-only behind ENABLE_LEGACY_WALLET_AUTH=true. Read at call time so tests and
// runtime env changes take effect.
const privyEnabled = () => !!process.env.PRIVY_APP_ID || !!process.env.PRIVY_JWT_VERIFICATION_KEY;
const legacyWalletAuth = () => process.env.ENABLE_LEGACY_WALLET_AUTH === "true";
import {
  authMessage, clearSessionCookie, newSessionToken, normalizeAddress,
  NONCE_TTL, optionalUser, readSessionToken, requireUser, SESSION_TTL, setSessionCookie,
  sha256Hex, verifyWalletSignature, type WalletType
} from "./auth.js";
import {
  addWalletSchema,
  addWrapperSchema,
  authNonceSchema,
  authVerifySchema,
  burnSubmittedSchema,
  cctpExitSchema,
  encryptedVaultEnvelopeSchema,
  fillSchema,
  idempotencyHeader,
  lockSchema,
  noteBackupSchema,
  prepareDepositSchema,
  proofRequestSchema,
  quoteAcceptanceSchema,
  requestQuotesSchema,
  settlementSchema,
  syncPrivyWalletsSchema,
  updateMeSchema,
  userDepositPrepareSchema,
  verifyBackupSchema,
  withdrawalSchema
} from "./schemas.js";

const CHAIN_FOR: Record<WalletType, string> = { EVM: "arbitrum-sepolia", STELLAR: "stellar-testnet" };
function randomNonce(): string { return randomUUID().replace(/-/g, ""); }

// FIX9: dev/legacy routes are unavailable unless ENABLE_DEV_ROUTES=true.
function requireDevRoutes(): void {
  if (process.env.ENABLE_DEV_ROUTES !== "true") {
    const e = new Error("dev route disabled (set ENABLE_DEV_ROUTES=true)") as Error & { statusCode: number };
    e.statusCode = 404; throw e;
  }
}

function idem(request: FastifyRequest): string {
  return idempotencyHeader.parse(request.headers)["idempotency-key"];
}

export async function registerRoutes(app: FastifyInstance, store = new Store(), queue = new JobQueue()): Promise<void> {
  app.get("/health", async () => {
    await store.health();
    return { ok: true };
  });

  app.get("/v1/config", async () => LOCKED_CCTP);
  app.get("/v1/contracts", async () => ({
    // Canonical contracts (the active settlement path; P1.1).
    shadePool: process.env.SHIELDED_POOL_CONTRACT,
    nullifierRegistry: process.env.NULLIFIER_REGISTRY_CONTRACT,
    verifierWithdraw: process.env.VERIFIER_WITHDRAW_CONTRACT,
    verifierTransfer: process.env.TRANSFER_VERIFIER_CONTRACT,
    verifierDepositNoteMint: process.env.VERIFIER_DEPOSIT_NOTE_MINT_CONTRACT,
    cctpForwarder: process.env.STELLAR_CCTP_FORWARDER_CONTRACT,
    usdcSac: process.env.STELLAR_TESTNET_USDC_SAC_CONTRACT,
    // Legacy contracts — DEPRECATED, not on the active path (P1.1).
    deprecated: {
      shadeVault: process.env.SHADE_VAULT_CONTRACT,
      commitmentTree: process.env.COMMITMENT_TREE_CONTRACT,
      complianceRegistry: process.env.COMPLIANCE_REGISTRY_CONTRACT,
      intentEscrow: process.env.INTENT_ESCROW_CONTRACT
    }
  }));
  app.get("/v1/balances/testnet", async () => ({ status: "requires setup:testnet for live balances" }));
  app.post("/v1/setup/validate", async () => ({ status: "run npm run setup:testnet" }));

  // Full health: DB + queue reachability + configured contracts.
  app.get("/v1/health/full", async () => {
    let db = false;
    try { await store.health(); db = true; } catch { /* down */ }
    return { ok: db, db, pool: process.env.SHIELDED_POOL_CONTRACT || null, network: process.env.STELLAR_NETWORK_PASSPHRASE ?? "testnet" };
  });

  // ---- Authentication (wallet-signature) ----
  app.post("/v1/auth/nonce", async (request) => {
    const body = authNonceSchema.parse(request.body);
    const address = normalizeAddress(body.wallet_type, body.address);
    const nonce = randomNonce();
    const message = authMessage(body.wallet_type, address, nonce);
    await store.createNonce(body.wallet_type, address, nonce, message, new Date(Date.now() + NONCE_TTL));
    return { wallet_type: body.wallet_type, address, nonce, message };
  });

  const verifyHandler = (walletType: WalletType) => async (request: FastifyRequest, reply: FastifyReply) => {
    const body = authVerifySchema.parse(request.body);
    const address = normalizeAddress(walletType, body.address);
    const message = await store.consumeNonce(walletType, address, body.nonce);
    if (!message) { reply.code(401); return { error: "invalid or expired nonce" }; }
    if (!verifyWalletSignature(walletType, address, message, body.signature)) { reply.code(401); return { error: "signature verification failed" }; }
    const userId = await store.upsertUserByWallet(walletType, CHAIN_FOR[walletType], address);
    const token = newSessionToken();
    await store.createSession(userId, sha256Hex(token), new Date(Date.now() + SESSION_TTL));
    await store.logActivity(userId, { event_type: "auth.login", entity_type: "wallet", entity_id: address, metadata: { walletType } });
    setSessionCookie(reply, token);
    return { user_id: userId, session_token: token, wallet_type: walletType, address };
  };
  app.post("/v1/auth/evm/verify", verifyHandler("EVM"));
  app.post("/v1/auth/stellar/verify", verifyHandler("STELLAR"));

  app.get("/v1/auth/session", async (request) => {
    const userId = await authedUserOptional(store, request);
    return { authenticated: !!userId, user_id: userId };
  });
  app.post("/v1/auth/logout", async (request, reply) => {
    const token = readSessionToken(request);
    if (token) await store.revokeSession(sha256Hex(token));
    clearSessionCookie(reply);
    return { ok: true };
  });

  // ---- User profile + wallets ----
  app.get("/v1/me", async (request) => {
    const userId = await authedUser(store, request);
    return store.getUser(userId);
  });
  app.patch("/v1/me", async (request) => {
    const userId = await authedUser(store, request);
    const body = updateMeSchema.parse(request.body);
    await store.updateUser(userId, body);
    return store.getUser(userId);
  });
  app.get("/v1/me/wallets", async (request) => {
    const userId = await authedUser(store, request);
    return { wallets: await store.listWallets(userId) };
  });
  // FIX2: sync Privy linked wallets into the backend (Privy-auth required). The
  // wallets are attributed to the AUTHENTICATED user's DID — never a client id.
  app.post("/v1/me/wallets/sync-privy", async (request) => {
    const auth = await requirePrivyUser(store, request);
    const body = syncPrivyWalletsSchema.parse(request.body);
    const n = await store.syncPrivyWallets(auth.userId, auth.privyUserId, body.wallets);
    await store.logActivity(auth.userId, { event_type: "wallet.sync_privy", metadata: { count: n } });
    return { synced: n, wallets: await store.listWallets(auth.userId) };
  });
  app.post("/v1/me/wallets", async (request, reply) => {
    const userId = await authedUser(store, request);
    const body = addWalletSchema.parse(request.body);
    const address = normalizeAddress(body.wallet_type, body.address);
    const message = await store.consumeNonce(body.wallet_type, address, body.nonce);
    if (!message || !verifyWalletSignature(body.wallet_type, address, message, body.signature)) { reply.code(401); return { error: "wallet signature verification failed" }; }
    const walletId = await store.addWallet(userId, body.wallet_type, CHAIN_FOR[body.wallet_type], address);
    await store.logActivity(userId, { event_type: "wallet.add", entity_type: "wallet", entity_id: address });
    return { wallet_id: walletId };
  });
  app.delete("/v1/me/wallets/:wallet_id", async (request, reply) => {
    const userId = await authedUser(store, request);
    const ok = await store.deleteWallet(userId, (request.params as { wallet_id: string }).wallet_id);
    if (!ok) { reply.code(409); return { error: "cannot delete (not found or primary)" }; }
    return { ok: true };
  });

  // ---- Per-user history ----
  app.get("/v1/me/deposits", async (request) => ({ deposits: await store.listByUser("cctp_deposits", await authedUser(store, request)) }));
  app.get("/v1/me/notes", async (request) => ({ notes: await store.listByUser("note_commitments", await authedUser(store, request)) }));
  app.get("/v1/me/withdrawals", async (request) => ({ withdrawals: await store.listByUser("withdrawals", await authedUser(store, request)) }));
  app.get("/v1/me/rfq", async (request) => ({ settlements: await store.listByUser("settlements", await authedUser(store, request)) }));
  app.get("/v1/me/cctp-exits", async (request) => ({ exits: await store.listByUser("cctp_exits", await authedUser(store, request)) }));
  app.get("/v1/me/note-backups", async (request) => ({ backups: await store.listByUser("encrypted_note_backups", await authedUser(store, request)) }));

  // DEV-ONLY legacy deposit prepare (builds the note server-side — the old model).
  // The canonical user path is POST /v1/deposits/prepare (client-side note, user-
  // signed burn) below. Kept for diagnostics behind the dev namespace.
  app.post("/v1/dev/deposits/prepare-legacy", async (request) => {
    requireDevRoutes(); // FIX9
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
    const userId = await authedUserOptional(store, request);
    if (userId) { await store.setRowUser("cctp_deposits", "deposit_id", depositId, userId); await store.logActivity(userId, { event_type: "deposit.prepare", entity_type: "deposit", entity_id: depositId }); }
    return { deposit_id: depositId, commitment, amount_usdc_7dp: amount7.toString() };
  });

  // ---- PHASE 6: user-signed CCTP deposit (no backend EVM key) ----
  // Returns approval + burn tx requests for the USER's wallet to sign. The backend
  // never burns USDC itself. Gated on: wallet owned, vault owned + backup verified +
  // recovery policy sufficient, supported chain, positive amount, root healthy.
  app.post("/v1/deposits/prepare", async (request) => {
    const auth = await requirePrivyUser(store, request);
    const body = userDepositPrepareSchema.parse(request.body);
    const idempotencyKey = idem(request);
    if (body.source_chain !== "arbitrum-sepolia") { const e = new Error("unsupported source_chain") as Error & { statusCode: number }; e.statusCode = 400; throw e; }
    if (BigInt(body.amount_usdc_6dp) <= 0n) { const e = new Error("amount must be positive") as Error & { statusCode: number }; e.statusCode = 400; throw e; }
    if (!(await store.userOwnsWallet(auth.userId, body.source_wallet_address))) { const e = new Error("source wallet not linked to user") as Error & { statusCode: number }; e.statusCode = 403; throw e; }
    if (!(await store.userOwnsVault(auth.userId, body.vault_id))) { const e = new Error("vault not owned by user") as Error & { statusCode: number }; e.statusCode = 403; throw e; }
    const ready = await store.vaultDepositReady(auth.userId, body.vault_id);
    if (!ready || !ready.ready) { const e = new Error(`vault not deposit-ready (backup=${ready?.backup_status}, policy=${ready?.recovery_policy_status})`) as Error & { statusCode: number }; e.statusCode = 409; throw e; }
    await assertRootHealthy(store);

    const amount6 = BigInt(body.amount_usdc_6dp);
    const amount7Max = usdc6ToStellar7(amount6);
    const usdcAddress = process.env.ARB_SEPOLIA_USDC_ADDRESS || LOCKED_CCTP.arbitrumSepoliaUsdc;
    const tokenMessenger = process.env.ARB_SEPOLIA_CCTP_TOKEN_MESSENGER || LOCKED_CCTP.arbitrumSepoliaTokenMessenger;
    const forwarder = process.env.STELLAR_CCTP_FORWARDER_CONTRACT || LOCKED_CCTP.stellarCctpForwarder;
    const pool = process.env.SHIELDED_POOL_CONTRACT || "";
    const mintRecipient = stellarContractToBytes32(forwarder);
    const destinationCaller = stellarContractToBytes32(forwarder);
    const hookData = encodeStellarForwardHook(pool);
    const maxFee = (amount6 / 1000n > 0n ? amount6 / 1000n : 1n).toString();
    const depositId = deterministicId({ namespace: "udep", parts: [idempotencyKey, body.commitment] });
    await store.createUserDeposit({
      depositId, idempotencyKey, userId: auth.userId, sourceChain: body.source_chain, sourceWalletAddress: body.source_wallet_address,
      vaultId: body.vault_id, sourceDomain: LOCKED_CCTP.arbitrumSepoliaDomain, destinationDomain: LOCKED_CCTP.stellarDomain,
      assetId: usdcAddress, amount6: amount6.toString(), amount7Max: amount7Max.toString(), commitment: body.commitment,
      encryptedNotePayloadHash: body.encrypted_note_payload_hash, policyId: body.policy_id
    });
    await store.logActivity(auth.userId, { event_type: "deposit.prepare", entity_type: "deposit", entity_id: depositId });
    return {
      deposit_id: depositId,
      approval_tx_request: { to: usdcAddress, abi: "function approve(address,uint256)", args: [tokenMessenger, amount6.toString()] },
      burn_tx_request: { to: tokenMessenger, abi: "function depositForBurnWithHook(uint256,uint32,bytes32,address,bytes32,uint256,uint32,bytes)", args: [amount6.toString(), LOCKED_CCTP.stellarDomain, mintRecipient, usdcAddress, destinationCaller, maxFee, FINALITY_THRESHOLD_CONFIRMED, hookData] },
      usdc_address: usdcAddress, token_messenger_address: tokenMessenger, destination_domain: LOCKED_CCTP.stellarDomain,
      mint_recipient: mintRecipient, destination_caller: destinationCaller, hook_data: hookData, forward_recipient: pool,
      max_fee: maxFee, finality_threshold: FINALITY_THRESHOLD_CONFIRMED, expected_amount_7dp_max: amount7Max.toString()
    };
  });

  // The user submits the burn tx hash; the relayer validates it against the deposit
  // before doing the Stellar side. No server EVM key was used to burn.
  app.post("/v1/deposits/:deposit_id/burn-submitted", async (request, reply) => {
    const auth = await requirePrivyUser(store, request);
    const depositId = (request.params as { deposit_id: string }).deposit_id;
    const body = burnSubmittedSchema.parse(request.body);
    const dep = await store.getDepositForUser(auth.userId, depositId);
    if (!dep) { reply.code(404); return { error: "deposit not found" }; }
    if (String(dep.source_wallet_address).toLowerCase() !== body.source_wallet_address.toLowerCase()) { reply.code(403); return { error: "wallet mismatch" }; }
    await store.setDepositBurnTx(depositId, body.burn_tx_hash);
    const job = await queue.enqueue("relayer", "CCTP_INBOUND_AFTER_USER_BURN", {
      deposit_id: depositId, burn_tx_hash: body.burn_tx_hash, source_wallet_address: body.source_wallet_address,
      expected_amount6: dep.amount_usdc_6dp, commitment: dep.commitment, vault_id: dep.vault_id,
      // bind the finality + maxFee the prepare step used, so the relayer enforces them.
      expected_finality: FINALITY_THRESHOLD_CONFIRMED, expected_max_fee6: dep.max_fee ?? undefined,
      encryptedNotePayloadHashHex: dep.encrypted_note_payload_hash, policyIdHex: dep.policy_id
    }, `user-burn:${depositId}`);
    await store.logActivity(auth.userId, { event_type: "deposit.burn_submitted", entity_type: "deposit", entity_id: depositId, tx_hash: body.burn_tx_hash });
    return { deposit_id: depositId, job_id: job.job_id, status: "queued" };
  });

  app.get("/v1/deposits/:deposit_id", async (request) => store.getById("cctp_deposits", "deposit_id", (request.params as { deposit_id: string }).deposit_id));
  // Composite inbound: burn -> attestation -> mint_and_forward -> register-note
  // (+ deposit proof) in one relayer job. The granular sub-steps below enqueue the
  // individual relayer job types for clients that drive the flow step by step.
  const depositStep = (suffix: string, jobType: string) =>
    app.post(`/v1/deposits/:deposit_id/${suffix}`, async (request) => {
      const depositId = (request.params as { deposit_id: string }).deposit_id;
      const job = await queue.enqueue("relayer", jobType, { deposit_id: depositId, ...(request.body as object) }, `${jobType}:${depositId}`);
      return { deposit_id: depositId, job_id: job.job_id, status: "queued" };
    });
  depositStep("process", "CCTP_INBOUND");
  depositStep("submit-burn", "CCTP_INBOUND_BURN");
  depositStep("fetch-attestation", "CCTP_FETCH_ATTESTATION");
  depositStep("mint-forward", "STELLAR_MINT_FORWARD");
  depositStep("register-note", "REGISTER_NOTE");

  app.post("/v1/notes/local/derive", async (request) => {
    requireDevRoutes(); // FIX9: note preimage generation belongs in the browser
    const note = generateNotePreimage(request.body as never);
    return { note_secret: "redacted", commitment: await poseidonCommitment(note) };
  });
  app.post("/v1/notes/commitment", async (request) => ({ commitment: await poseidonCommitment(request.body as never) }));
  app.get("/v1/notes/:commitment/status", async (request) => store.getById("note_commitments", "commitment", (request.params as { commitment: string }).commitment));
  // Client-side-encrypted note backup (server never sees plaintext or note secrets).
  app.post("/v1/notes/encrypted-backup", async (request) => {
    const userId = await authedUser(store, request);
    const body = noteBackupSchema.parse(request.body);
    await store.addNoteBackup(userId, body.commitment, body.encrypted_payload, body.encryption_version);
    await store.logActivity(userId, { event_type: "note.backup", entity_type: "note", entity_id: body.commitment });
    return { ok: true, commitment: body.commitment };
  });

  // ---- Note vaults (PHASE 4): encrypted-vault storage + recovery policy ----
  // The backend stores only ciphertext + wrapped keys and rejects plaintext.
  const ingestEnvelope = (env: EncryptedVaultEnvelope) => {
    validateVaultEnvelope(env);            // shape + plaintext gate
    assertNoPlaintextNoteFields(env);      // belt-and-suspenders
    return recoveryPolicyFor(env.wrappers as VaultWrapper[]);
  };

  app.post("/v1/note-vaults", async (request) => {
    const auth = await requirePrivyUser(store, request);
    assertNoPlaintextNoteFields(request.body); // scan RAW body before zod can strip unknown keys
    const env = encryptedVaultEnvelopeSchema.parse((request.body as { envelope: unknown }).envelope) as EncryptedVaultEnvelope;
    if (env.privy_user_id !== auth.privyUserId) { const e = new Error("envelope privy_user_id mismatch") as Error & { statusCode: number }; e.statusCode = 403; throw e; }
    const policy = ingestEnvelope(env);
    await store.createNoteVault({ userId: auth.userId, privyUserId: auth.privyUserId, vaultId: env.vault_id, envelope: env, ciphertext: env.ciphertext, aad: env.aad, recoveryPolicyStatus: policy });
    for (const w of env.wrappers) await store.addVaultWrapper(auth.userId, env.vault_id, w.type, w.metadata);
    await store.logActivity(auth.userId, { event_type: "vault.create", entity_type: "vault", entity_id: env.vault_id, metadata: { recovery_policy_status: policy } });
    return { vault_id: env.vault_id, backup_status: "created", recovery_policy_status: policy };
  });

  app.get("/v1/note-vaults", async (request) => {
    const auth = await requirePrivyUser(store, request);
    return { vaults: await store.listNoteVaults(auth.userId) };
  });
  app.get("/v1/note-vaults/:vault_id", async (request) => {
    const auth = await requirePrivyUser(store, request);
    const v = await store.getNoteVault(auth.userId, (request.params as { vault_id: string }).vault_id);
    if (!v) { const e = new Error("vault not found") as Error & { statusCode: number }; e.statusCode = 404; throw e; }
    return v;
  });
  app.put("/v1/note-vaults/:vault_id", async (request) => {
    const auth = await requirePrivyUser(store, request);
    assertNoPlaintextNoteFields(request.body);
    const vaultId = (request.params as { vault_id: string }).vault_id;
    const env = encryptedVaultEnvelopeSchema.parse((request.body as { envelope: unknown }).envelope) as EncryptedVaultEnvelope;
    if (env.vault_id !== vaultId || env.privy_user_id !== auth.privyUserId) { const e = new Error("vault id / identity mismatch") as Error & { statusCode: number }; e.statusCode = 403; throw e; }
    const policy = ingestEnvelope(env);
    const ok = await store.updateNoteVault(auth.userId, vaultId, { envelope: env, ciphertext: env.ciphertext, aad: env.aad, recoveryPolicyStatus: policy });
    if (!ok) { const e = new Error("vault not found") as Error & { statusCode: number }; e.statusCode = 404; throw e; }
    return { vault_id: vaultId, recovery_policy_status: policy };
  });

  // The client proves it could decrypt+restore the vault (cache-clear test) and
  // marks the backup verified — required before deposit.
  app.post("/v1/note-vaults/:vault_id/verify-backup", async (request, reply) => {
    // FIX3: require a non-empty proof-of-decrypt verification object + sufficient
    // recovery policy. The backend can't see plaintext, so it requires the client
    // to send the decrypt/compare result and stores it as metadata.
    const auth = await requirePrivyUser(store, request);
    const vaultId = (request.params as { vault_id: string }).vault_id;
    const body = verifyBackupSchema.parse(request.body);
    if (body.verification.vault_id !== vaultId) { reply.code(400); return { error: "verification vault_id mismatch" }; }
    const vault = await store.getNoteVault(auth.userId, vaultId);
    if (!vault) { reply.code(404); return { error: "vault not found" }; }
    if (vault.recovery_policy_status !== "sufficient" && vault.recovery_policy_status !== "strong") {
      reply.code(409); return { error: `recovery policy insufficient (${vault.recovery_policy_status})` };
    }
    await store.setVaultBackupVerified(auth.userId, vaultId, body.verification);
    await store.logActivity(auth.userId, { event_type: "vault.backup_verified", entity_type: "vault", entity_id: vaultId, metadata: { method: body.verification.method } });
    const ready = await store.vaultDepositReady(auth.userId, vaultId);
    return { vault_id: vaultId, backup_status: "verified", ...ready };
  });
  app.post("/v1/note-vaults/:vault_id/mark-restored", async (request, reply) => {
    const auth = await requirePrivyUser(store, request);
    const vaultId = (request.params as { vault_id: string }).vault_id;
    const ok = await store.setVaultBackupStatus(auth.userId, vaultId, "restored");
    if (!ok) { reply.code(404); return { error: "vault not found" }; }
    await store.logActivity(auth.userId, { event_type: "vault.restored", entity_type: "vault", entity_id: vaultId });
    return { vault_id: vaultId, backup_status: "restored" };
  });

  app.post("/v1/note-vaults/:vault_id/wrappers", async (request) => {
    const auth = await requirePrivyUser(store, request);
    assertNoPlaintextNoteFields(request.body);
    const vaultId = (request.params as { vault_id: string }).vault_id;
    const body = addWrapperSchema.parse(request.body);
    if (body.envelope.vault_id !== vaultId) { const e = new Error("vault id mismatch") as Error & { statusCode: number }; e.statusCode = 403; throw e; }
    const policy = ingestEnvelope(body.envelope as EncryptedVaultEnvelope);
    await store.updateNoteVault(auth.userId, vaultId, { envelope: body.envelope, ciphertext: body.envelope.ciphertext, aad: body.envelope.aad, recoveryPolicyStatus: policy });
    const wrapperId = await store.addVaultWrapper(auth.userId, vaultId, body.wrapper.type, body.wrapper.metadata);
    return { wrapper_id: wrapperId, recovery_policy_status: policy };
  });
  app.delete("/v1/note-vaults/:vault_id/wrappers/:wrapper_id", async (request, reply) => {
    const auth = await requirePrivyUser(store, request);
    const { vault_id, wrapper_id } = request.params as { vault_id: string; wrapper_id: string };
    const ok = await store.deleteVaultWrapper(auth.userId, vault_id, wrapper_id);
    if (!ok) { reply.code(404); return { error: "wrapper not found" }; }
    return { ok: true };
  });

  app.post("/v1/proofs/:kind/request", async (request) => {
    const userId = await authedUser(store, request); // FIX7: require auth
    const body = proofRequestSchema.parse({ ...(request.body as object), proof_type: (request.params as { kind: string }).kind });
    const idempotencyKey = idem(request);
    const proofJobId = deterministicId({ namespace: "proof", parts: [idempotencyKey, body.proof_type, hashJson(body.public_inputs)] });
    await store.insertGeneric("proof_jobs", {
      proof_job_id: proofJobId,
      idempotency_key: idempotencyKey,
      proof_type: body.proof_type,
      public_inputs_hash: hashJson(body.public_inputs),
      user_id: userId,
      status: "queued"
    });
    await store.transition({ entityType: "proof_job", entityId: proofJobId, toState: "queued" });
    // Enqueue the real prover job (the prover worker generates the Groth16 proof).
    // The witness payload (coin path + binding) is supplied by the client/relayer.
    const job = await queue.enqueue("prover", body.proof_type, { ...(body.witness ?? {}), user_id: userId } as Record<string, unknown>, `proof:${proofJobId}`);
    return { proof_job_id: proofJobId, job_id: job.job_id, status: "queued" };
  });
  app.get("/v1/proofs/:proof_job_id", async (request) => {
    const userId = await authedUser(store, request);
    const pj = await store.getById<{ user_id?: string }>("proof_jobs", "proof_job_id", (request.params as { proof_job_id: string }).proof_job_id);
    if (pj && pj.user_id && pj.user_id !== userId) { const e = new Error("not your proof job") as Error & { statusCode: number }; e.statusCode = 403; throw e; }
    return pj;
  });

  // PHASE 2 generic job status (prover/relayer queue): status + non-secret result + events.
  app.get("/v1/jobs/:job_id", async (request) => {
    await authedUser(store, request); // FIX7: job status requires auth
    const id = (request.params as { job_id: string }).job_id;
    const job = await queue.getJob(id);
    if (!job) { const e = new Error("job not found") as Error & { statusCode: number }; e.statusCode = 404; throw e; }
    return { job_id: job.job_id, type: job.job_type, queue: job.queue, status: job.status, attempts: job.attempts, result: job.result, error: job.error, events: await queue.getEvents(id) };
  });

  app.post("/v1/withdrawals/prepare", async (request) => { const userId = await authedUser(store, request); await assertRootHealthy(store); return createWithdrawal(request, store, userId); });
  // PHASE 7: build the UNSIGNED Soroban withdraw XDR for the user's Stellar wallet
  // (Freighter/Privy) to sign client-side. The backend never holds the user secret.
  app.post("/v1/withdrawals/build-xdr", async (request) => {
    await authedUser(store, request);
    await assertRootHealthy(store);
    const b = (request.body ?? {}) as { to?: string; proofHex?: string; publicHex?: string };
    if (!b.to || !b.proofHex || !b.publicHex) { const e = new Error("to, proofHex, publicHex required") as Error & { statusCode: number }; e.statusCode = 400; throw e; }
    const { buildInvokeXdr, withdrawParams, testnet } = await import("@shade/stellar-actions");
    const xdr = await buildInvokeXdr({ network: testnet(), source: b.to, contractId: process.env.SHIELDED_POOL_CONTRACT ?? "", method: "withdraw", params: withdrawParams(b.to, b.proofHex, b.publicHex) });
    return { unsigned_xdr: xdr, sign_with: "stellar_wallet", submit_to: "/v1/withdrawals/submit (signedXdr)" };
  });
  // Submit a prepared withdraw proof via the relayer (pool.withdraw on-chain).
  app.post("/v1/withdrawals/submit", async (request) => {
    await authedUser(store, request); // FIX7
    await assertRootHealthy(store);
    const b = (request.body ?? {}) as Record<string, unknown>;
    const job = await queue.enqueue("relayer", "WITHDRAW_PUBLIC_SUBMIT", b, b.idempotency_key ? `wd-submit:${b.idempotency_key}` : undefined);
    return { job_id: job.job_id, status: "queued" };
  });
  app.get("/v1/withdrawals/:withdrawal_id", async (request) => store.getById("withdrawals", "withdrawal_id", (request.params as { withdrawal_id: string }).withdrawal_id));

  app.post("/v1/intents", async (request) => {
    const userId = await authedUser(store, request); // FIX7/FIX8: auth required, store user_id
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
      user_id: userId,
      state: "INTENT_CREATED"
    });
    await store.transition({ entityType: "intent", entityId: intentHash, toState: "INTENT_CREATED" });
    await store.logActivity(userId, { event_type: "intent.create", entity_type: "intent", entity_id: intentHash });
    return { intent_hash: intentHash };
  });
  app.get("/v1/intents/:intent_hash", async (request) => store.getById("intents", "intent_hash", (request.params as { intent_hash: string }).intent_hash));
  app.get("/v1/intents/:intent_hash/quotes", async (request) => ({ quotes: await store.listQuotesByIntent((request.params as { intent_hash: string }).intent_hash) }));
  // Ask the solver service for a quote on an intent. If SOLVER_URL is configured we
  // call the real solver; the returned quote is persisted. Otherwise returns the
  // quotes already recorded for the intent.
  app.post("/v1/intents/:intent_hash/request-quotes", async (request) => {
    const userId = await authedUser(store, request); // FIX7/FIX8
    const intentHash = (request.params as { intent_hash: string }).intent_hash;
    await requireOwnedIntent(store, userId, intentHash);
    const body = requestQuotesSchema.parse(request.body);
    if (process.env.SOLVER_URL) {
      const resp = await fetch(`${process.env.SOLVER_URL}/v1/quote`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ intent_hash: intentHash, amount: body.amount, expiry_ledger: body.expiry_ledger })
      });
      if (!resp.ok) { const e = new Error(`solver responded ${resp.status}`) as Error & { statusCode: number }; e.statusCode = 502; throw e; }
      const sq = await resp.json() as { quote: Record<string, unknown>; quote_hash: string; solver_pubkey: string; solver_sig: string };
      await store.insertGeneric("quotes", {
        quote_id: sq.quote.quote_id, intent_hash: intentHash, quote_hash: sq.quote_hash, solver_id: sq.quote.solver_id,
        payload: sq.quote, quote_signature: sq.solver_sig, valid_until_ledger: sq.quote.valid_until_ledger, state: "QUOTE_RECEIVED"
      });
      return { requested: true, quote_id: sq.quote.quote_id };
    }
    return { requested: false, reason: "SOLVER_URL not configured", quotes: await store.listQuotesByIntent(intentHash) };
  });
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
    const userId = await authedUser(store, request); // FIX8
    const body = quoteAcceptanceSchema.parse(request.body);
    const quoteId = (request.params as { quote_id: string }).quote_id;
    await requireOwnedIntent(store, userId, body.intent_hash); // user must own the intent
    const lc = await store.rfqLifecycle(body.intent_hash, quoteId);
    if (!lc.quote) { const e = new Error("quote not found") as Error & { statusCode: number }; e.statusCode = 404; throw e; }
    if (lc.quote.intent_hash !== body.intent_hash) { const e = new Error("quote does not belong to intent") as Error & { statusCode: number }; e.statusCode = 409; throw e; }
    if (lc.accepted) { const e = new Error("a quote is already accepted for this intent (immutable)") as Error & { statusCode: number }; e.statusCode = 409; throw e; }
    const acceptanceId = deterministicId({ namespace: "accept", parts: [quoteId, body.user_signature_hash] });
    await store.insertGeneric("quote_acceptances", { acceptance_id: acceptanceId, quote_id: quoteId, intent_hash: body.intent_hash, user_signature_hash: body.user_signature_hash, user_id: userId });
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
  // Record execution of a fill (the solver performed the real destination-chain
  // payout and reports its tx hash). Marks the fill EXECUTED.
  app.post("/v1/fills/:fill_id/execute", async (request, reply) => {
    const fillId = (request.params as { fill_id: string }).fill_id;
    const b = (request.body ?? {}) as { destination_tx_hash?: string };
    if (!b.destination_tx_hash) { reply.code(400); return { error: "destination_tx_hash required" }; }
    const ok = await store.executeFill(fillId, b.destination_tx_hash);
    if (!ok) { reply.code(404); return { error: "fill not found" }; }
    await store.transition({ entityType: "fill", entityId: fillId, toState: "FILL_EXECUTED", txHash: b.destination_tx_hash });
    return { fill_id: fillId, state: "EXECUTED", destination_tx_hash: b.destination_tx_hash };
  });
  app.post("/v1/rfq/settle", async (request) => {
    // PHASE 8: strict RFQ lifecycle verification before enqueuing settlement.
    const userId = await authedUser(store, request);
    await assertRootHealthy(store);
    const body = settlementSchema.parse(request.body);
    const reject = (msg: string, code = 409): never => { const e = new Error(msg) as Error & { statusCode: number }; e.statusCode = code; throw e; };

    const lc = await store.rfqLifecycle(body.intent_hash, body.quote_id);
    if (!lc.intent) reject("intent not found", 404);
    if (lc.intent!.user_id && lc.intent!.user_id !== userId) reject("authenticated user does not own this intent", 403);
    if (!lc.quote) reject("quote not found", 404);
    if (lc.quote!.intent_hash !== body.intent_hash) reject("quote does not belong to intent");
    if (!lc.accepted) reject("quote is not accepted");
    if (!lc.fill) reject("fill not found for quote");
    if (lc.fill!.state !== "EXECUTED") reject("fill is not executed");
    if (body.fill_receipt_hash && lc.fill!.fill_receipt_hash !== body.fill_receipt_hash) reject("fill receipt hash mismatch");
    // expiry: the quote/intent must not be past their valid-until ledger.
    const proofReady = await store.getById<{ status?: string }>("proof_jobs", "proof_job_id", body.proof_job_id);
    if (!proofReady || proofReady.status !== "ready") reject("proof job is not ready");
    if (await store.isNullifierSpent(body.nullifier)) reject("nullifier already spent");
    // solver authorization is enforced on-chain (C4); the API records the lifecycle.

    const settlementId = deterministicId({ namespace: "settle", parts: [body.intent_hash, body.quote_id, body.nullifier] });
    await store.insertGeneric("settlements", { settlement_id: settlementId, ...body, state: "SETTLEMENT_SUBMITTED" });
    await store.transition({ entityType: "settlement", entityId: settlementId, toState: "SETTLEMENT_SUBMITTED" });
    await store.setRowUser("settlements", "settlement_id", settlementId, userId);
    await store.logActivity(userId, { event_type: "rfq.settle", entity_type: "settlement", entity_id: settlementId });
    return { settlement_id: settlementId, lifecycle_verified: true };
  });
  app.get("/v1/settlements/:settlement_id", async (request) => store.getById("settlements", "settlement_id", (request.params as { settlement_id: string }).settlement_id));

  app.post("/v1/cctp/outbound/prepare", async (request) => {
    const userId = await authedUser(store, request); // FIX7
    await assertRootHealthy(store);
    const body = cctpExitSchema.parse(request.body);
    const idempotencyKey = idem(request);
    const exitId = deterministicId({ namespace: "exit", parts: [idempotencyKey, body.nullifier] });
    await store.insertGeneric("cctp_exits", { exit_id: exitId, idempotency_key: idempotencyKey, ...body, user_id: userId, state: "prepared" });
    await store.transition({ entityType: "cctp_exit", entityId: exitId, toState: "prepared" });
    await store.logActivity(userId, { event_type: "cctp_exit.prepare", entity_type: "cctp_exit", entity_id: exitId });
    return { exit_id: exitId };
  });
  // Submit a prepared withdraw_cctp proof via the relayer (proof-bound outbound burn).
  app.post("/v1/cctp/outbound/submit", async (request) => {
    const userId = await authedUser(store, request); // FIX7
    await assertRootHealthy(store);
    const b = (request.body ?? {}) as Record<string, unknown>;
    if (b.exit_id) await requireOwnedExit(store, userId, String(b.exit_id));
    const job = await queue.enqueue("relayer", "WITHDRAW_CCTP_BURN", b, b.idempotency_key ? `exit-submit:${b.idempotency_key}` : undefined);
    return { job_id: job.job_id, status: "queued" };
  });
  // Granular outbound steps for clients driving the CCTP exit step by step.
  app.post("/v1/cctp/outbound/:exit_id/fetch-attestation", async (request) => {
    const userId = await authedUser(store, request); // FIX7
    const exitId = (request.params as { exit_id: string }).exit_id;
    await requireOwnedExit(store, userId, exitId);
    const job = await queue.enqueue("relayer", "CCTP_OUTBOUND_ATTESTATION", { exit_id: exitId, ...(request.body as object) }, `CCTP_OUTBOUND_ATTESTATION:${exitId}`);
    return { exit_id: exitId, job_id: job.job_id, status: "queued" };
  });
  app.post("/v1/cctp/outbound/:exit_id/complete-mint", async (request) => {
    const userId = await authedUser(store, request); // FIX7
    const exitId = (request.params as { exit_id: string }).exit_id;
    await requireOwnedExit(store, userId, exitId);
    const job = await queue.enqueue("relayer", "CCTP_OUTBOUND_MINT", { exit_id: exitId, ...(request.body as object) }, `CCTP_OUTBOUND_MINT:${exitId}`);
    return { exit_id: exitId, job_id: job.job_id, status: "queued" };
  });
  app.get("/v1/cctp/outbound/:exit_id", async (request) => store.getById("cctp_exits", "exit_id", (request.params as { exit_id: string }).exit_id));

  // ---- Activity timeline + live stream ----
  app.get("/v1/activity", async (request) => {
    const userId = await authedUser(store, request);
    return { activity: await store.listActivity(userId) };
  });
  // Server-Sent Events stream of the authenticated user's activity (polls the DB).
  app.get("/v1/activity/stream", async (request, reply) => {
    const userId = await authedUser(store, request);
    reply.raw.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
    let lastSent = "";
    const send = async () => {
      const rows = await store.listActivity(userId, 20);
      const payload = JSON.stringify(rows);
      if (payload !== lastSent) { lastSent = payload; reply.raw.write(`data: ${payload}\n\n`); }
    };
    await send();
    const timer = setInterval(() => { void send(); }, Number(process.env.ACTIVITY_STREAM_INTERVAL_MS ?? "3000"));
    request.raw.on("close", () => clearInterval(timer));
    return reply;
  });

  app.get("/v1/test-report/latest", async () => ({ path: "docs/test-report.generated.md" }));

  // ---- MPC committee routes ----
  // These proxy to the MPC committee service (MPC_COMMITTEE_URL) and persist
  // metadata to the mpc_* tables for audit and status tracking.
  const mpcUrl = () => process.env.MPC_COMMITTEE_URL ?? "http://localhost:8090";

  // Committee public keys — used by clients to encrypt intent amount shares.
  app.get("/v1/mpc/committee", async (_, reply) => {
    try {
      const resp = await fetch(`${mpcUrl()}/v1/mpc/committee`);
      if (!resp.ok) { reply.code(502); return { error: "committee unavailable" }; }
      return resp.json();
    } catch {
      reply.code(503);
      return { error: "MPC_COMMITTEE_URL not reachable — is mpc:dev running?" };
    }
  });

  // Submit an MPC intent (amount is secret-shared; only public metadata in DB).
  app.post("/v1/mpc/intents", async (request, reply) => {
    const body = request.body as Record<string, unknown>;
    const intentId = (body.intentId ?? body.intent_id) as string | undefined;
    if (!intentId) { reply.code(400); return { error: "intentId required" }; }
    const userId = await optionalUser(store, request);

    // 1. Forward to the committee coordinator first to get the session assignment.
    let data: Record<string, unknown>;
    try {
      const resp = await fetch(`${mpcUrl()}/v1/mpc/intents`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ intent: body })
      });
      data = await resp.json() as Record<string, unknown>;
      if (!resp.ok) { reply.code(502); return data; }
    } catch {
      reply.code(503);
      return { error: "MPC committee unreachable" };
    }

    const sessionId = (data.sessionId ?? data.session_id) as string | undefined;
    if (sessionId) {
      // Ensure the session row exists before inserting the intent (FK constraint).
      await store.pool.query(
        `INSERT INTO mpc_sessions (session_id) VALUES ($1) ON CONFLICT DO NOTHING`,
        [sessionId]
      );
    }

    // 2. Persist public metadata with the correct session_id from the committee.
    // Amount is NOT stored here — it lives only in the encrypted committee shares.
    await store.pool.query(
      `INSERT INTO mpc_intents
         (intent_id, session_id, user_id, input_asset, output_asset, expiry_ledger,
          policy_id, note_nullifier, note_commitment, recipient_commitment, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending')
       ON CONFLICT (intent_id) DO UPDATE SET session_id = EXCLUDED.session_id, updated_at = now()`,
      [
        intentId,
        sessionId ?? "unknown",
        userId ?? null,
        body.inputAsset ?? body.input_asset,
        body.outputAsset ?? body.output_asset,
        body.expiryLedger ?? body.expiry_ledger ?? 0,
        body.policyId ?? body.policy_id ?? "default",
        body.noteNullifier ?? body.note_nullifier ?? "",
        body.noteCommitment ?? body.note_commitment ?? "",
        body.recipientCommitment ?? body.recipient_commitment ?? ""
      ]
    );

    // 3. Persist encrypted shares for audit (amount remains encrypted — only ciphertext stored).
    const encryptedShares = (body.encryptedShares ?? []) as Array<{ nodeId: string; ciphertext: string; nonce: string; senderPubkey: string }>;
    for (const share of encryptedShares) {
      await store.pool.query(
        `INSERT INTO mpc_intent_shares (intent_id, node_id, ciphertext, nonce, sender_pubkey)
         VALUES ($1,$2,$3,$4,$5) ON CONFLICT (intent_id, node_id) DO NOTHING`,
        [intentId, share.nodeId, share.ciphertext, share.nonce, share.senderPubkey]
      );
    }

    if (userId) await store.logActivity(userId, { event_type: "mpc.intent.submit", entity_type: "mpc_intent", entity_id: intentId });
    return data;
  });

  // MPC intent status.
  app.get("/v1/mpc/intents/:intent_id", async (request, reply) => {
    const { intent_id } = request.params as { intent_id: string };
    const { rows } = await store.pool.query("SELECT * FROM mpc_intents WHERE intent_id=$1", [intent_id]);
    if (!rows[0]) { reply.code(404); return { error: "intent not found" }; }
    return rows[0];
  });

  // Session status (proxied to committee + local DB).
  app.get("/v1/mpc/sessions/:session_id", async (request, reply) => {
    const { session_id } = request.params as { session_id: string };
    try {
      const resp = await fetch(`${mpcUrl()}/v1/mpc/sessions/${session_id}`);
      if (!resp.ok) { reply.code(resp.status); return resp.json(); }
      return resp.json();
    } catch {
      reply.code(503);
      return { error: "MPC committee unreachable" };
    }
  });

  // Manually trigger a matching round for a session (dev/demo endpoint).
  app.post("/v1/mpc/sessions/:session_id/match", async (request, reply) => {
    const { session_id } = request.params as { session_id: string };
    try {
      const resp = await fetch(`${mpcUrl()}/v1/mpc/sessions/${session_id}/match`, { method: "POST" });
      const data = await resp.json() as Record<string, unknown>;
      if (!resp.ok) { reply.code(502); return data; }

      // Persist the signed batch if matching succeeded.
      if (data.ok && data.batch) {
        const batch = data.batch as Record<string, unknown>;
        const matches = batch.matches as unknown[];
        const sigs = batch.signatures as Array<{ nodeId: string; signingPubkey: string; signature: string }>;

        await store.pool.query(
          `INSERT INTO mpc_batches (batch_id, session_id, batch_hash, match_count, matches_json, signatures_json)
           VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
          [batch.batchId, session_id, batch.batchHash, matches.length, JSON.stringify(matches), JSON.stringify(sigs)]
        );

        // Denormalized per-node signature rows.
        for (const sig of sigs) {
          await store.pool.query(
            `INSERT INTO mpc_batch_signatures (batch_id, node_id, signing_pubkey, signature)
             VALUES ($1,$2,$3,$4) ON CONFLICT (batch_id, node_id) DO NOTHING`,
            [batch.batchId, sig.nodeId, sig.signingPubkey, sig.signature]
          );
        }

        // Update mpc_sessions and matched intent rows.
        await store.pool.query(
          "UPDATE mpc_sessions SET status='signed', match_count=$1, closed_at=now(), updated_at=now() WHERE session_id=$2",
          [matches.length, session_id]
        );
        for (const m of matches as Array<{ intentAId: string; intentBId: string; matchedAmount7dp: string }>) {
          await store.pool.query(
            "UPDATE mpc_intents SET status='matched', matched_with=$2, matched_amount_7dp=$3, updated_at=now() WHERE intent_id=$1",
            [m.intentAId, m.intentBId, m.matchedAmount7dp]
          );
          await store.pool.query(
            "UPDATE mpc_intents SET status='matched', matched_with=$2, matched_amount_7dp=$3, updated_at=now() WHERE intent_id=$1",
            [m.intentBId, m.intentAId, m.matchedAmount7dp]
          );
        }
      }
      return data;
    } catch {
      reply.code(503);
      return { error: "MPC committee unreachable" };
    }
  });

  // All completed signed batches.
  app.get("/v1/mpc/batches", async (_, reply) => {
    try {
      const resp = await fetch(`${mpcUrl()}/v1/mpc/batches`);
      if (!resp.ok) { reply.code(502); return { error: "committee unavailable" }; }
      return resp.json();
    } catch {
      reply.code(503);
      return { error: "MPC committee unreachable" };
    }
  });

  // Verify a signed batch (checks all committee node signatures).
  app.post("/v1/mpc/batches/verify", async (request, reply) => {
    try {
      const resp = await fetch(`${mpcUrl()}/v1/mpc/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request.body)
      });
      if (!resp.ok) { reply.code(502); return { error: "committee unavailable" }; }
      return resp.json();
    } catch {
      reply.code(503);
      return { error: "MPC committee unreachable" };
    }
  });

  // ── Shade Remit / Anchor routes (SEP-38 style) ───────────────────────────
  // These stubs implement the anchor discovery + payout lifecycle. The external
  // anchor adapter (MoneyGram / SEP-38 provider) is wired via ANCHOR_API_BASE env.
  // All routes return 501 when no adapter is configured so they are safe to ship.

  const anchorBase = () => process.env.ANCHOR_API_BASE ?? "";

  async function proxyAnchor(reply: FastifyReply, path: string, method = "GET", body?: unknown) {
    const base = anchorBase();
    if (!base) { reply.code(501); return { error: "no anchor adapter configured (set ANCHOR_API_BASE)" }; }
    const resp = await fetch(`${base}${path}`, {
      method,
      headers: { "content-type": "application/json", ...(process.env.ANCHOR_API_KEY ? { authorization: `Bearer ${process.env.ANCHOR_API_KEY}` } : {}) },
      body: body ? JSON.stringify(body) : undefined
    });
    reply.code(resp.status);
    return resp.json();
  }

  // GET /v1/anchors/discovery — list SEP-38/31 providers + corridors from ANCHOR_API_BASE.
  app.get("/v1/anchors/discovery", async (_, reply) => proxyAnchor(reply, "/info"));

  // POST /v1/anchors/quotes — request a fiat payout quote from the configured anchor.
  // Body: { asset, amount7dp, destination_currency, destination_country }
  app.post("/v1/anchors/quotes", async (request, reply) => {
    const userId = await authedUser(store, request);
    const body = request.body as Record<string, unknown>;
    const quoteId = randomUUID();
    const result = await proxyAnchor(reply, "/quotes", "POST", { ...body, client_id: userId });
    if (reply.statusCode < 300) {
      await store.insertGeneric("anchor_quotes", {
        quote_id: quoteId,
        user_id: userId,
        asset: String(body.asset ?? ""),
        amount_7dp: String(body.amount7dp ?? "0"),
        destination_currency: String(body.destination_currency ?? ""),
        destination_country: String(body.destination_country ?? ""),
        anchor_quote_id: (result as Record<string, unknown>).id ?? null,
        status: "quoted",
        raw: result
      }).catch(() => {/* non-fatal — quote is in memory */});
    }
    return result;
  });

  // POST /v1/anchors/payouts — initiate payout after settlement.
  // Body: { quote_id, settlement_id, recipient_info }
  app.post("/v1/anchors/payouts", async (request, reply) => {
    const userId = await authedUser(store, request);
    const body = request.body as Record<string, unknown>;
    const payoutId = randomUUID();
    const result = await proxyAnchor(reply, "/transactions", "POST", { ...body, client_id: userId });
    if (reply.statusCode < 300) {
      await store.insertGeneric("anchor_payouts", {
        payout_id: payoutId,
        user_id: userId,
        quote_id: String(body.quote_id ?? ""),
        settlement_id: String(body.settlement_id ?? ""),
        anchor_transaction_id: (result as Record<string, unknown>).id ?? null,
        status: "pending",
        raw: result
      }).catch(() => {/* non-fatal */});
    }
    return { payout_id: payoutId, ...result };
  });

  // GET /v1/anchors/payouts/:payout_id — track payout status.
  app.get("/v1/anchors/payouts/:payout_id", async (request, reply) => {
    await authedUser(store, request);
    const { payout_id } = request.params as { payout_id: string };
    const row = await store.getById<{ anchor_transaction_id?: string }>("anchor_payouts", "payout_id", payout_id);
    if (!row) { reply.code(404); return { error: "payout not found" }; }
    if (row.anchor_transaction_id) {
      return proxyAnchor(reply, `/transactions/${row.anchor_transaction_id}`);
    }
    return row;
  });

  // POST /v1/anchors/compliance-package — send encrypted compliance data to anchor.
  // Body: { payout_id, encrypted_package_hex }
  app.post("/v1/anchors/compliance-package", async (request, reply) => {
    await authedUser(store, request);
    const body = request.body as Record<string, unknown>;
    const { payout_id } = body;
    const row = await store.getById<{ anchor_transaction_id?: string }>("anchor_payouts", "payout_id", String(payout_id ?? ""));
    if (!row) { reply.code(404); return { error: "payout not found" }; }
    if (!row.anchor_transaction_id) { reply.code(400); return { error: "payout has no anchor transaction" }; }
    return proxyAnchor(reply, `/transactions/${row.anchor_transaction_id}/kyc_documents`, "POST", {
      encrypted_package: body.encrypted_package_hex
    });
  });
}

async function createWithdrawal(request: FastifyRequest, store: Store, userId: string) {
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
    user_id: userId,
    state: "prepared"
  });
  await store.transition({ entityType: "withdrawal", entityId: withdrawalId, toState: "prepared" });
  await store.logActivity(userId, { event_type: "withdrawal.prepare", entity_type: "withdrawal", entity_id: withdrawalId });
  return { withdrawal_id: withdrawalId };
}

// Unified auth: Privy by default; legacy session only when ENABLE_LEGACY_WALLET_AUTH.
async function authedUser(store: Store, request: FastifyRequest): Promise<string> {
  if (privyEnabled()) return (await requirePrivyUser(store, request)).userId;
  if (legacyWalletAuth()) return requireUser(store, request);
  const e = new Error("authentication not configured (set PRIVY_APP_ID or ENABLE_LEGACY_WALLET_AUTH)") as Error & { statusCode: number };
  e.statusCode = 401; throw e;
}
async function authedUserOptional(store: Store, request: FastifyRequest): Promise<string | null> {
  if (privyEnabled()) return (await optionalPrivyUser(store, request))?.userId ?? null;
  if (legacyWalletAuth()) return optionalUser(store, request);
  return null;
}

// FIX7/FIX8 ownership helpers. Throw 403 if the row isn't owned by userId.
async function requireOwnedIntent(store: Store, userId: string, intentHash: string): Promise<void> {
  const row = await store.getById<{ user_id?: string }>("intents", "intent_hash", intentHash);
  if (!row) { const e = new Error("intent not found") as Error & { statusCode: number }; e.statusCode = 404; throw e; }
  if (row.user_id && row.user_id !== userId) { const e = new Error("intent not owned by user") as Error & { statusCode: number }; e.statusCode = 403; throw e; }
}
async function requireOwnedExit(store: Store, userId: string, exitId: string): Promise<void> {
  const row = await store.getById<{ user_id?: string }>("cctp_exits", "exit_id", exitId);
  if (!row) { const e = new Error("exit not found") as Error & { statusCode: number }; e.statusCode = 404; throw e; }
  if (row.user_id && row.user_id !== userId) { const e = new Error("exit not owned by user") as Error & { statusCode: number }; e.statusCode = 403; throw e; }
}

// C7: refuse spends while the root auditor (P1.9) has flagged a critical root
// mismatch. Any unresolved ROOT_MISMATCH_CRITICAL finding blocks withdraw / RFQ
// settle / CCTP-exit preparation with a 409.
async function assertRootHealthy(store: Store): Promise<void> {
  const critical = await store.criticalRootMismatchCount();
  if (critical > 0) {
    const error = new Error(`ROOT_MISMATCH_CRITICAL: ${critical} unresolved root-audit finding(s); spends are blocked`);
    (error as Error & { statusCode: number }).statusCode = 409;
    throw error;
  }
}


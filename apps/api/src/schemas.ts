import { z } from "zod";

export const idempotencyHeader = z.object({
  "idempotency-key": z.string().min(8)
});

export const prepareDepositSchema = z.object({
  amount_usdc_6dp: z.string().regex(/^\d+$/),
  asset_id: z.string().min(1),
  owner_public_key: z.string().min(1),
  spend_public_key: z.string().min(1),
  compliance_tag: z.string().min(1),
  source_context: z.string().min(1),
  memo_commitment: z.string().min(1),
  encrypted_note_payload_hash: z.string().min(1),
  policy_id: z.string().min(1),
  shade_vault_contract: z.string().min(1)
});

export const proofRequestSchema = z.object({
  // Canonical proof job types — aligned with the prover worker (PHASE 2).
  proof_type: z.enum(["deposit_note_mint", "withdraw_public", "withdraw_cctp", "rfq_settlement", "private_transfer"]),
  public_inputs: z.record(z.unknown()),
  // Prover payload (coin path + binding params); passed through to the prover queue.
  witness: z.record(z.unknown()).optional()
});

export const withdrawalSchema = z.object({
  root: z.string().min(1),
  nullifier: z.string().min(1),
  asset_id: z.string().min(1),
  amount_public: z.string().regex(/^\d+$/),
  recipient: z.string().min(1),
  relayer_fee: z.string().regex(/^\d+$/),
  deadline_ledger: z.number().int().positive(),
  policy_id: z.string().min(1),
  pool_id: z.string().min(1),
  chain_id: z.string().min(1)
});

export const quoteAcceptanceSchema = z.object({
  intent_hash: z.string().min(1),
  user_signature_hash: z.string().min(1)
});

export const lockSchema = z.object({
  solver_id: z.string().min(1),
  lock_hash: z.string().min(1),
  amount: z.string().min(1),
  asset: z.string().min(1),
  expires_at_ledger: z.number().int().positive()
});

export const fillSchema = z.object({
  quote_id: z.string().uuid(),
  fill_receipt_hash: z.string().min(1),
  destination_tx_hash: z.string().optional(),
  amount: z.string().min(1),
  recipient: z.string().min(1)
});

export const settlementSchema = z.object({
  intent_hash: z.string().min(1),
  quote_id: z.string().uuid(),
  fill_id: z.string().optional(),
  fill_receipt_hash: z.string().optional(),
  proof_job_id: z.string().min(1),
  nullifier: z.string().min(1)
});

export const cctpExitSchema = z.object({
  nullifier: z.string().min(1),
  destination_domain: z.number().int(),
  destination_recipient: z.string().min(1),
  amount_usdc_7dp: z.string().regex(/^\d+$/),
  relayer_fee: z.string().regex(/^\d+$/)
});

// ---- PHASE 2 auth / user schemas ----

export const authNonceSchema = z.object({
  wallet_type: z.enum(["EVM", "STELLAR"]),
  address: z.string().min(1)
});

export const authVerifySchema = z.object({
  address: z.string().min(1),
  signature: z.string().min(1),
  nonce: z.string().min(1)
});

export const updateMeSchema = z.object({
  display_name: z.string().max(100).optional(),
  email: z.string().email().max(200).optional(),
  avatar_url: z.string().url().max(500).optional(),
  preferences: z.record(z.unknown()).optional()
});

export const addWalletSchema = z.object({
  wallet_type: z.enum(["EVM", "STELLAR"]),
  address: z.string().min(1),
  signature: z.string().min(1),
  nonce: z.string().min(1)
});

export const noteBackupSchema = z.object({
  commitment: z.string().min(1),
  encrypted_payload: z.string().min(1),
  encryption_version: z.string().default("v1")
});

export const requestQuotesSchema = z.object({
  amount: z.string().regex(/^\d+$/),
  expiry_ledger: z.number().int().positive().optional()
});

// ---- PHASE 4 note-vault schemas ----

const vaultWrapperSchema = z.object({
  id: z.string(),
  type: z.enum(["passkey_prf", "stellar_ed25519_signature", "recovery_file_secret", "recovery_kit_password", "evm_signature"]),
  status: z.enum(["active", "revoked"]),
  kdf: z.enum(["HKDF-SHA256", "PBKDF2-SHA256"]),
  salt: z.string(),
  wrapped_key: z.string(),
  diagnostic_only: z.boolean().optional(),
  metadata: z.record(z.unknown())
});

export const encryptedVaultEnvelopeSchema = z.object({
  version: z.literal("shade-encrypted-vault-v1"),
  vault_id: z.string().min(1),
  privy_user_id: z.string().min(1),
  cipher: z.object({ name: z.literal("AES-256-GCM"), iv: z.string(), tagLength: z.literal(128) }),
  aad: z.record(z.unknown()),
  ciphertext: z.string().min(1),
  wrappers: z.array(vaultWrapperSchema)
});

export const addWrapperSchema = z.object({
  wrapper: vaultWrapperSchema,
  // updated full envelope (the client re-encrypts/re-wraps client-side and uploads)
  envelope: encryptedVaultEnvelopeSchema
});

// ---- PHASE 6 user-signed CCTP deposit ----

// The user's wallet signs the burn; the backend never holds the user EVM key.
export const userDepositPrepareSchema = z.object({
  amount_usdc_6dp: z.string().regex(/^\d+$/),
  source_chain: z.string().min(1),                 // "arbitrum-sepolia"
  source_wallet_address: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  vault_id: z.string().min(1),
  commitment: z.string().min(1),                   // protocol (Poseidon) commitment from the prover
  encrypted_note_payload_hash: z.string().min(1),
  policy_id: z.string().min(1)
});

export const burnSubmittedSchema = z.object({
  burn_tx_hash: z.string().regex(/^0x[a-fA-F0-9]{64}$/),
  source_chain: z.string().min(1),
  source_wallet_address: z.string().regex(/^0x[a-fA-F0-9]{40}$/)
});

// FIX2: Privy linked-wallet sync. EVM 0x… (40 hex) or Stellar G… (56 base32).
export const syncPrivyWalletsSchema = z.object({
  wallets: z.array(z.object({
    wallet_type: z.enum(["EVM", "STELLAR"]),
    wallet_source: z.enum(["privy_embedded", "external", "freighter", "legacy"]).optional(),
    chain: z.string().min(1),
    address: z.string().min(1),
    privy_wallet_id: z.string().optional()
  }).refine((w) => w.wallet_type === "EVM" ? /^0x[a-fA-F0-9]{40}$/.test(w.address) : /^G[A-Z2-7]{55}$/.test(w.address), { message: "invalid address for wallet_type" })).min(1)
});

// Note recovery: returns full vault envelopes + note backups for client-side decryption.
export const noteRecoverSchema = z.object({
  vault_id: z.string().min(1).optional()
});

// FIX3: real backup verification — client must send a non-empty proof-of-decrypt.
export const verifyBackupSchema = z.object({
  verification: z.object({
    vault_id: z.string().min(1),
    decrypted_vault_hash: z.string().min(8),
    commitments_hash: z.string().min(1),
    method: z.enum(["stellar_ed25519_signature", "recovery_file_secret", "recovery_kit_password", "passkey_prf"]),
    verified_at_client: z.string().min(1)
  })
});

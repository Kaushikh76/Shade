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
  proof_type: z.enum(["deposit", "withdraw", "rfq", "fill_claim"]),
  public_inputs: z.record(z.unknown())
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

import { z } from "zod";

export const intentSchema = z.object({
  intent_type: z.literal("PRIVATE_RFQ"),
  version: z.literal("1.0"),
  user_pubkey_commitment: z.string().min(1),
  input_asset: z.string().min(1),
  output_asset: z.string().min(1),
  amount_mode: z.enum(["exact_in", "exact_out", "max_in"]),
  amount_commitment: z.string().min(1),
  min_output_commitment: z.string().min(1),
  expiry_ledger: z.number().int().positive(),
  allowed_solvers_root: z.string().min(1),
  compliance_policy_id: z.string().min(1),
  destination_commitment: z.string().min(1),
  replay_domain: z.literal("shade:stellar:testnet:rfq:v1"),
  signature: z.string().min(1)
});

export const quoteSchema = z.object({
  quote_id: z.string().uuid(),
  intent_hash: z.string().min(1),
  solver_id: z.string().min(1),
  input_asset: z.string().min(1),
  output_asset: z.string().min(1),
  gross_input: z.string().regex(/^\d+(\.\d+)?$/),
  net_output: z.string().regex(/^\d+(\.\d+)?$/),
  fee: z.string().regex(/^\d+(\.\d+)?$/),
  valid_until_ledger: z.number().int().positive(),
  solver_inventory_commitment: z.string().min(1),
  settlement_method: z.enum(["private_note", "stellar_payout", "cctp_exit", "proof_of_fill"]),
  quote_signature: z.string().min(1)
});

export type PrivateIntent = z.infer<typeof intentSchema>;
export type SolverQuote = z.infer<typeof quoteSchema>;

export const RFQ_STATES = [
  "INTENT_CREATED",
  "INTENT_ENCRYPTED",
  "INTENT_PUBLISHED_TO_ALLOWED_SOLVERS",
  "QUOTE_RECEIVED",
  "QUOTE_VALIDATED",
  "QUOTE_ACCEPTED",
  "SOLVER_INVENTORY_LOCKED",
  "FILL_CREATED",
  "FILL_EXECUTED_IF_REQUIRED",
  "PROOF_REQUESTED",
  "PROOF_GENERATED",
  "PROOF_VERIFIED_LOCALLY",
  "SETTLEMENT_SUBMITTED",
  "SETTLED",
  "FAILED_RECOVERABLE",
  "EXPIRED",
  "CANCELLED"
] as const;

export type RfqState = (typeof RFQ_STATES)[number];

export const PROOF_JOB_STATES = [
  "queued",
  "generating_witness",
  "proving",
  "verifying_locally",
  "submitting_onchain",
  "verified",
  "failed"
] as const;

export type ProofJobState = (typeof PROOF_JOB_STATES)[number];

export const DEPOSIT_STATES = [
  "prepared",
  "burn_submitted",
  "attestation_ready",
  "mint_forwarded",
  "note_registered",
  "failed_recoverable"
] as const;

export type DepositState = (typeof DEPOSIT_STATES)[number];

export type StateTransition = {
  entityType: string;
  entityId: string;
  fromState?: string;
  toState: string;
  reason?: string;
  txHash?: string;
  metadata?: Record<string, unknown>;
};

export type ProtocolConfig = {
  cctpVersion: "v2";
  arbitrumSepoliaDomain: number;
  stellarDomain: number;
  arbitrumSepoliaUsdc: string;
  arbitrumSepoliaTokenMessenger: string;
  arbitrumSepoliaMessageTransmitter: string;
  stellarCctpForwarder: string;
  stellarMessageTransmitter: string;
  stellarTokenMessengerMinter: string;
  stellarUsdcAsset: string;
};

export type DeterministicIdInput = {
  namespace: string;
  parts: readonly string[];
};

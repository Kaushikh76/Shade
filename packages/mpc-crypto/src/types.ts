/** A Shamir share: evaluation at x of the secret polynomial. */
export type Share = { x: bigint; y: bigint };

/** One committee node's public identity (sent to users so they can encrypt shares). */
export type CommitteeNodeInfo = {
  nodeId: string;
  encryptionPubkey: string; // hex, X25519 pubkey
  signingPubkey: string;    // hex, Ed25519 pubkey
};

/** Encrypted share for one committee node. */
export type EncryptedShare = {
  nodeId: string;
  ciphertext: string; // hex
  nonce: string;       // hex
  senderPubkey: string; // hex, ephemeral X25519 pubkey used for encryption
};

/** An MPC intent submitted by a user. Amount is secret-shared. */
export type MpcIntent = {
  intentId: string;
  userId: string;
  inputAsset: string;
  outputAsset: string;
  expiryLedger: number;
  policyId: string;
  noteNullifier: string;      // the note being spent
  noteCommitment: string;     // proves ownership
  recipientCommitment: string; // where output goes
  encryptedShares: EncryptedShare[]; // one per committee node
  submittedAt: number;
};

// multi-asset: price scale for MatchResult.rate, matching the mpc_settlement
// circuit's RATE_SCALE and the pool contract's Reflector-price convention.
export const RATE_SCALE = 100000000000000n; // 1e14

/**
 * Resolves the exchange rate between two symbolic assets (e.g. "USDC","XLM"):
 * price of 1 unit of `assetA` denominated in `assetB`, scaled by RATE_SCALE.
 * Must return RATE_SCALE for assetA === assetB (1:1). Implementations should
 * source this from Reflector (see apps/mpc-committee/src/reflector-rate.ts)
 * so the proposed rate passes the pool contract's on-chain deviation check.
 */
export type RateProvider = (assetA: string, assetB: string) => bigint | Promise<bigint>;

/** A matched pair produced by the committee. */
export type MatchResult = {
  intentAId: string;
  intentBId: string;
  matchedAmount7dp: string; // bigint as string; amount of inputAsset that A gives up
  inputAsset: string;
  outputAsset: string;
  // multi-asset: price of 1 unit of inputAsset in outputAsset, scaled RATE_SCALE.
  // B's leg (outputAsset amount) = floor(matchedAmount7dp * rate / RATE_SCALE) —
  // must match circuits/mpc_settlement/main.circom step 7 exactly (same integer
  // division) so the settlement proof's witness is consistent.
  rate: string;
};

/** A signed match batch: all committee nodes signed the batch hash. */
export type SignedMatchBatch = {
  batchId: string;
  sessionId: string;
  matches: MatchResult[];
  batchHash: string;           // hex sha256
  signatures: NodeSignature[];
};

export type NodeSignature = {
  nodeId: string;
  signingPubkey: string; // hex
  signature: string;     // hex, ed25519 over batchHash
};

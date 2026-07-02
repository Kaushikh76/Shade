import { createHash } from "node:crypto";

// Phase 7 (spec §11.3): SIMULATED remittance. This is a mock SEP-38-style payout
// flow — NO real fiat is moved and no real anchor is contacted. It exists to
// exercise the binding: a remit settlement commits to the quote amount, currency,
// recipient metadata commitment, expiry, anchor id, and policy id, and produces a
// simulated receipt whose hash matches the settlement.

export type RemitQuote = {
  quoteId: string;
  amount7dp: string;        // source note amount (7dp)
  payoutAmountMinor: string; // simulated fiat payout in minor units (e.g. paise)
  currency: string;         // e.g. "INR" — SIMULATED
  recipientMetadata: string; // opaque payout metadata (name/UPI/etc.) — committed, not stored
  anchorId: string;         // simulated anchor
  policyId: string;
  expiryLedger: number;
  simulated: true;          // ALWAYS true — no real fiat claim
};

function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

// Commitment to the recipient's payout metadata — the raw metadata is never bound
// directly, only its commitment (§11.3 "payout metadata commitment bound").
export function recipientMetadataCommitment(metadata: string, blindingHex: string): string {
  return "0x" + sha256(`${metadata}|${blindingHex}`);
}

// The settlement hash binds every field the remit proof must commit to. Any
// change to amount/currency/metadata/expiry/anchor/policy changes the hash.
export function remitSettlementHash(q: Omit<RemitQuote, "recipientMetadata"> & { recipientMetadataCommitment: string }): string {
  return "0x" + sha256(JSON.stringify({
    quoteId: q.quoteId,
    amount7dp: q.amount7dp,
    payoutAmountMinor: q.payoutAmountMinor,
    currency: q.currency,
    recipientMetadataCommitment: q.recipientMetadataCommitment,
    anchorId: q.anchorId,
    policyId: q.policyId,
    expiryLedger: q.expiryLedger,
    simulated: true
  }));
}

export type RemitReceipt = {
  quoteId: string;
  settlementHash: string;
  payoutAmountMinor: string;
  currency: string;
  anchorId: string;
  status: "SIMULATED_PAID";
  simulated: true;
};

// Produce a simulated payout receipt bound to the settlement hash. Rejects an
// expired quote (fail closed). currentLedger is the on-chain sequence at settle.
export function simulateRemitReceipt(
  q: RemitQuote,
  metadataBlindingHex: string,
  currentLedger: number
): { settlementHash: string; receipt: RemitReceipt } {
  if (currentLedger > q.expiryLedger) {
    throw new Error("remit quote expired");
  }
  const mc = recipientMetadataCommitment(q.recipientMetadata, metadataBlindingHex);
  const settlementHash = remitSettlementHash({ ...q, recipientMetadataCommitment: mc });
  const receipt: RemitReceipt = {
    quoteId: q.quoteId,
    settlementHash,
    payoutAmountMinor: q.payoutAmountMinor,
    currency: q.currency,
    anchorId: q.anchorId,
    status: "SIMULATED_PAID",
    simulated: true
  };
  return { settlementHash, receipt };
}

// A receipt is valid iff its settlementHash matches the (independently recomputed)
// settlement for the quote + metadata commitment.
export function receiptMatchesSettlement(receipt: RemitReceipt, q: RemitQuote, metadataBlindingHex: string): boolean {
  const mc = recipientMetadataCommitment(q.recipientMetadata, metadataBlindingHex);
  return receipt.settlementHash === remitSettlementHash({ ...q, recipientMetadataCommitment: mc });
}

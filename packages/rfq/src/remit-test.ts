import { simulateRemitReceipt, receiptMatchesSettlement, remitSettlementHash, recipientMetadataCommitment, type RemitQuote } from "./remit.js";

// Phase 7 (spec §11.3): simulated remittance binding.

let failed = 0;
function check(name: string, ok: boolean, detail = ""): void {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
  if (!ok) failed++;
}

const blinding = "0x" + "ab".repeat(16);
const quote: RemitQuote = {
  quoteId: "remit-1",
  amount7dp: "5000000",
  payoutAmountMinor: "41500", // simulated INR paise
  currency: "INR",
  recipientMetadata: "upi:alice@bank",
  anchorId: "mock-anchor-1",
  policyId: "shade:default-testnet-policy:v1",
  expiryLedger: 1000,
  simulated: true
};

// --- happy path: receipt is produced and matches the settlement ---
{
  const { settlementHash, receipt } = simulateRemitReceipt(quote, blinding, 500);
  check("simulated receipt is labeled simulated", receipt.simulated === true && receipt.status === "SIMULATED_PAID");
  check("receipt matches settlement hash", receiptMatchesSettlement(receipt, quote, blinding) && receipt.settlementHash === settlementHash);
  check("currency + payout bound in receipt", receipt.currency === "INR" && receipt.payoutAmountMinor === "41500");
}

// --- expired quote rejected (fail closed) ---
{
  let threw = false;
  try { simulateRemitReceipt(quote, blinding, 1001); } catch { threw = true; }
  check("expired quote rejected", threw);
}

// --- metadata change breaks the settlement binding ---
{
  const { receipt } = simulateRemitReceipt(quote, blinding, 500);
  const changed = { ...quote, recipientMetadata: "upi:mallory@bank" };
  check("changed recipient metadata breaks the binding", !receiptMatchesSettlement(receipt, changed, blinding));
}

// --- wrong currency changes the settlement hash ---
{
  const h1 = remitSettlementHash({ ...quote, recipientMetadataCommitment: recipientMetadataCommitment(quote.recipientMetadata, blinding) });
  const h2 = remitSettlementHash({ ...quote, currency: "USD", recipientMetadataCommitment: recipientMetadataCommitment(quote.recipientMetadata, blinding) });
  check("wrong currency changes the settlement hash", h1 !== h2);
}

// --- amount / anchor / policy / expiry all bound ---
{
  const base = recipientMetadataCommitment(quote.recipientMetadata, blinding);
  const h = remitSettlementHash({ ...quote, recipientMetadataCommitment: base });
  check("changing payout amount changes hash", remitSettlementHash({ ...quote, payoutAmountMinor: "99999", recipientMetadataCommitment: base }) !== h);
  check("changing anchor id changes hash", remitSettlementHash({ ...quote, anchorId: "other", recipientMetadataCommitment: base }) !== h);
  check("changing policy id changes hash", remitSettlementHash({ ...quote, policyId: "other", recipientMetadataCommitment: base }) !== h);
  check("changing expiry changes hash", remitSettlementHash({ ...quote, expiryLedger: 2000, recipientMetadataCommitment: base }) !== h);
}

if (failed > 0) {
  console.error(`\nREMIT TESTS FAILED: ${failed} failing`);
  process.exit(1);
}
console.log("\nREMIT TESTS PASS");

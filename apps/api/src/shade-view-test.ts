import { Keypair } from "@stellar/stellar-sdk";
import { signViewKeyReport, verifyViewKeyReport, canonicalReportPayload, type ViewKeyReportInput } from "./shade-view.js";

// Phase 7 (spec §11.2): Shade View selective-disclosure report.

let failed = 0;
function check(name: string, ok: boolean, detail = ""): void {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
  if (!ok) failed++;
}

const service = Keypair.random();
const input: ViewKeyReportInput = {
  userId: "did:privy:alice",
  timeRangeFrom: "2026-01-01T00:00:00Z",
  timeRangeTo: "2026-07-01T00:00:00Z",
  noteCommitments: ["0x" + "aa".repeat(32), "0x" + "bb".repeat(32)],
  disclosedNullifiers: ["0x" + "cc".repeat(32)],
  quoteId: "quote-1",
  policyId: "shade:default-testnet-policy:v1",
  proofLinks: ["https://stellar.expert/tx/abc"]
};

// --- report verifies ---
const report = signViewKeyReport(input, "report-1", service.secret());
check("signed report verifies against service pubkey", verifyViewKeyReport(report));
check("report carries the service pubkey + signature", /^[0-9a-f]{64}$/.test(report.servicePubkeyHex) && report.serviceSignatureHex.length > 0);

// --- tampering fails signature check ---
{
  const tampered = { ...report, noteCommitments: [...report.noteCommitments, "0x" + "ff".repeat(32)] };
  check("tampering the disclosed set fails verification", !verifyViewKeyReport(tampered));
  const tampered2 = { ...report, userId: "did:privy:mallory" };
  check("tampering the user id fails verification", !verifyViewKeyReport(tampered2));
  const tampered3 = { ...report, amountsDisclosed: [{ commitment: "x", amount7dp: "999", currency: "USD" }] };
  check("injecting an undisclosed amount fails verification", !verifyViewKeyReport(tampered3));
}

// --- a different service key cannot forge a report ---
{
  const mallory = Keypair.random();
  const forged = { ...report, servicePubkeyHex: Buffer.from(mallory.rawPublicKey()).toString("hex") };
  check("a swapped service pubkey fails verification", !verifyViewKeyReport(forged));
}

// --- no raw note secrets / spend material in the report (view-key cannot spend) ---
{
  const serialized = JSON.stringify(report).toLowerCase();
  const hasSecret = /"secret"|"nullifiersecret"|"spendkey"|"blinding"|"privatekey"|"masterkey"/.test(serialized);
  check("report contains no note-secret / spend-key fields (view key cannot spend)", !hasSecret);
  // A view-key report is data-only: it exposes commitments/nullifier HASHES that
  // are already public on-chain, never the openings needed to build a spend proof.
  check("only opt-in amounts are present (undisclosed by default)", (report.amountsDisclosed ?? []).length === 0);
}

// --- undisclosed notes stay hidden: only the user-selected commitments appear ---
{
  check("report discloses exactly the selected commitments", report.noteCommitments.length === 2 && !JSON.stringify(report).includes("dd".repeat(32)));
}

// --- canonical payload is order-independent (stable signature basis) ---
{
  const a = canonicalReportPayload({ ...report });
  const shuffled = { ...report, noteCommitments: [...report.noteCommitments].reverse(), proofLinks: [...report.proofLinks] };
  const b = canonicalReportPayload(shuffled);
  check("canonical payload is stable under commitment reordering", a === b);
}

if (failed > 0) {
  console.error(`\nSHADE-VIEW TESTS FAILED: ${failed} failing`);
  process.exit(1);
}
console.log("\nSHADE-VIEW TESTS PASS");

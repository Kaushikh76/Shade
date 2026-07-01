import { createHash, randomBytes } from "node:crypto";
import { Keypair, StrKey } from "@stellar/stellar-sdk";
import nacl from "tweetnacl";

// P2 #13 (Shade View): assemble and sign a selective-disclosure report per
// bible Sec 13.3. The report only ever contains values that are ALREADY
// public on-chain (note commitments, nullifiers, tx hashes) plus metadata the
// user already owns (quote/policy/anchor ids) — it never touches note
// secrets or plaintext amounts unless the user explicitly opts in via
// `discloseAmounts`. The signature lets a bank/auditor verify the report
// came from the Shade View service and was not tampered with in transit.

export type ViewKeyReportInput = {
  userId: string;
  timeRangeFrom?: string;
  timeRangeTo?: string;
  noteCommitments: string[];
  disclosedNullifiers: string[];
  quoteId?: string;
  policyId?: string;
  anchorId?: string;
  amountsDisclosed?: Array<{ commitment: string; amount7dp: string; currency: string }>;
  proofLinks: string[];
};

export type SignedViewKeyReport = ViewKeyReportInput & {
  reportId: string;
  generatedAt: string;
  servicePubkeyHex: string;
  serviceSignatureHex: string;
};

// Canonical (deterministic key order) JSON the signature is computed over —
// must match exactly what a verifier reconstructs from the persisted row.
export function canonicalReportPayload(r: Omit<SignedViewKeyReport, "servicePubkeyHex" | "serviceSignatureHex">): string {
  return JSON.stringify({
    reportId: r.reportId,
    userId: r.userId,
    generatedAt: r.generatedAt,
    timeRangeFrom: r.timeRangeFrom ?? null,
    timeRangeTo: r.timeRangeTo ?? null,
    noteCommitments: [...r.noteCommitments].sort(),
    disclosedNullifiers: [...r.disclosedNullifiers].sort(),
    quoteId: r.quoteId ?? null,
    policyId: r.policyId ?? null,
    anchorId: r.anchorId ?? null,
    amountsDisclosed: r.amountsDisclosed ?? [],
    proofLinks: [...r.proofLinks].sort()
  });
}

// Sign a report with the Shade View service's Ed25519 (Stellar) key. Same
// signing convention as the solver's quote signature (packages/rfq).
export function signViewKeyReport(input: ViewKeyReportInput, reportId: string, serviceSecret: string): SignedViewKeyReport {
  const kp = Keypair.fromSecret(serviceSecret);
  const unsigned = { ...input, reportId, generatedAt: new Date().toISOString() };
  const digest = createHash("sha256").update(canonicalReportPayload(unsigned)).digest();
  const sig = kp.sign(digest);
  return {
    ...unsigned,
    servicePubkeyHex: Buffer.from(StrKey.decodeEd25519PublicKey(kp.publicKey())).toString("hex"),
    serviceSignatureHex: sig.toString("hex")
  };
}

export function verifyViewKeyReport(report: SignedViewKeyReport): boolean {
  const { servicePubkeyHex, serviceSignatureHex, ...unsigned } = report;
  const digest = createHash("sha256").update(canonicalReportPayload(unsigned)).digest();
  const pk = StrKey.encodeEd25519PublicKey(Buffer.from(servicePubkeyHex, "hex"));
  return Keypair.fromPublicKey(pk).verify(digest, Buffer.from(serviceSignatureHex, "hex"));
}

// Optional encrypted attachment for a bank/auditor (bible: "optional encrypted
// attachment for bank/auditor"). Ephemeral X25519 + NaCl box, same scheme
// already used for MPC share delivery (packages/mpc-crypto).
export function encryptReportAttachment(report: SignedViewKeyReport, recipientPubkeyHex: string): { ciphertext: string; nonce: string; senderPubkey: string } {
  const ephemeralKp = nacl.box.keyPair();
  const recipientPk = Buffer.from(recipientPubkeyHex, "hex");
  const nonce = randomBytes(nacl.box.nonceLength);
  const plaintext = Buffer.from(JSON.stringify(report));
  const ciphertext = nacl.box(new Uint8Array(plaintext), new Uint8Array(nonce), new Uint8Array(recipientPk), ephemeralKp.secretKey);
  return {
    ciphertext: Buffer.from(ciphertext).toString("hex"),
    nonce: nonce.toString("hex"),
    senderPubkey: Buffer.from(ephemeralKp.publicKey).toString("hex")
  };
}

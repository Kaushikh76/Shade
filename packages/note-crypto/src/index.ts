import { randomBytes, createHash } from "node:crypto";

export type NotePreimage = {
  assetId: string;
  amount7dp: string;
  ownerPublicKey: string;
  spendPublicKey: string;
  blinding: string;
  nonce: string;
  complianceTag: string;
  sourceContext: string;
  memoCommitment: string;
};

export function generateNotePreimage(input: Omit<NotePreimage, "blinding" | "nonce">): NotePreimage {
  return {
    ...input,
    blinding: `0x${randomBytes(32).toString("hex")}`,
    nonce: `0x${randomBytes(32).toString("hex")}`
  };
}

export async function poseidonCommitment(note: NotePreimage): Promise<string> {
  const { poseidon } = await import("@iden3/js-crypto");
  const fields = noteToFields(note);
  const digest = poseidon.hash(fields);
  return `0x${BigInt(digest).toString(16).padStart(64, "0")}`;
}

export async function deriveNullifier(note: NotePreimage, domain = "shade:nullifier:v1"): Promise<string> {
  const { poseidon } = await import("@iden3/js-crypto");
  const fields = [
    fieldFromString(domain),
    fieldFromHex(note.nonce),
    fieldFromHex(note.blinding),
    fieldFromString(note.ownerPublicKey)
  ];
  const digest = poseidon.hash(fields);
  return `0x${BigInt(digest).toString(16).padStart(64, "0")}`;
}

function noteToFields(note: NotePreimage): bigint[] {
  return [
    fieldFromString(note.assetId),
    BigInt(note.amount7dp),
    fieldFromString(note.ownerPublicKey),
    fieldFromString(note.spendPublicKey),
    fieldFromHex(note.blinding),
    fieldFromHex(note.nonce),
    fieldFromString(note.complianceTag),
    fieldFromString(note.sourceContext),
    fieldFromString(note.memoCommitment)
  ];
}

function fieldFromString(value: string): bigint {
  const hash = createHash("sha256").update(value).digest("hex");
  return BigInt(`0x${hash}`) % FIELD_MODULUS;
}

function fieldFromHex(value: string): bigint {
  return BigInt(value) % FIELD_MODULUS;
}

const FIELD_MODULUS = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

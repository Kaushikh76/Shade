import { createHash, randomBytes } from "node:crypto";
import nacl from "tweetnacl";
import type { CommitteeNodeInfo, EncryptedShare, NodeSignature, MatchResult, SignedMatchBatch } from "./types.js";
import { shamirSplit, shamirReconstruct, encodeShare, decodeShare } from "./shamir.js";

// ---------- Committee node key management ----------

export type CommitteeNodeKeyPair = {
  nodeId: string;
  encryptionKeyPair: nacl.BoxKeyPair;  // X25519
  signingKeyPair: nacl.SignKeyPair;     // Ed25519
};

export function generateNodeKeyPair(nodeId: string): CommitteeNodeKeyPair {
  return {
    nodeId,
    encryptionKeyPair: nacl.box.keyPair(),
    signingKeyPair: nacl.sign.keyPair()
  };
}

export function nodePublicInfo(kp: CommitteeNodeKeyPair): CommitteeNodeInfo {
  return {
    nodeId: kp.nodeId,
    encryptionPubkey: Buffer.from(kp.encryptionKeyPair.publicKey).toString("hex"),
    signingPubkey: Buffer.from(kp.signingKeyPair.publicKey).toString("hex")
  };
}

// ---------- Share encryption (user-side) ----------

/**
 * Encrypt a Shamir share for delivery to a committee node.
 * Uses ephemeral X25519 ECDH + NaCl box (XSalsa20-Poly1305).
 * The sender uses a fresh ephemeral key for each share so nodes cannot correlate.
 */
export function encryptShareForNode(
  share: { x: string; y: string },
  recipientPubkeyHex: string,
  nodeId: string
): EncryptedShare {
  const ephemeralKp = nacl.box.keyPair();
  const recipientPk = Buffer.from(recipientPubkeyHex, "hex");
  const nonce = randomBytes(nacl.box.nonceLength);

  const plaintext = Buffer.from(JSON.stringify(share));
  const ciphertext = nacl.box(
    new Uint8Array(plaintext),
    new Uint8Array(nonce),
    new Uint8Array(recipientPk),
    ephemeralKp.secretKey
  );

  return {
    nodeId,
    ciphertext: Buffer.from(ciphertext).toString("hex"),
    nonce: nonce.toString("hex"),
    senderPubkey: Buffer.from(ephemeralKp.publicKey).toString("hex")
  };
}

/**
 * Split an amount (7dp bigint as string) into encrypted shares for N committee nodes.
 * threshold = 2 means any 2-of-N can reconstruct.
 */
export function splitAmountForCommittee(
  amount7dpStr: string,
  nodes: CommitteeNodeInfo[],
  threshold = 2
): EncryptedShare[] {
  const amount = BigInt(amount7dpStr);
  const rawShares = shamirSplit(amount, threshold, nodes.length);

  return nodes.map((node, i) => {
    const encoded = encodeShare(rawShares[i]);
    return encryptShareForNode(encoded, node.encryptionPubkey, node.nodeId);
  });
}

// ---------- Share decryption (node-side) ----------

/** Decrypt a share received by a committee node. */
export function decryptShare(
  encrypted: EncryptedShare,
  nodeEncryptionSecretKey: Uint8Array
): { x: string; y: string } {
  const ciphertext = Buffer.from(encrypted.ciphertext, "hex");
  const nonce = Buffer.from(encrypted.nonce, "hex");
  const senderPk = Buffer.from(encrypted.senderPubkey, "hex");

  const plaintext = nacl.box.open(
    new Uint8Array(ciphertext),
    new Uint8Array(nonce),
    new Uint8Array(senderPk),
    nodeEncryptionSecretKey
  );
  if (!plaintext) throw new Error("decryptShare: authentication failed — tampered ciphertext");
  return JSON.parse(Buffer.from(plaintext).toString()) as { x: string; y: string };
}

/** Reconstruct the amount from t or more decrypted shares. */
export function reconstructAmount(decryptedShares: Array<{ x: string; y: string }>): bigint {
  return shamirReconstruct(decryptedShares.map(decodeShare));
}

// ---------- Batch signing (node-side) ----------

export function computeBatchHash(batchId: string, matches: MatchResult[]): string {
  const canonical = JSON.stringify({
    batchId,
    matches: matches
      .map(m => ({ a: m.intentAId, b: m.intentBId, amt: m.matchedAmount7dp, in: m.inputAsset, out: m.outputAsset }))
      // Total order, tie-broken down to `b`: a comparator that never returns 0
      // is not a valid total order and can sort ties differently across JS
      // engines/versions, producing a non-deterministic batchHash for the
      // same logical match set.
      .sort((a, b) => a.a === b.a ? (a.b < b.b ? -1 : a.b > b.b ? 1 : 0) : (a.a < b.a ? -1 : 1))
  });
  return createHash("sha256").update(canonical).digest("hex");
}

export function signBatch(
  batchId: string,
  matches: MatchResult[],
  nodeKeyPair: CommitteeNodeKeyPair
): NodeSignature {
  const batchHash = computeBatchHash(batchId, matches);
  const msg = Buffer.from(batchHash, "hex");
  const sig = nacl.sign.detached(new Uint8Array(msg), nodeKeyPair.signingKeyPair.secretKey);

  return {
    nodeId: nodeKeyPair.nodeId,
    signingPubkey: Buffer.from(nodeKeyPair.signingKeyPair.publicKey).toString("hex"),
    signature: Buffer.from(sig).toString("hex")
  };
}

export function verifyNodeSignature(
  batchId: string,
  matches: MatchResult[],
  sig: NodeSignature
): boolean {
  const batchHash = computeBatchHash(batchId, matches);
  const msg = Buffer.from(batchHash, "hex");
  const pk = Buffer.from(sig.signingPubkey, "hex");
  const signature = Buffer.from(sig.signature, "hex");
  return nacl.sign.detached.verify(new Uint8Array(msg), new Uint8Array(signature), new Uint8Array(pk));
}

/**
 * Verify that a signed batch has valid signatures from the expected committee.
 * Threshold is counted over DISTINCT signer pubkeys — a repeated/replayed signature
 * from the same key must not count twice toward the threshold.
 */
export function verifySignedBatch(batch: SignedMatchBatch, committee: CommitteeNodeInfo[]): boolean {
  const expectedPubkeys = new Set(committee.map(n => n.signingPubkey));
  const seenSigners = new Set<string>();
  for (const sig of batch.signatures) {
    if (!expectedPubkeys.has(sig.signingPubkey)) return false;
    if (seenSigners.has(sig.signingPubkey)) return false; // duplicate signer — reject the whole batch
    if (!verifyNodeSignature(batch.batchId, batch.matches, sig)) return false;
    seenSigners.add(sig.signingPubkey);
  }
  return seenSigners.size >= Math.ceil(committee.length * 2 / 3);
}

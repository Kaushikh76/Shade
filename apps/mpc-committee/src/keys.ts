import pg from "pg";
import nacl from "tweetnacl";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { type CommitteeNodeKeyPair } from "@shade/mpc-crypto";

type KeyRow = {
  node_id: string;
  encryption_pubkey: string;
  encryption_secret: string; // ciphertext (see encryptSecret)
  signing_pubkey: string;
  signing_secret: string;    // ciphertext (see encryptSecret)
};

// P0 #6: committee secret keys must never sit in Postgres in plaintext — a
// single DB dump would otherwise hand over every node's signing key, defeating
// the whole point of a 2-of-3 committee. Secret keys are encrypted at rest
// with AES-256-GCM under MPC_KEY_ENCRYPTION_SECRET, a key that lives only in
// each node operator's environment (KMS/secrets-manager in production) and is
// never written to the database. A DB operator with only the DB can see
// public keys and ciphertext, never the plaintext secret keys.
function loadEncryptionKey(): Buffer {
  const hex = process.env.MPC_KEY_ENCRYPTION_SECRET;
  if (!hex || hex.length !== 64) {
    throw new Error(
      "MPC_KEY_ENCRYPTION_SECRET must be set to a 32-byte (64 hex char) key " +
      "to persist committee keys. Generate one with: openssl rand -hex 32 " +
      "— and keep it out of the database (env/KMS only)."
    );
  }
  return Buffer.from(hex, "hex");
}

function encryptSecret(plainHex: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plainHex, "hex")), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, ciphertext]).toString("hex");
}

function decryptSecret(encHex: string, key: Buffer): string {
  const raw = Buffer.from(encHex, "hex");
  const iv = raw.subarray(0, 12);
  const authTag = raw.subarray(12, 28);
  const ciphertext = raw.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString("hex");
}

function rowToKeyPair(row: KeyRow, encKey: Buffer): CommitteeNodeKeyPair {
  return {
    nodeId: row.node_id,
    encryptionKeyPair: {
      publicKey: Buffer.from(row.encryption_pubkey, "hex"),
      secretKey: Buffer.from(decryptSecret(row.encryption_secret, encKey), "hex")
    } as nacl.BoxKeyPair,
    signingKeyPair: {
      publicKey: Buffer.from(row.signing_pubkey, "hex"),
      secretKey: Buffer.from(decryptSecret(row.signing_secret, encKey), "hex")
    } as nacl.SignKeyPair
  };
}

function keyPairToRow(kp: CommitteeNodeKeyPair, encKey: Buffer): Omit<KeyRow, never> {
  return {
    node_id: kp.nodeId,
    encryption_pubkey: Buffer.from(kp.encryptionKeyPair.publicKey).toString("hex"),
    encryption_secret: encryptSecret(Buffer.from(kp.encryptionKeyPair.secretKey).toString("hex"), encKey),
    signing_pubkey: Buffer.from(kp.signingKeyPair.publicKey).toString("hex"),
    signing_secret: encryptSecret(Buffer.from(kp.signingKeyPair.secretKey).toString("hex"), encKey)
  };
}

// Load committee keypairs from DB, or generate and persist them if not found.
// This ensures keypairs survive process restarts so signed batches remain verifiable.
export async function loadOrGenerateKeys(
  dbUrl: string,
  nodeIds: readonly string[]
): Promise<CommitteeNodeKeyPair[]> {
  const encKey = loadEncryptionKey();
  const pool = new pg.Pool({ connectionString: dbUrl });
  try {
    // Ensure table exists (idempotent — migration 008 should have run, but be safe).
    await pool.query(`
      CREATE TABLE IF NOT EXISTS mpc_committee_keys (
        node_id             TEXT        PRIMARY KEY,
        encryption_pubkey   TEXT        NOT NULL,
        encryption_secret   TEXT        NOT NULL,
        signing_pubkey      TEXT        NOT NULL,
        signing_secret      TEXT        NOT NULL,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);

    const { rows } = await pool.query<KeyRow>(
      "SELECT * FROM mpc_committee_keys WHERE node_id = ANY($1) ORDER BY node_id",
      [nodeIds as string[]]
    );

    if (rows.length === nodeIds.length) {
      const byId = new Map(rows.map(r => [r.node_id, r]));
      console.log("[mpc-keys] loaded persistent committee keypairs from DB (decrypted with MPC_KEY_ENCRYPTION_SECRET)");
      return nodeIds.map(id => rowToKeyPair(byId.get(id)!, encKey));
    }

    // Generate fresh keys for any nodes not yet in DB.
    const existing = new Map(rows.map(r => [r.node_id, rowToKeyPair(r, encKey)]));
    const keypairs: CommitteeNodeKeyPair[] = [];

    for (const id of nodeIds) {
      if (existing.has(id)) {
        keypairs.push(existing.get(id)!);
        continue;
      }
      const kp: CommitteeNodeKeyPair = {
        nodeId: id,
        encryptionKeyPair: nacl.box.keyPair(),
        signingKeyPair: nacl.sign.keyPair()
      };
      const row = keyPairToRow(kp, encKey);
      await pool.query(
        `INSERT INTO mpc_committee_keys
           (node_id, encryption_pubkey, encryption_secret, signing_pubkey, signing_secret)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (node_id) DO NOTHING`,
        [row.node_id, row.encryption_pubkey, row.encryption_secret, row.signing_pubkey, row.signing_secret]
      );
      keypairs.push(kp);
    }

    console.log("[mpc-keys] generated and persisted new committee keypairs (secret keys encrypted at rest)");
    return keypairs;
  } finally {
    await pool.end();
  }
}

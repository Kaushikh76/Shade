-- MPC committee node keypairs (persistent across restarts).
-- encryption_pubkey / signing_pubkey are plaintext hex.
-- encryption_secret / signing_secret are AES-256-GCM ciphertext (hex-encoded
-- iv || authTag || ciphertext), encrypted under MPC_KEY_ENCRYPTION_SECRET —
-- a key that lives only in each node's environment (KMS/secrets-manager in
-- production), never in this database. See apps/mpc-committee/src/keys.ts.
-- A DB dump alone can no longer reconstruct any node's signing key.
CREATE TABLE IF NOT EXISTS mpc_committee_keys (
  node_id             TEXT        PRIMARY KEY,
  encryption_pubkey   TEXT        NOT NULL,
  encryption_secret   TEXT        NOT NULL,
  signing_pubkey      TEXT        NOT NULL,
  signing_secret      TEXT        NOT NULL,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

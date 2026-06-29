-- audit.md PHASE 2/4: Privy-first identity + note vaults.

-- Privy DID is the canonical user identity.
ALTER TABLE users ADD COLUMN IF NOT EXISTS privy_user_id text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS primary_auth_method text;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_privy_user_id ON users(privy_user_id) WHERE privy_user_id IS NOT NULL;

-- Wallet provenance (privy_embedded | external | freighter | legacy).
ALTER TABLE user_wallets ADD COLUMN IF NOT EXISTS privy_user_id text;
ALTER TABLE user_wallets ADD COLUMN IF NOT EXISTS wallet_source text;
ALTER TABLE user_wallets ADD COLUMN IF NOT EXISTS privy_wallet_id text;

-- Encrypted note vaults. The backend stores ONLY ciphertext + wrapped keys.
CREATE TABLE IF NOT EXISTS note_vaults (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  privy_user_id text NOT NULL,
  vault_id text UNIQUE NOT NULL,
  envelope jsonb NOT NULL,                 -- full encrypted envelope (no plaintext)
  ciphertext text NOT NULL,
  aad jsonb NOT NULL,
  backup_status text NOT NULL DEFAULT 'created',   -- created | verified | restored | failed
  recovery_policy_status text NOT NULL DEFAULT 'insufficient', -- insufficient | sufficient | strong
  last_backup_verified_at timestamptz,
  last_restored_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_note_vaults_user ON note_vaults(user_id);

CREATE TABLE IF NOT EXISTS note_vault_wrappers (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  vault_id text NOT NULL REFERENCES note_vaults(vault_id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  wrapper_type text NOT NULL,              -- passkey_prf | stellar_ed25519_signature | recovery_kit_password | evm_signature
  wrapper_status text NOT NULL DEFAULT 'active',
  metadata jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_note_vault_wrappers_vault ON note_vault_wrappers(vault_id);

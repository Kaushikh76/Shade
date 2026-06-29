-- audit.md PHASE 6: user-signed CCTP deposits. Record which wallet/vault the
-- deposit belongs to and the user-submitted burn tx so the relayer can validate it.

ALTER TABLE cctp_deposits ADD COLUMN IF NOT EXISTS source_wallet_address text;
ALTER TABLE cctp_deposits ADD COLUMN IF NOT EXISTS vault_id text;
ALTER TABLE cctp_deposits ADD COLUMN IF NOT EXISTS source_chain text;
ALTER TABLE cctp_deposits ADD COLUMN IF NOT EXISTS coin_path text; -- scratch path to the note opening (relayer-local)

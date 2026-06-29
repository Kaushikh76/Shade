CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS testnet_wallets (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  role text NOT NULL UNIQUE,
  chain text NOT NULL,
  public_address text NOT NULL,
  secret_ref text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS protocol_contracts (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text NOT NULL UNIQUE,
  network text NOT NULL,
  contract_id text NOT NULL,
  deploy_tx_hash text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cctp_deposits (
  deposit_id text PRIMARY KEY,
  idempotency_key text NOT NULL UNIQUE,
  source_domain integer NOT NULL,
  destination_domain integer NOT NULL,
  source_tx_hash text,
  cctp_nonce text,
  message_hash text,
  attestation_status text,
  stellar_mint_tx_hash text,
  vault_deposit_tx_hash text,
  asset_id text NOT NULL,
  amount_usdc_6dp numeric(40,0) NOT NULL,
  amount_usdc_7dp numeric(40,0) NOT NULL,
  commitment text NOT NULL,
  encrypted_note_payload_hash text NOT NULL,
  policy_id text NOT NULL,
  state text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS note_commitments (
  commitment text PRIMARY KEY,
  deposit_id text REFERENCES cctp_deposits(deposit_id),
  leaf_index bigint,
  root text,
  asset_id text NOT NULL,
  amount_usdc_7dp numeric(40,0) NOT NULL,
  policy_id text NOT NULL,
  status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS nullifier_spends (
  nullifier text PRIMARY KEY,
  settlement_id text,
  spent_tx_hash text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS proof_jobs (
  proof_job_id text PRIMARY KEY,
  idempotency_key text NOT NULL UNIQUE,
  proof_type text NOT NULL,
  public_inputs_hash text NOT NULL,
  artifact_path text,
  status text NOT NULL,
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS withdrawals (
  withdrawal_id text PRIMARY KEY,
  idempotency_key text NOT NULL UNIQUE,
  nullifier text NOT NULL,
  amount_usdc_7dp numeric(40,0) NOT NULL,
  recipient text NOT NULL,
  relayer_fee numeric(40,0) NOT NULL,
  deadline_ledger bigint NOT NULL,
  proof_job_id text REFERENCES proof_jobs(proof_job_id),
  tx_hash text,
  state text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS intents (
  intent_hash text PRIMARY KEY,
  idempotency_key text NOT NULL UNIQUE,
  encrypted_payload text NOT NULL,
  public_commitment jsonb NOT NULL,
  expiry_ledger bigint NOT NULL,
  policy_id text NOT NULL,
  user_signature text NOT NULL,
  state text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS quotes (
  quote_id text PRIMARY KEY,
  intent_hash text NOT NULL REFERENCES intents(intent_hash),
  quote_hash text NOT NULL UNIQUE,
  solver_id text NOT NULL,
  payload jsonb NOT NULL,
  quote_signature text NOT NULL,
  valid_until_ledger bigint NOT NULL,
  state text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS quote_acceptances (
  acceptance_id text PRIMARY KEY,
  quote_id text NOT NULL UNIQUE REFERENCES quotes(quote_id),
  intent_hash text NOT NULL REFERENCES intents(intent_hash),
  user_signature_hash text NOT NULL,
  accepted_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS solver_inventory_locks (
  lock_id text PRIMARY KEY,
  quote_id text NOT NULL REFERENCES quotes(quote_id),
  solver_id text NOT NULL,
  lock_hash text NOT NULL,
  amount text NOT NULL,
  asset text NOT NULL,
  expires_at_ledger bigint NOT NULL,
  state text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fills (
  fill_id text PRIMARY KEY,
  quote_id text NOT NULL REFERENCES quotes(quote_id),
  fill_receipt_hash text NOT NULL,
  destination_tx_hash text,
  amount text NOT NULL,
  recipient text NOT NULL,
  state text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS settlements (
  settlement_id text PRIMARY KEY,
  intent_hash text NOT NULL REFERENCES intents(intent_hash),
  quote_id text NOT NULL REFERENCES quotes(quote_id),
  fill_id text REFERENCES fills(fill_id),
  proof_job_id text REFERENCES proof_jobs(proof_job_id),
  nullifier text NOT NULL,
  stellar_tx_hash text,
  state text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cctp_exits (
  exit_id text PRIMARY KEY,
  idempotency_key text NOT NULL UNIQUE,
  nullifier text NOT NULL,
  destination_domain integer NOT NULL,
  destination_recipient text NOT NULL,
  amount_usdc_7dp numeric(40,0) NOT NULL,
  relayer_fee numeric(40,0) NOT NULL,
  proof_job_id text REFERENCES proof_jobs(proof_job_id),
  burn_tx_hash text,
  mint_tx_hash text,
  state text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS state_transitions (
  transition_id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  entity_type text NOT NULL,
  entity_id text NOT NULL,
  from_state text,
  to_state text NOT NULL,
  reason text,
  tx_hash text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS e2e_test_runs (
  run_id text PRIMARY KEY,
  command text NOT NULL,
  status text NOT NULL,
  report_path text,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);

CREATE INDEX IF NOT EXISTS state_transitions_entity_idx ON state_transitions(entity_type, entity_id, created_at);
CREATE INDEX IF NOT EXISTS quotes_intent_hash_idx ON quotes(intent_hash);
CREATE INDEX IF NOT EXISTS settlements_nullifier_idx ON settlements(nullifier);

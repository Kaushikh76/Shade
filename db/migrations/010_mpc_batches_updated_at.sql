-- Add updated_at to mpc_batches so the settler can stamp rows on status change.
ALTER TABLE mpc_batches ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

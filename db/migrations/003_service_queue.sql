-- PHASE 2: durable job queue (Postgres-as-queue). The API enqueues jobs; the
-- prover/relayer workers claim them with SELECT ... FOR UPDATE SKIP LOCKED, so
-- multiple workers can run without double-processing. No external broker needed.

CREATE TABLE IF NOT EXISTS service_jobs (
  job_id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  job_type text NOT NULL,               -- e.g. 'withdraw_public', 'CCTP_INBOUND_BURN'
  queue text NOT NULL,                  -- 'prover' | 'relayer'
  idempotency_key text UNIQUE,          -- optional dedup key from the API
  payload jsonb NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'queued',-- queued|<in-progress states>|ready|failed
  attempts int NOT NULL DEFAULT 0,
  max_attempts int NOT NULL DEFAULT 3,
  result jsonb,                         -- non-secret result (artifact paths, tx hashes)
  error text,
  claimed_at timestamptz,
  available_at timestamptz NOT NULL DEFAULT now(), -- retry backoff target
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_service_jobs_claim ON service_jobs(queue, status, available_at);

CREATE TABLE IF NOT EXISTS service_events (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  job_id uuid REFERENCES service_jobs(job_id) ON DELETE CASCADE,
  status text NOT NULL,
  detail text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_service_events_job ON service_events(job_id, created_at);

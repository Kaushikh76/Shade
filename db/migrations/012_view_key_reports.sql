-- P2 #13: Shade View selective-disclosure reports (bible Sec 13.3, endpoint
-- POST /v1/reports/view-key). A report bundles a set of PUBLIC, already-
-- on-chain values (commitments, nullifiers, tx hashes) the user chooses to
-- disclose to an auditor/anchor, signed by the Shade View service key for
-- integrity. It never touches note secrets (Principle #3) — commitments and
-- nullifiers are public by design; the report only adds selection + signing.

CREATE TABLE IF NOT EXISTS view_key_reports (
  report_id           uuid        PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id             uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  time_range_from     timestamptz,
  time_range_to       timestamptz,
  note_commitments    jsonb       NOT NULL DEFAULT '[]',
  disclosed_nullifiers jsonb      NOT NULL DEFAULT '[]',
  quote_id            text,
  policy_id           text,
  anchor_id           text,
  amount_disclosed    boolean     NOT NULL DEFAULT false,
  proof_links         jsonb       NOT NULL DEFAULT '[]',
  service_pubkey      text        NOT NULL,
  service_signature   text        NOT NULL,
  encrypted_attachment jsonb,
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_view_key_reports_user ON view_key_reports(user_id, created_at);

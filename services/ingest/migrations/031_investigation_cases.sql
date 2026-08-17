-- 031_investigation_cases.sql — AIM-706: case / investigation workflow.
--
-- Cases are the unit of investigation beyond the findings list: a security
-- analyst opens a case, attaches findings / users / tools (refs only), tracks
-- status, and exports a package for handoff.
--
-- Privacy notes:
--   * Attachments store refs only: finding UUIDs, user_ref HMAC pseudonyms,
--     or tool names. Labels are display hints (finding title, short ref).
--     Matched prompt content and cleartext identity NEVER land here.
--   * Cases are org-scoped (shared among analyst+) — not per-user UI prefs.
--     The API gates every route with the same privacy bar as /api/findings.
--   * case_events is append-only audit for the case itself (status changes,
--     notes, attach/detach). Immutable company audit trail (AIM-27) still
--     records the API mutations separately.

CREATE TABLE IF NOT EXISTS investigation_cases (
  case_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title        TEXT NOT NULL,
  description  TEXT,
  severity     TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'open',
  created_by   TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  closed_at    TIMESTAMPTZ,
  closed_by    TEXT,
  CONSTRAINT investigation_cases_severity_chk
    CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  CONSTRAINT investigation_cases_status_chk
    CHECK (status IN ('open', 'investigating', 'contained', 'closed'))
);

CREATE INDEX IF NOT EXISTS investigation_cases_status_updated_idx
  ON investigation_cases (status, updated_at DESC);

CREATE INDEX IF NOT EXISTS investigation_cases_severity_idx
  ON investigation_cases (severity);

CREATE TABLE IF NOT EXISTS case_attachments (
  attachment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id       UUID NOT NULL REFERENCES investigation_cases (case_id) ON DELETE CASCADE,
  kind          TEXT NOT NULL,
  ref           TEXT NOT NULL,
  label         TEXT,
  attached_by   TEXT NOT NULL,
  attached_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT case_attachments_kind_chk
    CHECK (kind IN ('finding', 'user', 'tool')),
  UNIQUE (case_id, kind, ref)
);

CREATE INDEX IF NOT EXISTS case_attachments_case_idx
  ON case_attachments (case_id);

CREATE TABLE IF NOT EXISTS case_events (
  event_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id    UUID NOT NULL REFERENCES investigation_cases (case_id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,
  body       TEXT,
  actor      TEXT NOT NULL,
  meta       JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT case_events_kind_chk
    CHECK (kind IN ('created', 'status_change', 'note', 'attach', 'detach', 'updated'))
);

CREATE INDEX IF NOT EXISTS case_events_case_created_idx
  ON case_events (case_id, created_at DESC);

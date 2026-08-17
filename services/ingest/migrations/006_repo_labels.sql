-- 006_repo_labels.sql — AIM-78: optional de-pseudonymization mapping for
-- repo_ref (salted-HMAC pseudonym, schema v1).
--
-- The Repos dashboard view and /api/repos endpoints show pseudonymized repo
-- refs to everyone. This table lets the security group attach a human-readable
-- label to a repo_ref (e.g. the repo name) — the ONLY de-pseudonymization
-- path, gated to the security group and audited on every read/write
-- (apps/api/src/routes/dashboard.js). Viewers never receive label values.
--
-- There is deliberately no FK to events.repo_ref: labels may be created for
-- refs not (yet) seen, and event retention must not cascade into governance
-- data.

CREATE TABLE IF NOT EXISTS repo_labels (
  repo_ref    TEXT PRIMARY KEY,         -- 64-hex HMAC pseudonym (schema v1)
  label       TEXT NOT NULL,            -- human-readable repo name
  created_by  TEXT NOT NULL,            -- security-admin email who set it
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 035_break_glass_grants.sql — enterprise break-glass control plane.
--
-- Pilot path: endpoint resubmit-within-TTL →
-- enforcement.action=confirmed. Enterprise path: durable grant records with
-- optional manager approval, time-boxed expiry, revoke, and exportable audit.
--
-- Privacy: subject_user_ref is the same pseudonym/user_ref collectors emit;
-- never store prompt text or matched secret content. reason/ticket_ref are
-- free-text operator notes (no secrets).

CREATE TABLE IF NOT EXISTS break_glass_grants (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id          TEXT NOT NULL DEFAULT 'secret-pattern-in-prompt'
                   CHECK (char_length(rule_id) BETWEEN 1 AND 64),
  -- Pseudonym / user_ref of the grantee (collector identity). Required for
  -- endpoint matching when secret_override_requires_manager is on.
  subject_user_ref TEXT NOT NULL
                   CHECK (subject_user_ref <> '' AND char_length(subject_user_ref) <= 256),
  subject_email    TEXT
                   CHECK (subject_email IS NULL OR char_length(subject_email) <= 320),
  team             TEXT
                   CHECK (team IS NULL OR char_length(team) <= 128),
  status           TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'approved', 'denied', 'revoked', 'expired')),
  -- Why the override was requested (operator note; never prompt content).
  reason           TEXT NOT NULL
                   CHECK (char_length(reason) BETWEEN 1 AND 2000),
  ticket_ref       TEXT
                   CHECK (ticket_ref IS NULL OR char_length(ticket_ref) <= 256),
  policy_hash      TEXT
                   CHECK (policy_hash IS NULL OR char_length(policy_hash) <= 128),
  requested_by     TEXT NOT NULL,
  requested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_by       TEXT,
  decided_at       TIMESTAMPTZ,
  decision_note    TEXT
                   CHECK (decision_note IS NULL OR char_length(decision_note) <= 2000),
  -- When status=approved: grant is usable until expires_at (required on approve).
  expires_at       TIMESTAMPTZ,
  revoked_by       TEXT,
  revoked_at       TIMESTAMPTZ,
  revoke_reason    TEXT
                   CHECK (revoke_reason IS NULL OR char_length(revoke_reason) <= 2000),
  -- Default duration requested (hours); manager may shorten on approve.
  requested_ttl_hours INT NOT NULL DEFAULT 4
                   CHECK (requested_ttl_hours BETWEEN 1 AND 168),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS break_glass_grants_status_expires_idx
  ON break_glass_grants (status, expires_at);
CREATE INDEX IF NOT EXISTS break_glass_grants_subject_idx
  ON break_glass_grants (subject_user_ref, rule_id, status);
CREATE INDEX IF NOT EXISTS break_glass_grants_requested_at_idx
  ON break_glass_grants (requested_at DESC);

COMMENT ON TABLE break_glass_grants IS
  'Enterprise break-glass grants: optional manager approval, TTL expiry, revoke.';

-- Append-only lifecycle trail for compliance export (who did what when).
CREATE TABLE IF NOT EXISTS break_glass_grant_events (
  id          BIGSERIAL PRIMARY KEY,
  grant_id    UUID NOT NULL REFERENCES break_glass_grants(id) ON DELETE CASCADE,
  event_type  TEXT NOT NULL
              CHECK (event_type IN (
                'requested', 'approved', 'denied', 'revoked', 'expired', 'note'
              )),
  actor       TEXT NOT NULL,
  detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS break_glass_grant_events_grant_idx
  ON break_glass_grant_events (grant_id, created_at);
CREATE INDEX IF NOT EXISTS break_glass_grant_events_created_idx
  ON break_glass_grant_events (created_at DESC);

COMMENT ON TABLE break_glass_grant_events IS
  'Append-only audit of break-glass grant lifecycle (compliance export).';

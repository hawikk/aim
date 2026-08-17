-- 017_alert_inbox_state.sql — shell-side ack/snooze state for the
-- unified cross-pillar alert inbox.
--
-- The inbox (apps/web/public/inbox.js over GET /api/alerts) is a
-- shell over alerts that live in the pillars' own stores. Acknowledgement is
-- shell state, deliberately NOT written back into any pillar (D1: the shell
-- reads the bus, it does not mutate the pillars) — so it needs a home of its
-- own. This table is that home: one row per alert_id an analyst has acted on,
-- in the same Postgres the rest of the shell state (saved views, findings
-- triage) already lives in, so it survives API restarts.
--
-- The row carries no alert content — no title, no resource, no pseudonyms —
-- only the join key and the triage act itself, so the privacy tier of the
-- inbox is unchanged by storing it.
--
-- Retention: rows are keyed to the bus retention window. An alert_id that has
-- aged out of secstack:alerts:v1 can never appear in the inbox again, so its
-- row is inert; it is purged with the findings data class (findings >= events
-- in the retention config, default 90d — state older than the oldest alert
-- the inbox can show has no operational value). Until a retention sweep
-- covers this table the bound is enforced manually:
--   DELETE FROM alert_inbox_state WHERE updated_at < now() - interval '90 days';
-- 'snoozed' rows additionally self-limit: a snooze is capped at 30 days by
-- the API and reads as open once expired.

CREATE TABLE IF NOT EXISTS alert_inbox_state (
  -- Join key to the bus alert (contract security.alert/v1 alert_id, a uuid4).
  -- Justification: the only durable identifier an ack can attach to; the bus
  -- cursor is not one (it shifts as the stream trims).
  alert_id      UUID PRIMARY KEY,
  -- 'acknowledged' | 'snoozed'. Open is the ABSENCE of a row, so no 'open'
  -- member and no resurrection ambiguity on re-delivery of the same alert_id.
  state         TEXT NOT NULL CHECK (state IN ('acknowledged', 'snoozed')),
  -- When the snooze ends; NULL iff state='acknowledged'. Read path treats an
  -- expired snooze as open. Justification: snooze-without-expiry is a silent
  -- drop with extra steps — the one outcome a security inbox may not have.
  snooze_until  TIMESTAMPTZ,
  -- Email of who last acked/snoozed (session identity). Justification: "who
  -- is owning this alert" is the point of ack; mirrors the immutable audit
  -- trail entry written on the same request. Retention: same 90d bound.
  actor         TEXT NOT NULL,
  -- Last state change. Justification: drives the 90d purge above and shows
  -- the analyst how stale a snooze is.
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The inbox batch-fetches state for the alert_ids of the page it just loaded
-- (WHERE alert_id = ANY(...)); the primary key already covers that probe, so
-- no extra index is needed.

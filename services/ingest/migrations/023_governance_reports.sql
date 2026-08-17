-- 023_governance_reports.sql — scheduled executive AI-governance
-- reports, stored so history is retained (one quarter minimum) and diffable.
--
-- Stores the full governance report (usage by team/tool/model, violations +
-- disposition trail, coverage truth, spend estimate) exactly as generated,
-- plus its print-ready HTML rendering and a sha256 content hash built with
-- the same canonical-JSON construction as the compliance evidence bundles
-- (apps/api/src/compliance-bundle.js) — one verifier covers both.
--
-- Generated from stored events/findings/devices only: the report job runs
-- no new collection, it re-aggregates what ingest + guardrail + enrollment
-- already persist.
--
-- Retention: the API report store purges rows older than
-- GOVERNANCE_REPORT_RETENTION_DAYS (default 100) but always keeps the newest
-- 14 reports, so at least one quarter of scheduled reports survives even if
-- the scheduler stalled (a gap in history must be visible, not silently
-- purged into looking complete).
--
-- Privacy notes:
--   * report aggregates metadata only — tool/team/model names, pseudonym
--     counts, token and cost rollups. No prompt/response text, no per-person
--     rows (per-user breakdowns stay behind the analyst+ aggregate API).
--   * html carries the same aggregate content as report, never more.

CREATE TABLE IF NOT EXISTS governance_reports (
  id              BIGSERIAL PRIMARY KEY,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind            TEXT NOT NULL CHECK (kind IN ('weekly', 'monthly', 'on_demand')),
  period_from     TIMESTAMPTZ NOT NULL,
  period_to       TIMESTAMPTZ NOT NULL,
  -- Full report JSON (headline, usage, violations + dispositions, coverage
  -- statement, spend, audit-chain verdict).
  report          JSONB NOT NULL,
  -- Print-ready HTML rendering of the same report (stored so the rendered
  -- artifact is itself retained and diffable, not just the data).
  html            TEXT NOT NULL,
  -- sha256 over the canonical report payload — same construction as the
  -- compliance snapshot bundle_hash.
  report_hash     TEXT NOT NULL,
  audit_chain_ok  BOOLEAN,
  -- Headline columns for list/diff queries without unpacking the JSONB.
  events_total    INTEGER NOT NULL DEFAULT 0,
  findings_total  INTEGER NOT NULL DEFAULT 0,
  findings_open   INTEGER NOT NULL DEFAULT 0,
  spend_usd       NUMERIC(14, 2) NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS governance_reports_created_idx
  ON governance_reports (created_at DESC);

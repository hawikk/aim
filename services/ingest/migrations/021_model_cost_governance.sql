-- 021_model_cost_governance.sql — per-team token/cost
-- budgets and scoped model/provider allowlists.
--
-- Charter:
--   * Per-team budgets on tokens and/or cost_estimate_usd with alerts at
--     warn (default 80%) and critical (default 100%) of the configured limit.
--   * Model/provider allowlists scoped global or per-team, with
--     observe → enforce rollout (mode column; enforce is opt-in).
--
-- Dependencies:
--   * events.team + events.cost_estimate_usd already exist (001/002).
--   * findings + finding_deliveries carry Sentinel delivery (003/005).
--   * Policy-engine match rules for model/provider live in
--     policies/guardrail/v1; this migration is the operational store the
--     budget evaluator and allowlist API use when the policy engine is
--     incomplete or when per-team overrides are needed. Empty tables =
--     degrade gracefully (no budget alerts, no model restriction beyond
--     the policy-as-code approved_providers / approved_models settings).
--
-- Privacy: team is an org unit name from identity resolution, not
-- a person. Budget and allowlist rows never store prompt content.

-- ---- team budgets --------------------------------------------------------

CREATE TABLE IF NOT EXISTS team_budgets (
  team              TEXT PRIMARY KEY,
  -- calendar_month: usage window is the current UTC calendar month.
  -- rolling_30d: usage window is the trailing 30 days from evaluation time.
  period            TEXT NOT NULL DEFAULT 'calendar_month'
                    CHECK (period IN ('calendar_month', 'rolling_30d')),
  -- At least one of token_budget / cost_budget_usd must be set.
  token_budget      BIGINT,
  cost_budget_usd   NUMERIC(14, 4),
  warn_pct          NUMERIC(5, 2) NOT NULL DEFAULT 80
                    CHECK (warn_pct > 0 AND warn_pct <= 100),
  critical_pct      NUMERIC(5, 2) NOT NULL DEFAULT 100
                    CHECK (critical_pct > 0 AND critical_pct <= 500),
  enabled           BOOLEAN NOT NULL DEFAULT true,
  note              TEXT,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by        TEXT,
  CHECK (token_budget IS NULL OR token_budget > 0),
  CHECK (cost_budget_usd IS NULL OR cost_budget_usd > 0),
  CHECK (token_budget IS NOT NULL OR cost_budget_usd IS NOT NULL),
  CHECK (warn_pct < critical_pct)
);

COMMENT ON TABLE team_budgets IS
  'Per-team token/cost budgets. Empty table = no budget alerts.';

-- Edge-trigger state so we fire once per (team, metric, threshold, period)
-- rather than re-paging on every guardrail cycle while still over budget.
CREATE TABLE IF NOT EXISTS budget_alert_state (
  team            TEXT NOT NULL,
  metric          TEXT NOT NULL CHECK (metric IN ('tokens', 'cost_usd')),
  threshold_pct   NUMERIC(5, 2) NOT NULL,
  period_start    TIMESTAMPTZ NOT NULL,
  fired_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  finding_id      UUID,
  PRIMARY KEY (team, metric, threshold_pct, period_start)
);

COMMENT ON TABLE budget_alert_state IS
  'Dedup state for team budget threshold findings.';

-- ---- model / provider allowlist ------------------------------------------

-- Allowlist semantics: when zero enabled rows exist for a scope (global or
-- team), that scope imposes no model/provider restriction (degrade open).
-- When one or more enabled rows exist for the effective scope, a (provider,
-- model) pair is permitted only if it matches at least one row.
--
-- Matching:
--   * provider NULL on a row = any provider
--   * model NULL on a row = any model for that provider
--   * both set = exact match on both
--
-- mode:
--   * observe — guardrail findings only (default, observe→enforce rollout)
--   * enforce — reserved for endpoint / inline enforcement once Security
--     flips the per-rule enforce flag; storage accepts it now so rollout
--     does not need a second migration.

CREATE TABLE IF NOT EXISTS model_provider_allowlist (
  id            BIGSERIAL PRIMARY KEY,
  scope_type    TEXT NOT NULL CHECK (scope_type IN ('global', 'team')),
  -- team name when scope_type = 'team'; NULL when scope_type = 'global'.
  scope_id      TEXT,
  provider      TEXT,
  model         TEXT,
  mode          TEXT NOT NULL DEFAULT 'observe'
                CHECK (mode IN ('observe', 'enforce')),
  enabled       BOOLEAN NOT NULL DEFAULT true,
  note          TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (
    (scope_type = 'global' AND scope_id IS NULL)
    OR (scope_type = 'team' AND scope_id IS NOT NULL AND scope_id <> '')
  ),
  CHECK (provider IS NOT NULL OR model IS NOT NULL)
);

-- One logical entry per (scope, provider, model). COALESCE so NULL
-- provider/model still participate in uniqueness.
CREATE UNIQUE INDEX IF NOT EXISTS uq_model_provider_allowlist_scope
  ON model_provider_allowlist (
    scope_type,
    COALESCE(scope_id, ''),
    COALESCE(provider, ''),
    COALESCE(model, '')
  );

CREATE INDEX IF NOT EXISTS idx_model_provider_allowlist_scope
  ON model_provider_allowlist (scope_type, scope_id)
  WHERE enabled;

COMMENT ON TABLE model_provider_allowlist IS
  'Scoped model/provider allowlist. Empty = no restriction.';

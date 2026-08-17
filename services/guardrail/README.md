# guardrail — policy evaluation engine (v1, platform observe-only)

Evaluates the canonical AI usage event stream (`packages/schema`, v1) against
versioned, in-repo policy rules (`policies/guardrail/v1/`) and emits structured
finding events. **Platform observe-only**: the engine never blocks — every
finding carries `decision: "observe"` (locked CEO decision, AIM-15). This is
**not** the endpoint enforcement path. Endpoint blocks for critical rules live
in collector hooks + `enforcement.json` (AIM-110 / AIM-296) and are audited on
usage events as `enforcement.{action,rule_id,policy_hash}` — see
[`docs/aim-440-enforcement-reconcile.md`](../../docs/aim-440-enforcement-reconcile.md).

- Design + policy proposal: [`docs/guardrail-engine-v1.md`](../../docs/guardrail-engine-v1.md)
- Ruleset: [`policies/guardrail/v1/core.yaml`](../../policies/guardrail/v1/core.yaml) — **content is a proposal to Security/CEO; changes go through PR review.**

## Quickstart

```bash
cd services/guardrail
PYTHONPATH=src python3 -m unittest discover -s tests        # 15 tests
PYTHONPATH=src python3 -m guardrail.cli validate-rules \
    --rules ../../policies/guardrail/v1                     # CI gate for policy PRs
PYTHONPATH=src python3 -m guardrail.cli evaluate \
    --rules ../../policies/guardrail/v1 \
    --events demo/events.ndjson \
    --findings demo/findings.ndjson \
    --audit demo/audit.ndjson
```

The evaluator reads NDJSON events from a file or stdin (`--events -`) and
streams findings/audit records as NDJSON. In the deployed topology this runs
as a post-ingest queue consumer (AIM-23/AIM-35); stdin mode is the pilot and
local-replay path.

Post-ingest Postgres mode (AIM-32): `evaluate-db` pulls events not yet in
`evaluated_events`, runs the same engine, and writes rows to the `findings`
table (idempotent — `UNIQUE (rule_id, event_id)`, `ON CONFLICT DO NOTHING`):

```bash
DATABASE_URL=postgres://aim:...@localhost:5432/aim \
    PYTHONPATH=src python3 -m guardrail.cli evaluate-db --rules ../../policies/guardrail/v1
```

Unattended compose form (AIM-65): `poll` runs `evaluate-db` on an interval so
findings populate without a manual command. This is the `guardrail` service in
the root `docker-compose.yml` — it comes up with the stack, drains every event
not yet in `evaluated_events`, and is idempotent, so a fresh `docker compose up`
boots the security dashboard with populated findings. It tolerates the startup
race (ingest migrations not yet applied): early ticks log `guardrail.poll.error`
and retry. Interval is `GUARDRAIL_POLL_INTERVAL` seconds (default 15).

Health endpoints (AIM-98): poll mode also serves `/healthz` (always 200) and
`/readyz` (200 once a tick succeeded within max(2× interval, 60s), else 503 —
fail-closed before the first tick) on 0.0.0.0:`GUARDRAIL_HEALTH_PORT`
(default 8090), for k8s liveness/readiness probes. The server is best-effort:
a bind failure is logged once and polling continues without it.

Alert delivery (AIM-76): findings that were newly inserted by a batch are
forwarded out of Postgres after that batch commits — edge-triggered on
`insert_finding` returning True, so conflicts/replays are never re-alerted.
Destinations (both off by default, stdlib-only HTTP, env-configured):

- **Generic webhook** — one HTTPS POST per batch of new findings, JSON array
  of records, HMAC-SHA256 over the body in `X-AIM-Signature: sha256=<hex>`.
  Env: `ALERT_WEBHOOK_URL`, `ALERT_WEBHOOK_SECRET` (required when the URL is
  set), `ALERT_WEBHOOK_MIN_SEVERITY` (low|medium|high|critical, default low).
- **Microsoft Sentinel** — Python port of `packages/alerting` (Log Analytics
  Data Collector API, SharedKey HMAC, CEF mapping, same retry policy).
  Env: `SENTINEL_WORKSPACE_ID`, `SENTINEL_SHARED_KEY`, optional
  `SENTINEL_LOG_TYPE` (default `AIGuardrailFinding`), `RUNBOOK_BASE_URL`.
- **Google Chat, email (SMTP)** (AIM-485) — one Cards V2 POST per batch to a space
  incoming-webhook. Webhook URL is env-only (`ALERT_GOOGLE_CHAT_WEBHOOK_URL`;
  the URL *is* the secret). Optional `ALERT_GOOGLE_CHAT_MIN_SEVERITY`
  (default `high`). Deep links use `AIM_BASE_URL` + `#/findings`. UI enable
  toggle lives under Rules → Alert destinations; engine fails closed if
  enabled without the env URL.
- **PagerDuty** (AIM-699 / AIM-586) — Events API v2 trigger per finding.
  Routing key is env-only (`ALERT_PAGERDUTY_ROUTING_KEY`). SOC-gated: off
  until enabled in policy. Pair with `settings.alerts.escalation_policies`
  for multi-stage routing (e.g. Slack → PagerDuty with timers). Operator
  proof: `python -m guardrail.cli notify-test --pagerduty`. See
  `docs/security/escalation-policies.md`.
- **Slack** (AIM-583) — optional Block Kit POST per batch. **Feature-flagged
  off by default** (`ALERT_SLACK_ENABLED`, SOC opt-in only). When enabled:
  env-only webhook URL (`ALERT_SLACK_WEBHOOK_URL`), optional
  `ALERT_SLACK_MIN_SEVERITY` (default `high`), same triage deep links via
  `AIM_BASE_URL`. See `docs/security/slack-alert-destination.md`.

All retry 429/5xx and network errors with exponential backoff (3 retries)
and fail fast on other 4xx. A delivery failure never rolls back the finding
insert and never crashes the run: it is logged as `guardrail.alert.error`
(JSON, stderr) and recorded in the `finding_deliveries` table (one row per
finding per destination, `status` delivered|failed — migration
`services/ingest/migrations/005_finding_deliveries.sql`). Payloads are
metadata-only: rule id, severity, pseudonymous refs, detector names — never
prompt/response content.

App-LLM new-sources → SOC (AIM-575): after each evaluate-db pass the runner
also scans for proxy events whose first-ever call to a provider-API provider
(full `DEFAULT_PROVIDERS` mirror of `endpoints.json` provider-api; override via
`APP_LLM_NEW_SOURCE_PROVIDERS`) falls inside `APP_LLM_NEW_SOURCE_LOOKBACK_HOURS`
(default 48). Each new `(host_ref, provider)` pair becomes one
`app-llm-new-source` finding (severity medium, taxonomy `app_llm_new_source` /
runbook `rb-app-llm-new-source`) and is forwarded through the same
webhook/Sentinel/Google Chat destinations. Edge trigger is
`UNIQUE (rule_id, event_id)` on the first event id — re-runs never re-page.
Proof: `python3 -m unittest tests.test_new_sources`.

Provider/model catalogue drift → SOC (AIM-738): the same evaluate-db pass then
runs `catalogue_drift` — first-ever **uncatalogued provider** strings
(`app-llm-new-provider`) and **unpriced model** ids (`app-llm-new-model`)
inside the lookback become Low findings (runbook
`rb-app-llm-catalogue-drift`). Known providers = all rule providers in
`collectors/proxy/endpoints.json`; known models = `PRICE_PER_MTOK` keys in
`apps/api/src/pricing.js`. Ownership map:
`docs/app-llm-provider-catalogue.md`. Proof:
`python3 -m unittest tests.test_catalogue_drift`.

```bash
DATABASE_URL=postgres://aim:...@localhost:5432/aim GUARDRAIL_POLL_INTERVAL=15 \
    PYTHONPATH=src python3 -m guardrail.cli poll --rules ../../policies/guardrail/v1
```

Restricted-repo matching (AIM-78): the `restricted-repo-access` rule matches
`event.repo_ref` against `settings.restricted_repos` in the ruleset — the
engine HMACs each configured repo path with `AIM_HASH_SALT` (same salt the
collectors use) and compares pseudonyms, so repo names never leave the policy
file. Without the salt the rule is inert (fail-closed; the evaluation detail
says `disabled`). `guardrail repo-ref <path>` prints the pseudonym a collector
would emit, for verifying config entries and crafting seed events:

```bash
AIM_HASH_SALT=... PYTHONPATH=src python3 -m guardrail.cli repo-ref /home/eng/payments-core
```

## Layout

- `src/guardrail/rules.py` — ruleset loading, validation, content hashing
- `src/guardrail/merge.py` — multi-source org+team+local pack merge with security floors (AIM-691); see [`docs/security/multi-source-policy-merge.md`](../../docs/security/multi-source-policy-merge.md)
- `src/guardrail/conditions.py` — condition-tree evaluation (the rule DSL)
- `src/guardrail/engine.py` — streaming evaluator, sliding-window state, findings + audit
- `src/guardrail/dbrunner.py` — post-ingest Postgres runner (evaluate-db, AIM-32) + alert delivery wiring (AIM-76)
- `src/guardrail/new_sources.py` — App-LLM new-sources signal → finding (AIM-575); first-ever proxy provider-API `(host_ref, provider)` inside lookback becomes an observe finding delivered on the AIM-76 path
- `src/guardrail/catalogue_drift.py` — App-LLM catalogue completeness alerts (AIM-738); first-ever uncatalogued provider / unpriced model → Low finding on the AIM-76 path
- `src/guardrail/notify.py` — webhook + Sentinel notifiers, HMAC signing, retry policy (AIM-76)
- `src/guardrail/notify.py` — webhook + Sentinel + Google Chat + optional Slack + PagerDuty notifiers, HMAC signing, retry policy (AIM-76 / AIM-485 / AIM-583 / AIM-699)
- `src/guardrail/escalation.py` — multi-stage escalation policies with timers (AIM-699)
- `src/guardrail/poller.py` — resilient interval poller (the compose service, AIM-65)
- `src/guardrail/health.py` — stdlib /healthz + /readyz server for poll mode (AIM-98)
- `src/guardrail/cli.py` — `evaluate` / `evaluate-db` / `poll` / `validate-rules` entry points
- `Dockerfile` — runtime image for the `guardrail` compose service
- `tests/` — unittest suite, incl. cross-check against canonical schema examples
- `demo/` — sample stream + generated findings/audit from the command above

Dependencies: PyYAML (engine) + psycopg (evaluate-db runner only).

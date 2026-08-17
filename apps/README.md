# Dashboards v1 (AIM-25), unified with the canonical event store (AIM-57)

Read-only usage dashboard answering: **who uses which AI tools, how often, for what** —
plus org-level AI provider traffic and unapproved-tool discovery. Metadata-only by design
(content policy, AIM-16): no prompt text, no response text, no file contents are ever
stored or displayed.

The dashboard reads the **canonical ingest store** (AIM-34/AIM-23): events keyed by
`event_id`, pseudonymous `host_ref`/`user_ref` (salted HMAC), `source` in
{`proxy`, `endpoint`}, nullable tokens/model/provider. Network-path (proxy) events have
no resolved user, so no query depends on a NOT-NULL user identity. The old
apps-local `events`/`directory_*` schema and seed path were removed on AIM-57.

## Components

- `apps/api` — Fastify read API (aggregate SQL over the ingest Postgres schema). Endpoints:
  - `GET /api/overview?days=N[&source=proxy|endpoint]` — active users/hosts, sessions, events, tokens, cost estimate, per-tool table (with proxy/endpoint split), daily trend
  - `GET /api/providers?days=N[&source=proxy|endpoint]` — org-level AI provider volumes + per-path (proxy vs endpoint) totals; the day-1 pilot view, works with proxy-only data (AIM-19 AC2)
  - `GET /api/teams?days=N` — per-team usage from ingest-time identity enrichment (AIM-49); unresolved identities bucket into `(unattributed)`
  - `GET /api/governance/budgets` · `PUT /api/governance/budgets/:team` · `GET /api/governance/budgets/utilization` — per-team token/cost budgets with 80/100% utilization (AIM-383); cost figures are estimates (`estimateNote` on every response; see `docs/cost-attribution-accuracy.md`)
  - `GET|POST /api/governance/model-allowlist` · `DELETE /api/governance/model-allowlist/:id` — scoped model/provider allowlist (global|team), observe→enforce mode (AIM-383)
  - Break-glass trail + enterprise grants (AIM-567 / AIM-784) — analyst+ list of endpoint `enforcement.action=confirmed` overrides; optional manager-approval grants with expiry/revoke; compliance audit export. Policy flag `secret_override_requires_manager` defaults **false** (pilot resubmit path). Migration: `services/ingest/migrations/035_break_glass_grants.sql`. Docs: `docs/aim-784-break-glass-enterprise.md`.
    - `GET /api/enforcement/break-glass` — endpoint override trail (+ CSV)
    - `GET|POST /api/enforcement/break-glass/grants` · `POST …/grants/:id/{approve,deny,revoke}` — grant lifecycle
    - `GET /api/enforcement/break-glass/active-grants` — endpoint sync bundle
    - `GET /api/enforcement/break-glass/audit-export?format=json|csv|bundle` — compliance evidence pack
  - `GET /api/tools/:tool?days=N` — per-tool models, token volumes, session counts, first/last seen
  - `GET /api/unapproved?days=N` — everything not on the sanctioned list: tool, provider, first-seen, event/user/team counts
  - `GET /api/flags?days=N` — guardrail match-flag aggregates by detector (observe-only)
  - `GET /api/users?days=N[&limit=&offset=]` — user-level rows (pseudonyms only), **gated** (see Authorization). AIM-866: `total` + offset pagination; JSON default/max `limit=100` (CSV export may use up to 10_000). p95 ≤ 400 ms (see `docs/api-read-path-pagination.md`, AIM-709 §4.1).
  - `GET /api/fleet[?limit=&offset=]` — enrolled-device coverage rollup, **gated** analyst+. AIM-866: `total` + offset pagination on `devices` (default/max 100); rollup counts remain fleet-wide. p95 ≤ 400 ms (same doc).
  - `GET /api/health`, `GET /api/me`
  - `GET /api/system/status` (AIM-290) — product health/coverage screen backend: ingest lag, throughput, DLQ, device liveness, identity coverage, CNAPP coverage (when `AIM_CNAPP_BASE_URL` set), gatehouse/guardrail/sentinel probes. Every tile has an explicit SLO and state in `{ok, degraded, broken, never_configured}`. Opt-in bus publishing: `SYSTEM_STATUS_ALERTS=1` (same Sentinel path).
  - `GET /api/install-health` (AIM-746) — enroll → first-evidence SLO for Ops: per-device latency (enroll → first heartbeat), fleet first usage event (first enroll → first `events.received_at`), p50/p95, lookback table, and SLO breach alert candidates (`ai_usage.install_first_evidence_breach`). SLO default 5m (`INSTALL_HEALTH_SLO_SEC`); lookback default 7d (`INSTALL_HEALTH_LOOKBACK_DAYS`). Gated analyst+.
  - `GET /api/destination-health` (AIM-704) — failed delivery SLO for alert destinations (webhook / email / Slack primary; plus sentinel, bus, chat, SIEM). Reads `finding_deliveries` over a rolling window (default 24h). Success-rate SLO default ≥99% (`DESTINATION_HEALTH_SUCCESS_PCT`); hard-fail absolute count default 3 (`DESTINATION_HEALTH_FAIL_HARD`). UI: `#/destination-health`. Opt-in bus publishing: `DESTINATION_HEALTH_ALERTS=1` → `ai_usage.destination_delivery_failed` / `_slo_breach` / `_fleet_failed`. Gated analyst+.
  - Findings triage + lifecycle SLA (AIM-442) — `GET /api/findings/summary` (unhandled criticals, age buckets, SLA breaches), list rows carry `ageHours`/`slaBreached`, `POST /api/findings/apply-suppressions` auto-closes proven-noise classes with transition reasons. Critical-ack SLA default 4h; opt-in bus publishing: `FINDING_SLA_ALERTS=1` → `ai_usage.finding_sla_breach`.
  - Detector FP rate SLO (AIM-672) — live pilot `session_fp_rate` for secret/PII findings: `GET /api/security/fp-rate?days=7`, weekly history in `fp_rate_snapshots` (`GET|POST /api/security/fp-rate/snapshots`). SLO default &lt;0.5% of sessions; breach pages via `DETECTOR_FP_RATE_ALERTS=1` → `ai_usage.detector_fp_rate_breach`. Contract: `docs/security/detector-fp-rate-slo.md`.
  - Executive AI-governance report (AIM-325 / AIM-382) — scheduled weekly/monthly answer to “what did AI tools do last period?” built only from stored events/findings/devices (no new collection). Org-level only; gated to security-admin / analyst / auditor. Includes usage by team/tool/model, violations with disposition trail (rule + `policy_hash`), coverage statement (devices reporting vs enrolled vs dark; green-when-blind when the feed is stale or enforcement posture is absent), and list-price spend. Renders HTML/PDF; retains ≥1 quarter of reports and diffs them.
    - `GET /api/governance/report?from=&to=&format=json|html|pdf|text` — live report
    - `GET /api/governance/reports` — retained report index
    - `POST /api/governance/reports` — store on-demand (security-admin)
    - `GET /api/governance/reports/:id[?format=]` — one stored report
    - `GET /api/governance/reports/:id/diff?against=` — structured period-over-period diff
    - Env: `GOVERNANCE_REPORTS=off` disables the in-process scheduler; `GOVERNANCE_REPORT_RETENTION_DAYS` (default 100); `GOVERNANCE_REPORT_MIN_KEEP` (default 14). Migration: `services/ingest/migrations/023_governance_reports.sql`.
  - Schema is owned and migrated by `services/ingest` — the API runs no migrations.
- `apps/web` — static dashboard UI (vanilla JS + Chart.js vendored via `node vendor.js`, no build step, no CDN).
  Served by `apps/api`. Tabs: Overview / **Status** (AIM-290) / Providers / Teams / Tools / Security / Users (Users tab visible only to analyst+ roles).
  Tab visibility is driven by `GET /api/me`: the server computes `capabilities`
  (`userLevel`, `findingsConsole`) from the verified session's role and
  reports `mode` (`enterprise`/`personal`). The UI never sniffs group names
  client-side; in `personal` mode the Teams tab is hidden (AIM-84).
  Adding a view: `docs/how-to-add-dashboard-view.md` (static vs module view
  checklist + the registration smoke guard). Design system:
  `docs/frontend-design-system.md`.

## Authorization (privacy gate)

- Authn: in-app OIDC SSO (authorization code flow + PKCE, HMAC-signed session
  cookie) when `AIM_OIDC_*` is set (AIM-95); otherwise personal/standalone
  mode for local use. Client-supplied identity headers are never trusted —
  there is no proxy-auth mode (AIM-302).
- Authz: org/team aggregates are visible to any authenticated user with a
  mapped role; **user-level rows require analyst or admin** — others
  get 403, and every denial is written to the audit trail.
- User-level rows show pseudonyms (`user_pseudonym`/`user_ref`) only; identity reveal stays behind
  identity-sync's role-gated endpoint (AIM-24, AIM-306). The Unapproved view shows counts, not identities.
- `AIM_AUTH_DEV=1` adds role-switch login endpoints for local development only.

## Sanctioned tools

Claude Code, Cursor, Kilo Code (AIM-16 seed). Live list is the `sanctioned_tools`
table (migration 022, AIM-484); admins mutate via `/api/sanctioned`. Module
`apps/api/src/sanctioned.js` caches the store. It is the enforcement mechanism,
not the policy decision (Security/Legal/CEO own policy).

## Run it

```sh
docker compose up -d postgres ingest           # ingest owns and applies the events schema
npm --prefix apps/api install
npm --prefix apps/web install
node apps/web/vendor.js                        # vendor Chart.js into apps/web/public/vendor
./scripts/seed-demo-events.sh                  # optional: post sample events to ingest
DATABASE_URL=postgres://aim:***@localhost:5432/aim PORT=8090 node apps/api/src/server.js
```

# Guardrail engine v1 — design & policy proposal

**Status:** implemented (observe-only)
**Posture:** detect-and-alert only — no blocking (locked policy decision, 2026-07-21;
AMENDED 2026-07-22 to "observe + endpoint blocking for
critical rules": the platform-side engine described here stays detect-and-alert only;
the amendment authorizes ENDPOINT hook blocking, specified in
`docs/inline-enforcement-design-2026-07.md` §Phase 1 and policy'd in
`policies/guardrail/v1/core.yaml` → `settings.enforcement`)

## What this is

Policy-as-code evaluation over the canonical AI usage event stream
(`packages/schema`, v1). Rules live in the repo at `policies/guardrail/v1/`,
are validated in CI, and every change goes through PR review. The engine
(`services/guardrail/`) consumes events post-ingest and emits structured
**finding** events; it never blocks, redacts, or stores content.

**Boundary the design enforces:** engineering owns the *mechanism*; Security
own the *content*. The shipped ruleset is explicitly marked as a proposal —
thresholds, allowlists, and severities need Security sign-off before they
are treated as enforced policy.

## Architecture

```
collectors/proxy ──► ingest API ──► queue ──► guardrail evaluator ──► findings ──► Sentinel
                                                            │ └── dashboard findings view
                                                            └──► audit log (append-only, every decision)
```

- **Streaming, post-ingest.** The evaluator is a single consumer today
  (`guardrail evaluate --events -` on stdin). Measured eval latency at pilot
  scale: **~0.1 ms per event** in-process — the < 1 minute event-to-finding
  budget is dominated by ingest/queue plumbing, not evaluation.
- **Stateless match rules + stateful threshold rules.** Threshold rules keep
  per-group sliding windows in memory (`user_ref`-keyed, edge-triggered so one
  crossing = one finding, refire only after the window drops below threshold).
  The state interface is two methods; it moves to Redis/Postgres when volume
  requires horizontal scale. Not needed at 700-endpoint pilot scale.
- **Every policy decision is logged.** Per (event, rule) an audit record is
  written: `fired | clear | error`, ruleset version, and `policy_hash`
  (SHA-256 of the ruleset content) so any finding traces back to the exact
  policy revision that produced it. Findings and audit records are NDJSON,
  append-only — the sink becomes the immutable audit store.
- **Metadata-only by construction.** Findings carry event ids, detector names,
  pseudonymized refs (`user_ref`, `host_ref`, `repo_ref`), and rule-match
  details. There is no code path that can attach prompt/response content —
  the canonical schema's `additionalProperties: false` rejects such events at
  ingest, and the engine only reads schema fields.

## Rule DSL (v1)

YAML, one or more files per ruleset directory. Two rule types:

- `match` — stateless condition tree over event fields (`all`/`any`, one
  nesting level). Ops: `eq, neq, in, not_in, contains, contains_detector,
  gt, gte, lt, lte`, plus settings-aware `not_in_approved_providers_for`,
  `in_off_hours`, `in_restricted_repos`,
  `mcp_call_to_unapproved_server`, `tool_call_action_class_in`, and
  `configured_mcp_server_unapproved`.
  **ABAC attribute leaves:** `attr: user|group|repo_class|tool`
  with ops `eq|neq|in|not_in` — see `docs/guardrail-abac-conditions.md`.
- `threshold` — sliding-window aggregation: `group_by` fields, `window_seconds`,
  `metric` (`count`, `sum_tokens`, `sum:<field>`), optional `filter` condition
  tree, fires on `gt`/`gte` crossing.

`contains_detector` matches `match_flags[]` entries by detector name, with
`prefix:*` glob — this is how secret/PII/policy detector outcomes drive rules
without any matched content leaving the endpoint.

## v1 rule set (PROPOSAL — awaiting Security approval)

| Rule | Type | Severity | Signal |
|---|---|---|---|
| `unapproved-tool` | match | high | `tool not_in approved_tools` (was `tool==other` only) |
| `unapproved-provider-or-model` | match | high | provider outside per-tool approved matrix, or `policy:unapproved-domain/provider` detector |
| `model-provider-not-permitted` | match | high | model/provider outside scoped allowlist |
| `restricted-repo-access` | match | critical | `repo_ref` matches `settings.restricted_repos` (HMAC + `AIM_HASH_SALT`; **inert until list+salt** — labelled) |
| `secret-pattern-in-prompt` | match | critical | `secret:*` detector fired (boolean only, never content) — 60-day security-win candidate |
| `pii-in-prompt` | match | low (warning tier) | `pii:*` detector fired — surfaces PII in findings, not just aggregates |
| `injection-attempt-in-prompt` | match | medium | `injection:*` detector fired — prose-class; expect defensive-discussion FPs |
| `unapproved-mcp-server` | match | high | MCP call outside `approved_mcp_servers` (empty = **deny-unlisted**, discovery closed) |
| `shell-tool-restricted-repo` | match | high | shell tool_call against restricted repo (**inert until list+salt**) |
| `network-tool-restricted-repo` | match | medium | network tool_call against restricted repo (**inert until list+salt**) |
| `unapproved-mcp-server-configured` | match | medium | inventory configured MCP outside allowlist (deny-unlisted) |
| `credential-shaped-tool-call` | match | high | tool_name matches credential-shaped substrings (metadata only) |
| `high-volume-repo-egress` | threshold | high | network tool_calls per repo/hour > 5 |
| `bulk-shell-hourly` | threshold | medium | shell tool_calls per user/hour > 250 |
| `high-volume-repo-tokens` | threshold | medium | tokens per repo/hour > 50M |
| `anomalous-volume-hourly` | threshold | medium | user > 500k tokens (in+out) in 1h |
| `off-hours-bulk-usage` | threshold | medium | user > 100 events in 24h during off-hours (20:00–07:00 local) |

Precision scorecard (28k-event corpus): `docs/aim-441-ruleset-precision.md`.

Open items for Security (not decided by engineering):

1. Approve/adjust the sanctioned provider matrix (`settings.approved_providers`).
2. **** MCP inventory found **0** servers in the pilot corpus.
   `mcp_allowlist_mode: deny_unlisted` with empty `approved_mcp_servers` is the
   formal proposal (deny all until Security adds servers by PR). Sign off or
   supply an approved seed list.
3. **** `restricted_repos` + `enforcement.restricted_repo_paths` are
   Security-populated (policy-as-code). Company-wide `AIM_HASH_SALT` must be set
   on guardrail + collectors (env/managed config; never commit). Until salt is set
   the restricted-repo family is **labelled inert** in the Rules dashboard.
4. Approve volume/off-hours/shell/repo thresholds after pilot triage.
5. Confirm off-hours definition with works-council guidance before any alert
   routing beyond the security team.
6. Decide finding severity → Sentinel routing (with).
7. asked for a "warning" severity on `pii-in-prompt`; it shipped as
   `low`. A distinct `warning` level would be a taxonomy change — Security's call.

## Rules transparency

The active ruleset is visible in the app without repo access:

- `GET /api/guardrail/rules` (security-group gated, same as `/api/findings`)
  reads the policy YAML from disk on every request and returns the rules,
  settings, a human-readable rendering of each condition/threshold, the
  engine-identical content hash (sha256 over the sorted raw policy files —
  matches `findings.policy_hash`), and per-rule firing counts / last-fired
  computed from the findings table (the durable firing history; engine audit
  records are streamed, not stored).
- The dashboard's **Rules** tab (`apps/web/public/rules.js`, security group
  only) renders that endpoint read-only. Tuning stays in
  `policies/guardrail/v1/*.yaml` via PR review (policy-as-code) — the viewer
  cannot drift from the loaded policy because it serves the same files.
- Finding detail in the triage console shows the firing rule's condition in
  plain language ("Why it fired") from the same endpoint.
- The humanizer (`apps/api/src/guardrail-policy.js`) mirrors the engine's
  condition ops; a new op in `conditions.py` renders as "unrecognized op"
  until mirrored there — loud, never silently wrong.

## Privacy notes (feeds DPIA pack)

- Engine input is already pseudonymized and content-free; the engine adds no
  new personal data — findings reference `user_ref`/`host_ref` hashes only.
- Off-hours analysis uses endpoint-local hour. The canonical schema does not
  carry it yet; the engine falls back to UTC hour meanwhile. **Proposal to
  ** add optional `local_hour` (int 0–23) — additive, avoids storing
  endpoint timezone while keeping off-hours detection meaningful.
- Threshold rules aggregate per `user_ref`. If the works council prefers
  team-level aggregation for volume rules, `group_by` changes to `team_ref`
  with no engine changes.

## Verification

- `services/guardrail/tests/` — unit tests including a drift guard that
  evaluates the canonical schema package's example events, and a test that
  every collector-emitted `pii:*` detector fires `pii-in-prompt`.
- `apps/api/test/guardrail-rules.test.js` — rules endpoint: security gating,
  engine-identical content hash, humanized condition/threshold text, firing
  stats from findings.
- `services/guardrail/demo/` — 7-event stream exercising every rule class:
  5 findings (see `demo/findings.ndjson`), 42 audit records
  (`demo/audit.ndjson`), max per-event eval latency 0.102 ms.
- `validate-rules` command is the CI gate for policy PRs (invalid DSL,
  duplicate rule ids, bad thresholds all fail closed).
- `scripts/tool-policy-e2e.mjs` — staging-style e2e for the
  per-tool-call rail: synthetic tool_use/inventory events through
  the real ingest API and `evaluate-db` against a scratch DB + staging
  ruleset overlay, asserting findings for `shell-tool-restricted-repo`,
  `network-tool-restricted-repo`, and `unapproved-mcp-server-configured`,
  plus webhook delivery of the new-MCP-server alert with a valid
  `X-AIM-Signature` HMAC (measurement: `docs/aim-97-tool-policy-e2e.json`).

## Not in v1 (deliberate)

- No blocking/enforcement actions (posture decision; engine has no actuation path at all).
- No regex/content scanning in the engine — detection happens at the collection point; the engine consumes boolean flags.
- No ML anomaly detection — fixed thresholds first, baseline data decides what comes next.
- No distributed state — single consumer is correct and simplest at pilot scale.

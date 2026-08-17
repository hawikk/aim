# Architecture overview

Product-facing pillar map (Gatehouse free PR-security, CNAPP link, banned
“CI/CD platform” framing): [product/stack-overview.md](./product/stack-overview.md)
and [product/gatehouse.md](./product/gatehouse.md).

## Problem

A 700+ person engineering org uses AI coding tools with no central
visibility. Security cannot answer "what are our engineers doing with AI
tools?" — and cannot detect unapproved tools or leaked secrets.

## Locked scoping decisions (amended)

- Endpoints: mostly Windows + WSL + Linux. Windows/WSL collectors are P0;
  macOS install path exists (`deploy/macos`).
- Deployment via Intune / MDM; IdP is Google Workspace (plus multi-IdP OIDC);
  SIEM is Microsoft Sentinel (CEF/webhook also supported).
- Collection: **hybrid** — proxy/network log ingestion for breadth, endpoint
  collectors (tool hooks + scan) for depth, OS egress + IdP OAuth for shadow AI.
- Sanctioned coding tools: Claude Code, Cursor, Kilo Code. Other
  first-class schema tools (e.g. `kimi_code`, `grok_build`) may be collected
  and shown in inventory while still scoring as unapproved until Security
  promotes them.
- Platform guardrail engine: **observe-only** findings (`decision: "observe"`).
  Endpoint hooks may **enforce** the managed `enforcement.json` bundle
  (secret-in-prompt block path).
- Content policy: **metadata-only** (tool, model, timestamps, token counts,
  repo/user/host pseudonyms, match flags). No prompt or code text stored.

## Path of record (single product path)

| Surface | Role |
| --- | --- |
| **`stack-aim-*` via security-stack gateway** (`https://ingest.localhost:8443` → product compose) | **Path of record** — demos, fleet truth, program metrics, dogfood |
| `aim-local-*` (`http://127.0.0.1:8080` / `:8181`) | Lab / pilot seed only — **do not** quote for fleet counts |
| Personal mode (`aim personal`) | Offline single-user SQLite dashboard; zero outbound |

Collectors should point at the product ingest (gateway or `stack-aim-ingest`).
If both stacks are running, treat dual-stack as an ops hazard: one host identity
can only heartbeat on one ingest registry at a time.

## Components (current tree)

| Component | Path | Purpose |
| --- | --- | --- |
| Platform API + dashboard API | `apps/api` | Auth (OIDC/SAML/dev), findings, fleet, coverage, governance, system status |
| Web UI | `apps/web` | Analyst console (hash-routed views: overview, fleet, security, coverage, shadow-AI, …) |
| Landing | `apps/landing` | Public product page |
| Ingest | `services/ingest` | Enroll / heartbeat / events; schema validation; Postgres + object archive |
| Guardrail | `services/guardrail` | Post-ingest policy engine → findings; SIEM/webhook notify |
| Gatehouse | `services/gatehouse` | Free PR-security pillar (Semgrep, Gitleaks, Checkov, Trivy; optional AI review) |
| Sentinel | `services/sentinel` | Alert bus consumer, triage, optional draft-PR remediation |
| Hygiene | `services/hygiene` | Full-history secret/token hygiene (not PR-diff) |
| Identity sync | `services/identity-sync` | Directory join, pseudonym resolve/reveal |
| Shadow AI | `services/shadow-ai` | IdP OAuth/SaaS grant inventory + coding-tool discovery |
| Endpoint collectors | `collectors/*` | Claude Code, Cursor, Kilo, Kimi, Grok Build, proxy, OS egress, adapter |
| CLI | `packaging/aim-cli` | `aim join` / `watch` / `doctor` / `personal` |
| Policy-as-code | `policies/guardrail`, `policies/mcp`, `policies/compliance` | Approved tools, MCP, framework map |
| Schema | `packages/schema` | Canonical event / alert / finding contracts |
| Deploy | `deploy/` | Helm, Linux/Windows/macOS install, Intune, air-gap, enforcement bundles |
| Infra | `infra/terraform`, compose | Postgres, MinIO, local/prod wiring |

## Data flow

```text
 endpoints / CI                    network / IdP
 ┌────────────────────┐           ┌──────────────────┐
 │ aim join + hooks   │           │ proxy log ingest │
 │ claude/cursor/…    │──events──▶│ os-egress        │──events──┐
 │ aim watch (user)   │  metadata │ shadow-ai IdP    │ metadata │
 └────────────────────┘  only     └──────────────────┘ only     │
        │                                                        ▼
        │              ┌────────────────────────────────────────────┐
        └─────────────▶│  services/ingest  (auth + schema + spool)  │
                       └──────────────────┬─────────────────────────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    ▼                     ▼                     ▼
             Postgres (SoR)         object store          guardrail
             events/devices         raw batches           evaluate-db
             findings                                     │
                    ▲                                     ▼
                    │                              findings + notify
             apps/api ◀──────────────────────────────┘
                    │
             apps/web + alert bus → sentinel / SIEM
```

1. Collectors and proxy pipelines emit **metadata-only** events (or match
   flags only for secrets/PII).
2. Ingest authenticates (device token or shared path), validates against
   schema (`additionalProperties: false`), writes Postgres + optional archive.
3. Guardrail evaluates events against `policies/guardrail/v1/core.yaml`.
4. Findings surface in the dashboard; high-value signals can page via the
   alert bus when destinations are configured.
5. Gatehouse and CNAPP publish onto the **same** `security.alert` bus shape
   where wired (product stack).

## Coverage & liveness

- Fleet enrollment + heartbeat: `POST /v1/enroll`, `POST /v1/heartbeat`
  (`docs/deployment/enrollment-and-heartbeat.md`).
- Collector coverage SLO (≥99% in-scope healthy): `docs/deployment/collector-coverage-slo.md`
  — surfaces on `GET /api/fleet` → `coverageSlo` and system-status when
  `SYSTEM_STATUS_ALERTS=1`.
- Pipeline idle: `GET /api/pipeline/liveness` (threshold
  `PIPELINE_IDLE_THRESHOLD_SECONDS`, default 2h).
- “What are we not seeing?”: `GET /api/coverage` / UI `#/coverage`.

## Non-goals (current product boundary)

- Multi-tenant SaaS control plane / billing (internal-only).
- Storing prompt or response content.
- Inline LLM gateway latency competition (observe-first architecture).
- Claiming live AI-reviewer quality from stub-mode eval numbers — model
  validation is a separate gate (`docs/aim-239-live-eval-2026-07-28.md`).

## Related

- Deployment rollout: `docs/deployment/rollout-plan.md`
- Privacy: `docs/privacy/data-minimization-and-pseudonymization.md`
- Blind spots: `docs/proxy-ingestion-blind-spots.md`
- Dogfood ops scripts (lab host): `~/dogfood/` (reenroll, weekly readout)

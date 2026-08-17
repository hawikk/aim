# Data Minimization & Pseudonymization — Event Schema v1

Audience: Security, Legal, works council, engineers building on the schema.
This document is the privacy rationale for `packages/schema/ai-usage-event.v1.schema.json`
and feeds the DPIA / works-council pack (AIM-29).

## Policy basis

CEO decision (AIM-15, 2026-07-21), locked in AIM-16: **metadata-only
collection**. EU / works-council scope is confirmed, so data minimization is
a launch blocker, not a nice-to-have. This schema is the technical
enforcement of that decision.

## What we collect and why

| Field | Purpose (why it is necessary) |
|---|---|
| `event_id`, `schema_version`, `timestamp`, `event_type` | Idempotent ingestion, ordering, sessionization, schema evolution |
| `source`, `collector.{name,version}` | Debugging, rollout tracking, detecting stale/insecure collectors |
| `endpoint_id`, `user_ref` | Correlate usage to a pseudonymous machine/user for security alerting and aggregate reporting. Pseudonymized — see below |
| `team` | Team-level aggregation for dashboards and chargeback-style reporting. Organizational, not personal, data; resolved from Google Workspace at ingestion |
| `tool`, `tool_version`, `provider`, `model` | Answer "which AI tools/models are in use"; detect unapproved tools/providers |
| `session_id` | Group events into sessions for usage analytics; opaque, not content-derived |
| `tokens_in`, `tokens_out`, `cost_estimate_usd`, `duration_ms` | Volume and cost analytics; anomaly detection signals (counts, not content) |
| `repo_ref` | Detect AI usage against restricted repositories. Pseudonymized hash |
| `match_flags.*` | The ONLY persisted output of content inspection — see below. v1.8 (AIM-225) adds a redacted `fingerprint` + match-location metadata to secret/pii flags so findings can be proven and deduped per secret instance |

## What we explicitly do NOT collect

- Prompt text, response text, file contents, code snippets — in any field,
  in any schema version. Enforced technically by the closed schema
  (`additionalProperties: false`): an event containing e.g. `prompt_text`
  fails validation and is rejected at ingestion. Regression-tested by
  `packages/schema/examples/invalid-content-field.json`.
- Working directory paths (`cwd_hash` from the early draft was **dropped**:
  `repo_ref` covers the restricted-repo use case; paths leak usernames and
  project names).
- Hostnames, IP addresses, usernames, email addresses anywhere in the event.
- Keystrokes, screen content, idle time, or any non-AI-tool activity.

## How content inspection works without storing content

Secret and PII detection run **at the collection point** (endpoint collector
or proxy), in memory, against content in transit. The content is never
persisted or transmitted. The only artifact that crosses the wire is a
boolean flag (`secret_pattern_match`, `pii_match`). An alert therefore says
"a secret-pattern matched in a Claude Code request from pseudonymous user X
at time T" — not what the secret was. Remediation happens out-of-band with
the engineer.

### Redacted fingerprints (schema v1.8, AIM-225)

Since v1.8, a secret/pii flag also carries a **redacted per-occurrence
fingerprint** so a finding can be *proven* and *deduped* without storing the
secret — adopted from Costa.app's secrets-detection posture (AIM-221, item
3): detect-and-prove, never detect-and-store.

- **Construction:** `HMAC-SHA256(key = company salt, "fp1" | detector |
  NFKC-folded, whitespace-stripped matched text)`, truncated to 64 bits (16
  hex chars). Keyed — never a plain hash — because low-entropy PII (emails,
  national ids) would otherwise be dictionary-invertible. The `fp1` domain
  separator prevents cross-correlation with the pseudonym HMACs
  (`user_ref`/`host_ref`/`repo_ref`) of the same string.
- **Computed and discarded at the endpoint:** the matched text exists only
  in collector memory during the scan. The fingerprint is stable while the
  company salt is unchanged, so the same secret sighted in 50 prompts
  collapses to one fingerprint; whitespace/Unicode-evasion forms of the same
  value normalize to the same fingerprint (structurally different encodings,
  e.g. base64-wrapped, intentionally do not). Salt rotation restarts dedupe
  continuity — same caveat as `repo_ref`.
- **What it is NOT:** not reversible, and not a verification oracle without
  the salt. An analyst holding only the fingerprint cannot recover the
  secret; the 64-bit truncation additionally guarantees the fingerprint
  carries at most a tiny fraction of the matched value's entropy.
- **Verification procedure (justified cases only):** to confirm a specific
  finding, an authorized analyst (security role) obtains the suspected
  content through the endpoint/EDR channel under the existing
  incident-response authorization, re-runs the collector's detector locally,
  and compares fingerprints. The platform never performs this lookup for
  you; there is deliberately no "reveal secret" code path.
- **Retention:** fingerprints introduce no new data class. They live inside
  `events.match_flags` (90-day events window) and `findings.evidence`
  (365-day findings window) and are purged by the same AIM-143 machinery,
  under the same `audit ≥ findings ≥ events` invariant. Endpoint checkpoints
  (personal mode, wire-state) store only the fingerprinted form — never the
  match — and age out with their stores.
- **Access control:** fingerprints ride the existing findings access path —
  the security group via `/api/findings` (SSO role gate); CSV export
  excludes evidence. The company salt stays in the platform KMS/secrets
  manager, security-role IAM only; a fingerprint without the salt is
  inert. The per-install fallback salt (unmanaged pilot devices) scopes
  dedupe to that device, which fails safe, not silent.
- **Fixture allowlist (AIM-541):** operators may keep an offline registry of
  fingerprints for **known cryptographically-dead** fixture secrets (secret
  corpus, dogfood dead keys). Entries are `detector + fingerprint + label +
  source` only — never raw secrets. Membership suggests incident cluster A
  (synthetic) in the findings UI. The registry is regenerated with the fleet
  `AIM_HASH_SALT` using the same `fp1|` contract; see
  `docs/security/fixture-fingerprint-registry.md`.

## Pseudonymization design

Goal: events are pseudonymous at rest; re-identification is possible only by
the security role, only for incident response, and is audited.

- **Scheme:** `HMAC-SHA256(key = company salt, message = canonical identifier)`,
  rendered lowercase hex with a type prefix:
  - `user_ref` = HMAC of the Google Workspace user ID (immutable numeric ID,
    not email, so address changes don't break correlation)
  - `endpoint_id` = HMAC of the machine GUID (Intune device ID)
  - `repo_ref` = HMAC of the normalized git remote URL
- **Salt management:** single company salt per environment, generated at
  deploy time, stored in the secrets manager (not in the repo, not in
  collector configs beyond what the endpoint needs to compute hashes).
  Access restricted to the security role via IAM. Salt rotation re-keys all
  identifiers and is treated as a breaking operational change (correlation
  across the rotation boundary is lost); rotation cadence proposed annually
  or on suspected compromise.
- **Re-identification path:** the identity-mapping service holds the
  salt and the Google Workspace directory. It exposes a narrow,
  security-role-only, fully audited lookup: `user_ref -> user`. Dashboards
  and general querying never see the mapping; they show pseudonyms or
  team-level aggregates.
- **Why not anonymous:** pure anonymity would make incident response
  impossible (we could not tell an engineer "you leaked a secret pattern").
  Salted-hash pseudonymization is the standard DPIA-friendly middle ground:
  no direct identifiers in the telemetry store, controlled and audited
  re-identification for security purposes only.

## Data-minimization review checklist applied to v1

- [x] Every field maps to a stated security/ops purpose (table above).
- [x] No direct identifiers (name, email, IP, hostname) in the schema.
- [x] No content; detection reduced to booleans computed at the edge.
- [x] `cwd_hash` dropped as redundant with `repo_ref`.
- [x] `team` is coarse organizational data, not personal.
- [x] Re-identification gated to security role + audit logging.
- [x] New fields require a privacy justification in the schema PR (see
  `packages/schema/README.md` change process).

## Retention — enforced defaults (AIM-143)

Retention is **enforced by default**, not opt-in. Every event past its
justified window is liability, not asset, so the stores age themselves out on
a schedule. Windows are per data class and configurable; the defaults below
are what ships:

| Data class | Default window | What it covers |
|---|---|---|
| `events` | **90 days** | raw usage telemetry (Postgres `events` + its bookkeeping; personal-mode SQLite; the date-partitioned `raw/` object-store batches) |
| `findings` | **365 days** | guardrail findings — a security record, kept longer than the events that produced them |
| `audit` | **730 days** | the purge audit trail itself, which must outlive what it explains |

**Ordering invariant:** `audit ≥ findings ≥ events`. A config that violates it
(e.g. an audit window shorter than the findings it describes) is **rejected**
with a clear error, and the purge fails closed — it skips the run and logs
rather than guessing a window. Same for any unparseable window.

**Boundary rule:** a row is purged iff its class timestamp is *strictly* older
than `now − window`. A row exactly at the window edge (age == window) is kept.

**Enforcement points:**
- **Server (Postgres):** a scheduled job in the ingest service deletes in
  bounded batches (no long table locks at fleet volume). FK dependents
  (`evaluated_events`, `finding_deliveries`) are removed with their parents.
  `services/ingest/src/retention.ts`.
- **Object store (MinIO/S3):** an ILM lifecycle rule expires the `raw/` batch
  prefix after the events window — the store enforces expiry itself, no sweep
  job to run or trust. Applied at ingest startup.
- **Personal mode (SQLite):** the collector prunes its local store on start and
  at most daily, using the same config surface and defaults.

**Auditability:** every server purge run writes one metadata-only record per
data class to `retention_audit` (class, window, cutoff, row count, dry-run
flag, run id) — deletions are explainable. **Blast radius:** a run can never
delete the audit records it just wrote (they are inside the audit window by
construction), and dry-run mode (`RETENTION_DRY_RUN=true`) reports what would
be deleted without deleting anything.

**Legal hold / litigation freeze does not exist yet.** There is currently no
mechanism to exempt specific records from retention for a legal hold; when a
hold is needed it must be handled operationally (out-of-band export) until the
machinery is built. Explicitly out of scope for AIM-143; tracked as a
follow-up.

Retention knobs (`RETENTION_EVENTS_DAYS`, `RETENTION_FINDINGS_DAYS`,
`RETENTION_AUDIT_DAYS`, `RETENTION_DRY_RUN`, `RETENTION_INTERVAL_HOURS`,
`RETENTION_BATCH_SIZE`) are documented in the README and `.env.example`.

## Residual risks to assess before you deploy

The mechanisms above are enforced by default, but they are not a complete
privacy assessment on their own. If you are deploying this in a jurisdiction
with employee-monitoring obligations, these are the questions a DPIA will ask
that the software cannot answer for you:

- **Aggregate windows.** Retention is enforced per data class, but if you
  enable longer team-aggregated rollups you are making a separate retention
  decision that needs its own justification.
- **Employee notice.** Pseudonymous collection still requires telling people
  what is collected. Where a works council or employee representative body
  applies, the consultation is yours to run.
- **Reveal access.** Identity reveal is a distinct capability rather than a
  role, and every reveal is audited — but who holds that capability is a
  policy decision, not a default.
- **Small cohorts.** Team-level dashboards can single out an individual when a
  team is small enough. Consider whether you need a minimum cohort size before
  aggregates are shown.

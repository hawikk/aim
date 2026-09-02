# Trust: metadata only

AIM is a security product. It is not a prompt logger. The contract below is
enforced in the event schema (`additionalProperties: false`) and in the
collectors: an event that tries to carry prompt text, tool arguments, file
contents, or plaintext identities is rejected.

This page is the public summary. The field-level rationale lives in
[data minimization](privacy/data-minimization-and-pseudonymization.md) and
the [auditor overview](privacy/auditor-privacy-overview.md).

## Personal-mode network claim

`aim personal` binds **127.0.0.1 only** and makes **zero outbound network
calls**. There is no ingest URL, no analytics beacon, no update check, and
no path that uploads prompt text or tool arguments. Verify by running it
with networking off.

The fleet path (`aim join <ingest-url>`) is opt-in and talks only to *your*
ingest. It still sends metadata-only events. There is no documented or
supported path that sends prompt bodies, tool args, URLs, or env
values off the box.

## What we collect, and why

| Class | Why it is necessary | Access |
| --- | --- | --- |
| Tool / model / provider identity | Answer "which AI tools are in use"; detect unapproved tools | Analyst dashboard; team aggregates |
| Token counts, cost estimates, timestamps | Volume, cost, anomaly signals (counts, not content) | Analyst dashboard |
| Pseudonymous `user_ref` / `host_ref` / `repo_ref` | Correlate usage to a machine/user for alerting without putting names on the wire. Salted HMAC computed **on the endpoint** | Dashboards show pseudonyms. Re-identification is a security-role-only, fully audited lookup |
| Boolean detection flags + detector name | Prove a secret/PII *pattern* matched, without storing the match | Findings; security role |
| MCP server `name` + `scope` | Inventory configured capabilities so unapproved servers are visible | MCP inventory; policy allowlist match |
| Enforcement decision metadata (`blocked` / `would_block` / …) | Audit what the endpoint did, not what it saw | Findings / usage events |

Every class maps to a security or ops purpose. New fields require a privacy
justification in the schema change.

## What we never collect

- Prompt text, response text, file contents, code snippets
- Tool-call arguments, command lines, URLs, env values (env may hold secrets)
- Emails, names, raw hostnames, IP addresses
- Keystrokes, screen content, idle time, or any non-AI-tool activity

Secret and PII detectors run **in memory** at the collection point. Matched
content is discarded immediately. Only the detector name (e.g.
`secret:aws-access-key`) is stored.

## Retention (enforced, not aspirational)

| Data class | Default window |
| --- | --- |
| Usage events | 90 days |
| Findings | 365 days |
| Audit trail | 730 days |

Ordering `audit ≥ findings ≥ events` is enforced. A config that violates it
fails closed (skip + log, never guess). Personal mode prunes its local
SQLite store on the same windows. Server purges leave a metadata-only audit
record. Knobs: `RETENTION_EVENTS_DAYS`, `RETENTION_FINDINGS_DAYS`,
`RETENTION_AUDIT_DAYS` (see `.env.example`).

There is currently no legal-hold exemption; a hold must be handled
out-of-band until that machinery exists.

## Access control

- Dashboards and general querying show **pseudonyms** or team-level
  aggregates. They cannot resolve a `user_ref` to a person.
- Re-identification (`user_ref → user`) is a **security-role-only**, fully
  audited lookup on the identity-mapping service. Reveal is a separate
  capability grant, not a default of the analyst role.
- The company salt lives in the platform secrets manager / KMS,
  security-role IAM only. A fingerprint or ref without the salt is inert.
- CSV export of findings excludes evidence payloads.
- Personal mode has no accounts: one implicit local user, loopback only.

This is the DPIA-friendly middle ground: no direct identifiers in the
telemetry store, controlled and audited re-identification for incident
response. Pure anonymity would make "you leaked a secret pattern"
impossible to say.

## Honest residual

Metadata-only does **not** mean "nothing personal can be inferred." Tool
names, MCP server names, and small-team patterns can still describe
employee activity. Mitigations are access control and aggregate
suppression, not prompt capture.

## Enforcement is not the lead, and it is not fleet-wide

The platform guardrail engine is detect-and-alert (`decision: "observe"`).
Some endpoint collectors can block **locally** when a managed
`enforcement.json` is loaded and the vendor exposes a pre-send hook. See
the [enforcement capability matrix](security/enforcement-capability-matrix.md).
A missing bundle fail-opens to observe.

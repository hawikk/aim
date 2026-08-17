# Packages

Shared libraries used by the services and apps in this repo.

| Package | What it is |
|---|---|
| [`schema/`](./schema) | `@aim/schema` — the source of truth for what the platform collects: the canonical `ai-usage-event` JSON Schema, the `security.alert/v1` publisher and consumer contract, and the `validate.py` validator plus conformance corpus that keep the metadata-only guarantee enforceable. |
| [`audit/`](./audit) | `@aim/audit` — tamper-evident append-only audit trail. Every record is hash-chained to its predecessor and HMAC-sealed, covering dashboard access, policy changes and finding lifecycle. |
| [`alerting/`](./alerting) | `@aim/alerting` — forwards guardrail findings to Microsoft Sentinel (Log Analytics ingestion), with the shared severity taxonomy and CEF rendering. |

Conventions when adding one:

- Named `@aim/<name>`, private, and consumed from source — no publish step.
- TypeScript packages typecheck with `tsc` and test with `node --test`; wired into root `pnpm test`.
- Keep runtime dependencies at zero unless justified in the PR.

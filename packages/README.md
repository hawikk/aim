# Packages

Shared libraries live here (telemetry event schema, policy engine, SIEM
connectors). None exist yet — the first ones land with the ingestion
workstream under AIM-16.

Conventions when adding one:

- Named `@aim/<name>`, private, TypeScript, built with `tsc`.
- Unit tests with `node --test`; wired into root `pnpm test`.
- Keep runtime dependencies at zero unless justified in the PR.

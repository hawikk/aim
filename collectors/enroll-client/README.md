# enroll-client — canonical fleet enroll/heartbeat client (AIM-136)

`enroll.py` here is the **single source of truth** for the fleet
enrollment + heartbeat client that runs inside every endpoint collector
(claude-code, cursor, kilo-code, kimi-code). The collectors ship as
standalone endpoint packages, so each carries a verbatim vendored copy —
the same pattern as [`../matcher-ruleset`](../matcher-ruleset).

## Workflow

1. Edit `enroll.py` in this directory — never the collector copies.
2. Run `python3 scripts/sync_enroll_client.py` to update the copies.
3. CI enforces sync (`sync_enroll_client.py --check`); the per-collector
   `tests/test_enroll.py` suites exercise the vendored copy in place.

## What the client does

- `install --ingest-url URL --enroll-token TOKEN` writes connection config,
  POSTs `/v1/enroll` with metadata only (random `host_id` UUID, hostname,
  OS string, collector version — never a hardware fingerprint), and stores
  the issued per-device token at `<state dir>/device_token` (mode 0600).
- The watch daemon (`maybe_heartbeat`) and the `heartbeat` command POST
  liveness to `/v1/heartbeat` on the same cadence
  (`DEFAULT_INTERVAL = 300s`) so the fleet coverage view can tell healthy
  devices from stale ones.
- Fails closed: every network call returns a result dict, never an
  exception — a collector must never crash the engineer's tool. On HTTP 401
  the local device token is deleted so a decommissioned/revoked device
  stops retrying.

## Why it's identical across collectors

The client depends only on each package's `__version__`, `config`, and
`state` modules, whose public interfaces (`config.ingest_url()`,
`config.config_path()`, `state.state_dir()`, `state.host_id()`,
`state.spool_path()`) are identical across the four collectors. That makes
the vendored copy byte-for-byte identical — no per-collector edits, so the
`--check` gate is a plain equality check.

Protocol reference: `docs/deployment/enrollment-and-heartbeat.md`.

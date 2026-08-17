# Runner hardening (D-C2)

Soft-path tooling for the co-located self-hosted runner. **Hard isolation requires a separate box** — see `docs/security/runner-hardening-d-c2.md`.

| Script | Purpose |
|---|---|
| `setup-networks.sh` | Create `aim-ci-isolated` (internal) + `aim-ci-jobs` |
| `isolation-proof.sh` | Negative tests: stack + sock + egress |
| `install-host.sh` | Networks + job-completed wipe hook |
| `hooks/job-completed.sh` | Wipe `GITHUB_WORKSPACE` under `_work` |
| `check-pull-request-triggers.sh` | Audit `pull_request` vs `pull_request_target` |

Related (under `deploy/runner/`): `watchdog-orphaned-job.sh` +
`install-watchdog.sh` — auto-restart `aim-ci-gce` when `busy=true` with
zero `in_progress` runs for >10 minutes. Does not change labels or use
`aim-local-hawik` as CI fallback.

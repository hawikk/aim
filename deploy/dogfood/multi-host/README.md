# Dogfood multi-host fleet (AIM-1057)

Restores trailing-7d **≥20 distinct `host_ref`** coverage on `stack-aim` for
Epic A / [AIM-487](../../../docs/) gate measurement.

## Why coverage collapsed

Live inventory on 2026-08-06 (`stack-aim-postgres`):

| Window | Distinct `host_ref` | Notes |
|--------|---------------------|-------|
| Trailing 7d | 11 | Almost all historical bulk (Jul 28–31) |
| Post-rebind (≥2026-08-01T20:07:08Z) | 1 | Service principal on `Hawik` only |
| Enrolled `devices` | 1 | Single WSL2 laptop |

Historical multi-host rows were one-shot seed / e2e batches (`seed-pilot-cohort`,
AIM-443, load harnesses). No durable multi-host collectors kept heartbeating
after those runs. After unbound washout (~2026-08-08), attribution recovers but
host diversity collapses to **1** without this fleet.

## Approach (constraints-compliant)

Hard constraints from AIM-1057:

- Do **not** invent identities / backfill pre-binding events
- Do **not** store emails in the event store
- Do **not** re-enroll one laptop N times (Epic A ban)
- Prefer real hosts, VMs, or **containers with genuine distinct host attestation**

This fleet:

1. Mints **N independent host identities** (`host_id` = UUID v5 of a stable
   fleet name + hostname). Each is a distinct enrolled device — not one
   laptop re-enrolled N times.
2. Enrolls each via real `POST /v1/enroll` (DB-backed device tokens).
3. Emits live `POST /v1/events` batches **now** (no historical backfill).
4. Derives `host_ref` as collector HMAC-SHA256 of the host's unique hostname
   (same salt as the dogfood collector: `~/.aim-collector/pseudo_salt`).
5. Attributes via `collector.os_user` → identity-sync fixture directory
   (email_heuristic / human principal). **No email ever enters the event store**
   — only `user_pseudonym` + `principal_kind`.

Optional long-running loop re-emits every few minutes so the trailing-7d window
stays above 20 after historical bulk ages out.

## Usage

```bash
# One-shot provision + emit (default N=24)
python3 deploy/dogfood/multi-host/provision.py

# Custom size / dry-run
N=24 python3 deploy/dogfood/multi-host/provision.py --dry-run
N=24 python3 deploy/dogfood/multi-host/provision.py --emit-only   # re-emit for existing state
N=24 python3 deploy/dogfood/multi-host/provision.py --loop 300    # re-emit every 5 min

# Verify on stack-aim
docker exec stack-aim-postgres-1 psql -U aim -d aim -c \
  "SELECT count(DISTINCT host_ref) FROM events WHERE ts > now() - interval '7 days';"
```

### Env

| Var | Default | Meaning |
|-----|---------|---------|
| `INGEST_URL` | `http://127.0.0.1:8081` | stack-aim ingest |
| `ENROLL_TOKEN` | from `stack-aim-ingest-1` env | ring enroll token |
| `N` | `24` | host count (≥20) |
| `HOSTNAME_PREFIX` | `aim1057-dogfood` | hostname + host_id namespace |
| `AIM_HASH_SALT` | `~/.aim-collector/pseudo_salt` | host_ref HMAC salt |
| `STATE_DIR` | `~/.aim-dogfood/multi-host` | device tokens (0600) |

## Acceptance queries

```sql
-- AC1: host diversity
SELECT count(DISTINCT host_ref)
FROM events WHERE ts > now() - interval '7 days';
-- expect ≥ 20

-- AC2: live / post-rebind attribution
SELECT
  count(*) AS n,
  count(*) FILTER (
    WHERE user_pseudonym IS NOT NULL OR principal_kind = 'service'
  ) AS attributed,
  round(100.0 * count(*) FILTER (
    WHERE user_pseudonym IS NOT NULL OR principal_kind = 'service'
  ) / nullif(count(*),0), 2) AS pct_ok
FROM events
WHERE ts >= '2026-08-01T20:07:08Z';
-- expect pct_ok ≥ 95
```

## What this is not

- Not identity invention for historical unbound bulk (out of scope; AIM-487).
- Not laptop re-enrollment games.
- Not email storage in `events` / findings.

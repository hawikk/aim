# Backup and restore runbook (AIM-98)

Covers both deployment shapes: docker compose (single host) and Helm
(Kubernetes). Commands are given for both; pick the block that matches your
deployment.

## What is precious

| Data | Where | Why |
| --- | --- | --- |
| **Postgres** | `pgdata` volume / DB PVC | System of record: telemetry metadata, policies, audit trail, findings, enrollments. Lose this and you lose the platform's history. |
| **MinIO bucket** | `minio-data` volume / object-store PVC | Raw event batches under `raw/` (see `docs/deployment/raw-batch-archival.md`) — the byte-exact forensics/replay copy. |
| **Config/secrets** | `.env`, helm values, tokens, `AIM_HASH_SALT` | Needed to make a restored stack *the same* stack. The salt especially: pseudonymized joins depend on it (AIM-78). Store in your secrets manager, not in the backup dir. |

**Not precious:** container images and the Helm chart — rebuildable from source
or re-transferable via the air-gap bundle. Never waste backup capacity on them.

## Backup

### Postgres (pg_dump, custom format)

Compose:

```sh
docker compose exec -T postgres \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --no-owner \
  > "backups/aim-pg-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

Helm (adjust release/namespace/container names to your chart):

```sh
kubectl exec -n aim deploy/aim-postgres -- \
  pg_dump -U aim -d aim --format=custom --no-owner \
  > "backups/aim-pg-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

Custom format (`-Fc`) is compressed, supports selective restore, and is the
format `pg_restore` parallelizes.

### MinIO bucket

Mirror the bucket with `mc` (runs anywhere that can reach the endpoint):

```sh
mc alias set aim "$OBJECT_STORE_ENDPOINT" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"
mc mirror --preserve aim/"$MINIO_BUCKET" "backups/minio/$MINIO_BUCKET/"
```

On Kubernetes, run this from a cron job or any host with network access to the
object-store service; on AWS this maps to S3 replication or a periodic
`aws s3 sync`.

### Schedule and retention

Cron example (nightly 02:15 UTC, compose host):

```cron
15 2 * * * cd /opt/aim && docker compose exec -T postgres pg_dump -U aim -d aim -Fc --no-owner | gpg --batch --yes -e -r backups@corp.local > backups/aim-pg-$(date -u +\%Y\%m\%dT\%H\%M\%SZ).dump.gpg
45 2 * * * mc mirror --preserve aim/aim-telemetry backups/minio/aim-telemetry/
```

Retention suggestion (proposal, not policy): **daily for 14 days, weekly for
8 weeks, monthly for 12 months** — e.g. via `restic`/`borg` or simple
date-based pruning (`find backups -name 'aim-pg-*.dump*' -mtime +14 -delete`
for the dailies).

### Encryption at rest

The dump contains pseudonymized-but-sensitive metadata (repo refs, tool usage
patterns, policy state). Pseudonymization is not anonymization — with the salt
or enough context it re-identifies. Therefore:

- Encrypt dumps at rest: `gpg -e -r <backup-recipient>` as above, or age, or
  your storage-side encryption (SSE-KMS on S3, encrypted volumes).
- Restrict access to the backup location like you restrict the database itself.
- Keep `AIM_HASH_SALT` in a secrets manager **separate** from the dumps, so a
  backup leak alone does not enable re-identification.

## Restore

Into a **fresh** stack (compose or helm — start the stack first so postgres is
up and empty, ingest migrations applied or about to be):

```sh
# 1. Stop writers so nothing inserts during restore:
docker compose stop ingest guardrail api
# helm: kubectl -n aim scale deploy/aim-ingest deploy/aim-guardrail deploy/aim-api --replicas=0

# 2. Restore Postgres (drop and recreate the DB for a clean slate):
docker compose exec -T postgres dropdb -U aim --if-exists aim
docker compose exec -T postgres createdb -U aim aim
gpg -d backups/aim-pg-20260722T021500Z.dump.gpg | \
  docker compose exec -T postgres pg_restore -U aim -d aim --no-owner
# helm: same pipeline via kubectl exec -i ... pg_restore -U aim -d aim --no-owner

# 3. Restore the object store:
mc mirror --preserve "backups/minio/$MINIO_BUCKET/" aim/"$MINIO_BUCKET"

# 4. Restart writers:
docker compose start ingest guardrail api
# helm: kubectl -n aim scale deploy/... --replicas=1
```

`pg_restore` into an existing schema is idempotent-safe if the DB is empty;
if in doubt, drop/recreate as above. Ingest re-applies migrations on boot
(`node dist/migrate.js`), which is harmless on an already-migrated schema.

### Verification

```sh
# Row counts — compare against the pre-incident numbers:
docker compose exec -T postgres psql -U aim -d aim -c \
  "SELECT count(*) AS events FROM events;"

# Latest event timestamp — should match roughly the backup time, not today:
docker compose exec -T postgres psql -U aim -d aim -c \
  "SELECT max(received_at) AS latest_event FROM events;"

# Findings/audit sanity:
docker compose exec -T postgres psql -U aim -d aim -c \
  "SELECT count(*) FROM evaluated_events;"

# Object store:
mc ls --recursive aim/"$MINIO_BUCKET"/raw/ | tail -5
```

Then open the dashboard and confirm recent history renders. If `max(received_at)`
is older than expected, you restored an old dump — check the filename date.

### Restore drills

A backup you have never restored is a rumor.

**Automated correctness proof (CI + local, AIM-291):**

```sh
./scripts/backup-restore-proof.sh
```

This spins two throwaway Postgres containers, seeds representative
events/findings/retention_audit rows plus a filesystem object-store tree,
`pg_dump -Fc` + mirrors `raw/`, destroys the source, restores into a clean
DB/dir, and asserts matching counts, a retention_audit sample hash, and the
`schema_migrations` ledger. CI runs it on every PR.

**Automated pilot drill with measured RTO/RPO (AIM-598):**

```sh
# Write a durable drill log under docs/deployment/drills/ and keep work dir:
mkdir -p docs/deployment/drills
DRILL_LOG_DIR=docs/deployment/drills KEEP_PROOF_DIR=1 \
  ./scripts/backup-restore-drill.sh
```

Same recovery path as the proof script, plus:

| Measurement | Definition |
| --- | --- |
| **RTO** | Wall-clock from incident (source destroyed) → all integrity checks pass |
| **RPO** | Backup age at incident (`incident_epoch - backup_epoch`); continuous drills are near-zero. Operational pilot RPO is the backup *schedule* (nightly → 24h). |

The script exits non-zero if integrity checks fail or measured RTO/RPO exceed
the pilot budgets (`PILOT_RTO_SECONDS` default 28800 / 8h, `PILOT_RPO_SECONDS`
default 86400 / 24h). On failure, file an issue under the deploy-maturity epic
with the `drill_id` and attach the log under `docs/deployment/drills/`.

**Quarterly operator drill (proposal):** still restore into a scratch *compose*
stack (not just throwaway Postgres) on a host with no production access,
including the verification queries above, and append the result next to the
automated drill log. The automated drill proves the restore *mechanism* and
technical RTO; the operator drill proves the runbook end-to-end.

## Disaster recovery targets (proposals, not policy)

These are starting points for the Security/Legal/product conversation, not
commitments:

| Tier | Proposal | Rationale |
| --- | --- | --- |
| **RPO** | 24 h (nightly backup) | Telemetry is observability data, not financial records; a day of lost events is annoying, not catastrophic. Tighten to 4–6 h (WAL archiving / more frequent dumps) if audit findings become compliance-critical. |
| **RTO** | 8 business hours | Restore is a scripted `pg_restore` + `mc mirror` measured in minutes-to-an-hour for realistic volumes; the slack covers detecting the incident, provisioning the fresh stack, and the restore drill being someone's second task of the day. |

Note the interplay with raw-batch archival: because every accepted batch also
lives in the object store, a Postgres-loss-with-MinIO-intact scenario can be
replayed from `raw/` (see raw-batch-archival.md), which can beat the pg_dump
RPO for the events table alone. The audit/policy tables have no such second
copy — pg_dump is their only lifeline.

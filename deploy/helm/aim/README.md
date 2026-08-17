# aim — AI Monitoring platform Helm chart

Full-stack install: Postgres, MinIO, ingest, guardrail evaluator, and the
dashboard (apps/api serving the bundled web UI). Migrations run as a
post-install/pre-upgrade hook job from the ingest image, so the schema always
matches the deployed release (roll-forward only — see
`docs/deployment/upgrades.md`).

## Quick start (throwaway cluster)

```sh
kind create cluster --name aim-dev
# build images from the repo root, then load them:
docker build -f services/ingest/Dockerfile    -t aim/ingest:0.1.0 .
docker build -f apps/api/Dockerfile           -t aim/api:0.1.0 .
docker build -f services/guardrail/Dockerfile -t aim/guardrail:0.1.0 .
kind load docker-image aim/ingest:0.1.0 aim/api:0.1.0 aim/guardrail:0.1.0 --name aim-dev

helm install aim deploy/helm/aim -f deploy/helm/aim/values-dev.yaml
kubectl port-forward svc/aim-api 8081:8080
API_URL=http://localhost:8081 node scripts/smoke.js
```

## Deployment shapes

| Values file | Shape |
| --- | --- |
| `values.yaml` (default) | Single-node, documented local-only credentials — dev only (`security.allowInsecureDefaults: true`) |
| `values-dev.yaml` | Throwaway cluster: no persistence, smallest footprint |
| `values-standard.yaml` | On-prem production: persistence, replicas, in-app OIDC SSO (`api.oidc`); **fail-closed** on local-only secrets / authDev / public data stores |
| `values-enterprise.yaml` | Multi-AZ enterprise: topologySpread + anti-affinity, NetworkPolicies, external Postgres/S3, PDBs + limits; same fail-closed posture |
| `values-airgapped.yaml` | Offline: `imagePullPolicy: Never` / internal registry; same fail-closed posture; use with `deploy/airgap/install-offline.sh` |

Security defaults audit and residual risks:
`docs/security/helm-values-security-defaults.md`.
Verify gates with `./scripts/helm-security-defaults-check.sh`.

## Upgrades

```sh
helm upgrade aim deploy/helm/aim
```

The pre-upgrade migrate job applies new migrations to existing data before
any pod rolls. Migrations are additive-only (contract in
`docs/deployment/upgrades.md`); `scripts/db-migration-rollforward.sh` proves
in CI that a previous-release database upgrades without data loss. Take a
backup first (`docs/deployment/backup-restore.md`).

## Health endpoints (consistent across services)

| Service | Liveness | Readiness | Port |
| --- | --- | --- | --- |
| ingest | `GET /healthz` | `GET /readyz` (checks Postgres + object store) | 8080 |
| api | `GET /api/health` | `GET /api/health` (unauthenticated by design) | 8080 |
| guardrail | `GET /healthz` | `GET /readyz` (503 until first poll tick succeeds; fail-closed) | 8090 |
| minio | `GET /minio/health/live` | `GET /minio/health/ready` | 9000 |
| postgres | `pg_isready` (exec) | `pg_isready` (exec) | 5432 |

## Air-gapped install

`deploy/airgap/build-bundle.sh` produces `aim-airgap-<version>.tar.gz`
(images + this chart + offline installer + manifest). Sign with
`deploy/airgap/sign-bundle.sh` (or `AIM_AIRGAP_SIGNING_KEY=...` during build)
and verify offline with `deploy/airgap/verify-bundle.sh` **before** unpack
. See `docs/deployment/air-gapped-install.md`.

## Secrets

The chart generates one Secret from `secrets.*` values. For anything beyond
a throwaway cluster, create your own and set `secrets.existingSecret`.

Required keys:

- `POSTGRES_PASSWORD`, `DATABASE_URL`
- `OBJECT_STORE_ACCESS_KEY`, `OBJECT_STORE_SECRET_KEY`
- `INGEST_TOKENS`, `ENROLL_TOKENS`
- `AIM_HASH_SALT`, `AIM_SESSION_SECRET`
- `AIM_OIDC_CLIENT_SECRET` (when `api.oidc.issuer` is set)

`values-standard.yaml` / `values-airgapped.yaml` set
`security.allowInsecureDefaults: false`, so `helm template` / install refuse
empty secrets, the documented local-only placeholders, missing OIDC, and
`api.authDev=true`. Prefer `secrets.existingSecret` over putting production
credentials in values files.

### Production sketch

```sh
helm upgrade --install aim deploy/helm/aim \
  -f deploy/helm/aim/values-standard.yaml \
  --set secrets.existingSecret=aim-prod-secrets \
  --set api.oidc.issuer=https://accounts.example.com \
  --set api.oidc.clientId=aim-dashboard
```

## High availability (pilot)

`values-standard.yaml` sets `ingest`/`api`/`guardrail` to 2 replicas and enables
PodDisruptionBudgets (`podDisruptionBudgets.enabled=true`). HA kill-drill
evidence: and `scripts/ha-smoke.sh`.
Security defaults audit: `docs/deployment/helm-security-defaults-audit.md`.

## Enterprise multi-AZ

`values-enterprise.yaml` adds zone topology spread, node anti-affinity,
NetworkPolicies (default-deny + allowlist), and **external** Postgres + object
store (`postgres.enabled` / `minio.enabled` false + `secrets.existingSecret` +
`objectStore.endpoint`). Operator guide:
`docs/deployment/enterprise-topology.md`. Proofs (no billable cloud):

```sh
./scripts/topology-failover-proof.sh # helm render + optional compose HA/RTO
./scripts/topology-render-proof.sh # helm-only subset
`docs/deployment/enterprise-topology.md`. Render proof (no cluster):

```sh
./scripts/topology-render-proof.sh
```

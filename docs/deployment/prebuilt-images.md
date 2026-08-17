# Prebuilt control-plane images

Cold `docker compose up --build` on a clean host is typically **10–20 minutes**
and is the dominant term in pilot time-to-green. It also flakes on low disk or
RAM. This document is the **pull path**: use versioned images from GHCR (or an
air-gap release bundle) so `install-pilot` prefers download over source build.

**Acceptance target:** pilot on a clean host with Docker already installed —
cold path **≤ 15 minutes** when images are available.

---

## What is published

Workflow: `.github/workflows/release-images.yml`

| Image (GHCR) | Source Dockerfile | Pilot role |
| --- | --- | --- |
| `ghcr.io/hawikk/aim-ingest` | `services/ingest/Dockerfile` | Ingest API (`:8080`) |
| `ghcr.io/hawikk/aim-api` | `apps/api/Dockerfile` | **Dashboard + read API** (`:8081`) |
| `ghcr.io/hawikk/aim-guardrail` | `services/guardrail/Dockerfile` | Post-ingest evaluator |
| `ghcr.io/hawikk/aim-identity-sync` | `services/identity-sync/Dockerfile` | Required by ingest health |

There is **no separate dashboard image** — the web UI is served by `aim-api`.

Also published (not required for the minimum pilot set; omitted by
`deploy/compose/docker-compose.pilot.yml`):

| Image | Notes |
| --- | --- |
| `aim-gatehouse` | PR-security pillar |
| `aim-sentinel` | Alerting / SIEM |
| `aim-hygiene` | Scanner + hygiene-cron |

### Tags (no floating `latest`)

| Event | Tag shape | Example |
| --- | --- | --- |
| Push to `main` / `workflow_dispatch` | `main-<shortsha>` | `main-498275d` |
| Push tag `v*` | the tag name | `v1.4.0` |

Immutable tags only. A mutable `latest` would let the verified artifact and the
runtime image drift — the opposite of the supply-chain property this product
sells. Images are **cosign-signed** (keyless) and carry build provenance
attestations; see `docs/adr-supply-chain-slsa.md`.

**Operator pin rule:** only use a `main-<shortsha>` from a **green**
`release-images` run whose summary lists **all four** pilot images
(`aim-ingest`, `aim-api`, `aim-guardrail`, `aim-identity-sync`). A cancelled or
partial matrix (historically: ingest cancelled while siblings pushed) is not a
valid pin — wait for the next fully green run, or re-run via
`workflow_dispatch` on `main`.

Publishing notes:

- `release-images` does **not** cancel in-flight `main` / tag / dispatch runs
  (only PR dry-builds cancel). That keeps the slow `aim-ingest` cell from
  being aborted mid-push when another commit lands on `main`.
- Matrix `max-parallel` is capped (currently 2) so a multi-ops-host future
  cannot OOM-kill the heavy `aim-ingest` Build-and-push step (historical
  failure: runner lost communication on CI run `31282707057`).

Third-party images (Postgres, MinIO, Redis) remain the pins already in
`docker-compose.yml` and are pulled from their public registries (or from the
air-gap bundle).

---

## Operator path A — GHCR pull (online pilot)

### 1. Prerequisites

- Docker Engine + Compose v2 plugin  
- Network access to `ghcr.io`  
- If packages are private: a token with `read:packages` and

```bash
echo "$GHCR_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USER --password-stdin
```

### 2. Choose a tag or digests

From the latest green **release-images** run on `main` (Actions → summary
table), copy either:

- the `main-<shortsha>` tag (same tag for every pilot image), or  
- each image's `sha256:…` digest (preferred for enterprise)

### 3. Pin file (recommended)

```bash
cp deploy/compose/images.pin.env.example deploy/compose/images.pin.env
# edit: set AIM_IMAGE_TAG=main-<shortsha>
#   or set AIM_*_IMAGE=ghcr.io/hawikk/aim-…@sha256:… for each service
```

### 4. Install (prefer pull)

```bash
git clone https://github.com/hawikk/aim.git
cd aim
# optional: set -a; . deploy/compose/images.pin.env; set +a
export AIM_IMAGE_TAG=main-<shortsha>   # if not using digest pins

./scripts/install-pilot.sh --pull
# or default prefer-pull (falls back to --build if pull fails):
# ./scripts/install-pilot.sh
```

What this runs under the hood:

```text
docker compose \
  -f docker-compose.yml \
  -f deploy/compose/docker-compose.pilot.yml \
  -f deploy/compose/docker-compose.pull.yml \
  pull && up -d
```

- **pilot.yml** — skips gatehouse / sentinel / hygiene-cron / shadow-ai so they
  are not cold-built.  
- **pull.yml** — sets `image:` to GHCR refs and clears `build:` with
  `build: !reset null` (required on Compose v2).

### 5. Verify

```bash
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/health
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8081/health
docker compose -f docker-compose.yml -f deploy/compose/docker-compose.pilot.yml ps
```

---

## Operator path B — Air-gap / release bundle

When the pilot host has **no** GHCR egress, use the existing offline bundle
(same three app images + third-party pins):

```bash
# Connected build host
deploy/airgap/build-bundle.sh 1.4.0
# Transfer deploy/airgap/out/aim-airgap-1.4.0.tar.gz (+ signatures)

# Air-gapped target
tar -xzf aim-airgap-1.4.0.tar.gz && cd aim-airgap-1.4.0
./install-offline.sh
```

Full procedure: [`air-gapped-install.md`](./air-gapped-install.md).

---

## Digest pin procedure (supply chain)

Prefer **digest references** over tags for any shared or long-lived pilot.

### Resolve digests

From a release-images workflow summary, copy the digest column, **or**:

```bash
# Requires auth if the package is private
crane digest ghcr.io/hawikk/aim-api:main-498275d
# → sha256:abc…

# Or:
docker buildx imagetools inspect ghcr.io/hawikk/aim-api:main-498275d \
  --format '{{.Manifest.Digest}}'
```

### Write pins

```bash
# deploy/compose/images.pin.env
AIM_INGEST_IMAGE=ghcr.io/hawikk/aim-ingest@sha256:…
AIM_API_IMAGE=ghcr.io/hawikk/aim-api@sha256:…
AIM_GUARDRAIL_IMAGE=ghcr.io/hawikk/aim-guardrail@sha256:…
AIM_IDENTITY_SYNC_IMAGE=ghcr.io/hawikk/aim-identity-sync@sha256:…
```

### Optional: verify cosign signature

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/hawikk/aim/\.github/workflows/release-images\.yml@' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/hawikk/aim-api@sha256:…
```

Record the four digests (and cosign output) in the change ticket for the pilot.

### Compose-level pin

`deploy/compose/docker-compose.pull.yml` reads `AIM_*_IMAGE` directly. When
those values contain `@sha256:…`, Compose pulls that exact manifest; retagging
the movable tag later cannot change what runs.

---

## Contributor path — source build still works

Developers iterating on Dockerfiles or unreleased code:

```bash
./scripts/install-pilot.sh --build
# equivalent core:
docker compose -f docker-compose.yml -f deploy/compose/docker-compose.pilot.yml up -d --build

# Full local stack (all pillars), original path:
docker compose up -d --build
# or: make dev
```

`--build` never requires GHCR credentials. Prefer-pull mode automatically falls
back to build when no tag/pin is configured or when pull fails.

---

## Env reference

| Variable | Purpose |
| --- | --- |
| `AIM_PILOT_IMAGE_MODE` | `prefer-pull` (default), `pull`, `build` |
| `AIM_IMAGE_TAG` | Shared tag for all pilot images (`main-<sha>` / `v*`) |
| `AIM_IMAGE_REGISTRY` | Default `ghcr.io/hawikk` |
| `AIM_INGEST_IMAGE` | Full ref (overrides tag for ingest) |
| `AIM_API_IMAGE` | Full ref for api/dashboard |
| `AIM_GUARDRAIL_IMAGE` | Full ref for guardrail |
| `AIM_IDENTITY_SYNC_IMAGE` | Full ref for identity-sync |
| `AIM_PULL_POLICY` | Compose pull_policy for app services (`always` default on pull path) |
| `AIM_IMAGE_PIN_FILE` | Alternate path to pin env file |
| `AIM_BIND_ADDR` | Default `0.0.0.0` in install-pilot (remote collectors) |
| `AIM_DATASTORE_BIND_ADDR` | Default `127.0.0.1` |

---

## Files

| Path | Role |
| --- | --- |
| `scripts/install-pilot.sh` | Prefer-pull install entrypoint |
| `deploy/compose/docker-compose.pull.yml` | GHCR image override + `build: !reset` |
| `deploy/compose/docker-compose.pilot.yml` | Drop non-pilot pillars from default up |
| `deploy/compose/images.pin.env.example` | Pin template |
| `.github/workflows/release-images.yml` | Build, push, sign, attest |
| `deploy/airgap/build-bundle.sh` | Offline bundle alternative |

---

## Related

- [`self-host-quickstart.md`](./self-host-quickstart.md) — laptop demo (`demo-stack-up.sh`)  
- [`air-gapped-install.md`](./air-gapped-install.md) — offline media

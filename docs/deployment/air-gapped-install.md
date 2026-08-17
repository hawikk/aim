# Air-gapped install

How to install the AI Monitoring platform on a host or cluster with **no
internet access** — the common case in enterprises where outbound egress is
blocked and every artifact crosses the air gap on approved media.

The unit of transfer is a single tarball, `aim-airgap-<version>.tar.gz`, built
on a connected machine by `deploy/airgap/build-bundle.sh` and installed on the
target by the bundled `install-offline.sh`.

## Bundle contents

| Entry | Purpose |
| --- | --- |
| `images.tar` | All container images (`docker save`): the three app images (`aim/ingest`, `aim/api`, `aim/guardrail`, tagged with the bundle version) plus the exact third-party images pinned in `docker-compose.yml` (postgres, **redis-bus**, minio, minio/mc) |
| `docker-compose.yml` + `env.example` | The pinned compose stack, for docker-based targets without Kubernetes |
| `docker-compose.airgap.yml` | Generated override: pins app image tags, forces `pull_policy: never`, and clears `build:` with `!reset` (Compose v2) |
| `chart/aim/` | The Helm chart, copied as-is from `deploy/helm/aim` at bundle time |
| `install-offline.sh` | Target-side installer: loads images, optionally pushes to an internal registry, emits/runs the pinned `helm upgrade --install` |
| `MANIFEST.txt` | Image list with sizes + sha256 of every file in the bundle |
| `README-airgap.md` | This document |

**Alongside the tarball** (not inside it), production releases also ship
Ed25519 signature companions — see [Sign the bundle](#sign-the-bundle-required-for-production-air-gap--aim-747):
`.sha256`, `.sig`, `.sha256.sig`, `.sigmeta.json`.

SSO is terminated in-app by the API (OIDC); no `sso-proxy`
(oauth2-proxy) is bundled. Point `api.oidc` at the site-internal IdP —
air-gapped environments typically run one anyway. Client-supplied identity
headers are never trusted.

## Building the bundle (connected machine)

```sh
# From the repo root. Version defaults to `git describe --tags --always --dirty`.
deploy/airgap/build-bundle.sh 1.4.0

# -> deploy/airgap/out/aim-airgap-1.4.0.tar.gz
```

Requires docker with network access. If `deploy/helm/aim` does not exist at
build time the bundle is still produced (with a warning), minus the chart —
the compose install path below then applies.

### Sign the bundle (required for production air-gap —)

Integrity alone (MANIFEST hashes) detects accidental corruption. **Signature
verification** proves the tarball came from your release pipeline and was not
swapped on the transfer medium.

```sh
# One-time: generate the release keypair (private key stays on build/CI only).
deploy/airgap/gen-signing-key.sh /secure/aim-airgap-keys
# -> aim-airgap-ed25519.pem (private)
# -> aim-airgap-ed25519.pub.pem (public — pin on targets)

# Option A — auto-sign at the end of build:
AIM_AIRGAP_SIGNING_KEY=/secure/aim-airgap-keys/aim-airgap-ed25519.pem \
  deploy/airgap/build-bundle.sh 1.4.0

# Option B — sign an existing tarball:
AIM_AIRGAP_SIGNING_KEY=/secure/aim-airgap-keys/aim-airgap-ed25519.pem \
  deploy/airgap/sign-bundle.sh deploy/airgap/out/aim-airgap-1.4.0.tar.gz
```

Signing produces, next to the tarball:

| Companion | Purpose |
| --- | --- |
| `aim-airgap-<ver>.tar.gz.sha256` | Digest of the tarball (GNU `sha256sum` line) |
| `aim-airgap-<ver>.tar.gz.sig` | Ed25519 detached signature over **full tarball bytes** |
| `aim-airgap-<ver>.tar.gz.sha256.sig` | Ed25519 signature over the `.sha256` file |
| `aim-airgap-<ver>.tar.gz.sigmeta.json` | Alg, key fingerprint, `signed_at` (not secret) |

Algorithm: **Ed25519** via OpenSSL `pkeyutl -rawin` (works fully offline; no
Rekor / cosign required on the air-gapped host). Record the public key
fingerprint (`sha256` of DER SPKI) in the change ticket.

## Transfer

Copy the **signed set** onto the approved transfer medium (USB stick,
file-drop host, artifact server) per your site process:

```
aim-airgap-1.4.0.tar.gz
aim-airgap-1.4.0.tar.gz.sha256
aim-airgap-1.4.0.tar.gz.sig
aim-airgap-1.4.0.tar.gz.sha256.sig
aim-airgap-1.4.0.tar.gz.sigmeta.json   # optional but recommended
```

**Do not** put the private key on the medium. The public key arrives on a
separate trust path (golden image, MDM, signed config, or pre-staged under
`/etc/aim/airgap-ed25519.pub.pem`).

In works-council / regulated environments, treat the bundle like any other
software import: container images + text files, no credentials — record
version, key fingerprint, and digest in the import ticket.

## Verify on the target (signature first —)

**Fail closed.** Do not unpack or run `install-offline.sh` until verify exits 0.

```sh
# Public key pre-pinned on the host (example path):
export AIM_AIRGAP_PUBKEY=/etc/aim/airgap-ed25519.pub.pem
# Optional pin from the change ticket:
export AIM_AIRGAP_KEY_FINGERPRINT=<sha256-of-der-pubkey>

# 1. Authenticity + outer integrity (before unpack):
deploy/airgap/verify-bundle.sh aim-airgap-1.4.0.tar.gz
# or: AIM_AIRGAP_PUBKEY=... ./verify-bundle.sh ./aim-airgap-1.4.0.tar.gz

# 2. Unpack only after VERIFY_OK:
tar -xzf aim-airgap-1.4.0.tar.gz
cd aim-airgap-1.4.0

# 3. Inner file hashes from the connected build (defense in depth):
grep -A9999 'Files (sha256)' MANIFEST.txt | tail -n +2 | sha256sum -c -

# Combined form (after unpack, from the parent directory that holds the tarball):
# AIM_AIRGAP_PUBKEY=... deploy/airgap/verify-bundle.sh aim-airgap-1.4.0.tar.gz \
#   --check-manifest ./aim-airgap-1.4.0
```

If any step fails (`VERIFY_FAIL`, digest mismatch, or a MANIFEST line that is
not `OK`), **stop**. Re-transfer from the signed release; do not install a
suspect medium.

### Why both outer signature and MANIFEST?

| Layer | Stops |
| --- | --- |
| Ed25519 `.sig` over tarball | Bundle swap / malicious rebuild on the USB |
| `.sha256` + `.sha256.sig` | Operators who only check a printed digest still get authenticity |
| Inner `MANIFEST.txt` hashes | Bit-rot of individual files after a partial extract |

### Drill

Re-run the offline sign/verify drill (no docker images required):

```sh
deploy/airgap/drill-sig-verify.sh
# -> docs/deployment/drills/drill-aim747-<timestamp>.md
```

## Prerequisites on the target

- **Docker path:** docker engine + compose plugin, nothing else.
- **Kubernetes path:** a reachable cluster (`kubectl` context configured),
  `helm` v3 CLI, and — strongly recommended — an internal registry the
  cluster nodes can pull from (e.g. Harbor). Without a registry, images are
  only present on the node where you run the installer; see below.

## Install path A — Kubernetes / Helm

```sh
# With an internal registry (multi-node clusters — the normal case):
REGISTRY=registry.corp.local:5000/aim ./install-offline.sh        # dry-run, prints the helm command
REGISTRY=registry.corp.local:5000/aim RUN_HELM=1 ./install-offline.sh   # actually install

# Single-node cluster, images loaded straight into the node runtime
# (pull policy forced to Never):
RUN_HELM=1 ./install-offline.sh
```

The installer:

1. `docker load`s every image from `images.tar`.
2. With `REGISTRY` set, retags each image as `<registry>/<original>` and
   pushes it.
3. Emits a `helm upgrade --install` with **every image pinned** and pull
   policy forced:
   - `--set global.imagePullPolicy=IfNotPresent` when a registry is used
     (pull once from the internal registry, never the internet), or
   - `--set global.imagePullPolicy=Never` when images are node-local (kubelet
     must never attempt a pull).
   - `--set global.imageRegistry=<registry>` when set.
   - Per image: `--set <component>.image.repository=... --set <component>.image.tag=...`
     where `<component>` is `ingest`, `api`, `guardrail`, `postgres`, `minio`,
     `minioInit`. (`redis` is loaded for the compose path but is not a Helm
     chart value — that is expected.)

Nothing in this flow touches the internet: images come from the tarball, the
chart is local, and the pull policy forbids registry fetches beyond the one
internal source you named.

Optional env: `RELEASE` (default `aim`), `NAMESPACE` (default `aim`),
`CHART_DIR` (default `./chart/aim`).

## Install path B — docker compose (single host, no cluster)

The bundle carries the exact `docker-compose.yml` from the repo **and** a
generated `docker-compose.airgap.yml` that pins the three bundled app images
and disables pulls. **Do not hand-write `build: null`** — Compose v2 keeps the
original `build:` context when merging that form; the bundle uses
`build: !reset null` instead (drill).

```sh
./install-offline.sh   # loads images.tar (helm step auto-skips without chart/)

cp env.example .env   # then edit secrets — do NOT ship the local-dev defaults

# Core offline path: only services covered by the airgap override + data plane.
# The full monorepo compose file also defines gatehouse/sentinel/hygiene/etc.
# which still have `build:` and are NOT in the offline bundle — either omit
# them with an explicit profile/core compose, or do not start those services.
docker compose \
  -f docker-compose.yml \
  -f docker-compose.airgap.yml \
  up -d postgres redis-bus minio minio-init ingest api guardrail
```

If you are on an older bundle without `docker-compose.airgap.yml`, generate
the same override (replace `1.4.0` with your bundle version):

```yaml
services:
  ingest:
    image: aim/ingest:1.4.0
    build: !reset null
    pull_policy: never
  api:
    image: aim/api:1.4.0
    build: !reset null
    pull_policy: never
  guardrail:
    image: aim/guardrail:1.4.0
    build: !reset null
    pull_policy: never
  postgres:   { pull_policy: never }
  redis-bus:  { pull_policy: never }
  minio:      { pull_policy: never }
  minio-init: { pull_policy: never }
```

Verify: `docker compose ... ps` shows the core services healthy, and the
dashboard answers on the configured `DASHBOARD_PORT`.

### Compose scope note

The offline bundle is the **core platform** (ingest + api + guardrail +
postgres + redis-bus + minio). Services such as `gatehouse`, `sentinel`,
`hygiene`, `identity-sync`, and `shadow-ai` still use `build:` in
`docker-compose.yml` and are **not** image-bundled. Operators who need those
on an air-gapped host must extend the bundle (extra `docker build` + `docker
save` on the connected side) — that is intentional product packaging, not a
silent pull.

## Upgrading an existing air-gapped install

Greenfield install and upgrade share the same offline artifacts. Schema
migrations ride inside the new ingest image and apply on start / via the Helm
pre-upgrade Job — see `docs/deployment/upgrades.md`.

### Before every upgrade

1. Confirm the new bundle's `MANIFEST.txt` checksums on the target.
2. Take a Postgres backup (and MinIO if you need object-store rollback):
   [backup-restore.md](backup-restore.md).
3. Record the running image tags and `schema_migrations` ledger for the
   post-upgrade check.

### Kubernetes / Helm

```sh
# From the untarred *new* version directory:
REGISTRY=registry.corp.local:5000/aim RUN_HELM=1 ./install-offline.sh
```

`install-offline.sh` always emits `helm upgrade --install` with every image
pinned. PVCs are left in place; the chart's pre-upgrade migrate Job applies
any new `NNN_*.sql` files before new pods serve traffic.

### docker compose

```sh
# 1. Load new images (and third-party pins) from the new bundle.
./install-offline.sh

# 2. Recreate app containers only — keep named volumes (pgdata, minio-data, alertbus).
docker compose \
  -f docker-compose.yml \
  -f docker-compose.airgap.yml \
  up -d --no-deps --force-recreate ingest api guardrail

# 3. Verify:
#    - curl -sf http://127.0.0.1:${INGEST_PORT:-8080}/healthz
#    - schema_migrations grew only by additive files
#    - pre-upgrade row counts / content hashes still match
```

Pin `PORT` / published ports consistently across releases. Older ingest
images default to container port **3000**; newer compose mappings often use
**8080**. An upgrade that changes the listen port without updating the
publish map looks like a failed upgrade (drill).

### Post-upgrade checks

- Ingest and API `/healthz` (or site equivalent) return OK.
- `SELECT id FROM schema_migrations ORDER BY id;` matches the new image's
  migration set (additive only).
- Sample business data (devices / events counts, content hash) unchanged.
- If anything fails: roll **application** tags back to the previous bundle
  (safe under the additive-migration contract); restore from backup only if
  data was corrupted — see `docs/deployment/upgrades.md` rollback.

## Troubleshooting

- **`docker load` fails / image missing later** — the tarball was truncated in
  transfer. Re-verify `sha256sum -c` against MANIFEST.txt first.
- **Pods stuck in `ImagePullBackOff`** — the cluster is trying to pull. Either
  you forgot `REGISTRY` (node-local images only exist where you loaded them;
  load the bundle on every node, or use a registry), or the pull policy didn't
  stick — confirm with `kubectl get deploy -o yaml | grep imagePullPolicy`.
- **`install-offline.sh` says the chart is missing** — the bundle was built
  before `deploy/helm/aim` existed. Rebuild the bundle from a checkout that
  has the chart, or use the compose path.
- **Registry push denied** — `docker login registry.corp.local:5000` first;
  the installer does not handle registry auth for you.
- **Clock skew on the target** — TLS and token checks get flaky; sync NTP via
  your internal time source before declaring the install broken.
- **Compose still tries to build images** — you used `build: null` (no-op in
  Compose v2 merge). Use the bundle's `docker-compose.airgap.yml` or
  `build: !reset null`.
- **`redis:7-alpine` missing offline** — rebuild the bundle from a tree that
  includes `redis-bus` in `deploy/airgap/build-bundle.sh` (post).
- **Health checks fail after upgrade but logs show the server up** — container
  listen port may have changed (3000 vs 8080). Align `ports:` mapping and
  `PORT` env with the image you just loaded.

## Backups

Once running, set up backup/restore per
[backup-restore.md](backup-restore.md) — the air gap changes nothing there
except that off-site copies stay on-site. Always take a backup immediately
before an air-gapped upgrade.

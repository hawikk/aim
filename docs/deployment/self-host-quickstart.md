# Self-host quickstart (external demo path)

**Audience:** an external engineer or small security team evaluating AI Monitoring  
**Goal:** clone → minimal config → **one command** → working dashboard  
**Time-to-green target:** ≤ 30 minutes on a clean laptop with Docker already installed  
(soft commercial self-hosted launch)

This is the supported **happy path** for the Unified Security Stack compose
layout used for AIM (and optional Gatehouse / CNAPP pointers). It is not a
production HA or multi-tenant guide.

---

## Non-goals

Explicitly **out of scope** for this document and the soft-launch demo path:

| Non-goal | Where it lives instead |
| --- | --- |
| Multi-tenant SaaS control plane / billing isolation | Cancelled / N/A (enterprise packaging notes) |
| Wiz-class CNAPP scale (10k+ cloud accounts, multi-AZ posture graph) | CNAPP enterprise track — not this demo |
| Positioning Gatehouse as a CI product / CI/CD SKU | Gatehouse is a **free PR-security pillar**, not a CI competitor |
| Production HA, multi-AZ Postgres, SSO/SAML | Enterprise later — see `enterprise-packaging.md`, `saml-sso-runbook.md` |
| Air-gapped offline media transfer | [`air-gapped-install.md`](./air-gapped-install.md) |

If you need those, stop here and open the linked runbooks — do not stretch this
demo stack into production.

---

## Prerequisites

| Requirement | Notes |
| --- | --- |
| **Docker Engine** + **Compose v2** (`docker compose`) | Desktop on macOS/Windows; Engine + plugin on Linux |
| **Python 3.11+** | Only for `scripts/ensure_dev_env.py` (stdlib + mint local secrets) |
| **~8 GB free RAM**, **~10 GB disk** for images | First `compose build` is the long pole |
| Free local ports (defaults) | `8080` ingest, `8081` dashboard, `5432` Postgres, `9000` MinIO, `8090` Gatehouse |
| Optional: `curl`, `ss` | Better preflight / health diagnostics |

No cloud account, no IdP, no paid registry credentials.

---

## Happy path (one command)

```bash
git clone https://github.com/hawikk/aim.git
cd aim

# Optional: copy sample env only if you need port overrides or custom tokens.
# Defaults in docker-compose.yml work out of the box for loopback demo.
# cp .env.example .env   # then edit ports if needed — never commit .env

./scripts/demo-stack-up.sh
```

What the script does:

1. **Preflight** — Docker daemon, Compose v2, Python, port conflicts, secret placeholders  
2. **Mint** stack-owned local secrets into gitignored `.env` (`GATEHOUSE_WEBHOOK_SECRET`, etc.) via `scripts/ensure_dev_env.py`  
3. **`docker compose up -d --build`** — Postgres, MinIO, identity-sync, ingest, guardrail, dashboard API, Gatehouse, …  
4. **Health wait** — ingest `/healthz` + dashboard `/api/health` (Gatehouse optional)  
5. **Seed** — `scripts/seed-pilot-cohort.sh` posts a deterministic 12-seat demo cohort  

Then open:

```text
http://127.0.0.1:8081
```

### Make alias

```bash
make demo-stack          # same as ./scripts/demo-stack-up.sh
make demo-stack-preflight
```

### Equivalent manual steps (if you prefer not to use the script)

```bash
python3 scripts/ensure_dev_env.py
docker compose up -d --build
# wait until these return 200:
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8081/api/health
SEED_BASE_URL=http://127.0.0.1:8080 ./scripts/seed-pilot-cohort.sh
```

---

## Production / private-network pilot

Laptop demo defaults bind **127.0.0.1** and seed fixture seats. For a private
EC2/VM pilot over NetBird/VPN use the dedicated entrypoint:

```bash
./scripts/install-pilot.sh
# sets AIM_BIND_ADDR=0.0.0.0, datastores loopback, no seed, no github-audit;
# waits for health; mints onboarding token + prints enroll one-liner
```

Equivalent manual knobs (prefer the script):

```bash
export AIM_BIND_ADDR=0.0.0.0
export AIM_DATASTORE_BIND_ADDR=127.0.0.1
./scripts/demo-stack-up.sh --no-seed
```

If a host was replaced while Docker’s data-root lived on a retained disk and
compose fails with missing snapshots or nil RWLayer, recover **without**
wiping Postgres volumes:

```bash
./scripts/demo-stack-recover.sh
# then:
./scripts/install-pilot.sh
```

## Verify the install

`ci-oneshot-pilot-smoke` checks that the one-shot install path is intact —
CLI modules present, compose file resolvable, and `aim join` always writing a
`token_file` (without it a device enrolls, heartbeats, and silently ships
nothing):

```bash
./scripts/ci-oneshot-pilot-smoke.sh
```

---

## First login / personal mode entry

With **no** `AIM_OIDC_*` variables set (compose default), the dashboard runs in
**personal / standalone mode**:

- Single local admin identity  
- No password form, no SSO redirect  
- Open `http://127.0.0.1:8081` in a browser  

This mode is **localhost-only by design**. Do not set `AIM_BIND_ADDR=0.0.0.0`
without turning on real SSO (Enterprise). Every published port already binds
`127.0.0.1` by default.

### Even lighter path (no Docker)

For **your own** AI tool usage only (no company fleet, no Postgres):

```bash
pipx install aimonitoring-security
aim personal
# → http://127.0.0.1:8787
```

See the README “personal mode” section. That path is **not** the multi-service
self-host demo; it is the free personal SKU.

---

## Health checks (what “green” means)

| Surface | URL | Expect |
| --- | --- | --- |
| Ingest | `http://127.0.0.1:8080/healthz` | HTTP 200 JSON `status: ok` |
| Dashboard API | `http://127.0.0.1:8081/api/health` | HTTP 200 JSON `status: ok` |
| Gatehouse (optional) | `http://127.0.0.1:8090/healthz` | HTTP 200 when the PR-security pillar is up |
| Compose | `docker compose ps` | `ingest`, `api` (and deps) **healthy** / **running** |

Optional deeper probes once seeded:

```bash
# Pipeline liveness (may report no_collectors until devices enroll)
curl -fsS http://127.0.0.1:8081/api/pipeline/liveness || true
```

---

## Failure modes

### 1. Missing Docker / daemon not running

**Symptom:** `Docker is not installed` or `Docker daemon is not reachable`  
**Fix:** Install Docker Desktop or Engine; start the service; confirm
`docker info` works for your user.

### 2. Missing Compose v2

**Symptom:** `docker: 'compose' is not a docker command`  
**Fix:** Install the Compose **plugin** (`docker compose version`), not only
legacy `docker-compose`.

### 3. Port conflicts

**Symptom:** script exits with `Port conflict(s) on 127.0.0.1:8080 …`  
**Fix options:**

```bash
# A) Stop the other process using the port
ss -lnt | grep -E ':(8080|8081|5432|9000|8090)'

# B) Override ports in gitignored .env
cat >> .env <<'EOF'
API_PORT=18080
DASHBOARD_PORT=18081
POSTGRES_PORT=15432
MINIO_API_PORT=19000
GATEHOUSE_PORT=18090
EOF
./scripts/demo-stack-up.sh
```

If a previous AIM stack is already healthy, the script reuses it instead of
failing.

### 4. Secret placeholders left in `.env`

**Symptom:** `Unresolved secret placeholder(s) in .env` listing key names only  
**Fix:** Replace `CHANGE_ME` / `REPLACE_ME` / `<...>` values, **or** delete those
lines and re-run so `ensure_dev_env.py` mints stack-owned secrets.

Committed sample only: **`.env.example`**. Real `.env` is gitignored. CI runs
gitleaks — never commit tokens or passwords.

### 5. Gatehouse crash-looping

**Symptom:** `gatehouse` restarts; webhook HMAC errors in logs  
**Cause:** empty `GATEHOUSE_WEBHOOK_SECRET` (fails closed)  
**Fix:** `python3 scripts/ensure_dev_env.py` then `docker compose up -d gatehouse`

### 6. Blank dashboard page

**Symptom:** browser shows blank at `:8081`  
**Checks:**

```bash
docker compose ps          # api should be Up / healthy
curl -fsS http://127.0.0.1:8081/api/health
docker compose logs --tail=100 api
```

WSL2 + Windows browser: `localhost:8081` still works (loopback forward). The
WSL eth0 IP does **not** — ports bind loopback only.

### 7. First image build is slow / times out

**Symptom:** health wait hits `HEALTH_TIMEOUT_SEC` (default 600s)  
**Fix:** re-run after images exist (`./scripts/demo-stack-up.sh --no-build`);
raise `HEALTH_TIMEOUT_SEC=1200`; ensure disk/RAM headroom. Cold builds often
dominate the 30-minute budget.

### 8. Seed fails with 401

**Symptom:** `seed-pilot-cohort.sh` unauthorized  
**Fix:** ensure `SEED_TOKEN` matches `INGEST_TOKENS` (compose default
`dev-token-change-me`). Do not treat that default as a production secret.

---

## Optional pillars (pointers only)

### Gatehouse (PR security — free pillar)

Runs in the same compose file on `:8090`. Local scan without GitHub:

```bash
docker compose build gatehouse
# see services/gatehouse/README.md
```

Design: `docs/gatehouse-github-app.md`.  
**Not** a CI product SKU.

### CNAPP

Not required for AIM dashboard green. IaC ↔ CNAPP rule parity for PRs lives
under Gatehouse (`docs/security/iac-cnapp-parity.md`). Full CNAPP
deploy is a separate track — do not expect Wiz-class scale from this laptop
demo.

### Helm / enterprise

| Shape | Entry |
| --- | --- |
| Kind / chart smoke | `deploy/helm/` + `values-dev.yaml` |
| On-prem pilot | `values-standard.yaml` |
| Multi-AZ enterprise | `values-enterprise.yaml` + `docs/deployment/enterprise-packaging.md` |
| Air-gap | [`air-gapped-install.md`](./air-gapped-install.md) |

---

## Secrets policy (demo)

| Artifact | Committed? | Purpose |
| --- | --- | --- |
| `.env.example` | Yes | Documented sample keys + localdev defaults |
| `.env` | **No** (gitignored) | Real local overrides + minted secrets |
| Compose defaults like `dev-token-change-me` | Yes (localdev labels) | Laptop-only; replace before any shared host |
| `GATEHOUSE_WEBHOOK_SECRET` | Minted into `.env` only | Never hardcoded in the script |

The demo script never prints secret values.

---

## Tear down

```bash
docker compose down       # stop containers, keep volumes
docker compose down -v    # also delete local Postgres / MinIO data
```

---

## Time-to-green (measured / dry-run notes)

| Step | Clean laptop estimate | Notes |
| --- | --- | --- |
| Clone | 1–3 min | Depends on network |
| Preflight (`--preflight-only`) | &lt; 10 s | Docker + ports |
| First `compose build` + pull | 10–20 min | Dominant; cache helps re-runs |
| **Prebuilt pull path** | **≤ 15 min** target | `./scripts/install-pilot.sh --pull` when GHCR images available — see [`prebuilt-images.md`](./prebuilt-images.md) |
| Health wait after images exist | 1–3 min | Migrations + ready probes |
| Seed pilot cohort | &lt; 1 min | Deterministic event_ids |
| **Total target** | **≤ 30 min** (build) / **≤ 15 min** (pull) | Re-run without rebuild if over |

**Dry-run / measured notes (agent host, 2026-08-02):**

| Check | Result |
| --- | --- |
| `./scripts/demo-stack-up.sh --preflight-only` | Pass — Docker Engine + Compose v2 + python3 |
| Port-conflict path | Pass — refuses default ports when another process holds them; prints override recipe |
| Placeholder path | Pass — refuses `.env` keys whose values match `CHANGE_ME` / `REPLACE_ME` / `<…>` (keys only logged) |
| Warm path (images + stack already up, health green) | **~0.5 s** wall (`--no-build --no-seed`, health reuse) |
| Cold path estimate | Dominated by first `compose build` / pulls (10–20 min typical); target ≤ 30 min remains |

Full cold build time is host-dependent; if wall time exceeds 30 minutes, the script prints an explicit warning — treat image cache / disk as the usual culprit, not dashboard logic. Operators should record their own wall clock on first eval and file an issue if the happy path exceeds 30 minutes with Docker pre-installed and free default ports.

---

## Related docs

- Root [`README.md`](../../README.md) — personal mode + link to this guide  
- [`prebuilt-images.md`](./prebuilt-images.md) — GHCR pull path + digest pins for pilot cold install
- [`air-gapped-install.md`](./air-gapped-install.md) — offline media  

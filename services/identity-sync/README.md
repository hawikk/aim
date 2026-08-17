# identity-sync

Google Workspace directory sync, endpoint-identity resolution, and pseudonymization
for the AI Monitoring platform (issue AIM-24).

## What it does

1. **Directory sync** — pulls users and org units from the Google Workspace Admin SDK
   Directory API on a schedule (hourly in prod) into reference tables. Leavers are
   marked `suspended`, never deleted, so historical event joins keep resolving.
   When `IDENTITY_SYNC_AIM_API_URL` + `IDENTITY_SYNC_SESSION_REVOKE_TOKEN` are set
   (AIM-714), newly suspended/missing users also trigger platform session revoke
   so live AIM SSO cookies die before `AIM_SESSION_TTL_HOURS`.
2. **Identity resolution** — the ingestion pipeline sends endpoint identity
   (`device_id`, `os_user`) per event; the service returns a **pseudonym + team**
   (never an email). See the join-key decision in
   [docs/identity-mapping-design.md](../../docs/identity-mapping-design.md).
3. **Pseudonymization** — events and dashboards carry `u_<hmac>` pseudonyms, not
   emails. Dashboards default to team-level aggregation.
4. **Grant-gated reveal** — `POST /reveal` maps a pseudonym back to a real identity,
   requires the `ai-monitoring-revealers` grant (the reveal group from
   `docs/access-control-model.md` §1, aligned with apps/api `AIM_REVEAL_GROUPS`)
   and a written justification, and writes
   **every** attempt (allowed or denied) to an append-only audit log.

## Layout

```
src/identity_sync/
  config.py            env-driven settings (IDENTITY_SYNC_* prefix)
  auth.py              verified-JWT caller authentication for the gated endpoints (AIM-306)
  db.py                SQLAlchemy models: dir_users, dir_org_units, device_mappings, audit_log
  directory_source.py  FixtureDirectorySource (dev) + GoogleDirectorySource (Admin SDK)
  sync.py              full-upsert sync, team derivation from OU path
  resolver.py          endpoint identity -> pseudonym + team (join-key chain)
  pseudonym.py         HMAC-SHA256 pseudonyms
  api.py               FastAPI: /health /sync /resolve /reveal
  __main__.py          CLI: identity-sync sync | serve
fixtures/              dev directory snapshot (Admin SDK field shapes)
fixtures/service_host_residual/
                       AIM-1117 residual wire-shape scenarios (dogfood companion)
tests/                 pytest suite
tests/test_service_host_principal_kind_harness.py
                       AIM-1117 service-host principal_kind regression harness
```

## Dev quickstart

The root `docker-compose.yml` already runs this service with the fixture
directory and points ingest at it (`IDENTITY_RESOLVE_URL`), so a plain
`docker compose up --build` gets team attribution with no manual steps.
To run it standalone instead:

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest                                        # run tests
# AIM-1117 residual harness only (package-level target; also runs in CI):
.venv/bin/pytest tests/test_service_host_principal_kind_harness.py -q
IDENTITY_SYNC_DATABASE_URL=sqlite:///./dev.db .venv/bin/identity-sync sync
IDENTITY_SYNC_DATABASE_URL=sqlite:///./dev.db .venv/bin/identity-sync serve
```

Try it:

```bash
# resolve endpoint identity -> pseudonym (what the ingest pipeline calls)
curl -s localhost:8080/resolve -H 'content-type: application/json' -d '{"os_user":"rpatel"}'

# reveal — gated by a verified bearer JWT (AIM-306); every attempt is audited
TOKEN=$(python3 -c 'import jwt,time; now=int(time.time()); print(jwt.encode(
  {"sub":"rpatel@example.com","email":"rpatel@example.com","groups":["ai-monitoring-revealers"],
   "iat":now,"exp":now+3600}, "localdev-only-not-a-secret", algorithm="HS256"))')
curl -s localhost:8080/reveal -H 'content-type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"user_pseudonym":"<from resolve>","reason":"secret-in-prompt alert triage SEC-123"}'
```

## Production wiring

- `IDENTITY_SYNC_DIRECTORY_SOURCE=google` + service account with domain-wide
  delegation, scopes `admin.directory.user.readonly` + `admin.directory.orgunit.readonly`.
- `IDENTITY_SYNC_DATABASE_URL` -> managed Postgres (same instance as the event store,
  separate schema with restricted grants).
- `IDENTITY_SYNC_PSEUDONYM_SECRET` from the secret manager. Rotation re-keys all
  pseudonyms — a deliberate, documented event (see design doc).
- Scheduling: hourly Cloud Scheduler -> this service's `/sync` (or a CronJob running
  `identity-sync sync`).
- Authn (AIM-306): the gated endpoints (`/reveal`, `POST /service-identities`)
  verify a caller-supplied bearer JWT themselves — either against the platform
  IdP's JWKS (`IDENTITY_SYNC_JWT_JWKS_URL`, prod) or an HS256 shared secret
  (`IDENTITY_SYNC_JWT_HS256_SECRET`, in-network service callers / dev). Client
  headers are never trusted; the audit actor comes from the verified token.
  With neither verifier set the gated endpoints fail closed (deny everything).

# Identity mapping: Google Workspace users/teams — design

Issue: · Owner: engineering · Status: implemented (dev), pending prod wiring
Code: `services/identity-sync/`

## 1. Purpose

Endpoint collectors and proxy logs see devices, OS users, and IPs — not people.
This service maps that telemetry to Google Workspace users and teams so the
platform can answer "which teams use which AI tools" while collecting the minimum
personal data our EU/works-council constraints allow.

## 2. Architecture

```
Google Workspace (Admin SDK, read-only)
        │  hourly scheduled sync
        ▼
identity-sync service ──► Postgres reference tables
        │                     dir_users, dir_org_units, device_mappings, audit_log
        │ POST /resolve (device_id, os_user)
        ▼
ingestion pipeline ──► events carry user_pseudonym + team  (never email)
        │
        ▼
dashboards: team-level by default
user-level drill-down ──► POST /reveal (security-analyst role + mandatory reason,
                           every attempt audit-logged)
```

Data minimization by construction: the event store and dashboards never contain
emails or names. The only email→pseudonym join lives inside this service's
restricted schema, behind the role-gated, audit-logged reveal endpoint.

## 3. ADR-001: join key between endpoint telemetry and directory users

**Decision:** a trust-ordered chain, implemented in `resolver.py`:

1. **`device_id` → Intune enrollment mapping** (authoritative). Intune knows which
   user enrolled each managed device; collectors report the Intune device id.
   This is the primary key for our mostly-Windows/Intune fleet.
2. **`os_user` → device_mappings hint** (collector-reported). Covers WSL/Linux and
   shared/enrolled-elsewhere devices; learned from first sighting and reviewed.
3. **Bare-username heuristic** — `jdoe` / `CORP\jdoe` → `jdoe@<primary-domain>`
   matched against the directory. Fallback for the pilot before Intune mapping
   coverage is complete; every resolution records *which* rule fired so we can
   measure heuristic share and drive it to ~0.
4. **Unresolved** — the event is kept with `user_pseudonym = NULL` and counted in
   an "unattributed usage" metric. We do not drop unattributed events (that would
   hide exactly the shadow-IT usage we exist to find), and we do not guess.

**Rejected alternatives:**
- *Cert-bound identity (mTLS per user)*: strongest binding but requires a user-cert
  rollout we don't have; revisit if we add blocking enforcement later.
- *Proxy auth identity as primary*: proxy logs only cover network-path collection;
  endpoint collectors are our depth source and don't share that identity.

**Metric to watch:** share of events resolved per rule. Pilot target: ≥80%
`device_id`, <5% unresolved.

## 4. Pseudonymization

- `user_pseudonym = "u_" + HMAC-SHA256(secret, lowercase(primary_email))[:32]`.
- Deterministic → per-user aggregation without storing identity in the event store.
- Keyed → the event store alone cannot be reversed to emails; key lives in the
  secret manager, separate from the database.
- Rotation = deliberate re-key: old/new pseudonyms stop joining. Cost is accepted
  (historical dashboards remain valid at team level; user-level history is
  re-derivable only via a privileged re-key job). Documented so Security can weigh
  rotation cadence as a policy question — **I propose annual or on-incident
  rotation; decision sits with Security/Legal.**

## 5. Access control & audit

- Dashboards default to **team-level** aggregation; no user pseudonyms are needed
  for the default views at all.
- User-level drill-down goes through `POST /reveal`, which requires:
  the `security-analyst` group on a bearer JWT the service verifies itself
  (IdP JWKS in prod, HS256 shared secret for in-network/dev callers
  client-supplied headers are never trusted), and a
  free-text justification (min length enforced).
- **Every** reveal attempt — allowed or denied — is appended to `audit_log`
  (actor, role, pseudonym, reason, outcome, timestamp). The table has no
  update/delete path in the API. Denied attempts are a detection signal and feed
  Sentinel alerting.
- Reveal is deliberately O(directory size) — pseudonym→email mappings are not
  persisted, so a bulk de-anonymization dump is not a single query away. At ~1k
  users this is milliseconds; revisit only if the directory grows 10x.

## 6. Privacy notes (feeds the DPIA pack)

- Collected identity data: work email, name, org unit, device↔user mapping. No
  prompt content anywhere in this service (metadata-only policy, per epic).
- Lawful-basis and works-council materials should reference: team-level default
  views, role-gated + reason-bound + audit-logged user-level access, leaver
  retention as `suspended` rows (propose: purge user rows N months after
  suspension per retention policy — **needs a Legal/HR retention decision**).
- The `reveal` audit log itself contains actor emails; include it in the DPIA
  inventory with the same retention policy.

## 7. Open items / follow-ups

- Intune enrollment feed populating `device_mappings` (depends on
  Intune packaging; until then `os_user` + heuristic rules carry the pilot).
- Prod wiring: Cloud Scheduler, managed Postgres, secret manager, gateway JWT
  validation (belongs to foundation).
- Retention decision for suspended-user rows (Legal/HR — will raise).
- Re-key runbook for pseudonym secret rotation.

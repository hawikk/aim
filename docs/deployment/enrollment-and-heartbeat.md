# Collector enrollment & heartbeat protocol (client wiring)

Status: **implemented**. Server side lives in `services/ingest`
(`src/device-store.ts` + the `/v1/enroll`, `/v1/heartbeat`, `/v1/coverage`
routes in `src/server.ts`, migration `004_devices.sql`). Client side is
`enroll.py` inside every endpoint collector (`aim_collector`,
`cursor_collector`, `kilo_collector`, `kimi_collector`): the one-line
install enrolls and stores the per-device token at
`<state dir>/device_token` (mode 0600), the `watch` daemon heartbeats on
start and every interval, and `python -m <collector> heartbeat` sends a
single liveness POST for timer/cron-driven deployments. The dashboard
fleet view consumes the same `devices` table via `GET /api/fleet`
(apps/api). Verified end-to-end (enroll → device token → heartbeat →
coverage `healthy`) in `services/ingest/test/devices.test.ts` and in
`collectors/*/tests/test_enroll.py` against a stub ingest.

The Linux packaging path (`deploy/linux/aim-collector-heartbeat.sh`,
driven by the device scan timer) remains supported and speaks the same
protocol; the in-collector client is the default for new installs.
Packaging install/enroll/heartbeat/uninstall under a prefixed root is
covered by `tests/e2e_linux_packaging.sh`.

One-line install UX (per collector):

```sh
python -m aim_collector install \
  --ingest-url https://ingest.corp.example \
  --enroll-token <ring enrollment token> \
  --token <events ingest token> \
  --ring ring0
```

This registers hooks (Claude Code / Cursor only), writes the config file
(events token goes to a 0600 file referenced by `token_file`, never
plaintext in the JSON), enrolls, and verifies connectivity with a first
heartbeat. `uninstall` removes hook registrations and the local device
token, so heartbeats stop cleanly; server-side revocation of the device
stays an admin action. A heartbeat that gets a 401 deletes the local
token for the same reason.

Windows Scheduled Task (`deploy/windows/Install-AIMCollector.ps1`) runs
`scan-once` + `flush` + `heartbeat` every 5 minutes.
`heartbeat` is a no-op until the device is enrolled (device_token present);
pilot token-only installs still rely on event last-seen for coverage.
Live Windows host verification of enrolled heartbeat remains a pilot residual.

Privacy note: everything here is metadata-only. Host identity is a random
UUID generated on-device (`state.host_id()`), not a hardware fingerprint —
deliberate, for works-council/DPIA posture.

## Pilot path (works today, no new ingest code)

Ring-0/1 devices use a **pre-shared ingest bearer token** distributed by the
installer (`/etc/aim-collector/token` or `%ProgramData%\AI-Monitoring\collector\token`).
The collector posts batches to the existing authenticated ingest endpoint.
"Enrollment" in the pilot = the installer drops a token + config and the
device starts reporting. When an enrollment token is also provisioned
(`AIM_ENROLL_TOKEN`), the device additionally enrolls for a per-device token
and heartbeats, so fleet coverage comes from the `devices` table (see
`GET /v1/coverage`). Without an enrollment token, coverage falls back to
`host_id` last-seen timestamps in the events table.

## Corporate golden images

Image-time install is supported via `deploy/golden-image/`: bake payload +
managed config (and optionally a **ring** enroll token), then **seal** so no
`host_id` / `device_token` is captured in the AMI/VHD. Each clone auto-enrolls
on first heartbeat cycle (or via `first-boot-enroll.sh` /
`FirstBoot-Enroll.ps1`). Full recipe:
`docs/deployment/zero-touch-golden-image.md`. Never ship a pre-enrolled
device identity in a clonable image.

## Protocol (implemented in `services/ingest`)

### POST /v1/enroll

Registers a device and issues a per-device token. Called once by the
installer (or first collector run) with an **enrollment token** (short-lived,
per-ring, issued by an admin via the API — not shipped in the package).

Request:
```json
{
  "host_id": "uuid-v4-generated-on-device",
  "hostname": "ws-1042",
  "os": "windows-11-23h2 | wsl-ubuntu-22.04 | linux-rhel9",
  "collector_version": "0.1.0",
  "ring": "ring0"
}
```
Response (201 on first enroll, 200 on idempotent re-enroll):
```json
{ "device_id": "uuid", "device_token": "...", "heartbeat_interval_sec": 300 }
```
Errors: 401 invalid enrollment token. Re-enroll with the same `host_id`
is idempotent and returns **200** `{ "device_id": ..., "already_enrolled": true }`
with **no** new token (the stored device token stays valid; token re-issue
requires admin action).

Per-device tokens replace the pre-shared token; a leaked device token can be
revoked without touching the ring. The pre-shared pilot token is retired
ring-by-ring as enrollment rolls out.

### POST /v1/heartbeat

Auth: device bearer token. Every `heartbeat_interval_sec` (default 300s),
also on collector start.

```json
{
  "host_id": "uuid",
  "collector_version": "0.1.0",
  "os": "...",
  "counters": { "events_emitted": 1234, "events_spooled": 3, "last_flush_ok": true },
  "config_version": "2026-07-21T00:00:00Z"
}
```
Response 200: `{ "status": "ok", "config_version": "..." }` — the collector
compares `config_version` and re-reads managed config when it changes
(managed version pinning signal; no self-update in v1).

A device with no heartbeat for >3 intervals is **dead** for coverage purposes.

## Coverage dashboard contract (consumes this)

Per device: `device_id, host_id, hostname, os, ring, collector_version,
enrolled_at, last_heartbeat_at, last_event_at, health ∈ {healthy, stale, dead, never_seen}`.

- deployed = devices with the app assigned in Intune (or install script run)
- healthy = heartbeat within 3 intervals
- fleet total = IdP/Intune device inventory for in-scope users

Acceptance criterion "deployed vs healthy vs fleet total" is a single query
over this table plus the Intune export.

## Hardening path (post-pilot)

- Token storage: DPAPI (Windows) / OS keychain (Linux) instead of ACL'd file.
- mTLS with device certs from Intune instead of bearer tokens.
- Enrollment tokens rotated per ring; per-device tokens short-lived with
  silent refresh via heartbeat.
- **Signed collector build identity:** each batch carries a
  `collector.build` block; ingest verifies Ed25519 signatures when
  `INGEST_ATTESTATION_MODE=shadow|enforce`. Install-time trust remains
  cosign/Sigstore (or internal CA). See
  `docs/security/collector-build-attestation.md`.

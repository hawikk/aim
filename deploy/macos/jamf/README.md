# Jamf Pro packaging — AIM Collector (macOS)

Package the macOS collector for deployment through Jamf Pro: a signed `.pkg`
plus an optional configuration profile, with secrets supplied at install time
(not baked into the package).

**Prerequisite (external):** Jamf Pro tenant with package upload + policy rights
and a ring-0 pilot smart/static group — owner: IT.

## Layout

```
deploy/macos/
  install.sh / uninstall.sh          # system installer (root)
  aim-collector-*.sh                 # LaunchDaemon wrappers
  launchd/*.plist                    # system LaunchDaemons
  jamf/
    build-pkg.sh                     # stage + pkgbuild (macOS CI or build host)
    scripts/postinstall              # pkg postinstall → install.sh
    scripts/preuninstall             # pkg preuninstall → uninstall.sh
    profiles/com.aimonitoring.collector.mobileconfig
    ea-collector-version.sh          # Extension Attribute for version detection
    README.md                        # this file
```

Installed paths (parity with Linux managed config):

| Path | Purpose |
|---|---|
| `/opt/aim-collector/` | Payload + scan/heartbeat/oob wrappers |
| `/etc/aim-collector/config.json` | Managed config (0644) |
| `/etc/aim-collector/token` | Ingest token (0640) |
| `/etc/aim-collector/version` | Detection string for EA / smart groups |
| `/Library/LaunchDaemons/com.aimonitoring.collector-*.plist` | 5‑min timers |

## Build the package

On a macOS build host (or GitHub Actions `macos-*` runner) with Xcode CLT:

```sh
# From repo root. VERSION defaults to 0.1.0.
./deploy/macos/jamf/build-pkg.sh
# → dist/macos/AIMonitoringCollector-0.1.0.pkg

# Optional: sign with Developer ID Installer identity
AIM_PKG_SIGN_IDENTITY="Developer ID Installer: Example Corp (TEAMID)" \
  ./deploy/macos/jamf/build-pkg.sh
```

On Linux CI the script still **stages** the package root and validates structure
(plists, postinstall, payload) without producing a `.pkg` — that stage is what
`scripts/jamf-pilot-proof.sh` exercises.

## Jamf Pro policy configuration

### Package

| Field | Value |
|---|---|
| Package | `AIMonitoringCollector-<version>.pkg` |
| Category | Security / AI Monitoring |
| Fill user templates | No |
| Restart | None |

### Policy (ring-0)

| Field | Value |
|---|---|
| Trigger | Recurring check-in (or once) |
| Frequency | Ongoing (idempotent install) |
| Scope | Smart group `aim-collector-ring0-macos` |
| Package | AIMonitoringCollector (Cache + Install) |

### Secrets injection (do **not** bake into the pkg)

Order of preference:

1. **Jamf encrypted script parameter / secret store** writes
   `/var/root/aim-secrets/token` (mode 0600) immediately before install, then
   postinstall / `install.sh` reads `AIM_TOKEN_FILE`.
2. **Pilot stopgap:** policy script parameters 4–7 map to
   `AIM_INGEST_URL`, `AIM_TOKEN`, `AIM_HASH_SALT`, `AIM_ENROLL_TOKEN`.
   Visible to Jamf admins — ring-0 only; rotate after pilot.

### Detection / smart group (Extension Attribute)

Upload `jamf/ea-collector-version.sh` as a Jamf Extension Attribute
(data type: String, input: Script). Smart group criterion:

```
AI Monitoring Collector Version  is  0.1.0
```

### Configuration profile

Upload `profiles/com.aimonitoring.collector.mobileconfig` as a **Computer**
configuration profile (scope = same ring group). Replace `REPLACE_INGEST_URL`
and the payload UUIDs before upload. Tokens are **not** in the profile.

### Uninstall

```sh
/opt/aim-collector/uninstall.sh
# or: AIM_PURGE_STATE=1 /opt/aim-collector/uninstall.sh
```

## Rollout rings

See `docs/deployment/rollout-plan.md`. Ring-0 = security team pilot group
(Jamf smart group `aim-collector-ring0-macos`).

## Versioning / updates

Bump `AIM_VERSION` / package filename. No collector self-update in v1 — update
channel stays with Jamf change control (same posture as Windows Intune).

## Pilot proof (CI / agent host)

```sh
./scripts/jamf-pilot-proof.sh
```

Stages the package, runs `install.sh` under `AIM_ROOT`, asserts layout +
version detection + clean uninstall residue. Does **not** require a Jamf
tenant or macOS host.

Full operator doc: `docs/deployment/jamf-macos.md`.

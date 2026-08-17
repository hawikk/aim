# Intune Win32 app packaging — AIM Collector (AIM-742)

Package the Windows collector as an `.intunewin` for deployment through
Microsoft Intune. **Prerequisite (external):** Intune tenant access with
Win32-app upload rights + a ring-0 pilot device group — owner: CEO/IT.

Related: enrollment protocol in
[`docs/deployment/enrollment-and-heartbeat.md`](../../../docs/deployment/enrollment-and-heartbeat.md),
rollout rings in
[`docs/deployment/rollout-plan.md`](../../../docs/deployment/rollout-plan.md),
pilot proof checklist in
[`docs/deployment/intune-pilot-proof.md`](../../../docs/deployment/intune-pilot-proof.md).

## Build the package

From the monorepo root (pulls the production collector from
`collectors/claude-code`, AIM-20):

```bash
./deploy/windows/stage-intunewin.sh
# → deploy/windows/out/staging/
```

Optional version pin for detection + wrap naming:

```bash
AIM_COLLECTOR_VERSION=0.1.0 ./deploy/windows/stage-intunewin.sh
```

Staging layout:

```
staging/
  Install-AIMCollector.ps1
  Uninstall-AIMCollector.ps1
  Detect-AIMCollector.ps1          # optional custom detection script
  Invoke-AIMCollectorCycle.ps1     # SYSTEM task: per-user scan/flush + heartbeat
  Install-AIMCollector-WSL.ps1     # optional remediation: enroll WSL distros
  app-spec.json                    # Intune portal / Graph field values
  STAGING_MANIFEST.txt
  WRAP.txt
  payload/
    aim_collector/                 # collectors/claude-code/aim_collector
  enforcement/
    enforcement.enforce.json       # AIM-440 endpoint enforce bundle
  wsl-linux/                       # Linux install path for the WSL bridge
  runtime/                         # optional: embeddable Python 3.11+
```

Wrap (on a Windows packaging host with the Microsoft Win32 Content Prep Tool):

```
IntuneWinAppUtil.exe -c staging -s Install-AIMCollector.ps1 -o out\aim-collector.intunewin
```

Embeddable CPython under `runtime\` is **recommended** — fleet machines are
not guaranteed to have Python on PATH. Download the embeddable package from
python.org, expand into `staging/runtime/`, then re-run wrap.

## Intune app configuration

Copy values from `app-spec.json` or the table below:

| Field | Value |
|---|---|
| Install command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-AIMCollector.ps1 -IngestUrl "%INGEST_URL%" -TokenFile "%TOKEN_PATH%" -EnrollTokenFile "%ENROLL_TOKEN_PATH%" -HashSalt "%HASH_SALT%" -Ring ring0 -Version 0.1.0` |
| Uninstall command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Uninstall-AIMCollector.ps1` |
| Install behavior | System |
| Device restart behavior | No specific action |
| Detection rule (preferred) | Registry `HKLM\SOFTWARE\AIMonitoring\Collector`, value `Version`, equals `0.1.0` |
| Detection rule (alt) | Custom script `Detect-AIMCollector.ps1` (also checks payload + scheduled task) |
| Requirements | Windows 10 21H2+ / Windows 11; x64 |
| Return codes | 0 = success, 1 = failed, 1618 = retry |

### Script package alternative (pilot without `.intunewin`)

When Win32 packaging is blocked on tooling access, the same installer can run
as an Intune **platform script** (System context) for ring-0:

1. Stage secrets to `%ProgramData%\AI-Monitoring\collector\token` via a prior
   remediation (preferred) or pass `-Token` on the command line (pilot only).
2. Deploy `Install-AIMCollector.ps1` + payload folder via a signed zip dropped
   by the script, **or** assign the full staged tree as a LOB Win32 app without
   the Content Prep Tool when the payload is already on a network share.
3. Detection remains the same registry rule.

This path is documented for pilot only; production rollout should use the
wrapped `.intunewin` so supersedence and version detection stay first-class.

### WSL bridge (optional remediation)

Assign `Install-AIMCollector-WSL.ps1` as a proactive remediation or
post-install dependency so each WSL distro gets the Linux collector path with
the same ring secrets the Windows host already holds.

## Secrets

Secrets (`Token`, `EnrollToken`, `HashSalt`) must NOT be baked into the
package. Options in order of preference:

1. Intune **remediation script** that fetches the ring token from a secrets
   broker into `%ProgramData%\AI-Monitoring\collector\` before detection runs.
2. Pilot stopgap: per-ring install command variant with `-Token` /
   `-EnrollToken` (visible in Intune console to Intune admins — acceptable for
   ring-0 only, rotate after pilot).

## What the scheduled task does

Every 5 minutes as SYSTEM (`Invoke-AIMCollectorCycle.ps1`):

1. Per-user `scan-once` + `flush` for profiles with `.aim-collector` or Claude
   settings (drains hook spools with the machine token).
2. Machine enroll (once, if `enroll-token` is present and no `device_token` yet).
3. Machine `heartbeat` → ingest `POST /v1/heartbeat` → fleet coverage via
   `GET /api/fleet` (deployed / healthy / stale / dead / never_seen).

## Versioning / updates

Managed version pinning via Intune supersedence: new package version bumps the
`Version` detection value; supersedence rule uninstalls the old app first.
No collector self-update mechanism in v1 (deliberate — update channel stays
with endpoint tooling, aligns with Wazuh/Intune change control).

## Verification (no Intune tenant required)

```bash
./deploy/windows/verify-intune-package.sh
```

This stages the package, asserts required files and a non-stub collector
payload, and writes a pilot-proof record under `docs/deployment/` when
requested. Live ring-0 install still needs CEO/IT Intune rights.

## Rollout rings

See `docs/deployment/rollout-plan.md`. Ring-0 = security team pilot group
(Intune device group `aim-collector-ring0`), assigned as "Required".

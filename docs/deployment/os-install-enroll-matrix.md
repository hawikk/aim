# OS install / enroll continuous matrix

**Status:** shipped
**Owner:** `founding-engineer` · **Page on failure:** `True`

Living contract: `docs/deployment/os-install-enroll-matrix.yaml`.
Gate: `python3 scripts/check_os_install_enroll_matrix.py --check`.
Scheduled: `.github/workflows/os-install-enroll-matrix.yml` (aim-ops).

## Why this exists

Dimension 18 (fit to locked constraints) requires Windows + WSL + Linux
endpoint install/enroll paths to stay real, not doc-only. This matrix is
the continuous CI/ops proof: structural contracts, dry-run install for
Linux/WSL, and Intune packaging contract for Windows. Failures page the
owner via sticky issue `OS install/enroll matrix FAILED`.

## Cells

| OS | Channel | Install | Uninstall | Dry-run |
| --- | --- | --- | --- | --- |
| `linux` | `native_bash` | `deploy/linux/install.sh` | `deploy/linux/uninstall.sh` | yes |
| `wsl` | `wsl_bash` | `deploy/linux/install.sh` | `deploy/linux/uninstall.sh` | yes |
| `windows` | `intune_win32` | `deploy/windows/Install-AIMCollector.ps1` | `deploy/windows/Uninstall-AIMCollector.ps1` | structural |

## Notes per cell

### `linux`

Native Linux host. Installer is root-owned systemd timer when available, cron fallback otherwise. Enroll token optional; without it pilot falls back to event last-seen coverage.

### `wsl`

WSL distro is a separate endpoint from the Windows host. Run deploy/linux/install.sh inside the distro (`wsl -d <distro> -- bash ...`). Heartbeat prefixes os with `wsl-` when /proc/version mentions Microsoft.

### `windows`

Windows host via Intune Win32. Scheduled task runs scan-once + flush + heartbeat every 5 min. EnrollToken is optional; without it pilot stays on event last-seen until enroll is provisioned.

## Local usage

```bash
python3 scripts/check_os_install_enroll_matrix.py --check
python3 scripts/check_os_install_enroll_matrix.py --self-test
python3 scripts/check_os_install_enroll_matrix.py --render  # refresh this doc
```

_Last rendered report: ok=True at 2026-08-17T12:17:32Z_

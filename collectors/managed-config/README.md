# Managed config paths

Endpoint collectors resolve a JSON file dropped by IT / MDM. Darwin used to
fall through to the Linux path (`/etc/aim-collector`). That is now a **legacy**
Jamf candidate only.

| OS | First-class managed directory |
|---|---|
| Windows | `%ProgramData%\AI-Monitoring\collector\` |
| macOS | `/Library/Application Support/AI-Monitoring/collector/` then `~/Library/Application Support/AI-Monitoring/collector/` |
| Linux / WSL | `/etc/aim-collector/` |

Per-user install (LaunchAgent, refuse root): `deploy/macos/managed-user/`.
System Jamf LaunchDaemon (existing): `deploy/macos/install.sh` + `deploy/macos/jamf/`.

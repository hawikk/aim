# macOS collector install

Two install surfaces. This directory holds both. Do not mix them.

| Path | Privilege | Unit | Managed config | When to use |
|---|---|---|---|---|
| **`managed-user/`** | logged-in user; **refuses root** | LaunchAgent `com.aimonitoring.aim-watch` | `~/Library/Application Support/AI-Monitoring/collector/` | Artifact IT wraps (Jamf “Execute as user”, Intune signed-in user). Same `aim join` + watcher flow as Linux. |
| `install.sh` + `jamf/` | root / pkg postinstall | LaunchDaemons `com.aimonitoring.collector-scan` + `…-oob-health` | `/etc/aim-collector/` (legacy, still honored) | Existing Jamf system package. Live fleet rollout remains. |

Notarized Developer ID signing is **not** shipped (no cert in-repo). Residual: unsigned `pkgbuild` layout under `jamf/`.

## What Jamf / Intune would call

Run as the **logged-in user**, never as root:

```sh
AIM_INGEST_URL=https://ingest.corp.example \
AIM_ENROLL_TOKEN_FILE=/path/to/ring-enroll-token \
./deploy/macos/managed-user/install.sh
```

| MDM | How to invoke |
|---|---|
| **Jamf Pro** | Script policy, **Execute Command as User** (not root). Files & Processes → Execute Command, or a script scoped to the user. |
| **Intune** | macOS shell-script policy, **Run script as signed-in user**. |

Secrets stay out of the script payload: drop the enroll token to a user-readable file (or inject via MDM secret) and pass `AIM_ENROLL_TOKEN_FILE`.

Optional: `AIM_TOKEN` / `AIM_TOKEN_FILE` (events bearer), `AIM_HASH_SALT`, `AIM_RING`, `AIM_CA_BUNDLE`.

## User-level unit

- **Label / filename:** `com.aimonitoring.aim-watch`
- **Path:** `~/Library/LaunchAgents/com.aimonitoring.aim-watch.plist`
- **Command:** `python3 -m aim watch` (same watcher `aim join` registers on Linux)
- **Scope:** current user only. `aim join` / this installer refuse uid 0.

First-class managed config the collectors read on Darwin:

1. `/Library/Application Support/AI-Monitoring/collector/config.json` (MDM can drop this without our installer being root)
2. `~/Library/Application Support/AI-Monitoring/collector/config.json` (this installer)
3. `/etc/aim-collector/config.json` (legacy only)

## Uninstall

```sh
./deploy/macos/managed-user/uninstall.sh
# also wipe ~/.aim-collector* :
AIM_PURGE_STATE=1 ./deploy/macos/managed-user/uninstall.sh
```

Or `aim uninstall` if the CLI is on `PATH`.

## Dry-run (Linux CI / no Mac)

```sh
bash scripts/macos-managed-user-proof.sh
```

Proves syntax, refuse-root, prefix install without root, LaunchAgent (not LaunchDaemon), and Darwin managed-config candidates.

## system package

See `jamf/README.md` and `docs/deployment/jamf-macos.md`. That path stays for existing Jamf tenants; it is **not** the least-privilege artifact.

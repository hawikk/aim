# Per-user macOS managed install

Least-privilege artifact IT wraps. Not a live Jamf/Intune fleet rollout.

**Jamf / Intune call (as the logged-in user):**

```sh
AIM_INGEST_URL=https://ingest.corp.example \
AIM_ENROLL_TOKEN_FILE=/path/to/enroll-token \
./deploy/macos/managed-user/install.sh
```

**User-level unit:** `com.aimonitoring.aim-watch`
(`~/Library/LaunchAgents/com.aimonitoring.aim-watch.plist`)

**Uninstall:** `./deploy/macos/managed-user/uninstall.sh`

See `../README.md` for the full operator table, managed-config search order,
and the separate root LaunchDaemon package.

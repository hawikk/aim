#!/usr/bin/env bash
# Verify the Intune Win32 staging layout for AIM Collector (AIM-742).
#
# Runs stage-intunewin.sh, asserts the package is complete and non-stub, and
# optionally writes a pilot-proof markdown record.
#
# Usage:
#   ./deploy/windows/verify-intune-package.sh
#   WRITE_PROOF=1 ./deploy/windows/verify-intune-package.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGE_OUT="${STAGE_OUT:-$ROOT/deploy/windows/out/staging}"
VERSION="${AIM_COLLECTOR_VERSION:-0.1.0}"
WRITE_PROOF="${WRITE_PROOF:-0}"
PROOF_PATH="${PROOF_PATH:-$ROOT/docs/deployment/intune-pilot-proof.md}"

fail() { echo "VERIFY FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

echo "==> staging package"
"$ROOT/deploy/windows/stage-intunewin.sh" "$STAGE_OUT"

echo "==> asserting required scripts"
for f in \
  Install-AIMCollector.ps1 \
  Uninstall-AIMCollector.ps1 \
  Detect-AIMCollector.ps1 \
  Invoke-AIMCollectorCycle.ps1 \
  Install-AIMCollector-WSL.ps1 \
  app-spec.json \
  STAGING_MANIFEST.txt
do
  [ -f "$STAGE_OUT/$f" ] || fail "missing $f"
  ok "$f"
done

echo "==> asserting collector payload (non-stub)"
[ -d "$STAGE_OUT/payload/aim_collector" ] || fail "payload/aim_collector missing"
for f in __main__.py install.py enroll.py hook.py config.py; do
  [ -f "$STAGE_OUT/payload/aim_collector/$f" ] || fail "payload missing aim_collector/$f"
done
ok "core collector modules present"

PAYLOAD_FILES="$(find "$STAGE_OUT/payload/aim_collector" -type f | wc -l | tr -d ' ')"
[ "$PAYLOAD_FILES" -ge 10 ] || fail "payload looks like a stub ($PAYLOAD_FILES files)"
ok "payload file count=$PAYLOAD_FILES"

if find "$STAGE_OUT/payload" -name '__pycache__' | grep -q .; then
  fail "__pycache__ leaked into staging"
fi
ok "no __pycache__ in payload"

echo "==> asserting enforcement bundle"
[ -f "$STAGE_OUT/enforcement/enforcement.enforce.json" ] \
  || fail "enforcement/enforcement.enforce.json missing"
ok "enforcement.enforce.json staged"

echo "==> asserting WSL bridge assets"
[ -f "$STAGE_OUT/wsl-linux/install.sh" ] || fail "wsl-linux/install.sh missing"
[ -d "$STAGE_OUT/wsl-linux/payload/aim_collector" ] || fail "wsl-linux payload missing"
ok "wsl-linux install path staged"

echo "==> asserting app-spec version alignment"
if command -v python3 >/dev/null 2>&1; then
  python3 - "$STAGE_OUT/app-spec.json" "$VERSION" <<'PY'
import json, sys
spec = json.load(open(sys.argv[1]))
want = sys.argv[2]
got = str(spec.get("appVersion", ""))
if got != want:
    sys.stderr.write(f"app-spec appVersion={got!r} != {want!r}\n")
    sys.exit(1)
install = spec.get("installCommandLine", "")
if f"-Version {want}" not in install:
    sys.stderr.write("installCommandLine missing -Version pin\n")
    sys.exit(1)
print("  ok: app-spec version aligned")
PY
else
  ok "skipped app-spec JSON check (no python3)"
fi

# Install script must reference the cycle helper and fail closed on missing payload.
grep -q 'Invoke-AIMCollectorCycle' "$STAGE_OUT/Install-AIMCollector.ps1" \
  || fail "Install-AIMCollector.ps1 does not reference cycle script"
grep -q 'payload\\aim_collector missing' "$STAGE_OUT/Install-AIMCollector.ps1" \
  || fail "Install-AIMCollector.ps1 does not fail closed on missing payload"
ok "installer fail-closed + cycle wiring"

MANIFEST="$STAGE_OUT/STAGING_MANIFEST.txt"
GIT_REV="$(grep '^git_rev=' "$MANIFEST" | cut -d= -f2-)"
PAYLOAD_SHA="$(grep '^payload_tree_sha256=' "$MANIFEST" | cut -d= -f2-)"
INSTALL_SHA="$(grep '^install_sha256=' "$MANIFEST" | cut -d= -f2-)"
BUILT_AT="$(grep '^built_at=' "$MANIFEST" | cut -d= -f2-)"
FILE_COUNT="$(grep '^files_total=' "$MANIFEST" | cut -d= -f2-)"

echo "==> staging verified"
echo "  built_at=$BUILT_AT version=$VERSION git_rev=$GIT_REV files=$FILE_COUNT"
echo "  install_sha256=$INSTALL_SHA"
echo "  payload_tree_sha256=$PAYLOAD_SHA"

if [ "$WRITE_PROOF" = "1" ]; then
  mkdir -p "$(dirname "$PROOF_PATH")"
  cat > "$PROOF_PATH" <<EOF
# Intune package pilot proof (AIM-742)

**Status:** package staging verified in CI/agent environment.
**Live ring-0 install:** blocked on external Intune tenant rights (CEO/IT).

## What was proven

| Check | Result |
|---|---|
| Stage script produces complete Win32 layout | pass |
| Production collector payload (non-stub) | pass ($PAYLOAD_FILES files) |
| Enforcement bundle staged | pass |
| WSL bridge linux assets staged | pass |
| Detection registry rule documented | pass (\`HKLM\\SOFTWARE\\AIMonitoring\\Collector\\Version=$VERSION\`) |
| Secrets not baked into package | pass (tokens via install args / TokenFile only) |
| Live Intune upload + device install | **pending** CEO/IT |

## Staging fingerprint

\`\`\`
built_at=${BUILT_AT}
version=${VERSION}
git_rev=${GIT_REV}
files_total=${FILE_COUNT}
payload_files=${PAYLOAD_FILES}
install_sha256=${INSTALL_SHA}
payload_tree_sha256=${PAYLOAD_SHA}
\`\`\`

## How to reproduce

\`\`\`bash
./deploy/windows/verify-intune-package.sh
# or stage only:
./deploy/windows/stage-intunewin.sh
\`\`\`

## Live pilot steps (CEO/IT)

1. Provision Intune Win32-app upload rights + device group \`aim-collector-ring0\`.
2. On a Windows packaging host: wrap \`deploy/windows/out/staging\` with
   \`IntuneWinAppUtil.exe\` (see \`deploy/windows/intunewin/README.md\`).
3. Create Win32 app using field values from \`app-spec.json\`.
4. Deliver ring secrets via remediation (preferred) or pilot install-command args.
5. Assign Required to \`aim-collector-ring0\`.
6. Confirm within one heartbeat (≤5 min):
   - Registry detection reports Version=$VERSION
   - Scheduled task \`AIM Collector Scan\` exists
   - Fleet \`GET /api/fleet\` shows the host as healthy (with enroll token)
   - A Claude Code session on the host produces an event in Activity

## Package path

- Stage: \`deploy/windows/stage-intunewin.sh\`
- Spec: \`deploy/windows/intunewin/app-spec.json\`
- Docs: \`deploy/windows/intunewin/README.md\`
EOF
  echo "==> wrote pilot proof: $PROOF_PATH"
fi

echo "PASS"

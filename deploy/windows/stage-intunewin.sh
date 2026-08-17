#!/usr/bin/env bash
# Stage the Intune Win32 package layout for AIM Collector (AIM-28 / AIM-742).
#
# Builds the directory tree that IntuneWinAppUtil.exe wraps. Pulls the
# production collector payload from collectors/claude-code (AIM-20) so the
# package is never a stub.
#
# Usage:
#   ./deploy/windows/stage-intunewin.sh [out-dir]
#
# Output layout (default: deploy/windows/out/staging):
#   Install-AIMCollector.ps1
#   Uninstall-AIMCollector.ps1
#   Detect-AIMCollector.ps1
#   Invoke-AIMCollectorCycle.ps1
#   Install-AIMCollector-WSL.ps1
#   payload/aim_collector/     # from collectors/claude-code
#   enforcement/               # enforce-mode endpoint bundle (AIM-440)
#   wsl-linux/                 # linux install path for WSL bridge
#   runtime/                   # optional; copy embeddable Python here yourself
#   STAGING_MANIFEST.txt
#   app-spec.json              # Intune field values for the operator
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:-$ROOT/deploy/windows/out/staging}"
PKG_SRC="$ROOT/collectors/claude-code/aim_collector"
WIN="$ROOT/deploy/windows"
LINUX="$ROOT/deploy/linux"
ENFORCE_SRC="$ROOT/deploy/enforcement/enforcement.enforce.json"
VERSION="${AIM_COLLECTOR_VERSION:-0.1.0}"

[ -d "$PKG_SRC" ] || { echo "collector payload missing at $PKG_SRC (AIM-20)" >&2; exit 1; }

rm -rf "$OUT"
mkdir -p "$OUT/payload" "$OUT/wsl-linux" "$OUT/enforcement"

cp -f "$WIN/Install-AIMCollector.ps1" "$OUT/"
cp -f "$WIN/Uninstall-AIMCollector.ps1" "$OUT/"
cp -f "$WIN/Detect-AIMCollector.ps1" "$OUT/"
cp -f "$WIN/Invoke-AIMCollectorCycle.ps1" "$OUT/"
cp -f "$WIN/Install-AIMCollector-WSL.ps1" "$OUT/"
cp -f "$WIN/intunewin/app-spec.json" "$OUT/app-spec.json"

# Production collector (no __pycache__, no tests).
rm -rf "$OUT/payload/aim_collector"
cp -a "$PKG_SRC" "$OUT/payload/aim_collector"
find "$OUT/payload" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$OUT/payload" -name '*.pyc' -delete
# Drop test modules if any leaked into the package tree.
find "$OUT/payload" -type d -name 'tests' -prune -exec rm -rf {} + 2>/dev/null || true

# Endpoint enforcement bundle (required for enforce-mode pilots).
if [ -f "$ENFORCE_SRC" ]; then
  cp -f "$ENFORCE_SRC" "$OUT/enforcement/enforcement.enforce.json"
elif [ -f "$PKG_SRC/default_enforcement.json" ]; then
  cp -f "$PKG_SRC/default_enforcement.json" "$OUT/enforcement/enforcement.enforce.json"
else
  echo "WARNING: no enforcement bundle found — installer will fail-open to observe" >&2
fi

# WSL bridge assets (same scripts the Linux path uses).
cp -a "$LINUX/install.sh" "$LINUX/uninstall.sh" \
      "$LINUX/aim-collector-scan.sh" "$LINUX/aim-collector-heartbeat.sh" \
      "$OUT/wsl-linux/"
if [ -d "$LINUX/systemd" ]; then
  cp -a "$LINUX/systemd" "$OUT/wsl-linux/systemd"
fi
# Also ship the collector for WSL installs that cannot reach the monorepo.
mkdir -p "$OUT/wsl-linux/payload"
cp -a "$OUT/payload/aim_collector" "$OUT/wsl-linux/payload/aim_collector"

# Count payload files for the manifest.
FILE_COUNT="$(find "$OUT" -type f | wc -l | tr -d ' ')"
PAYLOAD_FILES="$(find "$OUT/payload/aim_collector" -type f | wc -l | tr -d ' ')"
SHA_INSTALL="$(sha256sum "$OUT/Install-AIMCollector.ps1" | awk '{print $1}')"
SHA_PAYLOAD="$(
  # Stable content fingerprint of the collector tree (sorted paths + hashes).
  (cd "$OUT/payload/aim_collector" && find . -type f | sort | xargs sha256sum) \
    | sha256sum | awk '{print $1}'
)"

cat > "$OUT/STAGING_MANIFEST.txt" <<EOF
AIM Collector Intune staging (AIM-742)
built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
collector_src=collectors/claude-code/aim_collector
version=${VERSION}
files_total=${FILE_COUNT}
payload_files=${PAYLOAD_FILES}
install_sha256=${SHA_INSTALL}
payload_tree_sha256=${SHA_PAYLOAD}
git_rev=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)
EOF

# Operator-facing wrap instructions next to the tree.
cat > "$OUT/WRAP.txt" <<EOF
On a Windows packaging host with Microsoft Win32 Content Prep Tool:

  IntuneWinAppUtil.exe -c "$(basename "$(dirname "$OUT")")/staging" \\
    -s Install-AIMCollector.ps1 \\
    -o out\\aim-collector-${VERSION}.intunewin

Then upload out\\aim-collector-${VERSION}.intunewin as a Win32 app.
See deploy/windows/intunewin/README.md and app-spec.json for field values.
EOF

echo "staged: $OUT"
echo "  files=${FILE_COUNT} payload_files=${PAYLOAD_FILES} version=${VERSION}"
echo "next: IntuneWinAppUtil.exe -c $OUT -s Install-AIMCollector.ps1 -o out/aim-collector.intunewin"

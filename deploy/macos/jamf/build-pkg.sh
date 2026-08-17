#!/usr/bin/env bash
# — stage (and optionally pkgbuild) the Jamf macOS collector package.
#
# Always produces a staging tree under dist/macos/stage/. On macOS with
# pkgbuild available, also emits dist/macos/AIMonitoringCollector-<version>.pkg.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MACOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$MACOS_DIR/../.." && pwd)"
VERSION="${AIM_VERSION:-0.1.0}"
IDENTIFIER="${AIM_PKG_IDENTIFIER:-com.aimonitoring.collector}"
OUT_DIR="${AIM_PKG_OUT:-$REPO_ROOT/dist/macos}"
STAGE="$OUT_DIR/stage"
SCRIPTS_STAGE="$OUT_DIR/scripts"
PKG_NAME="AIMonitoringCollector-${VERSION}.pkg"

log() { printf '[aim-pkg] %s\n' "$*"; }
die() { printf '[aim-pkg] ERROR: %s\n' "$*" >&2; exit 1; }

rm -rf "$STAGE" "$SCRIPTS_STAGE"
mkdir -p \
  "$STAGE/opt/aim-collector" \
  "$STAGE/Library/LaunchDaemons" \
  "$STAGE/usr/local/libexec/aim-collector" \
  "$SCRIPTS_STAGE"

PKG_SRC="$REPO_ROOT/collectors/claude-code/aim_collector"
[ -d "$PKG_SRC" ] || die "missing collector payload at $PKG_SRC"
cp -a "$PKG_SRC" "$STAGE/opt/aim-collector/aim_collector"
find "$STAGE/opt/aim-collector" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true

if [ -d "$REPO_ROOT/collectors/integrity" ]; then
  cp -a "$REPO_ROOT/collectors/integrity" "$STAGE/opt/aim-collector/integrity"
  find "$STAGE/opt/aim-collector/integrity" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
  rm -rf "$STAGE/opt/aim-collector/integrity/tests" "$STAGE/opt/aim-collector/integrity/testdata" 2>/dev/null || true
fi

if [ -f "$REPO_ROOT/deploy/enforcement/enforcement.enforce.json" ]; then
  mkdir -p "$STAGE/opt/aim-collector/enforcement"
  cp "$REPO_ROOT/deploy/enforcement/enforcement.enforce.json" \
    "$STAGE/opt/aim-collector/enforcement/enforcement.enforce.json"
fi

for f in install.sh uninstall.sh aim-collector-scan.sh aim-collector-heartbeat.sh aim-collector-oob-health.sh; do
  [ -f "$MACOS_DIR/$f" ] || die "missing $MACOS_DIR/$f"
  install -m 0755 "$MACOS_DIR/$f" "$STAGE/opt/aim-collector/$f"
done
install -m 0755 "$MACOS_DIR/install.sh" "$STAGE/usr/local/libexec/aim-collector/install.sh"
install -m 0755 "$MACOS_DIR/uninstall.sh" "$STAGE/usr/local/libexec/aim-collector/uninstall.sh"

for label in com.aimonitoring.collector-scan com.aimonitoring.collector-oob-health; do
  src="$MACOS_DIR/launchd/${label}.plist"
  [ -f "$src" ] || die "missing $src"
  install -m 0644 "$src" "$STAGE/Library/LaunchDaemons/${label}.plist"
done

install -m 0755 "$SCRIPT_DIR/scripts/postinstall" "$SCRIPTS_STAGE/postinstall"
install -m 0755 "$SCRIPT_DIR/scripts/preuninstall" "$SCRIPTS_STAGE/preuninstall"

mkdir -p "$STAGE/etc/aim-collector"
printf '%s\n' "$VERSION" > "$STAGE/etc/aim-collector/version"
chmod 0644 "$STAGE/etc/aim-collector/version"

assert_file() { [ -e "$1" ] || die "stage missing $1"; }
assert_file "$STAGE/opt/aim-collector/aim_collector/__main__.py"
assert_file "$STAGE/opt/aim-collector/install.sh"
assert_file "$STAGE/opt/aim-collector/aim-collector-scan.sh"
assert_file "$STAGE/Library/LaunchDaemons/com.aimonitoring.collector-scan.plist"
assert_file "$STAGE/Library/LaunchDaemons/com.aimonitoring.collector-oob-health.plist"
assert_file "$STAGE/etc/aim-collector/version"
assert_file "$SCRIPTS_STAGE/postinstall"
assert_file "$SCRIPTS_STAGE/preuninstall"

for plist in "$STAGE/Library/LaunchDaemons"/*.plist; do
  if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$plist" >/dev/null || die "plutil failed: $plist"
  elif command -v xmllint >/dev/null 2>&1; then
    xmllint --noout "$plist" || die "xmllint failed: $plist"
  else
    grep -q '<key>Label</key>' "$plist" || die "plist missing Label: $plist"
  fi
done

MANIFEST="$OUT_DIR/stage-manifest.txt"
(
  cd "$STAGE"
  find . -type f | sort
) > "$MANIFEST"
log "staged package root at $STAGE ($(wc -l < "$MANIFEST") files)"
log "manifest: $MANIFEST"

if command -v pkgbuild >/dev/null 2>&1; then
  PKG_PATH="$OUT_DIR/$PKG_NAME"
  PKGBUILD_ARGS=(
    --root "$STAGE"
    --scripts "$SCRIPTS_STAGE"
    --identifier "$IDENTIFIER"
    --version "$VERSION"
    --install-location /
    "$PKG_PATH"
  )
  if [ -n "${AIM_PKG_SIGN_IDENTITY:-}" ]; then
    PKGBUILD_ARGS=(--sign "$AIM_PKG_SIGN_IDENTITY" "${PKGBUILD_ARGS[@]}")
  fi
  pkgbuild "${PKGBUILD_ARGS[@]}"
  log "built $PKG_PATH"
else
  log "pkgbuild not available — stage-only (run on macOS to emit .pkg)"
  printf 'stage-only\npkgbuild=missing\nversion=%s\n' "$VERSION" > "$OUT_DIR/build-mode.txt"
fi

log "done"

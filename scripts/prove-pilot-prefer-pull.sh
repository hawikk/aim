#!/usr/bin/env bash
# AIM-1148 — Prove cold pilot --prefer-pull / --pull path after release-images.
#
# Contract (fail closed):
#   1. AIM_IMAGE_TAG (or AIM_*_IMAGE pins) resolves all four pilot pillar images
#   2. install-pilot uses pull path (mode=pull) — NOT source build fallback
#   3. ingest /healthz + dashboard /api/health → HTTP 200
#   4. mint → aim join token_file → doctor config healthy (AIM-1136 parity)
#   5. wall-clock recorded; warn if pull path > 15 min
#
# Usage:
#   export AIM_IMAGE_TAG=main-5fba351
#   # docker login ghcr.io if packages are private
#   ./scripts/prove-pilot-prefer-pull.sh
#
# Env:
#   AIM_IMAGE_TAG              required unless AIM_*_IMAGE fully set
#   AIM_PROVE_PORT_BASE        default 19000
#   AIM_PROVE_IMAGE_MODE       pull (default, fail if missing) | prefer-pull
#   COMPOSE_PROJECT_NAME       isolated project (default aim-prove-pull-$$)
#   HEALTH_TIMEOUT_SEC         default 600
#   AIM_PROVE_KEEP=1           leave stack up on success
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

red() { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
info() { printf '→ %s\n' "$*"; }
pass() { green "PASS: $*"; }
die() { red "error: $*"; exit 1; }

BASE="${AIM_PROVE_PORT_BASE:-19000}"
export API_PORT=$((BASE + 80))
export DASHBOARD_PORT=$((BASE + 81))
export POSTGRES_PORT=$((BASE + 32))
export MINIO_API_PORT=$((BASE + 90))
export AIM_BIND_ADDR=127.0.0.1
export AIM_DATASTORE_BIND_ADDR=127.0.0.1
export HEALTH_TIMEOUT_SEC="${HEALTH_TIMEOUT_SEC:-600}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-aim-prove-pull-$$}"
export COMPOSE_PROFILES=""
unset COMPOSE_PROFILES || true
export COMPOSE_PROFILES=""

IMAGE_MODE="${AIM_PROVE_IMAGE_MODE:-pull}"
KEEP="${AIM_PROVE_KEEP:-0}"

case "$IMAGE_MODE" in
  pull|prefer-pull) ;;
  *) die "AIM_PROVE_IMAGE_MODE must be pull or prefer-pull (got ${IMAGE_MODE})" ;;
esac

if [[ -z "${AIM_IMAGE_TAG:-}" && -z "${AIM_INGEST_IMAGE:-}" ]]; then
  die "set AIM_IMAGE_TAG=main-<shortsha> (from green release-images) or AIM_*_IMAGE digests"
fi

# Cold-ish: drop any local copies of the target GHCR tags so compose must pull.
if [[ -n "${AIM_IMAGE_TAG:-}" ]]; then
  tag="$AIM_IMAGE_TAG"
  reg="${AIM_IMAGE_REGISTRY:-ghcr.io/hawikk}"
  info "Removing local copies of ${reg}/*:${tag} (force registry pull)"
  for img in aim-ingest aim-api aim-guardrail aim-identity-sync; do
    docker image rm -f "${reg}/${img}:${tag}" >/dev/null 2>&1 || true
  done
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aim-prove-pull.XXXXXX")"
TOKEN_FILE="$WORK/enroll.token"
HOME_DIR="$WORK/home"
LOG="$WORK/install-pilot.log"
mkdir -p "$HOME_DIR"
chmod 700 "$WORK"

cleanup() {
  local rc=$?
  if [[ "$KEEP" == "1" && "$rc" -eq 0 ]]; then
    yellow "KEEP=1 — leaving compose project ${COMPOSE_PROJECT_NAME} up"
  else
    info "teardown: docker compose down -v (project=${COMPOSE_PROJECT_NAME})"
    (
      cd "$ROOT"
      COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" \
        docker compose down -v --remove-orphans >/dev/null 2>&1 || true
    )
  fi
  rm -rf "$WORK" 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

info "AIM-1148 prove cold pull path"
info "  project=${COMPOSE_PROJECT_NAME}"
info "  mode_flag=--${IMAGE_MODE}"
info "  AIM_IMAGE_TAG=${AIM_IMAGE_TAG:-<pins>}"
info "  ports ingest=${API_PORT} dashboard=${DASHBOARD_PORT}"

STARTED_AT=$SECONDS

info "step 1/5: install-pilot --${IMAGE_MODE} --no-mint"
set +e
AIM_INSTALL_PILOT_REDACT_MINT=1 \
  bash "$ROOT/scripts/install-pilot.sh" "--${IMAGE_MODE}" --no-mint \
  2>&1 | tee "$LOG"
install_rc=${PIPESTATUS[0]}
set -e
if [[ "$install_rc" -ne 0 ]]; then
  die "install-pilot non-zero exit (${install_rc})"
fi
pass "install-pilot exited 0"

# Assert pull mode was used (not build fallback).
MODE_LINE="$(grep -E 'wall time: .* \(mode=' "$LOG" | tail -1 || true)"
if [[ -z "$MODE_LINE" ]]; then
  die "install-pilot log missing wall time / mode line"
fi
info "captured: ${MODE_LINE}"
if ! echo "$MODE_LINE" | grep -Eq '\(mode=pull\)'; then
  die "expected mode=pull (images pulled, not rebuilt); got: ${MODE_LINE}"
fi
pass "image path mode=pull (not build / not build-fallback)"

ELAPSED=$((SECONDS - STARTED_AT))
info "wall-clock so far: ${ELAPSED}s"
if (( ELAPSED > 900 )); then
  yellow "warning: cold pull path exceeded 15 min acceptance (${ELAPSED}s)"
else
  pass "wall-clock ≤15 min so far (${ELAPSED}s)"
fi

# 2) health (install-pilot already waited; re-check for log evidence)
info "step 2/5: health endpoints"
ingest_url="http://127.0.0.1:${API_PORT}/healthz"
dash_url="http://127.0.0.1:${DASHBOARD_PORT}/api/health"
ingest_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$ingest_url" || echo 000)"
dash_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$dash_url" || echo 000)"
if [[ "$ingest_code" != "200" || "$dash_code" != "200" ]]; then
  die "health not 200: ingest=${ingest_code} dashboard=${dash_code}"
fi
pass "health 200 (ingest /healthz + dashboard /api/health)"

# 3) mint
info "step 3/5: onboarding token mint"
python3 - "$DASHBOARD_PORT" "$TOKEN_FILE" <<'PY'
import json, os, stat, sys, urllib.error, urllib.request

dash = int(sys.argv[1])
path = sys.argv[2]
url = f"http://127.0.0.1:{dash}/api/onboarding/tokens"
payload = json.dumps({
    "name": "aim-1148-prove-pull",
    "maxEnrollments": 2,
    "expiresInDays": 1,
}).encode()
req = urllib.request.Request(
    url, data=payload, method="POST",
    headers={"Content-Type": "application/json", "Accept": "application/json"},
)
try:
    with urllib.request.urlopen(req, timeout=20) as resp:
        body = json.loads(resp.read().decode() or "{}")
        code = resp.status
except urllib.error.HTTPError as e:
    print(f"mint HTTP {e.code}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"mint error: {type(e).__name__}", file=sys.stderr)
    sys.exit(1)

secret = body.get("secret") or ""
if code not in (200, 201) or len(secret) < 16:
    print(f"mint bad response code={code} secret_len={len(secret)}", file=sys.stderr)
    sys.exit(1)

fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    f.write(secret)
os.chmod(path, 0o600)
print(f"minted prefix={secret[:8]} len={len(secret)} mode={oct(stat.S_IMODE(os.stat(path).st_mode))}")
PY
pass "onboarding mint OK (secret not logged)"

# 4) aim join
info "step 4/5: aim join writes token_file"
VENV="$WORK/venv"
python3 -m venv "$VENV"
if [[ -f "$ROOT/scripts/build_aim_cli.py" ]]; then
  python3 "$ROOT/scripts/build_aim_cli.py" >/dev/null
  WHEEL="$(ls "$ROOT"/packaging/aim-cli/dist/aimonitoring_security-*-py3-none-any.whl 2>/dev/null | head -1 || true)"
  if [[ -n "${WHEEL:-}" ]]; then
    "$VENV/bin/pip" install --quiet --no-index "$WHEEL"
  else
    "$VENV/bin/pip" install --quiet -e "$ROOT/packaging/aim-cli"
  fi
else
  "$VENV/bin/pip" install --quiet -e "$ROOT/packaging/aim-cli"
fi
AIM_BIN="$VENV/bin/aim"
[[ -x "$AIM_BIN" ]] || die "aim binary missing after install"

SECRET="$(cat "$TOKEN_FILE")"
set +e
HOME="$HOME_DIR" AIM_SERVICE_NO_ACTIVATE=1 \
  "$AIM_BIN" join "http://127.0.0.1:${API_PORT}" --token "$SECRET" \
  >"$WORK/join.out" 2>"$WORK/join.err"
join_rc=$?
set -e
SECRET="***"
unset SECRET
if [[ "$join_rc" -ne 0 ]]; then
  sed -E 's/[0-9a-f]{32,}/<redacted>/g' "$WORK/join.err" >&2 || true
  die "aim join non-zero (${join_rc})"
fi

python3 - "$HOME_DIR" <<'PY'
import json, sys
from pathlib import Path
home = Path(sys.argv[1])
state = home / ".aim-collector"
cfg = json.loads((state / "config.json").read_text())
tf = cfg.get("token_file")
if not tf:
    print("config.json missing token_file", file=sys.stderr)
    sys.exit(1)
token_path = Path(tf).expanduser()
expected = (state / "device_token").resolve()
if token_path.resolve() != expected or not token_path.is_file() or len(token_path.read_text().strip()) < 8:
    print("token_file contract failed", file=sys.stderr)
    sys.exit(1)
print(f"token_file ok path={token_path.name}")
PY
pass "aim join wrote token_file → device_token"

# 5) doctor
info "step 5/5: aim doctor --fix (token_file config)"
set +e
HOME="$HOME_DIR" AIM_SERVICE_NO_ACTIVATE=1 \
  "$AIM_BIN" doctor --fix --json \
  >"$WORK/doctor.json" 2>"$WORK/doctor.err"
doctor_rc=$?
set -e
python3 - "$HOME_DIR" "$WORK/doctor.json" <<'PY'
import json, sys
from pathlib import Path
home = Path(sys.argv[1])
doc_path = Path(sys.argv[2])
state = home / ".aim-collector"
cfg = json.loads((state / "config.json").read_text())
tf = cfg.get("token_file") or ""
expected = str((state / "device_token").resolve())
if not tf or Path(tf).expanduser().resolve() != Path(expected):
    print(f"token_file broken after doctor: {tf!r}", file=sys.stderr)
    sys.exit(1)
if not (state / "device_token").is_file():
    print("device_token missing after doctor", file=sys.stderr)
    sys.exit(1)
if doc_path.is_file() and doc_path.stat().st_size > 0:
    try:
        findings = json.loads(doc_path.read_text())
    except json.JSONDecodeError:
        findings = []
    if isinstance(findings, list):
        bad = [
            f for f in findings
            if isinstance(f, dict)
            and f.get("scope") == "config"
            and f.get("level") in ("FAIL", "WARN")
            and not f.get("fixed")
        ]
        if bad:
            print(f"doctor config findings still unhealthy: {bad}", file=sys.stderr)
            sys.exit(1)
print("doctor token_file config OK")
PY
if [[ "$doctor_rc" -ne 0 ]]; then
  yellow "aim doctor exit ${doctor_rc} (token_file config asserted OK; host residuals allowed)"
fi
pass "aim doctor --fix left token_file healthy"

TOTAL=$((SECONDS - STARTED_AT))
echo
green "AIM-1148 cold prefer-pull / pull path GREEN"
echo "  project=${COMPOSE_PROJECT_NAME}"
echo "  AIM_IMAGE_TAG=${AIM_IMAGE_TAG:-<pins>}"
echo "  mode=pull"
echo "  wall_clock_sec=${TOTAL}"
echo "  ingest=${ingest_url} → ${ingest_code}"
echo "  dashboard=${dash_url} → ${dash_code}"
echo "  contract: pull-not-build → health 200 → mint → join token_file → doctor config"
if (( TOTAL > 900 )); then
  yellow "NOTE: exceeded 15 min acceptance target (${TOTAL}s) — investigate network/registry/disk"
fi
exit 0

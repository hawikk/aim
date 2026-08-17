#!/usr/bin/env bash
# AIM-1127 / AIM-1136 — CI smoke: install-pilot → health → mint → join → doctor → token_file.
#
# Proves the product one-shot contract in a clean, isolated compose project:
#   1. ./scripts/install-pilot.sh exits 0
#   2. ingest /healthz and dashboard /api/health return HTTP 200
#   3. POST /api/onboarding/tokens mints a secret (never logged in full)
#   4. aim join writes config.json token_file → device_token with real content
#   5. aim doctor --fix leaves token_file healthy (config scope OK)
#
# Never prints secret values. Failures are non-zero with next-action stderr.
#
# Usage:
#   ./scripts/ci-oneshot-pilot-smoke.sh --self-test   # no Docker (PR-safe checks)
#   ./scripts/ci-oneshot-pilot-smoke.sh               # full live smoke (Docker)
#   ./scripts/ci-oneshot-pilot-smoke.sh --keep        # leave stack up on success
#
# Env:
#   AIM_ONESHOT_NO_BUILD=1     skip compose --build (use existing images)
#   AIM_ONESHOT_PORT_BASE=18000  base for isolated host ports
#   HEALTH_TIMEOUT_SEC         default 900 for cold builds
#   COMPOSE_PROJECT_NAME       default oneshot-smoke-<pid>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SELF_TEST=0
KEEP=0

usage() {
  cat <<'EOF'
AIM-1127 — one-shot pilot CI smoke (install-pilot → health → enroll).

Usage:
  ./scripts/ci-oneshot-pilot-smoke.sh --self-test
  ./scripts/ci-oneshot-pilot-smoke.sh
  ./scripts/ci-oneshot-pilot-smoke.sh --keep
  ./scripts/ci-oneshot-pilot-smoke.sh --help

Flags:
  --self-test   Structural + unit checks only (no Docker, no secrets)
  --keep        Do not docker compose down on success
  -h, --help    Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --self-test) SELF_TEST=1 ;;
    --keep) KEEP=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "error: unknown flag: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

red() { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
info() { printf '→ %s\n' "$*"; }
die() { red "FAIL: $*"; exit 1; }
pass() { green "PASS: $*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# --- self-test: structural contract without Docker --------------------------
self_test() {
  info "self-test: install-pilot + enroll + doctor token_file unit contract"
  [[ -x "$ROOT/scripts/install-pilot.sh" || -f "$ROOT/scripts/install-pilot.sh" ]] \
    || die "scripts/install-pilot.sh missing"
  [[ -f "$ROOT/scripts/demo-stack-up.sh" ]] || die "scripts/demo-stack-up.sh missing"
  [[ -f "$ROOT/scripts/demo-stack-recover.sh" ]] || die "scripts/demo-stack-recover.sh missing"
  [[ -f "$ROOT/scripts/print-device-enroll-oneliner.sh" ]] \
    || die "scripts/print-device-enroll-oneliner.sh missing"
  [[ -f "$ROOT/apps/web/public/enroll.sh" ]] || die "apps/web/public/enroll.sh missing"
  [[ -f "$ROOT/packaging/aim-cli/src/aim/join.py" ]] || die "aim join module missing"
  [[ -f "$ROOT/packaging/aim-cli/src/aim/doctor.py" ]] || die "aim doctor module missing"
  [[ -f "$ROOT/docs/deployment/self-host-quickstart.md" ]] \
    || die "self-host quickstart doc missing"
  [[ -f "$ROOT/deploy/compose/docker-compose.pilot.yml" ]] \
    || die "deploy/compose/docker-compose.pilot.yml missing (AIM-1126)"
  [[ -f "$ROOT/deploy/compose/docker-compose.pull.yml" ]] \
    || die "deploy/compose/docker-compose.pull.yml missing (AIM-1126)"

  local pilot="$ROOT/scripts/install-pilot.sh"
  # install-pilot must refuse github-audit by clearing COMPOSE_PROFILES.
  grep -q 'COMPOSE_PROFILES' "$pilot" \
    || die "install-pilot must manage COMPOSE_PROFILES (no github-audit on pilot path)"
  # Recover path must stay discoverable from install-pilot (LEAA host-kill).
  grep -q 'demo-stack-recover' "$pilot" \
    || die "install-pilot must point operators at demo-stack-recover"
  # Pilot path must not seed demo cohort (no seed-pilot-cohort invocation).
  if grep -q 'seed-pilot-cohort' "$pilot"; then
    die "install-pilot must not seed demo cohort"
  fi
  # Pilot-critical service set must include ingest + api (health + mint contract).
  grep -q 'ingest' "$pilot" || die "install-pilot must start ingest"
  grep -Eq 'api|AIM_API_IMAGE' "$pilot" || die "install-pilot must start api"
  # AIM-1126 image modes (Makefile + enterprise docs).
  for flag in --pull --build --prefer-pull --no-build --no-mint; do
    grep -q -- "$flag" "$pilot" || die "install-pilot must document/accept $flag"
  done
  # AIM-1124: preferred device path is enroll.sh one-liner (not bare aim join).
  grep -q 'print-device-enroll-oneliner.sh' "$pilot" \
    || die "install-pilot must source print-device-enroll-oneliner (AIM-1124)"
  grep -q 'device_enroll_command' "$pilot" \
    || die "install-pilot must call device_enroll_command"
  grep -q 'enroll.sh' "$pilot" || die "install-pilot must mention enroll.sh"
  grep -q 'One-liner (preferred — Python 3.11+, pipx; install + join + doctor)' "$pilot" \
    || die "install-pilot mint path must prefer enroll one-shot label"
  # Health contract endpoints (fail-closed).
  grep -q '/healthz' "$pilot" || die "install-pilot must wait on ingest /healthz"
  grep -q '/api/health' "$pilot" || die "install-pilot must wait on dashboard /api/health"

  # Doc must link this smoke (AIM-1127 / AIM-1136 acceptance).
  grep -q 'ci-oneshot-pilot-smoke' \
    "$ROOT/docs/deployment/self-host-quickstart.md" \
    || die "self-host quickstart must link ci-oneshot-pilot-smoke"

  # enroll.sh static contract (AIM-1124).
  if have python3 && [[ -f "$ROOT/scripts/test_enroll_sh.py" ]]; then
    info "self-test: scripts/test_enroll_sh.py"
    python3 "$ROOT/scripts/test_enroll_sh.py" || die "test_enroll_sh.py failed"
  fi

  # Unit: join always writes token_file.
  if have python3; then
    if [[ -d "$ROOT/packaging/aim-cli/tests" ]]; then
      info "self-test: pytest packaging/aim-cli/tests/test_join.py (token_file)"
      if python3 -c 'import pytest' 2>/dev/null; then
        (cd "$ROOT" && python3 -m pytest packaging/aim-cli/tests/test_join.py -q \
          -k 'token_file or write_user_config' --tb=line)
        if [[ -f "$ROOT/packaging/aim-cli/tests/test_doctor_token_file.py" ]]; then
          info "self-test: pytest packaging/aim-cli/tests/test_doctor_token_file.py"
          (cd "$ROOT" && PYTHONPATH="$ROOT/packaging/aim-cli/src${PYTHONPATH:+:$PYTHONPATH}" \
            python3 -m pytest packaging/aim-cli/tests/test_doctor_token_file.py -q --tb=line)
        fi
      else
        yellow "pytest not installed — checking join.py/doctor.py source for token_file"
        grep -q 'token_file' "$ROOT/packaging/aim-cli/src/aim/join.py" \
          || die "join.py must write token_file"
        grep -q 'token_file' "$ROOT/packaging/aim-cli/src/aim/doctor.py" \
          || die "doctor.py must repair token_file"
      fi
    fi
  fi

  # --help must not require Docker.
  bash "$ROOT/scripts/install-pilot.sh" --help >/dev/null
  bash "$ROOT/scripts/ci-oneshot-pilot-smoke.sh" --help >/dev/null
  bash "$ROOT/scripts/print-device-enroll-oneliner.sh" --help >/dev/null || true

  pass "self-test contract OK"
}

if [[ "$SELF_TEST" -eq 1 ]]; then
  self_test
  exit 0
fi

# --- full live smoke --------------------------------------------------------
need() { have "$1" || die "missing required tool: $1"; }
need docker
need python3
need curl

if ! docker info >/dev/null 2>&1; then
  die "Docker daemon not reachable"
fi
if ! docker compose version >/dev/null 2>&1; then
  die "Docker Compose v2 plugin missing"
fi

BASE="${AIM_ONESHOT_PORT_BASE:-18000}"
# Derive isolated ports from base so concurrent smokes can shift the base.
export API_PORT=$((BASE + 80))
export DASHBOARD_PORT=$((BASE + 81))
export POSTGRES_PORT=$((BASE + 32))
export MINIO_API_PORT=$((BASE + 90))
export GATEHOUSE_PORT=$((BASE + 91))
export AIM_BIND_ADDR=127.0.0.1
export AIM_DATASTORE_BIND_ADDR=127.0.0.1
export HEALTH_TIMEOUT_SEC="${HEALTH_TIMEOUT_SEC:-900}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-oneshot-smoke-$$}"
# Never enable github-audit.
export COMPOSE_PROFILES=""
unset COMPOSE_PROFILES || true
export COMPOSE_PROFILES=""

NO_BUILD_FLAG=()
if [[ "${AIM_ONESHOT_NO_BUILD:-0}" == "1" ]]; then
  NO_BUILD_FLAG=(--no-build)
  export AIM_INSTALL_PILOT_NO_BUILD=1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aim-oneshot-smoke.XXXXXX")"
TOKEN_FILE="$WORK/enroll.token"
HOME_DIR="$WORK/home"
mkdir -p "$HOME_DIR"
chmod 700 "$WORK"

cleanup() {
  local rc=$?
  if [[ "$KEEP" -eq 1 && "$rc" -eq 0 ]]; then
    yellow "KEEP=1 — leaving compose project ${COMPOSE_PROJECT_NAME} up"
  else
    info "teardown: docker compose down -v (project=${COMPOSE_PROJECT_NAME})"
    (
      cd "$ROOT"
      COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" \
        docker compose down -v --remove-orphans >/dev/null 2>&1 || true
    )
  fi
  # Always scrub token material.
  rm -rf "$WORK" 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

info "oneshot smoke project=${COMPOSE_PROJECT_NAME}"
info "ports ingest=${API_PORT} dashboard=${DASHBOARD_PORT} (bind ${AIM_BIND_ADDR})"

# 1) install-pilot (no mint — we mint redacted below)
info "step 1/5: install-pilot"
set +e
AIM_INSTALL_PILOT_REDACT_MINT=1 \
  bash "$ROOT/scripts/install-pilot.sh" --no-mint "${NO_BUILD_FLAG[@]}"
install_rc=$?
set -e
if [[ "$install_rc" -ne 0 ]]; then
  die "install-pilot non-zero exit (${install_rc}) — one-shot control plane regressing"
fi
pass "install-pilot exited 0"

# 2) health endpoints
info "step 2/5: health endpoints"
ingest_url="http://127.0.0.1:${API_PORT}/healthz"
dash_url="http://127.0.0.1:${DASHBOARD_PORT}/api/health"
ingest_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$ingest_url" || echo 000)"
dash_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$dash_url" || echo 000)"
if [[ "$ingest_code" != "200" || "$dash_code" != "200" ]]; then
  die "health not 200: ingest=${ingest_code} dashboard=${dash_code}"
fi
pass "health 200 (ingest + dashboard)"

# 3) onboarding mint (secret to 0600 file only; log prefix only)
info "step 3/5: onboarding token mint"
python3 - "$DASHBOARD_PORT" "$TOKEN_FILE" <<'PY'
import json, os, stat, sys, urllib.error, urllib.request

dash = int(sys.argv[1])
path = sys.argv[2]
url = f"http://127.0.0.1:{dash}/api/onboarding/tokens"
payload = json.dumps({
    "name": "ci-oneshot-smoke",
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
    raw = e.read().decode(errors="replace")[:200]
    # Never include possible secret-shaped substrings beyond status.
    print(f"mint HTTP {e.code}", file=sys.stderr)
    print(raw[:120].replace("\n", " "), file=sys.stderr)
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
# Metadata only — never the secret.
print(f"minted prefix={secret[:8]} len={len(secret)} mode={oct(stat.S_IMODE(os.stat(path).st_mode))}")
PY
pass "onboarding mint OK (secret not logged)"

# 4) aim join → token_file
info "step 4/5: aim join writes token_file"
# Prefer building the wheel offline (stdlib build script) then installing.
VENV="$WORK/venv"
python3 -m venv "$VENV"
# Build wheel when possible; else editable install from packaging tree.
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
# Clear secret variable from bash history path: use file redirect via env file.
# Join must not echo the token; AIM_SERVICE_NO_ACTIVATE avoids systemd on runner.
set +e
HOME="$HOME_DIR" AIM_SERVICE_NO_ACTIVATE=1 \
  "$AIM_BIN" join "http://127.0.0.1:${API_PORT}" --token "$SECRET" \
  >"$WORK/join.out" 2>"$WORK/join.err"
join_rc=$?
set -e
# Scrub secret from shell memory as much as bash allows.
SECRET="***"
unset SECRET

if [[ "$join_rc" -ne 0 ]]; then
  red "aim join failed (exit ${join_rc})"
  # Show join stderr without token-shaped long hex if present.
  sed -E 's/[0-9a-f]{32,}/<redacted>/g' "$WORK/join.err" >&2 || true
  die "aim join non-zero"
fi

# Assert token_file contract (P3).
python3 - "$HOME_DIR" <<'PY'
import json, os, sys
from pathlib import Path

home = Path(sys.argv[1])
state = home / ".aim-collector"
cfg_path = state / "config.json"
if not cfg_path.is_file():
    print("missing config.json", file=sys.stderr)
    sys.exit(1)
cfg = json.loads(cfg_path.read_text())
tf = cfg.get("token_file")
if not tf:
    print("config.json missing token_file key (P3 regression)", file=sys.stderr)
    sys.exit(1)
token_path = Path(tf).expanduser()
expected = (state / "device_token").resolve()
if token_path.resolve() != expected:
    print(f"token_file path mismatch: {token_path} != {expected}", file=sys.stderr)
    sys.exit(1)
if not token_path.is_file():
    print(f"token_file path does not exist: {token_path}", file=sys.stderr)
    sys.exit(1)
body = token_path.read_text().strip()
if len(body) < 8:
    print("device_token empty or too short", file=sys.stderr)
    sys.exit(1)
mode = oct(token_path.stat().st_mode & 0o777)
print(f"token_file ok path={token_path.name} mode={mode} len={len(body)}")
# Never print token body.
PY
pass "aim join wrote token_file → device_token"

# 5) aim doctor --fix must keep token_file healthy (config scope).
# Residual WARN/FAIL on auto-start (no user systemd bus) or enforcement
# bundle is host-environment noise — not a clean-path product regression.
# We fail closed only if config/token_file is unhealthy after --fix.
info "step 5/5: aim doctor --fix (token_file config)"
set +e
HOME="$HOME_DIR" AIM_SERVICE_NO_ACTIVATE=1 \
  "$AIM_BIN" doctor --fix --json \
  >"$WORK/doctor.json" 2>"$WORK/doctor.err"
doctor_rc=$?
set -e
# Always assert token_file still correct after doctor.
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
tok = state / "device_token"
if not tok.is_file() or len(tok.read_text().strip()) < 8:
    print("device_token missing/empty after doctor", file=sys.stderr)
    sys.exit(1)

# If doctor produced JSON, require no FAIL on config scope.
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
# doctor may exit non-zero for host auto-start/enforcement residuals; log only.
if [[ "$doctor_rc" -ne 0 ]]; then
  yellow "aim doctor exit ${doctor_rc} (token_file config asserted OK; host residuals allowed)"
  sed -E 's/[0-9a-f]{32,}/<redacted>/g' "$WORK/doctor.err" >&2 || true
fi
pass "aim doctor --fix left token_file healthy"

echo
green "AIM-1127/AIM-1136 oneshot pilot smoke GREEN"
echo "  project=${COMPOSE_PROJECT_NAME}"
echo "  ingest=${ingest_url}"
echo "  dashboard=${dash_url}"
echo "  contract: install-pilot → health 200 → mint → join token_file → doctor config"
exit 0

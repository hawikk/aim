#!/usr/bin/env bash
# Private-network pilot control-plane one-shot.
#
# Collapses the LEAA multi-day pilot install into a single product entrypoint:
#
#   git clone … && cd ai-monitoring
#   ./scripts/install-pilot.sh
#   # → ingest /healthz + dashboard /api/health = 200
# # → prints enroll.sh one-liner (install + join + doctor)
#
# Prefer prebuilt GHCR (or pin-file) images so a clean host skips the 10–20 min
# cold `compose build`. Fall back to source build for contributors
# or when images are unavailable.
#
# Pilot defaults:
#   - AIM_BIND_ADDR=0.0.0.0          (private NIC / overlay; CI may override)
#   - AIM_DATASTORE_BIND_ADDR=127.0.0.1
#   - no demo seed
#   - no github-audit profile (no GITHUB_TOKEN required — P2)
#   - pilot compose filter (gatehouse/sentinel/shadow-ai not cold-built)
#   - clear health timeout + next-action errors
#
# Never prints secret values in CI. Operator path may show the enroll token
# once on stdout when minting is enabled.
#
# Usage:
#   ./scripts/install-pilot.sh                 # prefer-pull, fall back to build
#   ./scripts/install-pilot.sh --pull          # pull only (fail if images missing)
#   ./scripts/install-pilot.sh --build         # force source build
#   ./scripts/install-pilot.sh --no-build      # compose up without --build (CI reuse)
#   ./scripts/install-pilot.sh --no-mint       # skip onboarding mint (CI redacts separately)
#   ./scripts/install-pilot.sh --preflight-only
#   ./scripts/install-pilot.sh --full-stack    # omit docker-compose.pilot.yml
#   ./scripts/install-pilot.sh --help
#
# Docs:
#   docs/deployment/self-host-quickstart.md
#   docs/deployment/air-gapped-install.md
#   scripts/ci-oneshot-pilot-smoke.sh   (CI contract: install → health → enroll)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- pilot defaults (env may override; CI smoke pins loopback + free ports) -
export AIM_BIND_ADDR="${AIM_BIND_ADDR:-0.0.0.0}"
export AIM_DATASTORE_BIND_ADDR="${AIM_DATASTORE_BIND_ADDR:-127.0.0.1}"
# Never enable the github-audit profile on the pilot path (P2 / LEAA).
unset COMPOSE_PROFILES || true
export COMPOSE_PROFILES=""

BIND_ADDR="${AIM_BIND_ADDR}"
DATASTORE_BIND="${AIM_DATASTORE_BIND_ADDR}"
API_PORT="${API_PORT:-8080}"
DASHBOARD_PORT="${DASHBOARD_PORT:-8081}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
MINIO_API_PORT="${MINIO_API_PORT:-9000}"
HEALTH_TIMEOUT_SEC="${HEALTH_TIMEOUT_SEC:-600}"
# Health + mint always hit loopback (stack may publish on 0.0.0.0).
HEALTH_HOST="${AIM_HEALTH_HOST:-127.0.0.1}"
export API_PORT DASHBOARD_PORT POSTGRES_PORT MINIO_API_PORT HEALTH_TIMEOUT_SEC

IMAGE_MODE="${AIM_PILOT_IMAGE_MODE:-prefer-pull}" # prefer-pull | pull | build | no-build
PREFLIGHT_ONLY=0
PILOT_COMPOSE=1
MINT=1
REGISTRY="${AIM_IMAGE_REGISTRY:-ghcr.io/hawikk}"
PIN_FILE="${AIM_IMAGE_PIN_FILE:-$ROOT/deploy/compose/images.pin.env}"

usage() {
  cat <<'EOF'
AIM pilot control-plane one-shot.

Happy path: clone → ./scripts/install-pilot.sh → health green → enroll.sh one-liner

Usage:
  ./scripts/install-pilot.sh                 # prefer prebuilt images; build fallback
  ./scripts/install-pilot.sh --pull          # require prebuilt images (no build)
  ./scripts/install-pilot.sh --build         # force source build (contributors)
  ./scripts/install-pilot.sh --no-build      # compose up without --build (CI reuse)
  ./scripts/install-pilot.sh --no-mint       # do not mint; print manual enroll path
  ./scripts/install-pilot.sh --preflight-only
  ./scripts/install-pilot.sh --full-stack
  ./scripts/install-pilot.sh --help

Flags:
  --pull             Pull GHCR/pin images only; exit non-zero if pull fails
  --build            Force `docker compose up --build` (skip image pull path)
  --prefer-pull      Try pull, fall back to build (default)
  --no-build         Start existing local images without --build (CI / warm host)
  --no-mint          Skip POST /api/onboarding/tokens (CI smoke mints redacted)
  --full-stack       Do not apply docker-compose.pilot.yml (start all default services)
  --preflight-only   Docker / ports / disk hints only
  -h, --help         Show this help

Env:
  AIM_IMAGE_TAG              e.g. main-498275d or v1.4.0 (tag mode)
  AIM_IMAGE_REGISTRY         default ghcr.io/hawikk
  AIM_INGEST_IMAGE, AIM_API_IMAGE, AIM_GUARDRAIL_IMAGE, AIM_IDENTITY_SYNC_IMAGE
                             full refs (tag or @sha256: digest) — preferred pins
  AIM_IMAGE_PIN_FILE         path to pin env file (default deploy/compose/images.pin.env)
  AIM_BIND_ADDR              default 0.0.0.0 for remote collectors
  AIM_DATASTORE_BIND_ADDR    default 127.0.0.1
  AIM_PUBLIC_HOST            host printed in enroll command (NetBird IP / DNS)
  AIM_INGEST_PUBLIC_URL      full ingest base URL override for enroll one-liner
  API_PORT, DASHBOARD_PORT, POSTGRES_PORT, MINIO_API_PORT
  HEALTH_TIMEOUT_SEC         default 600
  COMPOSE_PROJECT_NAME       isolate compose projects (CI smoke sets this)
  AIM_PILOT_IMAGE_MODE       prefer-pull | pull | build | no-build
  AIM_INSTALL_PILOT_NO_BUILD=1  same as --no-build
  AIM_INSTALL_PILOT_REDACT_MINT=1  mint OK but never print enroll secret (CI)

Docs:
  docs/deployment/self-host-quickstart.md
  docs/deployment/air-gapped-install.md
  scripts/ci-oneshot-pilot-smoke.sh   (CI contract: install → health → enroll)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pull) IMAGE_MODE=pull ;;
    --build) IMAGE_MODE=build ;;
    --prefer-pull) IMAGE_MODE=prefer-pull ;;
    --no-build) IMAGE_MODE=no-build ;;
    --no-mint) MINT=0 ;;
    --full-stack) PILOT_COMPOSE=0 ;;
    --preflight-only) PREFLIGHT_ONLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "error: unknown flag: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ "${AIM_INSTALL_PILOT_NO_BUILD:-0}" == "1" ]]; then
  IMAGE_MODE=no-build
fi

red() { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
info() { printf '→ %s\n' "$*"; }
die() { red "error: $*"; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

http_ok() {
  local url="$1"
  if have curl; then
    curl -fsS --max-time 3 "$url" >/dev/null 2>&1
    return $?
  fi
  python3 - "$url" <<'PY' 2>/dev/null
import sys, urllib.request
url = sys.argv[1]
try:
    with urllib.request.urlopen(url, timeout=3) as r:
        sys.exit(0 if 200 <= r.status < 300 else 1)
except Exception:
    sys.exit(1)
PY
}

http_code() {
  local url="$1"
  if have curl; then
    curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null || echo "000"
    return 0
  fi
  python3 - "$url" <<'PY' 2>/dev/null || echo "000"
import sys, urllib.request
url = sys.argv[1]
try:
    with urllib.request.urlopen(url, timeout=5) as r:
        print(r.status)
except Exception:
    print("000")
PY
}

port_in_use() {
  local host="$1" port="$2"
  if have python3; then
    python3 - "$host" "$port" <<'PY' 2>/dev/null
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.4)
try:
    s.connect((host, port))
except OSError:
    sys.exit(1)
else:
    sys.exit(0)
finally:
    s.close()
PY
    return $?
  fi
  return 1
}

bytes_free() {
  df -PB1 "$ROOT" 2>/dev/null | awk 'NR==2 {print $4}' || df -P "$ROOT" | awk 'NR==2 {print $4 * 1024}'
}

detect_public_host() {
  if [[ -n "${AIM_PUBLIC_HOST:-}" ]]; then
    echo "$AIM_PUBLIC_HOST"
    return 0
  fi
  if [[ -n "${AIM_INGEST_HOST:-}" ]]; then
    echo "$AIM_INGEST_HOST"
    return 0
  fi
  # Prefer a non-loopback global address (NetBird / private NIC) when present.
  if have ip; then
    local cand
    cand="$(ip -4 -o addr show scope global 2>/dev/null \
      | awk '{print $4}' | cut -d/ -f1 | head -1 || true)"
    if [[ -n "$cand" ]]; then
      echo "$cand"
      return 0
    fi
  fi
  if have hostname; then
    local hn
    hn="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
    if [[ -n "$hn" && "$hn" != "localhost" ]]; then
      echo "$hn"
      return 0
    fi
  fi
  echo "127.0.0.1"
}

fail_hints() {
  cat >&2 <<EOF

  Next actions:
    1. docker compose -f docker-compose.yml -f deploy/compose/docker-compose.pilot.yml ps
    2. docker compose -f docker-compose.yml -f deploy/compose/docker-compose.pilot.yml logs --tail=80 ingest api
    3. If Docker data-root looks corrupt after a host replace:
         ./scripts/demo-stack-recover.sh
    4. Re-run: ./scripts/install-pilot.sh
  Docs: docs/deployment/self-host-quickstart.md
  Recover helper: scripts/demo-stack-up.sh --preflight-only  (Docker/ports only)
EOF
}

# --- preflight ---------------------------------------------------------------
preflight() {
  info "Preflight (Docker, Compose, ports, disk)"
  have docker || die "docker not found — install Docker Engine + Compose plugin"
  docker info >/dev/null 2>&1 || die "docker daemon not reachable (is Docker running?)"
  docker compose version >/dev/null 2>&1 || die "docker compose plugin missing"
  have curl || die "curl required for health checks"

  local free
  free="$(bytes_free || echo 0)"
  if [[ "$free" =~ ^[0-9]+$ ]] && (( free < 8 * 1024 * 1024 * 1024 )); then
    yellow "warning: less than ~8 GiB free on $(df -P "$ROOT" | awk 'NR==2{print $6}') (free=${free} bytes)"
    yellow "         cold builds and image pulls often flake on disk; free space or use --pull"
  fi

  # If the stack is already healthy on the chosen ports, skip conflict fail.
  INGEST_URL="http://${HEALTH_HOST}:${API_PORT}/healthz"
  DASH_URL="http://${HEALTH_HOST}:${DASHBOARD_PORT}/api/health"
  if http_ok "$INGEST_URL" && http_ok "$DASH_URL"; then
    green "preflight ok (stack already healthy on :${API_PORT}/:${DASHBOARD_PORT})"
    return 0
  fi

  local conflicts=0
  for spec in \
    "${BIND_ADDR}:${API_PORT}:ingest" \
    "${BIND_ADDR}:${DASHBOARD_PORT}:dashboard/api" \
    "${DATASTORE_BIND}:${POSTGRES_PORT}:postgres" \
    "${DATASTORE_BIND}:${MINIO_API_PORT}:minio"; do
    IFS=: read -r host port label <<<"$spec"
    local probe_host="$host"
    [[ "$host" == "0.0.0.0" ]] && probe_host="127.0.0.1"
    if port_in_use "$probe_host" "$port"; then
      red "port in use: ${host}:${port} (${label})"
      conflicts=1
    fi
  done
  if (( conflicts )); then
    die "free the ports above or override API_PORT / DASHBOARD_PORT / POSTGRES_PORT / MINIO_API_PORT"
  fi

  green "preflight ok"
}

# --- image resolution --------------------------------------------------------
load_pin_file() {
  if [[ -f "$PIN_FILE" ]]; then
    info "Loading image pins from ${PIN_FILE#"$ROOT"/}"
    # shellcheck disable=SC1090
    set -a
    # shellcheck source=/dev/null
    . "$PIN_FILE"
    set +a
    REGISTRY="${AIM_IMAGE_REGISTRY:-$REGISTRY}"
  fi
}

resolve_tag_images() {
  local tag="${AIM_IMAGE_TAG:-}"
  if [[ -z "$tag" ]]; then
    return 1
  fi
  export AIM_INGEST_IMAGE="${AIM_INGEST_IMAGE:-${REGISTRY}/aim-ingest:${tag}}"
  export AIM_API_IMAGE="${AIM_API_IMAGE:-${REGISTRY}/aim-api:${tag}}"
  export AIM_GUARDRAIL_IMAGE="${AIM_GUARDRAIL_IMAGE:-${REGISTRY}/aim-guardrail:${tag}}"
  export AIM_IDENTITY_SYNC_IMAGE="${AIM_IDENTITY_SYNC_IMAGE:-${REGISTRY}/aim-identity-sync:${tag}}"
  export AIM_GATEHOUSE_IMAGE="${AIM_GATEHOUSE_IMAGE:-${REGISTRY}/aim-gatehouse:${tag}}"
  export AIM_SENTINEL_IMAGE="${AIM_SENTINEL_IMAGE:-${REGISTRY}/aim-sentinel:${tag}}"
  export AIM_HYGIENE_IMAGE="${AIM_HYGIENE_IMAGE:-${REGISTRY}/aim-hygiene:${tag}}"
  export AIM_IMAGE_TAG="$tag"
  export AIM_IMAGE_REGISTRY="$REGISTRY"
  return 0
}

pilot_images_resolved() {
  [[ -n "${AIM_INGEST_IMAGE:-}" && -n "${AIM_API_IMAGE:-}" \
    && -n "${AIM_GUARDRAIL_IMAGE:-}" && -n "${AIM_IDENTITY_SYNC_IMAGE:-}" ]]
}

print_image_plan() {
  info "Image plan (pilot set)"
  printf '  ingest:         %s\n' "${AIM_INGEST_IMAGE}"
  printf '  api/dashboard:  %s\n' "${AIM_API_IMAGE}"
  printf '  guardrail:      %s\n' "${AIM_GUARDRAIL_IMAGE}"
  printf '  identity-sync:  %s\n' "${AIM_IDENTITY_SYNC_IMAGE}"
}

compose_base_args() {
  COMPOSE_ARGS=(-f docker-compose.yml)
  if (( PILOT_COMPOSE )); then
    COMPOSE_ARGS+=(-f deploy/compose/docker-compose.pilot.yml)
  fi
}

compose_pull_args() {
  compose_base_args
  COMPOSE_ARGS+=(-f deploy/compose/docker-compose.pull.yml)
}

ensure_env() {
  if [[ ! -f .env ]]; then
    info "Creating .env from .env.example"
    cp .env.example .env
    chmod 600 .env 2>/dev/null || true
  fi
  # Pilot knobs — write only if missing (do not clobber operator secrets).
  if have python3; then
    AIM_BIND_ADDR="$BIND_ADDR" AIM_DATASTORE_BIND_ADDR="$DATASTORE_BIND" \
      python3 - <<'PY'
import os
from pathlib import Path
path = Path(".env")
text = path.read_text(encoding="utf-8") if path.exists() else ""
lines = text.splitlines()
keys = {
    "AIM_BIND_ADDR": os.environ.get("AIM_BIND_ADDR", "0.0.0.0"),
    "AIM_DATASTORE_BIND_ADDR": os.environ.get("AIM_DATASTORE_BIND_ADDR", "127.0.0.1"),
}
for key, val in keys.items():
    found = False
    out = []
    for line in lines:
        if line.startswith(f"{key}=") or line.startswith(f"#{key}="):
            if line.startswith(f"{key}="):
                found = True
                out.append(line)
            else:
                out.append(line)
        else:
            out.append(line)
    if not found:
        out.append(f"{key}={val}")
    lines = out
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
  fi
  # Mint stack-owned secrets (gatehouse etc.) when missing — never print values.
  if [[ -f scripts/ensure_dev_env.py ]]; then
    python3 scripts/ensure_dev_env.py || true
  fi
}

wait_health() {
  local deadline=$(( SECONDS + HEALTH_TIMEOUT_SEC ))
  local ingest_url="http://${HEALTH_HOST}:${API_PORT}/healthz"
  local dash_url="http://${HEALTH_HOST}:${DASHBOARD_PORT}/api/health"
  info "Waiting for health (timeout ${HEALTH_TIMEOUT_SEC}s)"
  info "  ingest:    $ingest_url"
  info "  dashboard: $dash_url"
  while (( SECONDS < deadline )); do
    if http_ok "$ingest_url" && http_ok "$dash_url"; then
      green "install-pilot: health OK (ingest + dashboard HTTP 200)"
      return 0
    fi
    sleep 3
  done
  local ingest_code dash_code
  ingest_code="$(http_code "$ingest_url")"
  dash_code="$(http_code "$dash_url")"
  red "install-pilot: health timeout ingest=${ingest_code} dashboard=${dash_code}"
  fail_hints
  return 1
}

do_pull_up() {
  compose_pull_args
  print_image_plan
  info "Pulling prebuilt images"
  if ! docker compose "${COMPOSE_ARGS[@]}" pull; then
    return 1
  fi
  info "Starting pilot stack (pull path, no --build)"
  AIM_BIND_ADDR="$BIND_ADDR" AIM_DATASTORE_BIND_ADDR="$DATASTORE_BIND" \
    COMPOSE_PROFILES="" \
    docker compose "${COMPOSE_ARGS[@]}" up -d --pull missing
}

do_build_up() {
  compose_base_args
  info "Starting pilot stack (source build path)"
  yellow "note: cold compose build is often 10–20 min and can flake on low disk/RAM"
  AIM_BIND_ADDR="$BIND_ADDR" AIM_DATASTORE_BIND_ADDR="$DATASTORE_BIND" \
    COMPOSE_PROFILES="" \
    docker compose "${COMPOSE_ARGS[@]}" up -d --build
}

do_nobuild_up() {
  compose_base_args
  info "Starting pilot stack (no-build — reuse existing images)"
  AIM_BIND_ADDR="$BIND_ADDR" AIM_DATASTORE_BIND_ADDR="$DATASTORE_BIND" \
    COMPOSE_PROFILES="" \
    docker compose "${COMPOSE_ARGS[@]}" up -d
}

# --- onboarding mint + enroll.sh one-liner ------------------------
print_manual_mint_path() {
  local dash="$1"
  local ingest_public="$2"
  local public_host
  public_host="$(detect_public_host)"
  # shellcheck source=scripts/print-device-enroll-oneliner.sh
  source "$ROOT/scripts/print-device-enroll-oneliner.sh"
  local enroll_placeholder
  enroll_placeholder="$(
    device_enroll_command --host "$public_host" --token '<enrollment-secret>'
  )"
  cat <<EOF

  Personal-mode mint path (run on the control plane host):
    curl -sS -X POST ${dash}/api/onboarding/tokens \\
      -H 'Content-Type: application/json' \\
      -d '{"name":"pilot","maxEnrollments":50,"expiresInDays":14}'
    # Response field "secret" is the cleartext enroll token (once).
    # Then on each engineer device (preferred one-shot —):
    #   ${enroll_placeholder}
    # Or if aim is already installed:
    #   aim join ${ingest_public} --token <secret>
    #   aim doctor --fix && aim status

  Dashboard (browser, personal/local-admin — no SSO when AIM_OIDC_* unset):
    http://${HEALTH_HOST}:${DASHBOARD_PORT}
    Open Onboarding and mint from the UI if API mint is denied.

EOF
}

mint_onboarding_token() {
  local dash="http://${HEALTH_HOST}:${DASHBOARD_PORT}"
  local ingest_public="http://$(detect_public_host):${API_PORT}"
  if [[ -n "${AIM_INGEST_PUBLIC_URL:-}" ]]; then
    ingest_public="${AIM_INGEST_PUBLIC_URL%/}"
  fi
  local redact="${AIM_INSTALL_PILOT_REDACT_MINT:-0}"

  info "Minting onboarding enrollment token (personal / local-admin mode)"
  if ! have curl && ! have python3; then
    yellow "Neither curl nor python3 available to mint token."
    print_manual_mint_path "$dash" "$ingest_public"
    return 0
  fi

  local body resp_file http_code
  resp_file="$(mktemp)"
  body='{"name":"pilot-install","maxEnrollments":50,"expiresInDays":14}'
  http_code=""

  if have curl; then
    http_code="$(
      curl -sS -o "$resp_file" -w '%{http_code}' \
        -X POST "${dash}/api/onboarding/tokens" \
        -H 'Content-Type: application/json' \
        -d "$body" \
        --max-time 15 2>/dev/null || echo "000"
    )"
  else
    http_code="$(
      python3 - "$dash" "$body" "$resp_file" <<'PY' 2>/dev/null || echo "000"
import json, sys, urllib.request, urllib.error
dash, body, path = sys.argv[1], sys.argv[2], sys.argv[3]
req = urllib.request.Request(
    dash.rstrip("/") + "/api/onboarding/tokens",
    data=body.encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=15) as r:
        open(path, "w", encoding="utf-8").write(r.read().decode())
        print(r.status)
except urllib.error.HTTPError as e:
    open(path, "w", encoding="utf-8").write(e.read().decode() if e.fp else "")
    print(e.code)
except Exception:
    print("000")
PY
    )"
  fi

  if [[ "$http_code" != "201" && "$http_code" != "200" ]]; then
    yellow "install-pilot: onboarding mint failed (HTTP ${http_code:-unknown})"
    yellow "  dashboard may need DB migrations / personal mode; mint deferred"
    print_manual_mint_path "$dash" "$ingest_public"
    rm -f "$resp_file"
    return 0
  fi

  local secret="" aim_join=""
  local public_host
  public_host="$(detect_public_host)"
  # shellcheck source=scripts/print-device-enroll-oneliner.sh
  source "$ROOT/scripts/print-device-enroll-oneliner.sh"

  if have python3; then
    local parsed
    parsed="$(
      python3 - "$resp_file" "$ingest_public" <<'PY'
import json, sys
path, ingest = sys.argv[1], sys.argv[2]
data = json.load(open(path, encoding="utf-8"))
secret = (data.get("secret") or "").replace("\n", "")
if not secret:
    sys.exit(0)
print(secret)
print(f"aim join {ingest} --token {secret}")
PY
    )" || true
    if [[ -n "$parsed" ]]; then
      secret="$(printf '%s\n' "$parsed" | sed -n '1p')"
      aim_join="$(printf '%s\n' "$parsed" | sed -n '2p')"
    fi
  else
    secret="$(grep -oE '"secret"[[:space:]]*:[[:space:]]*"[^"]+"' "$resp_file" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
    if [[ -n "$secret" ]]; then
      aim_join="aim join ${ingest_public} --token ${secret}"
    fi
  fi
  rm -f "$resp_file"

  if [[ -z "${secret:-}" ]]; then
    yellow "Mint response missing secret field."
    print_manual_mint_path "$dash" "$ingest_public"
    return 0
  fi

  green "install-pilot: onboarding token minted (prefix=${secret:0:8} len=${#secret})"

  if [[ "$redact" == "1" ]]; then
    info "install-pilot: enroll secret redacted (CI mode)"
    return 0
  fi

  # Prefer enroll.sh one-shot (install + join + doctor + token_file verify).
  # Token is printed only to this TTY; enroll.sh itself never logs it.
  local enroll_cmd
  enroll_cmd="$(
    device_enroll_command --host "$public_host" --token "$secret"
  )"

  cat <<EOF

══════════════════════════════════════════════════════════════════
  Device enroll (minted once — store offline; not re-shown)
══════════════════════════════════════════════════════════════════

  Ingest (collector target):
    ${ingest_public}

  One-liner (preferred — Python 3.11+, pipx; install + join + doctor):
    ${enroll_cmd}

  Alternate (aim already on PATH):
    ${aim_join}
    aim doctor --fix && aim status

  Offline wheel (air-gap / private mirror):
    AIM_WHEEL=/path/to/aimonitoring_security-*.whl bash enroll.sh \\
      --url ${ingest_public} --token <secret-from-above>

  Proof after enroll: config.json must contain token_file → device_token (P3)

  Override printed host next time:
    AIM_PUBLIC_HOST=<netbird-ip-or-dns> ./scripts/install-pilot.sh

  Mint another token later (personal mode, loopback on control plane):
    curl -sS -X POST http://${HEALTH_HOST}:${DASHBOARD_PORT}/api/onboarding/tokens \\
      -H 'Content-Type: application/json' \\
      -d '{"name":"pilot-more","maxEnrollments":50,"expiresInDays":14}'

══════════════════════════════════════════════════════════════════
EOF
}

success_banner() {
  local host
  host="$(detect_public_host)"
  cat <<EOF

$(green "Pilot control plane is up.")

  Ingest:     http://${host}:${API_PORT}/healthz
  Dashboard:  http://${host}:${DASHBOARD_PORT}/
  Local check: http://${HEALTH_HOST}:${API_PORT}/healthz
               http://${HEALTH_HOST}:${DASHBOARD_PORT}/api/health

  Bind: AIM_BIND_ADDR=${BIND_ADDR}  datastores=${DATASTORE_BIND}
  Demo seed: off   github-audit profile: off (COMPOSE_PROFILES='')

  Tear down:
    docker compose -f docker-compose.yml -f deploy/compose/docker-compose.pilot.yml down
    docker compose -f docker-compose.yml -f deploy/compose/docker-compose.pilot.yml down -v

  Corrupt Docker after abrupt host kill:
    ./scripts/demo-stack-recover.sh

  Docs:
    docs/deployment/self-host-quickstart.md
    docs/deployment/air-gapped-install.md
EOF
}

# --- main --------------------------------------------------------------------
info "install-pilot: AIM_BIND_ADDR=${BIND_ADDR} API_PORT=${API_PORT} DASHBOARD_PORT=${DASHBOARD_PORT}"
info "install-pilot: COMPOSE_PROFILES='' (github-audit profile off)"
info "install-pilot: image mode=${IMAGE_MODE} pilot_compose=${PILOT_COMPOSE}"

preflight
if (( PREFLIGHT_ONLY )); then
  green "install-pilot: preflight OK"
  exit 0
fi

INGEST_URL="http://${HEALTH_HOST}:${API_PORT}/healthz"
DASH_URL="http://${HEALTH_HOST}:${DASHBOARD_PORT}/api/health"

ensure_env
load_pin_file

STARTED_AT=$SECONDS
MODE_USED=""

if http_ok "$INGEST_URL" && http_ok "$DASH_URL"; then
  yellow "install-pilot: stack already healthy on :${API_PORT}/:${DASHBOARD_PORT} — reusing"
  MODE_USED=reuse
else
  case "$IMAGE_MODE" in
    build)
      set +e
      do_build_up
      up_rc=$?
      set -e
      [[ "$up_rc" -eq 0 ]] || { red "install-pilot: compose up --build failed (exit ${up_rc})"; fail_hints; exit "$up_rc"; }
      MODE_USED=build
      ;;
    no-build)
      set +e
      do_nobuild_up
      up_rc=$?
      set -e
      [[ "$up_rc" -eq 0 ]] || { red "install-pilot: compose up (no-build) failed (exit ${up_rc})"; fail_hints; exit "$up_rc"; }
      MODE_USED=no-build
      ;;
    pull)
      pilot_images_resolved || resolve_tag_images || \
        die "pull mode needs AIM_*_IMAGE pins, images.pin.env, or AIM_IMAGE_TAG (see docs/deployment/prebuilt-images.md)"
      pilot_images_resolved || die "pilot image refs incomplete after resolution"
      set +e
      do_pull_up
      up_rc=$?
      set -e
      [[ "$up_rc" -eq 0 ]] || die "image pull/up failed — check GHCR auth (docker login ghcr.io) and tags"
      MODE_USED=pull
      ;;
    prefer-pull)
      if pilot_images_resolved || resolve_tag_images; then
        if pilot_images_resolved && do_pull_up; then
          MODE_USED=pull
        else
          yellow "prebuilt pull failed or incomplete — falling back to source build"
          set +e
          do_build_up
          up_rc=$?
          set -e
          [[ "$up_rc" -eq 0 ]] || { red "install-pilot: compose up --build failed (exit ${up_rc})"; fail_hints; exit "$up_rc"; }
          MODE_USED=build-fallback
        fi
      else
        yellow "no AIM_IMAGE_TAG / pin file / AIM_*_IMAGE — using source build"
        yellow "tip: set AIM_IMAGE_TAG=main-<shortsha> from release-images for ≤15 min cold path"
        set +e
        do_build_up
        up_rc=$?
        set -e
        [[ "$up_rc" -eq 0 ]] || { red "install-pilot: compose up --build failed (exit ${up_rc})"; fail_hints; exit "$up_rc"; }
        MODE_USED=build
      fi
      ;;
    *)
      die "unknown AIM_PILOT_IMAGE_MODE=${IMAGE_MODE}"
      ;;
  esac
fi

wait_health || exit 1

# Re-assert codes for the CI contract message.
ingest_code="$(http_code "$INGEST_URL")"
dash_code="$(http_code "$DASH_URL")"
if [[ "$ingest_code" != "200" || "$dash_code" != "200" ]]; then
  die "health contract failed: ingest=${ingest_code} dashboard=${dash_code}"
fi

ELAPSED=$(( SECONDS - STARTED_AT ))
info "wall time: ${ELAPSED}s (mode=${MODE_USED})"
if [[ "$MODE_USED" == pull ]] && (( ELAPSED > 900 )); then
  yellow "warning: pull path exceeded 15 min (${ELAPSED}s) — check network / registry / disk"
elif [[ "$MODE_USED" == build* ]] && (( ELAPSED > 1800 )); then
  yellow "warning: build path exceeded 30 min (${ELAPSED}s) — consider prebuilt images"
fi

success_banner

if [[ "$MINT" -ne 1 ]]; then
  info "install-pilot: skipping onboarding mint (--no-mint)"
  print_manual_mint_path \
    "http://${HEALTH_HOST}:${DASHBOARD_PORT}" \
    "http://$(detect_public_host):${API_PORT}"
  green "install-pilot: complete"
  exit 0
fi

mint_onboarding_token || yellow "Token mint step failed (non-fatal — control plane is up)."
green "install-pilot: complete"
exit 0

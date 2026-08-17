#!/usr/bin/env bash
# AIM-1035 — External-ready one-command self-host / demo stack path.
#
# Happy path for an external engineer or small team:
#   clone → (optional minimal .env) → ./scripts/demo-stack-up.sh → dashboard
#
# Brings up the Unified Security Stack compose project (AIM + Gatehouse +
# supporting services), waits for health checks, optionally seeds demo data.
#
# Never prints secret values. Never commits .env.
#
# Usage:
#   ./scripts/demo-stack-up.sh              # preflight + up + health + seed
#   ./scripts/demo-stack-up.sh --preflight-only
#   ./scripts/demo-stack-up.sh --no-seed
#   ./scripts/demo-stack-up.sh --no-build   # use existing images
#   ./scripts/demo-stack-up.sh --help
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- defaults (override via env or flags) -----------------------------------
BIND_ADDR="${AIM_BIND_ADDR:-127.0.0.1}"
API_PORT="${API_PORT:-8080}"
DASHBOARD_PORT="${DASHBOARD_PORT:-8081}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
MINIO_API_PORT="${MINIO_API_PORT:-9000}"
GATEHOUSE_PORT="${GATEHOUSE_PORT:-8090}"
HEALTH_TIMEOUT_SEC="${HEALTH_TIMEOUT_SEC:-600}"
# Health + port probes must use a connectable address. Publishing on 0.0.0.0
# (enterprise pilot) still answers on loopback — never curl http://0.0.0.0/…
# as the primary probe (some hosts / curl builds mishandle it).
if [[ -n "${AIM_HEALTH_HOST:-}" ]]; then
  HEALTH_HOST="$AIM_HEALTH_HOST"
elif [[ "$BIND_ADDR" == "0.0.0.0" || "$BIND_ADDR" == "::" || -z "$BIND_ADDR" ]]; then
  HEALTH_HOST="127.0.0.1"
else
  HEALTH_HOST="$BIND_ADDR"
fi
SEED=1
BUILD=1
PREFLIGHT_ONLY=0
DETACH=1

usage() {
  cat <<'EOF'
AIM-1035 — External-ready one-command self-host / demo stack path.

Happy path: clone → (optional minimal .env) → ./scripts/demo-stack-up.sh → dashboard

Usage:
  ./scripts/demo-stack-up.sh              # preflight + up + health + seed
  ./scripts/demo-stack-up.sh --preflight-only
  ./scripts/demo-stack-up.sh --no-seed
  ./scripts/demo-stack-up.sh --no-build   # use existing images
  ./scripts/demo-stack-up.sh --help

Flags:
  --preflight-only   Check Docker, ports, env; do not start containers
  --no-seed          Skip scripts/seed-pilot-cohort.sh after health is green
  --no-build         docker compose up without --build
  --foreground       docker compose up without -d (Ctrl-C tears down attach)
  -h, --help         Show this help

Env (optional):
  AIM_BIND_ADDR, API_PORT, DASHBOARD_PORT, POSTGRES_PORT, MINIO_API_PORT,
  GATEHOUSE_PORT, HEALTH_TIMEOUT_SEC, SEED_TOKEN, COMPOSE_PROJECT_NAME

Docs: docs/deployment/self-host-quickstart.md
  Enterprise pilot one-shot: ./scripts/install-pilot.sh
  Recover after corrupt Docker data-root: ./scripts/demo-stack-recover.sh
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --preflight-only) PREFLIGHT_ONLY=1 ;;
    --no-seed) SEED=0 ;;
    --no-build) BUILD=0 ;;
    --foreground) DETACH=0 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "error: unknown flag: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

# --- helpers ----------------------------------------------------------------
red() { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
info() { printf '→ %s\n' "$*"; }
die() { red "error: $*"; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# Returns 0 if something is already listening on host:port (TCP).
port_in_use() {
  local host="$1" port="$2"
  # Prefer a connect probe — reliable across ss column layouts and IPv4/IPv6.
  if have python3; then
    python3 - "$host" "$port" <<'PY' 2>/dev/null
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.4)
try:
    # connect_ex == 0 means something accepted the connection
    sys.exit(0 if s.connect_ex((host, port)) == 0 else 1)
finally:
    s.close()
PY
    return $?
  fi
  if have ss; then
    # Match either *:port or host:port listeners.
    # NOTE: awk END always runs after exit — use a flag, do not exit 1 in END
    # after a successful match (that was a false "free" bug).
    ss -lnt 2>/dev/null | awk -v want="$port" '
      NR > 1 {
        n = split($4, a, ":");
        if (a[n] == want) { found = 1; exit }
      }
      END { exit found ? 0 : 1 }
    ' && return 0
    return 1
  fi
  return 1
}

http_ok() {
  local url="$1"
  if have curl; then
    curl -fsS --max-time 3 "$url" >/dev/null 2>&1
    return $?
  fi
  if have python3; then
    python3 - "$url" <<'PY' 2>/dev/null
import sys, urllib.request
url = sys.argv[1]
try:
    with urllib.request.urlopen(url, timeout=3) as r:
        sys.exit(0 if 200 <= r.status < 300 else 1)
except Exception:
    sys.exit(1)
PY
    return $?
  fi
  return 1
}

# --- preflight --------------------------------------------------------------
preflight() {
  info "Preflight (self-host demo stack)"

  if ! have docker; then
    red "Docker is not installed or not on PATH."
    cat >&2 <<'EOF'

  Install Docker Engine + Compose v2, then re-run this script:
    https://docs.docker.com/get-docker/

  macOS: Docker Desktop. Linux: docker.io + docker-compose-plugin.
  Confirm with:  docker version && docker compose version
EOF
    return 1
  fi

  if ! docker info >/dev/null 2>&1; then
    red "Docker daemon is not reachable (is the engine running?)."
    cat >&2 <<'EOF'

  Start Docker Desktop / the docker service, then re-run.
  Linux:  sudo systemctl start docker
  Also ensure your user can talk to the daemon (docker group) or use rootless.
EOF
    return 1
  fi

  if ! docker compose version >/dev/null 2>&1; then
    red "Docker Compose v2 plugin missing (need: docker compose …)."
    cat >&2 <<'EOF'

  Install the Compose plugin (not the legacy docker-compose Python package).
    https://docs.docker.com/compose/install/
EOF
    return 1
  fi

  if ! have python3; then
    die "python3 is required (for scripts/ensure_dev_env.py). Install Python 3.11+."
  fi

  # Port conflicts — only warn if the listener is not already our healthy stack.
  # Probe HEALTH_HOST (loopback when publishing 0.0.0.0) so pilot bind works.
  local conflicts=()
  local p
  for p in "$API_PORT" "$DASHBOARD_PORT" "$POSTGRES_PORT" "$MINIO_API_PORT" "$GATEHOUSE_PORT"; do
    if port_in_use "$HEALTH_HOST" "$p"; then
      conflicts+=("${BIND_ADDR}:$p")
    fi
  done

  if [[ ${#conflicts[@]} -gt 0 ]]; then
    # If dashboard already answers health, treat as "stack already up".
    if http_ok "http://${HEALTH_HOST}:${DASHBOARD_PORT}/api/health"; then
      yellow "Ports already in use, but dashboard health is green — reusing running stack."
      yellow "  in use: ${conflicts[*]}"
    else
      red "Port conflict(s) on ${conflicts[*]}"
      cat >&2 <<EOF

  Free the ports, or override them in a gitignored .env (see .env.example):
    API_PORT=18080
    DASHBOARD_PORT=18081
    POSTGRES_PORT=15432
    MINIO_API_PORT=19000
    GATEHOUSE_PORT=18090

  Then re-run:  ./scripts/demo-stack-up.sh
  Inspect listeners:  ss -lnt | grep -E ':(${API_PORT}|${DASHBOARD_PORT}|${POSTGRES_PORT})'
EOF
      return 1
    fi
  fi

  # Secret placeholders in .env (if present)
  if [[ -f "$ROOT/.env" ]]; then
    local bad
    bad="$(
      grep -E '^(POSTGRES_PASSWORD|MINIO_ROOT_PASSWORD|GATEHOUSE_WEBHOOK_SECRET|INGEST_TOKENS|IDENTITY_SYNC_JWT_HS256_SECRET)=' \
        "$ROOT/.env" 2>/dev/null \
        | grep -Ei 'CHANGE_ME|REPLACE_ME|TODO|YOUR_SECRET|xxx+|<.*>' || true
    )"
    if [[ -n "$bad" ]]; then
      red "Unresolved secret placeholder(s) in .env:"
      # Print keys only — never values.
      echo "$bad" | cut -d= -f1 | sed 's/^/  /' >&2
      cat >&2 <<'EOF'

  Edit .env: replace placeholders with real local-only values, or delete the
  key lines and re-run so ensure_dev_env can mint stack-owned secrets.
  Sample only: .env.example (committed). Real secrets never belong in git.
EOF
      return 1
    fi
  fi

  green "Preflight OK (Docker + Compose + python3; ports clear or stack healthy)."
  return 0
}

mint_env() {
  info "Minting stack-owned local secrets into gitignored .env (if missing)"
  python3 "$ROOT/scripts/ensure_dev_env.py"
}

bring_up() {
  local args=(up)
  if [[ "$DETACH" -eq 1 ]]; then
    args+=(-d)
  fi
  if [[ "$BUILD" -eq 1 ]]; then
    args+=(--build)
  fi
  info "Starting compose stack: docker compose ${args[*]}"
  # shellcheck disable=SC2086
  if ! docker compose "${args[@]}"; then
    red "docker compose ${args[*]} failed."
    cat >&2 <<'EOF'

  Next actions:
    docker compose ps
    docker compose logs --tail=80
    # After abrupt host kill with retained Docker data-root (missing snapshot /
    # nil RWLayer), recover without wiping named volumes:
    ./scripts/demo-stack-recover.sh
    # Enterprise pilot re-entry:
    ./scripts/install-pilot.sh
EOF
    return 1
  fi
}

wait_health() {
  local deadline=$((SECONDS + HEALTH_TIMEOUT_SEC))
  local ingest_url="http://${HEALTH_HOST}:${API_PORT}/healthz"
  local dash_url="http://${HEALTH_HOST}:${DASHBOARD_PORT}/api/health"
  local gate_url="http://${HEALTH_HOST}:${GATEHOUSE_PORT}/healthz"

  info "Waiting for health (timeout ${HEALTH_TIMEOUT_SEC}s)"
  info "  ingest:    $ingest_url"
  info "  dashboard: $dash_url"
  info "  gatehouse: $gate_url (optional pillar)"
  if [[ "$BIND_ADDR" != "$HEALTH_HOST" ]]; then
    info "  publish bind: ${BIND_ADDR} (probes use ${HEALTH_HOST})"
  fi

  local ingest_ok=0 dash_ok=0 gate_ok=0
  while (( SECONDS < deadline )); do
    http_ok "$ingest_url" && ingest_ok=1 || ingest_ok=0
    http_ok "$dash_url" && dash_ok=1 || dash_ok=0
    http_ok "$gate_url" && gate_ok=1 || gate_ok=0
    if [[ "$ingest_ok" -eq 1 && "$dash_ok" -eq 1 ]]; then
      green "Health green: ingest + dashboard"
      if [[ "$gate_ok" -eq 1 ]]; then
        green "Gatehouse health green on :${GATEHOUSE_PORT}"
      else
        yellow "Gatehouse not healthy yet (optional). Check: docker compose logs gatehouse"
      fi
      return 0
    fi
    sleep 3
  done

  red "Timed out waiting for ingest + dashboard health after ${HEALTH_TIMEOUT_SEC}s."
  cat >&2 <<EOF

  Next actions:
    docker compose ps
    docker compose logs --tail=80 ingest api
    curl -v $ingest_url
    curl -v $dash_url
    # Corrupt Docker metadata after abrupt VM kill (retained data-root):
    ./scripts/demo-stack-recover.sh
    # Then re-run the installer you used:
    ./scripts/demo-stack-up.sh
    # or (private-network pilot):
    ./scripts/install-pilot.sh
EOF
  return 1
}

seed_demo() {
  if [[ "$SEED" -ne 1 ]]; then
    info "Skipping seed (--no-seed)"
    return 0
  fi
  if [[ ! -x "$ROOT/scripts/seed-pilot-cohort.sh" && ! -f "$ROOT/scripts/seed-pilot-cohort.sh" ]]; then
    yellow "seed-pilot-cohort.sh missing; skip seed"
    return 0
  fi
  info "Seeding demo pilot cohort (12 seats / fixture teams)"
  SEED_BASE_URL="http://${HEALTH_HOST}:${API_PORT}" \
    bash "$ROOT/scripts/seed-pilot-cohort.sh"
}

print_next_steps() {
  cat <<EOF

══════════════════════════════════════════════════════════════════
  Self-host demo stack is ready
══════════════════════════════════════════════════════════════════

  Dashboard (personal / standalone mode — local admin, no SSO):
    http://${HEALTH_HOST}:${DASHBOARD_PORT}

  Ingest API:
    http://${HEALTH_HOST}:${API_PORT}
    health: http://${HEALTH_HOST}:${API_PORT}/healthz

  Gatehouse (optional PR-security pillar):
    http://${HEALTH_HOST}:${GATEHOUSE_PORT}/healthz

  First login / personal mode entry
  ---------------------------------
  With no AIM_OIDC_* set (the compose default), the dashboard runs in
  personal/standalone mode: a single local admin identity, loopback-only.
  Open the dashboard URL above in a browser — no password form.

  Do NOT publish AIM_BIND_ADDR beyond 127.0.0.1 without SSO (Enterprise).

  Tear down
  ---------
    docker compose down          # keep volumes
    docker compose down -v       # wipe local Postgres/MinIO data

  Docs
  ----
    docs/deployment/self-host-quickstart.md
    README.md  → "Self-host demo (one command)"
    Enterprise pilot (0.0.0.0 bind, no seed): ./scripts/install-pilot.sh

══════════════════════════════════════════════════════════════════
EOF
}

# --- main -------------------------------------------------------------------
START_TS=$(date +%s)

preflight || exit 1

if [[ "$PREFLIGHT_ONLY" -eq 1 ]]; then
  green "Preflight-only complete (full stack wall-clock not measured)."
  exit 0
fi

# If already healthy, skip rebuild/up unless images forced.
if http_ok "http://${HEALTH_HOST}:${DASHBOARD_PORT}/api/health" \
  && http_ok "http://${HEALTH_HOST}:${API_PORT}/healthz"; then
  yellow "Stack already healthy — skipping compose up."
else
  mint_env
  bring_up || exit 1
fi

wait_health || exit 1
seed_demo || yellow "Seed failed (non-fatal). You can re-run: SEED_BASE_URL=http://${HEALTH_HOST}:${API_PORT} ./scripts/seed-pilot-cohort.sh"
print_next_steps

END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))
info "Elapsed wall time this run: ${ELAPSED}s"
if (( ELAPSED > 1800 )); then
  yellow "Note: exceeded 30-minute time-to-green target on this host (first image build is the usual culprit)."
fi

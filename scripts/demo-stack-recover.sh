#!/usr/bin/env bash
# Recover a self-host / pilot compose stack when Docker metadata on a reused
# data-root is corrupt after an abrupt host kill.
#
# Symptoms:
#   - docker compose up fails: "parent snapshot ... does not exist"
#   - start fails: "RWLayer of container ... is unexpectedly nil"
#
# Safe for named volumes (pgdata, minio-data, …): this never passes --volumes.
# Usage:
#   ./scripts/demo-stack-recover.sh
#   ./scripts/demo-stack-recover.sh --no-build
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BUILD=1
for a in "$@"; do
  case "$a" in
    --no-build) BUILD=0 ;;
    -h|--help)
      sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

log() { echo "[demo-stack-recover] $*"; }

command -v docker >/dev/null 2>&1 || { echo "docker required" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "docker daemon not running" >&2; exit 1; }

log "compose down (keep volumes)"
docker compose down --remove-orphans 2>/dev/null || true

log "remove residual containers (not volumes)"
ids="$(docker ps -aq 2>/dev/null || true)"
if [ -n "${ids}" ]; then
  # shellcheck disable=SC2086
  docker rm -f ${ids} 2>/dev/null || true
fi
docker container prune -f >/dev/null 2>&1 || true

log "prune buildkit cache (images may rebuild)"
docker builder prune -af >/dev/null 2>&1 || true

log "named volumes retained:"
docker volume ls || true

if [ "${BUILD}" -eq 1 ]; then
  log "compose up -d --build"
  docker compose up -d --build
else
  log "compose up -d (no build)"
  docker compose up -d
fi

log "waiting for health"
for i in $(seq 1 60); do
  if curl -fsS --max-time 3 http://127.0.0.1:8080/healthz >/dev/null 2>&1 \
     && curl -fsS --max-time 3 http://127.0.0.1:8081/api/health >/dev/null 2>&1; then
    log "health OK after ${i} tries"
    exit 0
  fi
  sleep 5
done
echo "error: health not green; see docker compose ps / logs" >&2
exit 1

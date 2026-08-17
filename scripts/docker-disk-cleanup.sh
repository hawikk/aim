#!/usr/bin/env bash
# docker-disk-cleanup.sh — reclaim local Docker disk safely.
#
# Default policy:
#   1. Prune stopped containers
#   2. Prune dangling images
#   3. Keep the N newest tags per repository (default 2); never delete an
#      image ID still referenced by any container
#   4. Optionally drop known ephemeral / one-off experiment tags
#   5. Prune unused build cache
#   6. Prune dangling (anonymous unused) volumes only — never named volumes
#   7. Prune unused networks
#
# Usage:
#   scripts/docker-disk-cleanup.sh              # safe default
#   scripts/docker-disk-cleanup.sh --keep 1     # keep only newest tag/repo
#   scripts/docker-disk-cleanup.sh --dry-run    # print actions only
#   scripts/docker-disk-cleanup.sh --aggressive # also remove ephemeral name patterns
#   scripts/docker-disk-cleanup.sh --no-volumes # skip volume prune
#   scripts/docker-disk-cleanup.sh --no-builder # skip builder prune
#
# Safe by design:
#   - Never touches running containers
#   - Never force-removes images still referenced by containers
#   - Volume prune is dangling-only (anonymous unused), not `volume prune -a`
set -euo pipefail

KEEP=2
DRY_RUN=0
AGGRESSIVE=0
DO_VOLUMES=1
DO_BUILDER=1

usage() {
  sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep)
      KEEP="${2:?}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --aggressive)
      AGGRESSIVE=1
      shift
      ;;
    --no-volumes)
      DO_VOLUMES=0
      shift
      ;;
    --no-builder)
      DO_BUILDER=0
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "unknown arg: $1" >&2
      usage
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker not found on PATH" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "error: cannot talk to docker daemon" >&2
  exit 1
fi

run() {
  if (( DRY_RUN )); then
    echo "DRY-RUN: $*"
  else
    "$@"
  fi
}

echo "===== docker-disk-cleanup start $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
echo "keep=$KEEP dry_run=$DRY_RUN aggressive=$AGGRESSIVE volumes=$DO_VOLUMES builder=$DO_BUILDER"
echo
echo "=== BEFORE ==="
df -h / 2>/dev/null | tail -1 || true
docker system df || true

# Full image IDs referenced by any existing container (running or stopped).
mapfile -t USED_IDS < <(docker ps -aq | xargs -r docker inspect --format '{{.Image}}' 2>/dev/null | sort -u || true)
mapfile -t USED_REFS < <(docker ps -a --format '{{.Image}}' 2>/dev/null | sort -u || true)
echo "Protected container image IDs: ${#USED_IDS[@]}"

is_protected() {
  local ref="$1" id="$2"
  local full
  full=$(docker image inspect --format '{{.Id}}' "$id" 2>/dev/null || true)
  local u
  for u in "${USED_IDS[@]+"${USED_IDS[@]}"}"; do
    [[ -n "$full" && "$full" == "$u" ]] && return 0
  done
  # Compose often stores image as "stack-aim-api" (implicit :latest).
  local repo="${ref%:*}"
  local tag="${ref##*:}"
  local r
  for r in "${USED_REFS[@]+"${USED_REFS[@]}"}"; do
    [[ "$r" == "$ref" ]] && return 0
    [[ "$r" == "$id" ]] && return 0
    [[ "$r" == "$repo" && ( "$tag" == "latest" || "$tag" == "$ref" ) ]] && return 0
  done
  return 1
}

echo
echo "=== 1) Stopped containers ==="
run docker container prune -f

echo
echo "=== 2) Dangling images ==="
run docker image prune -f

if (( AGGRESSIVE )); then
  echo
  echo "=== 3a) Ephemeral / one-off experiment tags ==="
  # Name patterns from agent workspaces, acceptance runs, local registries.
  # Keep anything still referenced by a container.
  EPHEMERAL_GLOBS=(
    'acceptance-*'
    'aim289-*'
    'aim23*'
    'aim450-*'
    'ai-monitoring-*'
    'localhost:5000/*'
    'localhost:5001/*'
    'littlewiz-app:aim303*'
    'portfolio:*'
    'guardraild:e2e'
    'aim/api:*dirty*'
    'aim/api:drill-*'
    'aim/guardrail:*dirty*'
    'aim/guardrail:drill-*'
    'aim/ingest:*dirty*'
    'aim/ingest:drill-*'
    'gatehouse:dev'
  )
  while IFS=$'\t' read -r repo tag id; do
    [[ -z "${repo:-}" ]] && continue
    ref="${repo}:${tag}"
    matched=0
    for pat in "${EPHEMERAL_GLOBS[@]}"; do
      case "$ref" in
        $pat) matched=1; break ;;
      esac
    done
    (( matched )) || continue
    if is_protected "$ref" "$id"; then
      echo "  keep in-use: $ref"
      continue
    fi
    echo "  rmi ephemeral $ref"
    if (( DRY_RUN )); then
      continue
    fi
    docker rmi "$ref" 2>/dev/null || true
  done < <(docker images --format '{{.Repository}}\t{{.Tag}}\t{{.ID}}')
fi

echo
echo "=== 3b) Per-repo retention (keep $KEEP newest tags) ==="
mapfile -t REPOS < <(docker images --format '{{.Repository}}' | grep -v '^<none>$' | sort -u || true)
DELETED=0
SKIPPED=0
for repo in "${REPOS[@]+"${REPOS[@]}"}"; do
  mapfile -t LINES < <(
    docker images --format '{{.Repository}}|{{.Tag}}|{{.ID}}|{{.CreatedAt}}' "$repo" 2>/dev/null | \
      grep -v '|none|' | while IFS='|' read -r r t id created; do
        ts=$(date -d "$created" +%s 2>/dev/null || echo 0)
        printf '%s|%s|%s|%s\n' "$r" "$t" "$id" "$ts"
      done | sort -t'|' -k4,4nr
  )
  count=${#LINES[@]}
  (( count <= KEEP )) && continue
  idx=0
  for line in "${LINES[@]}"; do
    IFS='|' read -r r t id ts <<<"$line"
    idx=$((idx + 1))
    (( idx <= KEEP )) && continue
    ref="$r:$t"
    if is_protected "$ref" "$id"; then
      echo "  keep in-use: $ref"
      SKIPPED=$((SKIPPED + 1))
      continue
    fi
    echo "  rmi $ref"
    if (( DRY_RUN )); then
      DELETED=$((DELETED + 1))
      continue
    fi
    if docker rmi "$ref" 2>/dev/null; then
      DELETED=$((DELETED + 1))
    else
      echo "    (still referenced — ok)"
      SKIPPED=$((SKIPPED + 1))
    fi
  done
done
echo "Retention: deleted_tags=$DELETED skipped_inuse_or_ref=$SKIPPED"

echo
echo "=== 4) Dangling images (second pass) ==="
run docker image prune -f

if (( DO_BUILDER )); then
  echo
  echo "=== 5) Build cache (unused) ==="
  # -a removes unused build cache; does not affect running containers.
  run docker builder prune -af
fi

if (( DO_VOLUMES )); then
  echo
  echo "=== 6) Dangling volumes only (anonymous unused) ==="
  # Never use --all: named compose volumes (postgres data etc.) stay.
  run docker volume prune -f
fi

echo
echo "=== 7) Unused networks ==="
run docker network prune -f

echo
echo "=== AFTER ==="
df -h / 2>/dev/null | tail -1 || true
docker system df || true
echo "image_tags: $(docker images --format '{{.Repository}}:{{.Tag}}' | wc -l)"
echo "dangling_images: $(docker images -f dangling=true -q | wc -l)"
echo "volumes: $(docker volume ls -q | wc -l)"
echo "containers: $(docker ps -aq | wc -l) (running: $(docker ps -q | wc -l))"
echo "===== docker-disk-cleanup done $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="

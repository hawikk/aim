#!/usr/bin/env bash
# Offline installer for the AIM air-gapped bundle.
# Runs on the TARGET host, from the untarred bundle directory.
#
# Usage: ./install-offline.sh
#
# Env:
#   REGISTRY   internal registry to retag + push images into
#              (e.g. registry.corp.local:5000/aim). Empty = images stay local
#              to this host's container runtime and helm is told imagePullPolicy=Never.
#   RUN_HELM=1 actually run the helm install instead of only printing it
#   RELEASE    helm release name (default: aim)
#   NAMESPACE  kubernetes namespace (default: aim)
#   CHART_DIR  path to the chart (default: ./chart/aim from the bundle)
#
# This script NEVER pulls from the internet: images come from images.tar, and
# the emitted helm command pins every image and forces IfNotPresent/Never.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

RELEASE="${RELEASE:-aim}"
NAMESPACE="${NAMESPACE:-aim}"
CHART_DIR="${CHART_DIR:-./chart/aim}"
REGISTRY="${REGISTRY:-}"
RUN_HELM="${RUN_HELM:-0}"

if [[ ! -f images.tar ]]; then
  echo "error: images.tar not found — run this from the untarred bundle directory." >&2
  exit 1
fi

echo "==> Loading images from images.tar"
LOAD_OUTPUT="$(docker load -i images.tar)"
echo "$LOAD_OUTPUT"

# `docker load` prints "Loaded image: <repo>:<tag>" per image.
mapfile -t LOADED_IMAGES < <(echo "$LOAD_OUTPUT" | sed -n 's/^Loaded image: //p' | sort -u)
if [[ ${#LOADED_IMAGES[@]} -eq 0 ]]; then
  echo "error: docker load reported no images; is images.tar intact? Check MANIFEST.txt hashes." >&2
  exit 1
fi
echo "==> Loaded ${#LOADED_IMAGES[@]} images"

# Optional: retag and push into an internal registry so every cluster node can
# resolve them without internet access.
if [[ -n "$REGISTRY" ]]; then
  echo "==> Retagging and pushing into ${REGISTRY}"
  for image in "${LOADED_IMAGES[@]}"; do
    target="${REGISTRY%/}/${image}"
    echo "    ${image} -> ${target}"
    docker tag "$image" "$target"
    docker push "$target"
  done
  PULL_POLICY="IfNotPresent"
else
  echo "==> REGISTRY not set; images remain local to this host (imagePullPolicy=Never)"
  PULL_POLICY="Never"
fi

# Map an image repository to the chart value prefix it controls. These keys
# are the contract with the Helm chart (deploy/helm/aim) — the chart author
# must honour <key>.repository / <key>.tag, global.imageRegistry, and
# global.imagePullPolicy.
#
# redis is compose-only today (alert bus in docker-compose.yml); the Helm
# chart does not ship a redis dependency, so we skip it without warning.
value_key_for() {
  case "$1" in
    aim/ingest)    echo "ingest.image" ;;
    aim/api)       echo "api.image" ;;
    aim/guardrail) echo "guardrail.image" ;;
    postgres)      echo "postgres.image" ;;
    minio/minio)   echo "minio.image" ;;
    minio/mc)      echo "minioInit.image" ;;
    redis)         echo "__compose_only__" ;;
    *)             echo "" ;;
  esac
}

SET_ARGS=(
  "--set" "global.imagePullPolicy=${PULL_POLICY}"
)
if [[ -n "$REGISTRY" ]]; then
  SET_ARGS+=("--set" "global.imageRegistry=${REGISTRY%/}")
fi
for image in "${LOADED_IMAGES[@]}"; do
  repo="${image%:*}"
  tag="${image##*:}"
  key="$(value_key_for "$repo")"
  if [[ -z "$key" ]]; then
    echo "warning: no chart value mapping for image ${repo} — not passed to helm." >&2
    continue
  fi
  if [[ "$key" == "__compose_only__" ]]; then
    echo "    note: ${repo} is compose-only (not in Helm chart) — image loaded, not passed to helm."
    continue
  fi
  SET_ARGS+=("--set" "${key}.repository=${repo}" "--set" "${key}.tag=${tag}")
done

if [[ ! -d "$CHART_DIR" ]]; then
  echo
  echo "No Helm chart in this bundle (${CHART_DIR} missing) — skipping the helm step."
  echo "Images are loaded; for docker-based install/upgrade:"
  echo "  docker compose -f docker-compose.yml -f docker-compose.airgap.yml up -d"
  echo "(see README-airgap.md). Or re-bundle with deploy/helm/aim present."
  exit 0
fi

# helm upgrade --install is intentional: greenfield install AND in-place
# upgrades of an existing release share this path. Volumes / PVCs
# are left alone; the pre-upgrade migrate Job applies schema deltas.
HELM_CMD=(
  helm upgrade --install "$RELEASE" "$CHART_DIR"
  --namespace "$NAMESPACE" --create-namespace
  "${SET_ARGS[@]}"
)

echo
if [[ "$RUN_HELM" == "1" ]]; then
  echo "==> RUN_HELM=1 — running (upgrade --install):"
  printf '    %q' "${HELM_CMD[@]}"; echo
  "${HELM_CMD[@]}"
else
  echo "Dry-run (set RUN_HELM=1 to execute). Exact command:"
  printf '  %q' "${HELM_CMD[@]}"; echo
  echo
  echo "Upgrade note: the same command upgrades an existing release in place."
  echo "Take a Postgres backup first (docs/deployment/backup-restore.md)."
fi

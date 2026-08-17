#!/usr/bin/env bash
# topology render check — delegates to proof when present.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -x "$ROOT/scripts/topology-render-proof.sh" ]]; then
  exec "$ROOT/scripts/topology-render-proof.sh"
fi
# Fallback: minimal helm assertions (enterprise values).
CHART="$ROOT/deploy/helm/aim"
helm template aim "$CHART" -f "$CHART/values-enterprise.yaml" \
  --set objectStore.endpoint=https://s3.example.invalid \
  --set api.oidc.issuer=https://login.example.invalid \
  --set api.oidc.clientId=aim-dashboard-render-proof \
  | grep -q topologySpreadConstraints
echo "RESULT: PASS — minimal topology render (fallback)"

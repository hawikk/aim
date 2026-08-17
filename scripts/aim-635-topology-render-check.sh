#!/usr/bin/env bash
# AIM-635 topology render check — delegates to AIM-769 proof when present.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -x "$ROOT/scripts/aim-769-topology-render-proof.sh" ]]; then
  exec "$ROOT/scripts/aim-769-topology-render-proof.sh"
fi
# Fallback: minimal helm assertions (enterprise values).
CHART="$ROOT/deploy/helm/aim"
helm template aim "$CHART" -f "$CHART/values-enterprise.yaml" \
  --set objectStore.endpoint=https://s3.example.invalid \
  --set api.oidc.issuer=https://login.example.invalid \
  --set api.oidc.clientId=aim-dashboard-render-proof \
  | grep -q topologySpreadConstraints
echo "RESULT: PASS — minimal topology render (fallback)"

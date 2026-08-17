#!/usr/bin/env bash
# AIM-601: prove helm chart security defaults fail closed where required.
#
# Exit 0 only when:
#   - dev shape renders
#   - production overlay without secrets/OIDC fails
#   - production overlay with real secrets + OIDC renders
#   - public postgres/minio Service types always fail
#   - authDev on production overlay fails
#   - all rendered Services are ClusterIP in the happy path
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART="${ROOT}/deploy/helm/aim"
HELM="${HELM:-helm}"

if ! command -v "$HELM" >/dev/null 2>&1; then
  echo "helm not found on PATH (set HELM=... if installed elsewhere)" >&2
  exit 2
fi

pass=0
fail=0

expect_ok() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "PASS  $name"
    pass=$((pass + 1))
  else
    echo "FAIL  $name (expected success)" >&2
    fail=$((fail + 1))
  fi
}

expect_fail() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "FAIL  $name (expected helm template to fail)" >&2
    fail=$((fail + 1))
  else
    echo "PASS  $name"
    pass=$((pass + 1))
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 1) Dev / default shapes still work (throwaway clusters).
expect_ok "values-dev renders" \
  "$HELM" template aim "$CHART" -f "$CHART/values-dev.yaml"
expect_ok "chart defaults render" \
  "$HELM" template aim "$CHART"

# 2) Production overlay alone must fail closed (local-only secrets + no OIDC).
expect_fail "values-standard without secrets/OIDC fails" \
  "$HELM" template aim "$CHART" -f "$CHART/values-standard.yaml"
expect_fail "values-airgapped without secrets/OIDC fails" \
  "$HELM" template aim "$CHART" -f "$CHART/values-airgapped.yaml"
expect_fail "values-enterprise without secrets/OIDC fails" \
  "$HELM" template aim "$CHART" -f "$CHART/values-enterprise.yaml"

# 3) Production overlay with real secrets + OIDC succeeds.
PROD_SETS=(
  --set secrets.existingSecret=aim-prod-secrets
  --set api.oidc.issuer=https://idp.example.test
  --set api.oidc.clientId=aim-dashboard
)
expect_ok "values-standard with existingSecret + OIDC renders" \
  "$HELM" template aim "$CHART" -f "$CHART/values-standard.yaml" "${PROD_SETS[@]}"
expect_ok "values-enterprise with existingSecret + OIDC renders" \
  "$HELM" template aim "$CHART" -f "$CHART/values-enterprise.yaml" "${PROD_SETS[@]}"

# Capture happy-path manifest for service-type assertions.
"$HELM" template aim "$CHART" -f "$CHART/values-standard.yaml" "${PROD_SETS[@]}" \
  >"$TMP/prod.yaml"

# 4) authDev forbidden on production posture.
expect_fail "authDev blocked under values-standard" \
  "$HELM" template aim "$CHART" -f "$CHART/values-standard.yaml" "${PROD_SETS[@]}" \
  --set api.authDev=true

# 5) Public data-store Services always blocked (even on dev shape).
expect_fail "postgres LoadBalancer always blocked" \
  "$HELM" template aim "$CHART" -f "$CHART/values-dev.yaml" \
  --set postgres.service.type=LoadBalancer
expect_fail "minio NodePort always blocked" \
  "$HELM" template aim "$CHART" -f "$CHART/values-dev.yaml" \
  --set minio.service.type=NodePort

# 6) Public app Services blocked under production unless allowPublicServices.
expect_fail "api LoadBalancer blocked without allowPublicServices" \
  "$HELM" template aim "$CHART" -f "$CHART/values-standard.yaml" "${PROD_SETS[@]}" \
  --set api.service.type=LoadBalancer
expect_ok "api LoadBalancer allowed with allowPublicServices=true (residual-risk accept)" \
  "$HELM" template aim "$CHART" -f "$CHART/values-standard.yaml" "${PROD_SETS[@]}" \
  --set api.service.type=LoadBalancer \
  --set security.allowPublicServices=true

# 7) Chart-generated local-only secrets blocked even if OIDC is set.
expect_fail "local-only postgres password blocked under production" \
  "$HELM" template aim "$CHART" -f "$CHART/values-standard.yaml" \
  --set api.oidc.issuer=https://idp.example.test \
  --set api.oidc.clientId=aim-dashboard \
  --set secrets.oidcClientSecret=real-oidc-secret \
  --set secrets.postgresPassword=localdev-only-not-a-secret \
  --set secrets.minioRootPassword=not-the-default-but-ok-long \
  --set secrets.ingestTokens=not-the-default-token \
  --set secrets.hashSalt=prod-hash-salt-value \
  --set secrets.sessionSecret=prod-session-secret-value

# 8) Happy-path Services must declare ClusterIP.
if grep -E '^\s*type:\s*(LoadBalancer|NodePort)\s*$' "$TMP/prod.yaml" >/dev/null; then
  echo "FAIL  production render contains public Service type" >&2
  grep -nE 'kind: Service|type:' "$TMP/prod.yaml" | head -40 >&2
  fail=$((fail + 1))
else
  # Require at least one explicit ClusterIP (we pin type on all four Services).
  if grep -E '^\s*type:\s*ClusterIP\s*$' "$TMP/prod.yaml" >/dev/null; then
    echo "PASS  production Services are ClusterIP (no public type)"
    pass=$((pass + 1))
  else
    echo "FAIL  production render missing explicit ClusterIP Service types" >&2
    fail=$((fail + 1))
  fi
fi

# 9) Ingress without TLS fails under production.
expect_fail "ingress without TLS blocked under production" \
  "$HELM" template aim "$CHART" -f "$CHART/values-standard.yaml" "${PROD_SETS[@]}" \
  --set ingress.enabled=true \
  --set ingress.host=aim.example.test \
  --set ingress.tls=false

echo
echo "helm-security-defaults-check: ${pass} passed, ${fail} failed"
if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

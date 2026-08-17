#!/usr/bin/env bash
# AIM-769 / AIM-722 — topology render proof (helm template assertions).
# AIM-769 — topology render proof (helm template assertions).
#
# No live multi-AZ cluster required. Renders the chart with
# values-enterprise.yaml and asserts:
#   - topologySpreadConstraints on api/ingest/guardrail
#   - pod anti-affinity
#   - NetworkPolicies (default-deny + allow paths)
#   - no in-cluster Postgres/MinIO when external mode
#   - PDBs + resource limits present
#
# Usage: ./scripts/aim-769-topology-render-proof.sh
# Exit 0 on PASS, 1 on FAIL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART="$ROOT/deploy/helm/aim"
VALUES_ENTERPRISE="$CHART/values-enterprise.yaml"
FAILURES=0

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }

echo "== AIM-769/AIM-722 enterprise topology render proof =="
echo "== AIM-769 enterprise topology render proof =="
echo "chart: $CHART"

if ! command -v helm >/dev/null 2>&1; then
  fail "helm not installed"
  exit 1
fi

[[ -f "$VALUES_ENTERPRISE" ]] && pass "present: values-enterprise.yaml" || fail "missing: values-enterprise.yaml"
[[ -f "$CHART/templates/networkpolicy.yaml" ]] && pass "present: networkpolicy.yaml" || fail "missing: networkpolicy.yaml"
[[ -f "$ROOT/docs/deployment/enterprise-topology.md" ]] && pass "present: enterprise-topology.md" || fail "missing: enterprise-topology.md"

if [[ $FAILURES -gt 0 ]]; then
  echo "Aborting render — prerequisites missing."
  exit 1
fi

RENDER="$(mktemp)"
trap 'rm -f "$RENDER"' EXIT

echo ""
echo "-- helm template (enterprise / external data plane) --"
# AIM-601 fail-closed: enterprise profile requires OIDC + existingSecret.
# Supply dummy OIDC for pure template proof (no live IdP needed).
if ! helm template aim-ent "$CHART" -f "$VALUES_ENTERPRISE" \
  --set api.oidc.issuer=https://login.example.invalid \
  --set api.oidc.clientId=aim-dashboard-render-proof \
  >"$RENDER" 2>/tmp/aim-769-helm-err.txt; then
  fail "helm template failed"
  cat /tmp/aim-769-helm-err.txt >&2
  exit 1
fi
pass "helm template succeeded ($(wc -l <"$RENDER") lines)"

# --- topology ---
if grep -q 'topologySpreadConstraints:' "$RENDER"; then
  pass "topologySpreadConstraints rendered"
else
  fail "topologySpreadConstraints missing from render"
fi

if grep -q 'topology.kubernetes.io/zone' "$RENDER"; then
  pass "zone topologyKey present"
else
  fail "zone topologyKey missing"
fi

if grep -q 'podAntiAffinity:' "$RENDER"; then
  pass "podAntiAffinity rendered"
else
  fail "podAntiAffinity missing"
fi

# Expect TSC on each of the three app deployments (count >= 3).
tsc_count=$(grep -c 'topologySpreadConstraints:' "$RENDER" || true)
if [[ "$tsc_count" -ge 3 ]]; then
  pass "topologySpreadConstraints on ≥3 workloads (got $tsc_count)"
else
  fail "expected ≥3 topologySpreadConstraints blocks, got $tsc_count"
fi

# --- NetworkPolicy ---
np_count=$(grep -c 'kind: NetworkPolicy' "$RENDER" || true)
if [[ "$np_count" -ge 4 ]]; then
  pass "NetworkPolicy count ≥4 (got $np_count)"
else
  fail "expected ≥4 NetworkPolicies, got $np_count"
fi

if grep -q 'name: aim-ent-default-deny\|name: aim-ent-aim-default-deny' "$RENDER" \
  || grep -E 'name: .*-default-deny' "$RENDER" >/dev/null; then
  pass "default-deny NetworkPolicy present"
else
  fail "default-deny NetworkPolicy missing"
fi

# --- external mode: no in-cluster data plane ---
if grep -E 'kind: StatefulSet' "$RENDER" | grep -qi postgres; then
  fail "in-cluster postgres StatefulSet rendered (expected external)"
elif grep -q 'name:.*postgres' "$RENDER" && grep -A2 'kind: StatefulSet' "$RENDER" | grep -qi postgres; then
  fail "postgres StatefulSet present"
else
  # Stronger: no StatefulSet at all when only postgres used one
  if grep -q 'kind: StatefulSet' "$RENDER"; then
    fail "unexpected StatefulSet in external enterprise render"
  else
    pass "no in-cluster Postgres StatefulSet"
  fi
fi

if grep -E 'kind: Deployment' -A5 "$RENDER" | grep -q 'name: minio' 2>/dev/null; then
  :
fi
# Count minio Deployment by name pattern
if grep -E 'name: .*minio$' "$RENDER" | grep -v NetworkPolicy | grep -v 'allow-minio' | grep -v objectstore >/dev/null 2>&1; then
  # Check specifically for Deployment named *-minio (not NetworkPolicy)
  if awk '
    /^kind: Deployment$/ { d=1; next }
    d && /^metadata:$/ { m=1; next }
    d && m && /name:.*-minio$/ { found=1 }
    /^---$/ { d=0; m=0 }
    END { exit found ? 0 : 1 }
  ' "$RENDER"; then
    fail "in-cluster minio Deployment rendered (expected external)"
  else
    pass "no in-cluster MinIO Deployment"
  fi
else
  pass "no in-cluster MinIO Deployment"
fi

# minio-init job should also be absent
if grep -q 'minio-init' "$RENDER" && grep -B20 'minio-init' "$RENDER" | grep -q 'kind: Job'; then
  fail "minio-init Job rendered with minio.enabled=false"
else
  pass "no minio-init Job in external mode"
fi

# --- PDBs + limits ---
pdb_count=$(grep -c 'kind: PodDisruptionBudget' "$RENDER" || true)
if [[ "$pdb_count" -ge 3 ]]; then
  pass "PDBs for multi-replica services (got $pdb_count)"
else
  fail "expected ≥3 PodDisruptionBudgets, got $pdb_count"
fi

if grep -q 'memory: 1Gi' "$RENDER" || grep -q 'memory: "1Gi"' "$RENDER"; then
  pass "memory limits present"
else
  fail "enterprise memory limits not found"
fi

# --- app replicas ≥ 2 ---
for c in api ingest guardrail; do
  # look for replicas near deployment name
  if awk -v comp="$c" '
    $0 ~ "name:.*-"comp"$" { hit=1 }
    hit && /replicas:/ {
      if ($2+0 >= 2) { ok=1 }
      hit=0
    }
    END { exit ok ? 0 : 1 }
  ' "$RENDER"; then
    pass "replicas≥2 for $c"
  else
    # fallback: any replicas: 2 in file is weak; check values
    if grep -A20 "name:.*-$c$" "$RENDER" | grep -q 'replicas: 2'; then
      pass "replicas≥2 for $c"
    else
      fail "replicas≥2 missing for $c"
    fi
  fi
done

# --- OBJECT_STORE_ENDPOINT is external ---
if grep -q 'OBJECT_STORE_ENDPOINT' "$RENDER" && grep -A2 'OBJECT_STORE_ENDPOINT' "$RENDER" | grep -q 's3.amazonaws.com\|https://'; then
  pass "OBJECT_STORE_ENDPOINT points external"
else
  fail "OBJECT_STORE_ENDPOINT not external in render"
fi

# --- baseline (default values) still renders in-cluster data plane ---
echo ""
echo "-- helm template (default values, sanity) --"
DEFAULT_RENDER="$(mktemp)"
if helm template aim-dev "$CHART" >"$DEFAULT_RENDER" 2>/tmp/aim-769-helm-err2.txt; then
  if grep -q 'kind: StatefulSet' "$DEFAULT_RENDER"; then
    pass "default values still include Postgres StatefulSet"
  else
    fail "default values missing Postgres StatefulSet"
  fi
  if grep -q 'kind: NetworkPolicy' "$DEFAULT_RENDER"; then
    fail "NetworkPolicy should be off by default"
  else
    pass "NetworkPolicy disabled on default values"
  fi
else
  fail "default helm template failed"
  cat /tmp/aim-769-helm-err2.txt >&2
fi
rm -f "$DEFAULT_RENDER"

echo ""
if [[ $FAILURES -eq 0 ]]; then
  echo "RESULT: PASS ($FAILURES failures)"
  exit 0
else
  echo "RESULT: FAIL ($FAILURES failures)"
  exit 1
fi

#!/usr/bin/env bash
# AIM-553 / AIM-601 — static security defaults audit for the Helm chart.
#
# No cluster required. Checks values + templates for pilot-unsafe defaults and
# the presence of hardening introduced for score 7→8.
#
# Usage: ./scripts/aim-553-helm-security-audit.sh
# Exit 0 on PASS, 1 on FAIL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART="$ROOT/deploy/helm/aim"
FAILURES=0
WARNINGS=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }
warn() { echo "WARN: $1"; WARNINGS=$((WARNINGS + 1)); }

echo "== AIM-553 Helm security defaults audit =="
echo "chart: $CHART"

need_file() {
  [[ -f "$1" ]] && pass "present: ${1#$ROOT/}" || fail "missing: ${1#$ROOT/}"
}

need_file "$CHART/values.yaml"
need_file "$CHART/values-standard.yaml"
need_file "$CHART/values-dev.yaml"
need_file "$CHART/values-airgapped.yaml"
need_file "$CHART/templates/pdb.yaml"
need_file "$CHART/templates/_helpers.tpl"

# --- Dev defaults may carry local-only secrets (documented) -----------------
if grep -q 'localdev-only-not-a-secret' "$CHART/values.yaml"; then
  pass "values.yaml keeps localdev markers (dev chart — expected)"
else
  warn "values.yaml has no localdev marker (ok if deliberately purged)"
fi

# --- Standard profile must not enable authDev --------------------------------
if grep -E '^[[:space:]]*authDev:[[:space:]]*true([[:space:]]|$)' "$CHART/values-standard.yaml" >/dev/null; then
  fail "values-standard.yaml has authDev: true"
else
  pass "values-standard.yaml does not enable authDev"
fi

# --- Standard profile must enable multi-replica + PDBs -----------------------
for key in 'ingest:' 'api:'; do
  :
done
if grep -A2 '^ingest:' "$CHART/values-standard.yaml" | grep -q 'replicas: 2'; then
  pass "standard ingest.replicas=2"
else
  fail "standard ingest.replicas is not 2"
fi
if grep -A2 '^api:' "$CHART/values-standard.yaml" | grep -q 'replicas: 2'; then
  pass "standard api.replicas=2"
else
  fail "standard api.replicas is not 2"
fi
if grep -A3 '^guardrail:' "$CHART/values-standard.yaml" | grep -q 'replicas: 2'; then
  pass "standard guardrail.replicas=2"
else
  fail "standard guardrail.replicas is not 2"
fi
if grep -A2 'podDisruptionBudgets:' "$CHART/values-standard.yaml" | grep -q 'enabled: true'; then
  pass "standard podDisruptionBudgets.enabled=true"
else
  fail "standard profile does not enable PDBs"
fi

# --- Security contexts wired into app templates ------------------------------
for tpl in api.yaml ingest.yaml guardrail.yaml migrate-job.yaml; do
  f="$CHART/templates/$tpl"
  if grep -q 'aim.appContainerSecurityContext' "$f" && grep -q 'aim.appPodSecurityContext' "$f"; then
    pass "securityContext helpers in templates/$tpl"
  else
    fail "missing securityContext helpers in templates/$tpl"
  fi
done

# Vendor components intentionally NOT forced to app UID
if grep -q 'aim.appContainerSecurityContext' "$CHART/templates/postgres.yaml"; then
  fail "postgres template should not use app securityContext helper (vendor UID)"
else
  pass "postgres template leaves vendor security defaults"
fi
if grep -q 'aim.appContainerSecurityContext' "$CHART/templates/minio.yaml"; then
  fail "minio template should not use app securityContext helper (vendor UID)"
else
  pass "minio template leaves vendor security defaults"
fi

# --- Defaults: runAsNonRoot + drop ALL ---------------------------------------
if grep -A20 '^security:' "$CHART/values.yaml" | grep -q 'runAsNonRoot: true'; then
  pass "default security.podSecurityContext.runAsNonRoot=true"
else
  fail "default values missing runAsNonRoot: true"
fi
if grep -A30 '^security:' "$CHART/values.yaml" | grep -q 'drop:'; then
  pass "default security.containerSecurityContext drops capabilities"
else
  fail "default values missing capabilities.drop"
fi

# --- Standard must not set authDev true; should document existingSecret ------
if grep -q 'existingSecret' "$CHART/values-standard.yaml"; then
  pass "standard profile documents secrets.existingSecret"
else
  fail "standard profile missing secrets.existingSecret guidance"
fi

# --- NOTES warn on missing OIDC ---------------------------------------------
if grep -q 'no OIDC is configured' "$CHART/templates/NOTES.txt"; then
  pass "NOTES.txt warns when OIDC is unset"
else
  fail "NOTES.txt missing OIDC warning"
fi

# --- Ingress default off -----------------------------------------------------
if grep -A3 '^ingress:' "$CHART/values.yaml" | grep -q 'enabled: false'; then
  pass "ingress disabled by default"
else
  fail "ingress is not disabled by default"
fi

# --- Optional: helm template if helm binary present --------------------------
if command -v helm >/dev/null 2>&1; then
  RENDER="$(mktemp -d "${TMPDIR:-/tmp}/aim553-helm.XXXXXX")"
  if helm template aim "$CHART" -f "$CHART/values-standard.yaml" \
      --set api.oidc.issuer=https://accounts.example.test \
      --set api.oidc.clientId=aim-pilot \
      --set secrets.existingSecret=aim-prod-secrets \
      >"$RENDER/standard.yaml" 2>"$RENDER/err.txt"; then
    pass "helm template values-standard.yaml renders"
    if grep -q 'kind: PodDisruptionBudget' "$RENDER/standard.yaml"; then
      pass "rendered manifests include PodDisruptionBudget"
    else
      fail "rendered manifests missing PodDisruptionBudget"
    fi
    if grep -q 'allowPrivilegeEscalation: false' "$RENDER/standard.yaml"; then
      pass "rendered manifests set allowPrivilegeEscalation: false"
    else
      fail "rendered manifests missing allowPrivilegeEscalation: false"
    fi
    # Must not embed localdev password when existingSecret is set
    if grep -q 'localdev-only-not-a-secret' "$RENDER/standard.yaml"; then
      fail "rendered standard still embeds localdev-only-not-a-secret"
    else
      pass "rendered standard does not embed localdev secret material"
    fi
  else
    fail "helm template failed: $(head -5 "$RENDER/err.txt" | tr '\n' ' ')"
  fi
  rm -rf "$RENDER"
else
  warn "helm binary not installed — skipped render checks (static checks only)"
fi

echo "=="
echo "warnings: $WARNINGS"
if (( FAILURES > 0 )); then
  echo "RESULT: FAIL (${FAILURES} check(s) failed)"
  exit 1
fi
echo "RESULT: PASS — Helm security defaults audit clean"
exit 0

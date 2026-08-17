#!/usr/bin/env bash
# Audit pull_request vs pull_request_target for PR-head checkout safety.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"
echo "=== workflows with pull_request_target ==="
if grep -RIn --include='*.yml' --include='*.yaml' 'pull_request_target' .github/workflows; then
  echo
  echo "=== checkout refs in those files (must not be PR head) ==="
  for f in $(grep -RIl --include='*.yml' --include='*.yaml' 'pull_request_target' .github/workflows); do
    echo "--- $f ---"
    grep -nE 'pull_request_target|checkout|ref:' "$f" || true
  done
else
  echo "(none)"
fi
echo
echo "=== all pull_request triggers ==="
grep -RIn --include='*.yml' --include='*.yaml' -E '^\s*pull_request:' .github/workflows || true

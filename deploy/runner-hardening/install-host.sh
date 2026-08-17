#!/usr/bin/env bash
# Install D-C2 host pieces that do not require root:
#   - aim-ci-isolated / aim-ci-jobs networks
#   - job-completed wipe hook env for the runner
#
# Does NOT create a dedicated OS user or iptables rules (needs root).
# See docs/security/runner-hardening-d-c2.md for the separate-box path.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
RUNNER_HOME="${RUNNER_HOME:-$HOME/actions-runner-aim266}"

bash "$ROOT/setup-networks.sh"

HOOK_SRC="$ROOT/hooks/job-completed.sh"
HOOK_DST="$RUNNER_HOME/hooks/job-completed.sh"
mkdir -p "$RUNNER_HOME/hooks"
cp "$HOOK_SRC" "$HOOK_DST"
chmod +x "$HOOK_DST"

ENV_FILE="$RUNNER_HOME/.env"
if ! grep -q 'ACTIONS_RUNNER_HOOK_JOB_COMPLETED' "$ENV_FILE" 2>/dev/null; then
  {
    echo ""
    echo "# / D-C2: wipe workspace between jobs"
    echo "ACTIONS_RUNNER_HOOK_JOB_COMPLETED=$HOOK_DST"
  } >>"$ENV_FILE"
  echo "appended ACTIONS_RUNNER_HOOK_JOB_COMPLETED to $ENV_FILE"
else
  echo "ACTIONS_RUNNER_HOOK_JOB_COMPLETED already set in $ENV_FILE"
fi

echo
echo "Installed host pieces under $RUNNER_HOME"
echo "Restart the runner process to pick up .env changes:"
echo "  cd $RUNNER_HOME && ./start-clean.sh  # or your service unit"

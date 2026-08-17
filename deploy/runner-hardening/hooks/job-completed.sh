#!/usr/bin/env bash
# ACTIONS_RUNNER_HOOK_JOB_COMPLETED — wipe the job work tree so the next job
# cannot read prior checkout/artifacts (D-C2 precondition 5).
set -euo pipefail
WORK="${GITHUB_WORKSPACE:-}"
if [[ -z "$WORK" || ! -d "$WORK" ]]; then
  echo "job-completed hook: no GITHUB_WORKSPACE; skip wipe"
  exit 0
fi
case "$WORK" in
  */actions-runner*/_work/*|*/_work/*)
    echo "job-completed hook: wiping $WORK"
    find "$WORK" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    echo "job-completed hook: wipe done"
    ;;
  *)
    echo "job-completed hook: refusing wipe outside runner _work: $WORK"
    exit 0
    ;;
esac

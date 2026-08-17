#!/usr/bin/env bash
# AIM-635: automated DR game day — wraps backup-restore-proof with timing + JSON log.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROOF="$ROOT/scripts/backup-restore-proof.sh"
OUT="${OUT:-}"
START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
START_S=$(date +%s)

echo "== AIM-635 DR game day =="
echo "start: $START_ISO"
echo "proof: $PROOF"

if [[ ! -x "$PROOF" ]]; then
  chmod +x "$PROOF" 2>/dev/null || true
fi

set +e
"$PROOF"
RC=$?
set -e

END_S=$(date +%s)
END_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
WALL=$((END_S - START_S))
STATUS="PASS"
if [[ "$RC" -ne 0 ]]; then STATUS="FAIL"; fi

echo "end:   $END_ISO"
echo "wall_seconds: $WALL"
echo "backup_restore_exit: $RC"
echo "RESULT: $STATUS — DR game day (empirical dump/restore RTO sample ${WALL}s)"

if [[ -n "$OUT" ]]; then
  mkdir -p "$(dirname "$OUT")"
  cat >"$OUT" <<JSON
{
  "kind": "aim-635-dr-gameday",
  "startedAt": "$START_ISO",
  "endedAt": "$END_ISO",
  "wallSeconds": $WALL,
  "backupRestoreExit": $RC,
  "status": "$STATUS",
  "rpoPilotHours": 24,
  "rtoPilotBusinessHours": 8,
  "rpoEnterpriseMinutes": 15,
  "rtoEnterpriseMinutes": 60,
  "notes": "wallSeconds is empirical local dump/restore time, not enterprise failover SLA"
}
JSON
  echo "wrote $OUT"
fi

exit "$RC"

#!/usr/bin/env bash
# — push the declared enforce bundle to this host.
#
# Usage:
#   ./scripts/deploy-enforcement.sh           # user state dir (fleet enforce)
#   sudo ./scripts/deploy-enforcement.sh --managed
#   ./scripts/deploy-enforcement.sh --shadow  # emergency rollback
# ./scripts/deploy-enforcement.sh --pilot # pilot overlay (PII + restricted-repo)
#   sudo ./scripts/deploy-enforcement.sh --pilot --managed
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE=enforce
MANAGED=0

for a in "$@"; do
  case "$a" in
    --managed) MANAGED=1 ;;
    --shadow) MODE=shadow ;;
    --pilot) MODE=pilot ;;
    -h|--help)
      sed -n '2,10p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

SRC="$ROOT/deploy/enforcement/enforcement.${MODE}.json"
[ -f "$SRC" ] || { echo "missing $SRC" >&2; exit 1; }

if [ "$MANAGED" -eq 1 ]; then
  if [ "$(id -u)" -ne 0 ]; then
    echo "managed path requires root (or re-run with sudo)" >&2
    exit 1
  fi
  install -d -m 0755 /etc/aim-collector
  install -m 0644 "$SRC" /etc/aim-collector/enforcement.json
  DEST=/etc/aim-collector/enforcement.json
else
  DEST="${AIM_STATE_DIR:-$HOME/.aim-collector}/enforcement.json"
  mkdir -p "$(dirname "$DEST")"
  install -m 0644 "$SRC" "$DEST"
fi

echo "installed $SRC → $DEST"
python3 -c "
import json, sys
p = json.load(open(sys.argv[1]))
rules = p.get('rules') or {}
print(
    'mode=', p.get('mode'),
    'hash=', p.get('policy_hash'),
    'secret=', rules.get('secret-pattern-in-prompt'),
    'pii=', rules.get('pii-in-prompt'),
    'restricted_repo=', rules.get('restricted-repo-access'),
)
" "$DEST"

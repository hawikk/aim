#!/usr/bin/env bash
# Replay a (sanitized) proxy log sample through the ingestion connector and
# verify the output — the acceptance check for IT-provided samples.
#
# Usage:
#   ./replay_sample.sh <sample-file> [format]
#
# format defaults to "auto" (sniff each line). The script:
#   1. runs proxy_ingest.py over the sample (stdout sink),
#   2. validates every emitted event (built-in checks, plus full JSON Schema
#      validation against the canonical v1 schema when the `jsonschema`
#      package is available),
#   3. exits non-zero if the sample produced zero events or any event is
#      invalid — so IT can iterate on their export until this passes.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLE="${1:?usage: replay_sample.sh <sample-file> [format]}"
FORMAT="${2:-auto}"
SCHEMA="$HERE/../../packages/schema/schema/v1/ai-usage-event.schema.json"

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

python3 "$HERE/proxy_ingest.py" \
    --collector replay-check \
    --format "$FORMAT" \
    --input "$SAMPLE" \
    --sink file --output "$OUT" \
    --salt-file "$(mktemp -u)" \
    --coverage

python3 - "$OUT" "$SCHEMA" <<'EOF'
import json, os, sys

out_path, schema_path = sys.argv[1], sys.argv[2]
events = [json.loads(l) for l in open(out_path) if l.strip()]
if not events:
    print("FAIL: sample produced 0 AI events — check format/detection DB", file=sys.stderr)
    sys.exit(1)

try:
    import jsonschema
    schema = json.load(open(schema_path)) if os.path.exists(schema_path) else None
except ImportError:
    schema = None

if schema:
    for i, e in enumerate(events):
        jsonschema.validate(e, schema)
    print(f"OK: {len(events)} events, all valid against canonical v1 schema")
else:
    print(f"OK: {len(events)} events, connector built-in validation passed "
          "(install jsonschema for full schema check)")
EOF

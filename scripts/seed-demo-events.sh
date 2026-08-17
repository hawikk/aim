#!/usr/bin/env bash
# Seed a local stack with the valid example events from packages/schema.
# Usage: ./scripts/seed-demo-events.sh
# Env:   SEED_BASE_URL (default http://localhost:3000)
#        SEED_TOKEN    (default dev-token-change-me; must match INGEST_TOKENS)
set -euo pipefail

BASE_URL="${SEED_BASE_URL:-http://localhost:3000}"
TOKEN="${SEED_TOKEN:-dev-token-change-me}"
SAMPLES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../packages/schema/examples" && pwd)"

payload=$(SAMPLES_DIR="$SAMPLES_DIR" node -e '
  const fs = require("node:fs");
  const path = require("node:path");
  const dir = process.env.SAMPLES_DIR;
  const events = fs.readdirSync(dir)
    .filter((f) => f.startsWith("valid-") && f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")));
  process.stdout.write(JSON.stringify({ events }));
')

echo "Posting ${SAMPLES_DIR} samples to ${BASE_URL}/v1/events ..."
curl -sfS -X POST "${BASE_URL}/v1/events" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$payload"
echo

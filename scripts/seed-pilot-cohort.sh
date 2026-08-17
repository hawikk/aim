#!/usr/bin/env bash
# Seed a synthetic 12-seat cross-team pilot cohort (AIM-31, extended in AIM-114)
# through the real ingest API. Events conform to the canonical AIM-18 schema v1
# (packages/schema/schema/v1/ai-usage-event.schema.json) — metadata-only,
# salted-HMAC-style pseudonyms, second-precision UTC timestamps.
#
# Each seat maps to a user in the identity-sync dev fixture directory
# (services/identity-sync/fixtures) and posts its own batch with a
# `collector: { os_user }` identity block, so ingest resolves every event to a
# pseudonym + fixture team (AIM-49). The 12 seats span all 12 fixture teams —
# /api/teams shows real team rows instead of one (unattributed) bucket.
#
# The cohort is deterministic (fixed pseudonyms, seeded PRNG) so re-runs are
# idempotent: the same event_ids are regenerated and ingest dedups them. Note
# that dedup means re-seeding does NOT retro-attribute events stored before
# identity resolution was wired — use a fresh stack for a fully attributed view.
#
# Usage: ./scripts/seed-pilot-cohort.sh
# Env:   SEED_BASE_URL (default http://localhost:3000)
#        SEED_TOKEN    (default dev-token-change-me; must match INGEST_TOKENS)
#        PILOT_DAYS    (default 7) days of history to synthesize
set -euo pipefail

BASE_URL="${SEED_BASE_URL:-http://localhost:3000}"
TOKEN="${SEED_TOKEN:-dev-token-change-me}"
DAYS="${PILOT_DAYS:-7}"

payload_file=$(mktemp)
trap 'rm -f "$payload_file"' EXIT

PILOT_DAYS="$DAYS" node -e '
  const crypto = require("node:crypto");

  // Deterministic PRNG (mulberry32) so re-seeding produces identical event_ids.
  let state = 0xa1310001;
  const rand = () => {
    state |= 0; state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const pick = (arr) => arr[Math.floor(rand() * arr.length)];
  const hex = (s) => crypto.createHash("sha256").update(s).digest("hex");
  const uuid = (s) => {
    const h = hex(s);
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
  };

  const days = Number.parseInt(process.env.PILOT_DAYS, 10);
  const now = Date.now();

  // 12 seats, one fixture user per fixture team (services/identity-sync/
  // fixtures/directory_users.json). os_user is attested as collector identity
  // per batch and resolves via the email heuristic (<user>@example.com).
  const SEAT_USERS = [
    "jdoe",      // Engineering
    "rpatel",    // Security
    "agarcia",   // Data
    "tkim",      // Design
    "nguyen",    // Marketing
    "owallace",  // Sales
    "hschmidt",  // Finance
    "bkumar",    // People
    "eivanova",  // Legal
    "cmoore",    // Support
    "ytanaka",   // IT
    "fosei",     // Research
  ];
  // Tools per seat reflect a realistic mix: everyone has claude_code, some
  // also cursor / kilo_code.
  const seats = SEAT_USERS.map((os_user, i) => {
    const n = i + 1;
    const tools = ["claude_code"];
    if (n <= 5) tools.push("cursor");
    if (n <= 3) tools.push("kilo_code");
    return {
      os_user,
      host_ref: hex(`pilot-sec-seat-${n}-host`),
      user_ref: hex(`pilot-sec-seat-${n}-user`),
      repo_ref: hex(`pilot-sec-repo-${(n % 3) + 1}`),
      tools,
    };
  });

  const MODELS = {
    claude_code: { provider: "anthropic", model: "claude-sonnet-4-5", version: "1.0.62" },
    cursor: { provider: "anthropic", model: "claude-sonnet-4-5", version: "0.45.3" },
    kilo_code: { provider: "openai", model: "gpt-4o", version: "3.1.2" },
  };

  // One batch per seat: the collector identity block attests the endpoint
  // identity once per batch and is stamped onto every event it carries.
  const batches = seats.map((seat) => ({ collector: { os_user: seat.os_user }, events: [] }));
  const push = (seatIdx, e) => batches[seatIdx].events.push(e);

  for (let d = days; d >= 1; d--) {
    const dayStart = new Date(now - d * 86400000);
    dayStart.setUTCHours(9, 0, 0, 0); // work starts ~09:00 UTC
    for (let s = 0; s < seats.length; s++) {
      const seat = seats[s];
      for (const tool of seat.tools) {
        const n = 2 + Math.floor(rand() * 5); // 2-6 events per tool per day
        const session = `sess-${hex(seat.user_ref).slice(0, 8)}-d${d}-${tool}`;
        for (let k = 0; k < n; k++) {
          const ts = new Date(dayStart.getTime() + Math.floor(rand() * 8 * 3600) * 1000);
          const tokensIn = 2000 + Math.floor(rand() * 40000);
          const tokensOut = 500 + Math.floor(rand() * 6000);
          const m = MODELS[tool];
          push(s, {
            schema_version: "1.0",
            event_id: uuid(`${seat.user_ref}:${tool}:d${d}:${k}`),
            ts: ts.toISOString().replace(/\.\d{3}Z$/, "Z"),
            source: "endpoint",
            tool,
            tool_version: m.version,
            provider: m.provider,
            model: m.model,
            session_id: session,
            tokens_in: tokensIn,
            tokens_out: tokensOut,
            cost_estimate_usd: Math.round((tokensIn * 3e-6 + tokensOut * 15e-6) * 1e6) / 1e6,
            host_ref: seat.host_ref,
            user_ref: seat.user_ref,
            repo_ref: seat.repo_ref,
            match_flags: [],
          });
        }
      }
    }
  }

  // Unapproved-tool discovery: seats 3 and 7 ran windsurf (api.codeium.com),
  // observed via the proxy source. Flagged by the policy detector.
  for (const seatNo of [3, 7]) {
    const seat = seats[seatNo - 1];
    for (let d = days; d >= 1; d--) {
      const ts = new Date(now - d * 86400000 + 10 * 3600 * 1000);
      push(seatNo - 1, {
        schema_version: "1.0",
        event_id: uuid(`windsurf:${seat.user_ref}:d${d}`),
        ts: ts.toISOString().replace(/\.\d{3}Z$/, "Z"),
        source: "proxy",
        tool: "other",
        tool_raw: "windsurf",
        tool_version: "1.8.21",
        session_id: `proxy-${hex(seat.host_ref).slice(0, 8)}-d${d}`,
        host_ref: seat.host_ref,
        user_ref: seat.user_ref,
        match_flags: [
          { detector: "policy:unapproved-domain", category: "policy", severity: "medium" },
        ],
      });
    }
  }

  // One secret-detector hit (metadata-only flag; the matched content is never
  // stored) to exercise the findings path: seat 5, claude_code, day 2.
  {
    const seat = seats[4];
    const ts = new Date(now - 2 * 86400000 + 14 * 3600 * 1000);
    push(4, {
      schema_version: "1.0",
      event_id: uuid(`secret-flag:${seat.user_ref}`),
      ts: ts.toISOString().replace(/\.\d{3}Z$/, "Z"),
      source: "endpoint",
      tool: "claude_code",
      tool_version: MODELS.claude_code.version,
      provider: MODELS.claude_code.provider,
      model: MODELS.claude_code.model,
      session_id: `sess-${hex(seat.user_ref).slice(0, 8)}-d2-claude_code`,
      tokens_in: 12040,
      tokens_out: 1830,
      cost_estimate_usd: 0.0636,
      host_ref: seat.host_ref,
      user_ref: seat.user_ref,
      repo_ref: seat.repo_ref,
      match_flags: [
        { detector: "secret:aws-access-key", category: "secret", severity: "high" },
      ],
    });
  }

  process.stdout.write(JSON.stringify({ batches }));
' > "$payload_file"

count=$(node -e 'const p=JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8"));console.log(p.batches.reduce((a,b)=>a+b.events.length,0))' "$payload_file")
echo "Posting ${count} synthetic pilot events (12 seats, ${DAYS} days) to ${BASE_URL}/v1/events ..."
# Ingest caps a batch at 500 events (MAX_BATCH_SIZE, services/ingest) and the
# collector identity block applies per batch, so post each seat separately
# (sub-chunked at 400 for safety with larger PILOT_DAYS).
node -e '
  const fs = require("node:fs");
  const https = require("node:http");
  const payload = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const base = new URL(process.argv[2]);
  const token = process.argv[3];
  const CHUNK = 400;
  const post = (collector, batch) => new Promise((resolve, reject) => {
    const req = https.request({
      hostname: base.hostname, port: base.port, path: "/v1/events", method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => (res.statusCode < 300 ? resolve(JSON.parse(data)) : reject(new Error(`HTTP ${res.statusCode}: ${data}`))));
    });
    req.on("error", reject);
    req.end(JSON.stringify({ collector, events: batch }));
  });
  (async () => {
    let accepted = 0, duplicates = 0, rejected = 0;
    for (const { collector, events } of payload.batches) {
      for (let i = 0; i < events.length; i += CHUNK) {
        const r = await post(collector, events.slice(i, i + CHUNK));
        accepted += r.accepted ?? 0; duplicates += r.duplicates ?? 0; rejected += (r.rejected ?? []).length;
      }
    }
    console.log(JSON.stringify({ accepted, duplicates, rejected }));
  })().catch((e) => { console.error(e.message); process.exit(1); });
' "$payload_file" "$BASE_URL" "$TOKEN"
echo
echo "Done. Verify with:"
echo "  psql \"\$DATABASE_URL\" -c \"SELECT tool, count(*), count(DISTINCT user_ref) seats FROM events GROUP BY tool ORDER BY 1;\""
echo "  psql \"\$DATABASE_URL\" -c \"SELECT team, count(*) FROM events GROUP BY team ORDER BY 1;\""

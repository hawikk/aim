#!/usr/bin/env node
/**
 * acceptance suite for the ingestion pipeline.
 *
 * Implementation-agnostic: runs against any deployed ingest service and
 * checks the acceptance criteria end to end:
 *
 *   1. Auth: missing/invalid collector token → 401.
 *   2. Unknown schema_version rejected loudly (clear error naming the version).
 *   3. Mixed batch: valid events land, invalid ones rejected with errors.
 *   4. Idempotency: replaying event_ids yields duplicates, not double storage.
 *   5. Load: 5k events/min sustained (default 2 min) with zero HTTP errors.
 *   6. Zero loss: every acknowledged event is stored exactly once
 *      (verified via DB count when reachable, else via full replay dedupe).
 *   7. Observability: /healthz, /readyz, /metrics present.
 *
 * Usage:
 *   INGEST_TOKEN=... node scripts/ingest-acceptance.mjs
 *
 * Env: INGEST_URL (default http://127.0.0.1:8080), INGEST_TOKEN (required),
 *      LOAD_RATE_PER_MIN (5000), LOAD_DURATION_S (120), PGDB (aim),
 *      SKIP_LOAD=1 to run only functional checks.
 */
import { randomUUID, createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

const BASE = process.env.INGEST_URL ?? "http://127.0.0.1:8080";
const TOKEN = process.env.INGEST_TOKEN;
const RATE = Number(process.env.LOAD_RATE_PER_MIN ?? 5000);
const DURATION = Number(process.env.LOAD_DURATION_S ?? 120);
const SKIP_LOAD = process.env.SKIP_LOAD === "1";

if (!TOKEN) {
  console.error("INGEST_TOKEN is required");
  process.exit(2);
}

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
}

const hex64 = (s) => createHash("sha256").update(s).digest("hex");

/** schema v1 event (metadata-only) — the shape collectors emit. */
function makeEvent(overrides = {}) {
  return {
    schema_version: "1.0",
    event_id: randomUUID(),
    // RFC 3339, second precision (schema pattern forbids fractional seconds).
    ts: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    host_ref: hex64(`host-${Math.floor(Math.random() * 700)}`),
    user_ref: hex64(`user-${Math.floor(Math.random() * 700)}`),
    tool: "claude_code",
    tool_version: "1.0.0",
    model: "claude-opus-4",
    provider: "anthropic",
    session_id: randomUUID(),
    tokens_in: 500,
    tokens_out: 120,
    repo_ref: hex64("repo-example"),
    match_flags: [],
    source: "endpoint",
    ...overrides,
  };
}

async function postEvents(events, token = TOKEN) {
  const headers = { "content-type": "application/json" };
  if (token !== null) headers.authorization = `Bearer ${token}`;
  const res = await fetch(`${BASE}/v1/events`, {
    method: "POST",
    headers,
    body: JSON.stringify({ events }),
  });
  let body = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON error body */
  }
  return { status: res.status, body };
}

async function dbCount(sql) {
  // Count via compose postgres without requiring host psql.
  const { stdout } = await execFileP("docker", [
    "compose", "exec", "-T", "postgres",
    "psql", "-U", "aim", "-d", process.env.PGDB ?? "aim", "-tAc", sql,
  ]);
  return Number(stdout.trim());
}

// ---------- 1. auth ----------
{
  const noTok = await postEvents([makeEvent()], null);
  const badTok = await postEvents([makeEvent()], "definitely-wrong-token");
  check("auth: missing token → 401", noTok.status === 401, `got ${noTok.status}`);
  check("auth: invalid token → 401", badTok.status === 401, `got ${badTok.status}`);
}

// ---------- 2. unknown schema_version rejected loudly ----------
{
  const r = await postEvents([makeEvent({ schema_version: "99.0" })]);
  const text = JSON.stringify(r.body);
  check(
    "unknown schema_version rejected",
    (r.status === 400 || r.status === 422 || (r.status === 200 && (r.body?.rejected?.length ?? 0) === 1)) &&
      /99\.0|unsupported|unknown/i.test(text),
    `status=${r.status} body=${text.slice(0, 160)}`,
  );
}

// ---------- 3. mixed batch ----------
const mixedValid = [makeEvent(), makeEvent()];
{
  const bad1 = makeEvent();
  delete bad1.event_id;
  const bad2 = makeEvent({ event_type: "not_a_type" });
  const r = await postEvents([mixedValid[0], bad1, mixedValid[1], bad2]);
  const rejectedLen = r.body?.rejected?.length ?? 0;
  check(
    "mixed batch: valid accepted, invalid rejected with errors",
    r.status === 200 && r.body?.accepted === 2 && rejectedLen === 2,
    `status=${r.status} accepted=${r.body?.accepted} rejected=${rejectedLen}`,
  );
}

// ---------- 4. idempotent replay ----------
{
  const replay = await postEvents(mixedValid);
  const body = replay.body ?? {};
  const dupes = body.duplicates ?? body.duplicate ?? null;
  const ok =
    (typeof dupes === "number" && dupes === 2) ||
    (body.accepted === 0 && (body.rejected?.length ?? 0) === 0) ||
    (typeof body.accepted === "number" && body.accepted === 0);
  check(
    "idempotency: replayed event_ids not double-stored",
    ok,
    `status=${replay.status} body=${JSON.stringify(body).slice(0, 160)}`,
  );
}

// ---------- 7. observability endpoints (before load, cheap) ----------
for (const [path, name] of [
  ["/healthz", "health check"],
  ["/readyz", "readiness check"],
  ["/metrics", "metrics endpoint"],
]) {
  try {
    const res = await fetch(`${BASE}${path}`);
    check(`observability: ${name} (${path})`, res.status === 200, `got ${res.status}`);
  } catch (err) {
    check(`observability: ${name} (${path})`, false, String(err));
  }
}

// ---------- 5/6. load + zero loss ----------
if (!SKIP_LOAD) {
  const BATCH = 50;
  const intervalMs = 1000 / (RATE / 60 / BATCH);
  const sentIds = [];
  let httpErrors = 0;
  let non200 = 0;
  const t0 = Date.now();
  const inflight = new Set();

  console.log(
    `\nload: ${RATE} events/min for ${DURATION}s (batches of ${BATCH} every ${intervalMs.toFixed(0)}ms)`,
  );
  const timer = setInterval(() => {
    if ((Date.now() - t0) / 1000 >= DURATION) return clearInterval(timer);
    const events = Array.from({ length: BATCH }, () => makeEvent());
    for (const e of events) sentIds.push(e.event_id);
    const p = postEvents(events)
      .then((r) => {
        if (r.status !== 200) non200++;
      })
      .catch(() => httpErrors++)
      .finally(() => inflight.delete(p));
    inflight.add(p);
  }, intervalMs);

  while ((Date.now() - t0) / 1000 < DURATION || inflight.size > 0) {
    await new Promise((r) => setTimeout(r, 1000));
  }
  console.log(
    `load sent: ${sentIds.length} events, http_errors=${httpErrors}, non200=${non200}, elapsed=${((Date.now() - t0) / 1000).toFixed(0)}s`,
  );
  check("load: 5k/min sustained without HTTP errors", httpErrors === 0 && non200 === 0,
    `${sentIds.length} events, errors=${httpErrors}, non200=${non200}`);

  // Zero loss via DB when reachable.
  let dbVerified = false;
  for (let attempt = 0; attempt < 30 && !dbVerified; attempt++) {
    try {
      const stored = await dbCount("SELECT count(*) FROM events");
      const distinct = await dbCount("SELECT count(DISTINCT event_id) FROM events");
      check(
        "zero loss: stored == distinct event_ids, >= load + functional accepted",
        stored === distinct && stored >= sentIds.length,
        `stored=${stored} distinct=${distinct} sent=${sentIds.length}`,
      );
      dbVerified = true;
    } catch {
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  if (!dbVerified) {
    // Fallback: replay the full load set; everything must come back as known.
    let known = 0;
    for (let i = 0; i < sentIds.length; i += BATCH) {
      const ids = sentIds.slice(i, i + BATCH);
      const events = ids.map((id) => makeEvent({ event_id: id }));
      const r = await postEvents(events);
      const body = r.body ?? {};
      known += body.duplicates ?? (body.accepted === 0 ? ids.length : 0);
    }
    check("zero loss (replay fallback): all sent ids already stored", known === sentIds.length,
      `known=${known}/${sentIds.length}`);
  }
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);

#!/usr/bin/env node
/**
 * AIM-32 canary end-to-end: secret-in-prompt detection, collector flags →
 * Postgres finding → security triage, against a scratch database.
 *
 * Pipeline under test (all real, no mocks):
 *   synthetic canary event (match_flags only, NO secret material)
 *     → real ingest API (bearer auth, AJV schema enforcement)
 *     → guardrail evaluate-db runner (real engine, policies/guardrail/v1)
 *     → findings table
 *     → triage API (GET /api/findings, PATCH /api/findings/:id)
 *
 * Also verifies the privacy boundary: the stored event carries no content
 * fields, and ingest rejects an event that tries to attach a `prompt` field
 * (schema additionalProperties:false).
 *
 * Prereqs:
 *   - the repo's compose Postgres running (`docker compose up -d postgres`),
 *     OR CANARY_DSN pointing at a scratch database you own;
 *   - ingest built (`pnpm --filter @aimon/ingest build`);
 *   - the root .venv with guardrail installed (`pip install -e services/guardrail`).
 *
 * Usage:
 *   node scripts/aim-32-canary-e2e.mjs
 *
 * Env: CANARY_DSN (default postgres://aim:localdev-only-not-a-secret@localhost:5432/aim_canary_32),
 *      CANARY_DB_NAME (derived from CANARY_DSN path), SKIP_DB_CREATE=1 to use
 *      CANARY_DSN as-is, INGEST_PORT (18080), API_PORT (18081),
 *      MEASUREMENT_OUT (docs/aim-32-canary-measurement.json).
 */
import { randomUUID, createHash } from "node:crypto";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const execFileP = promisify(execFile);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const DSN = process.env.CANARY_DSN ?? "postgres://aim:localdev-only-not-a-secret@localhost:5432/aim_canary_32";
const DB_NAME = new URL(DSN).pathname.replace(/^\//, "");
const TOKEN = "canary-token-not-a-secret";
const INGEST_PORT = Number(process.env.INGEST_PORT ?? 18080);
const API_PORT = Number(process.env.API_PORT ?? 18081);
const INGEST_URL = `http://127.0.0.1:${INGEST_PORT}`;
const API_URL = `http://127.0.0.1:${API_PORT}`;
const MEASUREMENT_OUT = process.env.MEASUREMENT_OUT ?? join(ROOT, "docs", "aim-32-canary-measurement.json");

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
}

const hex64 = (s) => createHash("sha256").update(s).digest("hex");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Run SQL against the canary DB via the compose Postgres container. */
async function psql(sql, db = DB_NAME) {
  const { stdout } = await execFileP("docker", [
    "compose", "exec", "-T", "postgres",
    "psql", "-U", "aim", "-d", db, "-tAc", sql,
  ], { cwd: ROOT });
  return stdout.trim();
}

async function waitFor(url, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch { /* not up yet */ }
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${url}`);
    await sleep(300);
  }
}

function spawnService(name, cmd, args, env) {
  const child = spawn(cmd, args, { cwd: ROOT, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  child.stderr.on("data", (d) => process.stderr.write(`[${name}] ${d}`));
  return child;
}

const children = [];
let ttdMs = null;
let exitCode = 1;
try {
  // ---- 0. scratch database -------------------------------------------------
  if (process.env.SKIP_DB_CREATE !== "1") {
    await psql(`DROP DATABASE IF EXISTS ${DB_NAME}`, "postgres");
    await psql(`CREATE DATABASE ${DB_NAME}`, "postgres");
    console.log(`scratch database ${DB_NAME} created (compose postgres)`);
  }

  // ---- 1. start ingest (applies migrations 001-003 on boot) + dashboard api
  children.push(spawnService("ingest", "node", ["services/ingest/dist/index.js"], {
    DATABASE_URL: DSN, INGEST_TOKENS: TOKEN, PORT: String(INGEST_PORT),
  }));
  children.push(spawnService("api", "node", ["apps/api/src/server.js"], {
    DATABASE_URL: DSN, PORT: String(API_PORT), AIM_AUTH_DEV: "1",
  }));
  await waitFor(`${INGEST_URL}/readyz`);
  await waitFor(`${API_URL}/api/health`);
  console.log("ingest + api up\n");

  // ---- 2. canary event: exactly what a collector emits for a secret match —
  // flags only. There is NO secret material anywhere in this script. ---------
  const canaryEvent = {
    schema_version: "1.0",
    event_id: randomUUID(),
    ts: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    host_ref: hex64("aim32-canary-host"),
    user_ref: hex64("aim32-canary-user"),
    tool: "claude_code",
    tool_version: "1.0.62",
    model: "claude-sonnet-4-5",
    provider: "anthropic",
    session_id: randomUUID(),
    tokens_in: 100,
    tokens_out: 50,
    repo_ref: hex64("aim32-canary-repo"),
    match_flags: [{ detector: "secret:aws-access-key", category: "secret", severity: "high" }],
    source: "endpoint",
  };

  const t0 = Date.now();
  const post = await fetch(`${INGEST_URL}/v1/events`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
    body: JSON.stringify({ events: [canaryEvent] }),
  });
  const postBody = await post.json();
  check("canary event accepted by ingest", post.status === 200 && postBody.accepted === 1,
    `status=${post.status} body=${JSON.stringify(postBody)}`);

  // ---- 3. run the post-ingest evaluator ------------------------------------
  const evalRun = await execFileP(join(ROOT, ".venv/bin/python"), [
    "-m", "guardrail.cli", "evaluate-db", "--rules", "policies/guardrail/v1",
  ], { cwd: ROOT, env: { ...process.env, DATABASE_URL: DSN } });
  console.log(`evaluate-db: ${evalRun.stderr.trim()}`);

  // ---- 4. finding visible via triage API; measure time-to-detect -----------
  let finding = null;
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    const res = await fetch(`${API_URL}/api/findings?rule_id=secret-pattern-in-prompt`);
    const body = await res.json();
    if (body.total >= 1) { finding = body.findings[0]; break; }
    await sleep(200);
  }
  ttdMs = finding ? Date.now() - t0 : null;
  check("secret-pattern-in-prompt finding visible via triage API", Boolean(finding),
    ttdMs != null ? `time-to-detect ${ttdMs}ms (event POST → finding visible)` : "not found within 10s");
  if (finding) {
    check("finding severity is critical, decision observe", finding.severity === "critical" && finding.decision === "observe",
      `severity=${finding.severity} decision=${finding.decision}`);
    const cnt = Number(await psql(`SELECT count(*) FROM findings WHERE rule_id = 'secret-pattern-in-prompt'`));
    check("exactly one finding row in Postgres", cnt === 1, `count=${cnt}`);
  }

  // ---- 5. triage it ---------------------------------------------------------
  if (finding) {
    const patch = await fetch(`${API_URL}/api/findings/${finding.findingId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ status: "acknowledged", note: "AIM-32 canary: detector verified end-to-end" }),
    });
    const patched = await patch.json();
    check("triage PATCH acknowledged + note", patch.status === 200 && patched.status === "acknowledged",
      `status=${patch.status}`);
    const persisted = await psql(
      `SELECT status || '|' || coalesce(triage_note,'') || '|' || coalesce(triaged_by,'') FROM findings WHERE finding_id = '${finding.findingId}'`);
    check("triage persisted in Postgres", persisted.startsWith("acknowledged|AIM-32 canary"),
      persisted);
  }

  // ---- 6. privacy boundary ---------------------------------------------------
  {
    const keys = await psql(`SELECT string_agg(k, ',' ORDER BY k) FROM events e, LATERAL jsonb_object_keys(e.payload) k WHERE e.event_id = '${canaryEvent.event_id}'`);
    const CONTENT_KEYS = ["prompt", "content", "response", "completion", "code", "message", "messages", "text"];
    const leaked = keys.split(",").filter((k) => CONTENT_KEYS.includes(k));
    check("stored canary event carries no content fields", leaked.length === 0, `payload keys: ${keys}`);

    const dirty = { ...canaryEvent, event_id: randomUUID(), prompt: "canary content field — must be rejected" };
    const res = await fetch(`${INGEST_URL}/v1/events`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({ events: [dirty] }),
    });
    const body = await res.json();
    const rejected = body?.rejected?.length === 1 && body?.accepted === 0;
    check("ingest rejects event with a prompt field (additionalProperties:false)", res.status === 200 && rejected,
      `status=${res.status} rejected=${JSON.stringify(body?.rejected ?? [])}`);
  }

  // ---- 7. dashboard /api/flags shows the detector (regression: object flags)
  {
    const res = await fetch(`${API_URL}/api/flags`);
    const body = await res.json();
    const det = body.detectors?.find((d) => d.detector === "secret:aws-access-key");
    check("/api/flags aggregates the canary detector", Boolean(det && det.hits === 1),
      JSON.stringify(det ?? body.detectors));
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (ttdMs != null) console.log(`time-to-detect: ${ttdMs}ms (canary, single-event batch)`);
  exitCode = failed.length === 0 ? 0 : 1;

  writeFileSync(MEASUREMENT_OUT, JSON.stringify({
    issue: "AIM-32",
    kind: "canary",
    at: new Date().toISOString(),
    time_to_detect_ms: ttdMs,
    checks_passed: results.length - failed.length,
    checks_total: results.length,
    results,
  }, null, 2) + "\n");
  console.log(`measurement written to ${MEASUREMENT_OUT}`);
} finally {
  for (const c of children) c.kill("SIGTERM");
  await sleep(500);
  for (const c of children) if (!c.killed) c.kill("SIGKILL");
}
process.exit(exitCode);

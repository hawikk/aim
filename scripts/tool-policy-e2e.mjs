#!/usr/bin/env node
/**
 * staging e2e: per-tool-call guardrail rules fire end-to-end and the
 * new-MCP-server alert is delivered through the webhook path.
 *
 * Pipeline under test (all real, no mocks):
 *   synthetic tool_use + inventory events (metadata-only)
 *     → real ingest API (bearer auth, AJV schema enforcement, schema v1.2)
 *     → guardrail evaluate-db against a STAGING RULESET OVERLAY
 *       (shipped core.yaml + staging-overlay.yaml whose restricted_repos
 *       lists the canary repo; AIM_HASH_SALT set so HMAC matching is live)
 *     → findings table (assert shell/network/inventory rules fired)
 *     → ALERT_WEBHOOK_URL pointed at a local receiver; assert the
 *       unapproved-mcp-server-configured finding arrives with a valid
 *       X-AIM-Signature HMAC and a finding_deliveries 'delivered' row.
 *
 * There is NO content anywhere in this script: tool_calls entries are
 * metadata-only aggregates, inventory entries are name+scope only.
 *
 * Prereqs (same as scripts/canary-e2e.mjs):
 *   - the repo's compose Postgres running (`docker compose up -d postgres`);
 *   - ingest built (`pnpm --filter @aimon/ingest build`);
 *   - the root .venv with guardrail installed editable.
 *
 * Usage:
 *   node scripts/tool-policy-e2e.mjs
 *
 * Env: CANARY_DSN (default postgres://aim:localdev-only-not-a-secret@localhost:5432/aim_tool_policy_97),
 *      SKIP_DB_CREATE=1 to use CANARY_DSN as-is, INGEST_PORT (18082),
 *      AIM_HASH_SALT_E2E (default "aim97-staging-salt-not-production"),
 *      MEASUREMENT_OUT (docs/aim-97-tool-policy-e2e.json).
 */
import { randomUUID, createHash, createHmac } from "node:crypto";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { createServer } from "node:http";
import { copyFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const execFileP = promisify(execFile);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const DSN = process.env.CANARY_DSN ?? "postgres://aim:localdev-only-not-a-secret@localhost:5432/aim_tool_policy_97";
const DB_NAME = new URL(DSN).pathname.replace(/^\//, "");
const TOKEN = "aim97-e2e-token-not-a-secret";
const SALT = process.env.AIM_HASH_SALT_E2E ?? "aim97-staging-salt-not-production";
const WEBHOOK_SECRET = "aim97-webhook-secret-not-a-secret";
const RESTRICTED_REPO = "/staging/secrets-vault"; // cleartext stays in the overlay, never in events
const INGEST_PORT = Number(process.env.INGEST_PORT ?? 18082);
const INGEST_URL = `http://127.0.0.1:${INGEST_PORT}`;
const MEASUREMENT_OUT = process.env.MEASUREMENT_OUT ?? join(ROOT, "docs", "aim-97-tool-policy-e2e.json");

const TARGET_RULES = [
  "shell-tool-restricted-repo",
  "network-tool-restricted-repo",
  "unapproved-mcp-server-configured",
];

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
}

const hex64 = (s) => createHash("sha256").update(s).digest("hex");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Run SQL against the scratch DB via the compose Postgres container. */
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

/** Local webhook receiver: records {headers, rawBody} per POST. */
function startWebhookReceiver() {
  const received = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      received.push({ headers: req.headers, rawBody: Buffer.concat(chunks) });
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, received, port: server.address().port }));
  });
}

const children = [];
let stagingRulesDir = null;
let webhookServer = null;
let exitCode = 1;
try {
  // ---- 0. scratch database -------------------------------------------------
  if (process.env.SKIP_DB_CREATE !== "1") {
    await psql(`DROP DATABASE IF EXISTS ${DB_NAME}`, "postgres");
    await psql(`CREATE DATABASE ${DB_NAME}`, "postgres");
    console.log(`scratch database ${DB_NAME} created (compose postgres)`);
  }

  // ---- 1. staging ruleset overlay: shipped policy + restricted_repos -------
  // load_ruleset merges settings across sorted files, so core.yaml loads first
  // and staging-overlay.yaml (sorts after) replaces restricted_repos. The
  // cleartext repo path lives only in this throwaway overlay — events and
  // findings carry the HMAC pseudonym, exactly like production.
  stagingRulesDir = mkdtempSync(join(tmpdir(), "aim97-rules-"));
  copyFileSync(join(ROOT, "policies/guardrail/v1/core.yaml"), join(stagingRulesDir, "core.yaml"));
  writeFileSync(join(stagingRulesDir, "staging-overlay.yaml"),
    `# staging overlay — NOT shipped policy. Activates the restricted-repo
# rail for the e2e canary repo; approved_mcp_servers stays empty (discovery
# mode), so the inventory event below fires unapproved-mcp-server-configured.
settings:
  restricted_repos: ["${RESTRICTED_REPO}"]
`);
  console.log(`staging ruleset overlay at ${stagingRulesDir}`);

  // ---- 2. repo_ref pseudonym via the real CLI helper (same HMAC the engine
  // and collectors use) ------------------------------------------------------
  const { stdout: repoRef } = await execFileP(join(ROOT, ".venv/bin/python"), [
    "-m", "guardrail.cli", "repo-ref", RESTRICTED_REPO,
  ], { cwd: ROOT, env: { ...process.env, AIM_HASH_SALT: SALT } });
  const REPO_REF = repoRef.trim();
  check("repo_ref derived via guardrail repo-ref", /^[0-9a-f]{64}$/.test(REPO_REF), REPO_REF.slice(0, 12) + "…");

  // ---- 3. start ingest (applies migrations on boot) + webhook receiver -----
  children.push(spawnService("ingest", "node", ["services/ingest/dist/index.js"], {
    DATABASE_URL: DSN, INGEST_TOKENS: TOKEN, PORT: String(INGEST_PORT),
  }));
  const webhook = await startWebhookReceiver();
  webhookServer = webhook.server;
  const WEBHOOK_URL = `http://127.0.0.1:${webhook.port}/aim76-hook`;
  await waitFor(`${INGEST_URL}/readyz`);
  console.log(`ingest up on :${INGEST_PORT}, webhook receiver on :${webhook.port}\n`);

  // ---- 4. synthetic events (metadata-only by construction) -----------------
  const ts = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const base = {
    schema_version: "1.2",
    ts,
    host_ref: hex64("aim97-e2e-host"),
    user_ref: hex64("aim97-e2e-user"),
    tool: "claude_code",
    tool_version: "1.0.62",
    model: "claude-sonnet-4-5",
    provider: "anthropic",
    match_flags: [],
    source: "endpoint",
  };
  const shellEvent = {
    ...base,
    event_id: randomUUID(),
    event_type: "tool_use",
    session_id: randomUUID(),
    repo_ref: REPO_REF,
    tool_calls: [{ tool_name: "run command", mcp_server: null, action_class: "shell", count: 2, duration_ms: 800 }],
  };
  const networkEvent = {
    ...base,
    event_id: randomUUID(),
    event_type: "tool_use",
    session_id: randomUUID(),
    repo_ref: REPO_REF,
    tool_calls: [{ tool_name: "web fetch", mcp_server: null, action_class: "network", count: 1, duration_ms: 1200 }],
  };
  const inventoryEvent = {
    ...base,
    event_id: randomUUID(),
    event_type: "inventory",
    session_id: `inv_${randomUUID()}`,
    model: null,
    provider: null,
    configured_mcp_servers: [{ name: "rogue-internal-wiki", scope: "user" }],
  };

  const post = await fetch(`${INGEST_URL}/v1/events`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
    body: JSON.stringify({ events: [shellEvent, networkEvent, inventoryEvent] }),
  });
  const postBody = await post.json();
  check("all 3 synthetic events accepted by ingest (schema v1.2)",
    post.status === 200 && postBody.accepted === 3,
    `status=${post.status} body=${JSON.stringify(postBody)}`);

  // ---- 5. run the real post-ingest evaluator with webhook delivery ---------
  const evalRun = await execFileP(join(ROOT, ".venv/bin/python"), [
    "-m", "guardrail.cli", "evaluate-db", "--rules", stagingRulesDir,
  ], {
    cwd: ROOT,
    env: {
      ...process.env,
      DATABASE_URL: DSN,
      AIM_HASH_SALT: SALT,
      ALERT_WEBHOOK_URL: WEBHOOK_URL,
      ALERT_WEBHOOK_SECRET: WEBHOOK_SECRET,
    },
  });
  console.log(`evaluate-db: ${evalRun.stderr.trim()}`);

  // ---- 6. assert the three per-tool rules fired in the findings table ------
  for (const ruleId of TARGET_RULES) {
    const cnt = Number(await psql(`SELECT count(*) FROM findings WHERE rule_id = '${ruleId}'`));
    check(`finding row for ${ruleId}`, cnt === 1, `count=${cnt}`);
  }
  {
    const row = await psql(
      `SELECT severity || '|' || decision FROM findings WHERE rule_id = 'shell-tool-restricted-repo'`);
    check("shell finding is high/observe", row === "high|observe", row);
    const evidence = await psql(
      `SELECT evidence::text FROM findings WHERE rule_id = 'shell-tool-restricted-repo'`);
    const leaked = ["duration_ms", "800", RESTRICTED_REPO, "secrets-vault"].filter((s) => evidence.includes(s));
    check("shell finding evidence is metadata-only (no counts/durations/cleartext repo)",
      leaked.length === 0, leaked.length ? `leaked: ${leaked}` : "clean");
  }
  {
    const evidence = await psql(
      `SELECT evidence::text FROM findings WHERE rule_id = 'unapproved-mcp-server-configured'`);
    check("inventory finding names the unapproved server",
      evidence.includes("rogue-internal-wiki"), "");
  }

  // ---- 7. webhook delivery (path): signature + payload + audit row --
  {
    const hook = webhook.received.find((r) => r.headers["x-aim-signature"]);
    check("webhook receiver got a signed batch", Boolean(hook),
      `batches received: ${webhook.received.length}`);
    if (hook) {
      const sig = hook.headers["x-aim-signature"];
      const expected = "sha256=" + createHmac("sha256", WEBHOOK_SECRET).update(hook.rawBody).digest("hex");
      check("X-AIM-Signature is a valid HMAC-SHA256 over the body", sig === expected, sig);

      const records = JSON.parse(hook.rawBody.toString("utf8"));
      const rec = records.find((r) => r.FindingType === "unapproved-mcp-server-configured");
      check("new-MCP-server alert delivered via webhook", Boolean(rec),
        rec ? `severity=${rec.Severity} runbook=${rec.RunbookUrl}` : `types: ${records.map((r) => r.FindingType)}`);
      if (rec) {
        check("delivered alert classified on the taxonomy (no Low/rb-unknown fallback)",
          rec.Severity === "Medium" && rec.RunbookUrl.includes("rb-"), `${rec.Severity} ${rec.RunbookUrl}`);
        const blob = JSON.stringify(rec);
        const leaked = ["duration_ms", "secrets-vault"].filter((s) => blob.includes(s));
        check("webhook payload is metadata-only", leaked.length === 0,
          leaked.length ? `leaked: ${leaked}` : "clean");
      }
    }
    const delivered = await psql(
      `SELECT count(*) FROM finding_deliveries fd JOIN findings f ON f.finding_id = fd.finding_id
       WHERE f.rule_id = 'unapproved-mcp-server-configured' AND fd.destination = 'webhook' AND fd.status = 'delivered'`);
    check("finding_deliveries records the webhook delivery", Number(delivered) === 1, `rows=${delivered}`);
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  exitCode = failed.length === 0 ? 0 : 1;

  writeFileSync(MEASUREMENT_OUT, JSON.stringify({
    kind: "staging-e2e",
    at: new Date().toISOString(),
    pipeline: "ingest API -> guardrail evaluate-db (staging ruleset overlay) -> findings + webhook",
    rules_proven_live: TARGET_RULES,
    checks_passed: results.length - failed.length,
    checks_total: results.length,
    results,
  }, null, 2) + "\n");
  console.log(`measurement written to ${MEASUREMENT_OUT}`);
} finally {
  for (const c of children) c.kill("SIGTERM");
  if (webhookServer) webhookServer.close();
  if (stagingRulesDir) rmSync(stagingRulesDir, { recursive: true, force: true });
  await sleep(500);
  for (const c of children) if (!c.killed) c.kill("SIGKILL");
}
process.exit(exitCode);

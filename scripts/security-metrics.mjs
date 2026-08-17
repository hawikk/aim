#!/usr/bin/env node
/**
 * security metrics report. Queries the findings/event store and emits
 * a markdown report to stdout. Numbers from a canary database are labelled
 * CANARY; run against a pilot database for organic numbers.
 *
 * Usage:
 * node scripts/security-metrics.mjs >
 *
 * Env: CANARY_DSN / DATABASE_URL (default: the canary scratch DB),
 *      MEASUREMENT (path to the canary measurement JSON written by
 *      scripts/canary-e2e.mjs).
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const execFileP = promisify(execFile);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const DSN = process.env.CANARY_DSN ?? process.env.DATABASE_URL
  ?? "postgres://aim:localdev-only-not-a-secret@localhost:5432/aim_canary_32";
const DB_NAME = new URL(DSN).pathname.replace(/^\//, "");
const MEASUREMENT = process.env.MEASUREMENT ?? join(ROOT, "docs", "aim-32-canary-measurement.json");
const IS_CANARY = DB_NAME.includes("canary");
const LABEL = IS_CANARY ? "canary" : "live";

async function psql(sql) {
  const { stdout } = await execFileP("docker", [
    "compose", "exec", "-T", "postgres",
    "psql", "-U", "aim", "-d", DB_NAME, "-tAc", sql,
  ], { cwd: ROOT });
  return stdout.trim();
}

const q = (sql) => psql(sql).then((s) => (s === "" ? [] : s.split("\n").map((l) => l.split("|"))));

let measurement = null;
try {
  measurement = JSON.parse(readFileSync(MEASUREMENT, "utf8"));
} catch { /* no canary measurement available */ }

const [events] = (await psql("SELECT count(*) FROM events")).split("\n");
const [evaluated] = (await psql("SELECT count(*) FROM evaluated_events")).split("\n");
const byRule = await q("SELECT rule_id, severity, count(*) FROM findings GROUP BY 1, 2 ORDER BY 3 DESC");
const bySeverity = await q("SELECT severity, count(*) FROM findings GROUP BY 1 ORDER BY 2 DESC");
const byStatus = await q("SELECT status, count(*) FROM findings GROUP BY 1 ORDER BY 2 DESC");
const detectors = await q(
  "SELECT f ->> 'detector', count(*) FROM events e, LATERAL jsonb_array_elements(e.match_flags) f GROUP BY 1 ORDER BY 2 DESC");
const tools = await q("SELECT tool, source, count(*) FROM events GROUP BY 1, 2 ORDER BY 3 DESC");
const totalFindings = bySeverity.reduce((a, r) => a + Number(r[1]), 0);

const row = (cells) => `| ${cells.join(" | ")} |`;
const lines = [
  `# security metrics — ${new Date().toISOString().slice(0, 10)}`,
  "",
  `Source: \`${DB_NAME}\` (${LABEL}). ${IS_CANARY
    ? "All numbers below are CANARY-derived: one synthetic secret-in-prompt event driven end-to-end by `scripts/canary-e2e.mjs`. They prove the pipeline works; they say nothing about organic detection rates."
    : "Live database figures."}`,
  "",
  "## Time-to-detect",
  "",
  measurement && measurement.time_to_detect_ms != null
    ? `- **${measurement.time_to_detect_ms} ms** from event POST at the ingest API to the finding visible via the triage API (${measurement.kind ?? "canary"}, measured ${measurement.at}, single-event batch, ingest + evaluate-db + API on one host).`
    : "- No measurement available (run scripts/canary-e2e.mjs first).",
  "- The evaluator is invoked manually / on a schedule in v1; organic time-to-detect is the scheduling interval plus this processing time.",
  "",
  "## Pipeline counts",
  "",
  row(["metric", "value"]),
  row(["---", "---"]),
  row(["events stored", events]),
  row(["events evaluated by guardrail", evaluated]),
  row(["findings total", String(totalFindings)]),
  "",
  "## Findings by rule",
  "",
  row(["rule", "severity", "count"]),
  row(["---", "---", "---"]),
  ...(byRule.length ? byRule.map((r) => row([r[0], r[1], r[2]])) : [row(["(none)", "", "0"])]),
  "",
  "## Findings by triage state",
  "",
  row(["status", "count"]),
  row(["---", "---"]),
  ...(byStatus.length ? byStatus.map((r) => row([r[0], r[1]])) : [row(["(none)", "0"])]),
  "",
  "## Detector hits (collector match flags)",
  "",
  row(["detector", "hits"]),
  row(["---", "---"]),
  ...(detectors.length ? detectors.map((r) => row([r[0], r[1]])) : [row(["(none)", "0"])]),
  "",
  "## Coverage",
  "",
  "Collectors live in this repo and able to emit schema-v1 events with `secret:*` match flags:",
  "",
  "- `collectors/claude-code` (endpoint hook, 10 regex detectors incl. secret:aws-access-key, github-token, private-key-block, slack-token, generic-api-key-assignment)",
  "- `collectors/cursor`, `collectors/kilo-code` (endpoint collectors)",
  "- `collectors/proxy` (network path)",
  "",
  "Tools seen in this database:",
  "",
  row(["tool", "source", "events"]),
  row(["---", "---", "---"]),
  ...(tools.length ? tools.map((r) => row([r[0], r[1], r[2]])) : [row(["(none)", "", "0"])]),
  "",
  `Ruleset: policies/guardrail/v1 (6 rules, observe-only). Detection pack awaiting Security approval (see docs/readout-60-day-security-win.md).`,
  "",
];
console.log(lines.join("\n"));

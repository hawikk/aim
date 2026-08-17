#!/usr/bin/env node
/**
 * shadow-mode would-block report. Aggregates the endpoint
 * enforcement audit records (schema v1.5 `enforcement`, carried in the
 * events.payload JSONB) and emits a markdown report to stdout.
 *
 * This is the bake artifact for the enforce gates: before any rule flips to
 * `enforce: true`, Security reviews the would-block rate per rule per day
 * for false positives. A rule with a sustained non-trivial would-block rate
 * on clean prompts is NOT a candidate for enforcement.
 *
 * COVERAGE FIRST. The 2026-07-22 baseline of this report said "0 would_block"
 * and was worthless: no endpoint was running the enforcement-aware collector,
 * so zero was the only number it could ever have printed. A gate artifact that
 * renders "nobody is watching" identically to "nothing is happening" is the
 * silent-drop failure mode pointed at the enforcement decision itself. So the
 * report now computes its own denominator from the schema v1.7
 * `enforcement_posture` marker (emitted on every event by an enforcement-aware
 * hook, decision or not) and refuses to present a clean verdict it has not
 * earned:
 *
 *   exit 0 — coverage sufficient; the numbers below mean what they say.
 *   exit 3 — NO COVERAGE: nothing was observed. Not a clean bake.
 *   exit 4 — INSUFFICIENT: real coverage, too little of it to conclude from.
 *
 * Usage:
 * node scripts/shadow-report.mjs >
 *   node scripts/shadow-report.mjs --self-test
 *
 * Env: CANARY_DSN / DATABASE_URL (default: local dev DB),
 *      SINCE (ISO date; default: 14 days back),
 *      MIN_PROMPTS / MIN_ENDPOINTS (bake sufficiency thresholds).
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const execFileP = promisify(execFile);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

// Bake sufficiency. Deliberately modest: this gates "can Security read these
// numbers at all", not "is the rule safe" — that judgement stays with the
// ruleset sign-off. A single endpoint's prompts are not a fleet signal, hence
// the endpoint floor alongside the prompt floor.
const MIN_PROMPTS = Number(process.env.MIN_PROMPTS ?? 500);
const MIN_ENDPOINTS = Number(process.env.MIN_ENDPOINTS ?? 5);

/**
 * The verdict is a pure function of the coverage counts so it can be tested
 * without a database — see --self-test. Order matters: absence of a collector
 * outranks absence of a policy bundle, because it is the wider hole.
 */
export function coverageVerdict(c, min = { prompts: MIN_PROMPTS, endpoints: MIN_ENDPOINTS }) {
  if (c.endpointsAware === 0) {
    return {
      code: "NO_COVERAGE", exit: 3,
      headline: "NO COVERAGE — no endpoint ran an enforcement-aware collector in this window.",
      detail: `${c.endpointsTotal} endpoint(s) reported telemetry; 0 of them emit the enforcement posture marker. `
        + "Every enforcement count below is structurally zero and proves nothing about the fleet.",
    };
  }
  if (c.endpointsPolicyLoaded === 0) {
    return {
      code: "NO_POLICY", exit: 3,
      headline: "NO COVERAGE — enforcement-aware collectors are deployed, but no endpoint has a policy bundle.",
      detail: `${c.endpointsAware} endpoint(s) run the collector and 0 have loaded an enforcement policy, so no rule `
        + "can fire on any of them (every decide_* path returns early without a bundle). "
        + "The delivery channel for enforcement.json is the thing to fix, not the ruleset.",
    };
  }
  if (c.promptsEvaluated < min.prompts || c.endpointsPolicyLoaded < min.endpoints) {
    return {
      code: "INSUFFICIENT", exit: 4,
      headline: "INSUFFICIENT BAKE — real coverage, but too little to draw a false-positive conclusion from.",
      detail: `${c.promptsEvaluated} prompt(s) evaluated across ${c.endpointsPolicyLoaded} covered endpoint(s); `
        + `the floor for a gate decision is ${min.prompts} prompts across ${min.endpoints} endpoints. `
        + "Numbers below are real as far as they go — they are a progress check, not a sign-off input.",
    };
  }
  return {
    code: "SUFFICIENT", exit: 0,
    headline: "COVERAGE SUFFICIENT — the counts below are a readable false-positive signal.",
    detail: `${c.promptsEvaluated} prompt(s) evaluated across ${c.endpointsPolicyLoaded} covered endpoint(s). `
      + "Sufficient coverage is a precondition for the gate review, not the gate itself: works-council "
      + "consultation and critical-ruleset sign-off are unaffected by anything in this report.",
  };
}

/** Endpoints that are enforcement-aware but have no bundle, plus endpoints on
 * a earlier collector: both are invisible to the bake and both are worth
 *  naming even when the overall verdict is fine. */
export function coverageGaps(c) {
  const gaps = [];
  const dark = c.endpointsTotal - c.endpointsAware;
  if (dark > 0) {
    gaps.push(`${dark} endpoint(s) report telemetry but emit no posture marker — earlier collector build. `
      + "They can never contribute a would-block, and they would not be protected by an enforce rollout either.");
  }
  const unbundled = c.endpointsAware - c.endpointsPolicyLoaded;
  if (unbundled > 0) {
    gaps.push(`${unbundled} enforcement-aware endpoint(s) have no policy bundle loaded — policy delivery gap. `
      + "Rules cannot fire there; their prompts are not in the denominator.");
  }
  return gaps;
}

async function psql(sql, dbName) {
  const { stdout } = await execFileP("docker", [
    "compose", "exec", "-T", "postgres",
    "psql", "-U", "aim", "-d", dbName, "-tAc", sql,
  ], { cwd: ROOT });
  return stdout.trim();
}

async function main() {
  const DSN = process.env.CANARY_DSN ?? process.env.DATABASE_URL
    ?? "postgres://aim:localdev-only-not-a-secret@localhost:5432/aim";
  const DB_NAME = new URL(DSN).pathname.replace(/^\//, "");
  const SINCE = process.env.SINCE
    ?? new Date(Date.now() - 14 * 86400e3).toISOString().slice(0, 10);

  const q = (sql) => psql(sql, DB_NAME)
    .then((s) => (s === "" ? [] : s.split("\n").map((l) => l.split("|"))));
  const scalar = async (sql) => Number(((await q(sql))[0] ?? ["0"])[0] ?? 0);

  // enforcement audit records live in the payload JSONB (schema v1.5); there is
  // no dedicated column — the record is rule_id + action + policy_hash only.
  const ENF = "payload -> 'enforcement'";
  const POS = "payload -> 'enforcement_posture'";
  const base = `FROM events WHERE ${ENF} IS NOT NULL AND ts >= '${SINCE}'`;
  const endpointWindow = `FROM events WHERE source = 'endpoint' AND ts >= '${SINCE}'`;

  // Coverage denominator (schema v1.7 posture marker) — computed before the
  // decision counts, because it decides whether they can be read at all.
  const coverage = {
    endpointsTotal: await scalar(`SELECT count(DISTINCT host_ref) ${endpointWindow}`),
    endpointsAware: await scalar(
      `SELECT count(DISTINCT host_ref) ${endpointWindow} AND ${POS} IS NOT NULL`),
    endpointsPolicyLoaded: await scalar(
      `SELECT count(DISTINCT host_ref) ${endpointWindow} AND ${POS} ->> 'policy' = 'loaded'`),
    promptsEvaluated: await scalar(
      `SELECT count(*) ${endpointWindow} AND ${POS} ->> 'policy' = 'loaded'`
      + ` AND ${POS} ->> 'evaluated' = 'true'`),
  };
  const byMode = await q(
    `SELECT ${POS} ->> 'mode', count(DISTINCT host_ref) ${endpointWindow}`
    + ` AND ${POS} ->> 'policy' = 'loaded' GROUP BY 1 ORDER BY 1`);

  const totals = await q(
    `SELECT ${ENF} ->> 'action', count(*) ${base} GROUP BY 1 ORDER BY 1`);
  const byRule = await q(
    `SELECT ${ENF} ->> 'rule_id', ${ENF} ->> 'action', count(*) ${base} GROUP BY 1, 2 ORDER BY 1, 2`);
  const byDay = await q(
    `SELECT ts::date, ${ENF} ->> 'rule_id', ${ENF} ->> 'action', count(*) ${base} GROUP BY 1, 2, 3 ORDER BY 1, 2`);
  const byDetector = await q(
    `SELECT f ->> 'detector', count(*) FROM events e, LATERAL jsonb_array_elements(e.match_flags) f
     WHERE e.payload -> 'enforcement' IS NOT NULL AND e.ts >= '${SINCE}' GROUP BY 1 ORDER BY 2 DESC`);
  const policyHashes = await q(
    `SELECT coalesce(${ENF} ->> 'policy_hash', '(none)'), count(*) ${base} GROUP BY 1 ORDER BY 2 DESC`);
  const blockedTotal = Number((totals.find((r) => r[0] === "blocked") ?? [0, 0])[1]);
  const wouldBlockTotal = Number((totals.find((r) => r[0] === "would_block") ?? [0, 0])[1]);
  const confirmedTotal = Number((totals.find((r) => r[0] === "confirmed") ?? [0, 0])[1]);

  const verdict = coverageVerdict(coverage);
  const gaps = coverageGaps(coverage);
  const rate = coverage.promptsEvaluated > 0
    ? `${(100 * wouldBlockTotal / coverage.promptsEvaluated).toFixed(2)}% of evaluated prompts`
    : "not computable — zero evaluated prompts";

  const row = (cells) => `| ${cells.join(" | ")} |`;
  const lines = [
    `# endpoint enforcement — shadow-mode would-block report`,
    "",
    `Source: \`${DB_NAME}\`, events since ${SINCE}. Generated ${new Date().toISOString().slice(0, 10)} by \`scripts/shadow-report.mjs\`.`,
    "",
    `## Verdict: ${verdict.code}`,
    "",
    `**${verdict.headline}**`,
    "",
    verdict.detail,
    "",
    `## Coverage (the denominator)`,
    "",
    row(["measure", "value"]),
    row(["---", "---:"]),
    row(["endpoints reporting telemetry", coverage.endpointsTotal]),
    row(["…running an enforcement-aware collector", coverage.endpointsAware]),
    row(["…with an enforcement policy bundle loaded", coverage.endpointsPolicyLoaded]),
    row(["prompts actually evaluated by the rules", coverage.promptsEvaluated]),
    "",
    ...(byMode.length
      ? [row(["kill-switch mode", "endpoints"]), row(["---", "---:"]), ...byMode.map(row), ""]
      : []),
    ...(gaps.length ? ["Gaps:", "", ...gaps.map((g) => `- ${g}`), ""] : []),
    `Coverage is measured from the schema v1.7 \`enforcement_posture\` marker, which an`,
    `enforcement-aware hook emits on every event whether or not a rule fires. Endpoints`,
    `missing the marker are running an older collector; endpoints with \`policy: absent\``,
    `never received a bundle. Neither can produce a would-block, so neither may be read`,
    `as evidence of a clean fleet. PreToolUse decisions (MCP / restricted-repo) are`,
    `covered by endpoint posture but not by the per-prompt denominator: PreToolUse emits`,
    `telemetry only when a rule fires, by design, so there is no per-tool-call count here.`,
    "",
    `## Decisions`,
    "",
    `**would_block (shadow, nothing interrupted): ${wouldBlockTotal} · blocked (enforced): ${blockedTotal} · confirmed: ${confirmedTotal}**`,
    "",
    `Shadow would-block rate: ${rate}.`,
    "",
    `Gate review guidance: a rule is ready for \`enforce: true\` when its would-block`,
    `rate is explained by true positives (real secrets, genuinely unapproved MCP`,
    `servers). Any sustained would-block volume on clean prompts = tune the detector`,
    `first. Blocking stays behind the works-council + ruleset sign-off gates regardless`,
    `of what these numbers say — and a zero here is only meaningful when the verdict`,
    `above is SUFFICIENT.`,
    "",
    `## Per rule`,
    "",
    row(["rule_id", "action", "events"]),
    row(["---", "---", "---:"]),
    ...byRule.map(row),
    "",
    `## Per day`,
    "",
    row(["day", "rule_id", "action", "events"]),
    row(["---", "---", "---", "---:"]),
    ...byDay.map(row),
    "",
    `## Detector mix behind the decisions`,
    "",
    row(["detector", "events"]),
    row(["---", "---:"]),
    ...byDetector.map(row),
    "",
    `## Policy bundles in play`,
    "",
    row(["policy_hash", "events"]),
    row(["---", "---:"]),
    ...policyHashes.map(row),
    "",
  ];

  process.stdout.write(lines.join("\n"));
  return verdict.exit;
}

/**
 * Self-test: the verdict table is the load-bearing logic here, and it is the
 * part that must not quietly drift back to "0 is fine". Runs without a DB.
 * Mutate any branch of coverageVerdict and a case below goes red.
 */
function selfTest() {
  const min = { prompts: 500, endpoints: 5 };
  const cases = [
    // [label, counts, expected code]
    ["no telemetry at all", { endpointsTotal: 0, endpointsAware: 0, endpointsPolicyLoaded: 0, promptsEvaluated: 0 }, "NO_COVERAGE"],
    ["fleet reporting, no aware collector (the 2026-07-22 baseline)",
      { endpointsTotal: 37, endpointsAware: 0, endpointsPolicyLoaded: 0, promptsEvaluated: 0 }, "NO_COVERAGE"],
    ["aware collectors, no bundle delivered",
      { endpointsTotal: 37, endpointsAware: 37, endpointsPolicyLoaded: 0, promptsEvaluated: 0 }, "NO_POLICY"],
    ["bundle on too few endpoints",
      { endpointsTotal: 37, endpointsAware: 37, endpointsPolicyLoaded: 4, promptsEvaluated: 9000 }, "INSUFFICIENT"],
    ["enough endpoints, too few prompts",
      { endpointsTotal: 37, endpointsAware: 37, endpointsPolicyLoaded: 20, promptsEvaluated: 499 }, "INSUFFICIENT"],
    ["exactly at both floors",
      { endpointsTotal: 37, endpointsAware: 37, endpointsPolicyLoaded: 5, promptsEvaluated: 500 }, "SUFFICIENT"],
    ["healthy bake", { endpointsTotal: 37, endpointsAware: 37, endpointsPolicyLoaded: 30, promptsEvaluated: 12000 }, "SUFFICIENT"],
  ];
  let failed = 0;
  for (const [label, counts, expected] of cases) {
    const got = coverageVerdict(counts, min);
    const ok = got.code === expected;
    // A clean verdict must never carry a non-zero exit, and vice versa: the
    // exit code is what a caller wires into CI, so it cannot drift from code.
    const exitOk = (got.code === "SUFFICIENT") === (got.exit === 0);
    if (!ok || !exitOk) failed++;
    console.log(`${ok && exitOk ? "ok  " : "FAIL"} ${label}: ${got.code} (exit ${got.exit}), want ${expected}`);
  }
  // Gap reporting must call out both invisible populations even when the
  // overall verdict is SUFFICIENT — a passing bake can still be half-blind.
  const gaps = coverageGaps({ endpointsTotal: 40, endpointsAware: 35, endpointsPolicyLoaded: 30, promptsEvaluated: 9000 });
  if (gaps.length !== 2) {
    failed++;
    console.log(`FAIL gaps: want 2 (5 dark + 5 unbundled), got ${gaps.length}`);
  } else {
    console.log("ok   gaps: dark endpoints and unbundled endpoints both reported");
  }
  const none = coverageGaps({ endpointsTotal: 30, endpointsAware: 30, endpointsPolicyLoaded: 30, promptsEvaluated: 9000 });
  if (none.length !== 0) {
    failed++;
    console.log(`FAIL gaps: full coverage should report none, got ${none.length}`);
  } else {
    console.log("ok   gaps: full coverage reports none");
  }
  console.log(failed === 0 ? "\nself-test PASSED" : `\nself-test FAILED (${failed})`);
  return failed === 0 ? 0 : 1;
}

if (process.argv.includes("--self-test")) {
  process.exit(selfTest());
}
process.exit(await main());

#!/usr/bin/env node
//
// AIM-211 — reconcile merges made during the Actions blackout (AIM-209).
//
//   node scripts/blackout_reconcile.mjs --self-test   # prove the rules bite
//   node scripts/blackout_reconcile.mjs               # report (read-only)
//   node scripts/blackout_reconcile.mjs --file-issue  # + open the record issue
//
// WHY THIS IS A SWEEP AND NOT A PASSIVE RECLASSIFICATION
//
// `merge-audit.yml` runs on `push` to main and audits the commits carried by
// that push. GitHub does not replay events that occurred while Actions was
// disabled. So when Actions returns, the blackout merges are not "flagged as
// bypasses" -- by default they are never audited AT ALL, and the audit's first
// post-return run reports `clean` while thirty days of manual merges sit on
// main with no verdict attached to them. A scan reporting success with nothing
// in scope is the same silent pass the audit exists to catch, so reconciliation
// has to be an explicit backfill with a named target list.
//
// (Both failure modes are real. The tip of main is a blackout merge, so a
// `workflow_dispatch` of the audit resolves `context.sha` to it and DOES report
// it as a bypass. The passive path under-reports; the manual path mis-reports.)
//
// WHAT MAKES `blackout` AN HONEST CLASS AND NOT A LAUNDERING ONE
//
// The window is a coarse date filter; it never decides a verdict on its own.
// The verdict comes from structural evidence about each required check:
//
//   * absent                -- no check run at the PR head at all.
//   * never executed        -- a check run exists and says `failure`, but its
//                              job ran ZERO steps. GitHub refused to start it.
//                              It verified nothing, so it is not evidence the
//                              code was bad -- and equally not evidence it was
//                              good. This is the quota-exhaustion signature.
//   * executed              -- the job ran steps and reported a real verdict.
//
// A merge inside the window whose non-green required checks all `absent` or
// `never executed` is `blackout`. A merge inside the window with even ONE
// required check that actually executed and came back red is a `bypass`, window
// or no window. That single discrimination is the whole integrity of this file:
// without it, "it was during the blackout" would excuse merging over a genuine
// red test, which is precisely the thing the audit exists to catch.
//
// Note the zero-step rule is deliberately stated as "the job executed nothing",
// not "the job was killed for quota". A job that dies in setup for any other
// reason also verified nothing, and should be classified the same way. Timing
// is never used: a 2-second failure is not the signal, an empty step list is.

import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";

const REPO = process.env.AIM_REPO || "hawikk/aim";

// ---------------------------------------------------------------------------
// the classifier -- pure, so both this sweep and the audit's tests can drive it
// ---------------------------------------------------------------------------

export const ABSENT = "absent";
export const NEVER_EXECUTED = "never_executed";
export const EXECUTED = "executed";

/**
 * State of one required check at a PR head.
 * `run` is a check run augmented with `executed_steps` (null when unknowable).
 */
export function checkState(run) {
  if (!run) return { state: ABSENT, detail: "never reported" };
  // A job with an empty step list produced no verdict. Applies to Actions check
  // runs only; a third-party check has no steps and is taken at its word.
  if (run.executed_steps === 0) {
    return {
      state: NEVER_EXECUTED,
      detail: `${run.conclusion ?? run.status} but the job executed 0 steps`,
    };
  }
  if (run.status !== "completed") {
    return { state: EXECUTED, detail: run.status, green: false };
  }
  return {
    state: EXECUTED,
    detail: run.conclusion,
    green: run.conclusion === "success",
  };
}

export function inWindow(mergedAt, window) {
  if (!window?.start) return false;
  const t = Date.parse(mergedAt);
  if (Number.isNaN(t)) return false;
  if (t < Date.parse(window.start)) return false;
  // An open window has no upper bound. A closed one stops at `end` exactly, so
  // the class cannot creep forward over merges made after Actions came back.
  return window.end == null || t <= Date.parse(window.end);
}

/**
 * @returns {{cls: "clean"|"blackout"|"bypass", green: string[], notVerdict: object[], red: object[]}}
 */
export function classifyMerge({ mergedAt, requiredChecks, runsByName, window }) {
  const green = [];
  const notVerdict = []; // absent / never executed -- no verdict either way
  const red = []; // actually ran and actually failed

  for (const name of requiredChecks) {
    const st = checkState(runsByName.get(name));
    if (st.state === EXECUTED && st.green) green.push(name);
    else if (st.state === EXECUTED) red.push({ name, why: st.detail });
    else notVerdict.push({ name, why: st.detail });
  }

  if (!red.length && !notVerdict.length) return { cls: "clean", green, notVerdict, red };

  // A check that ran and failed is a bypass no matter when it was merged.
  if (red.length) return { cls: "bypass", green, notVerdict, red };

  if (inWindow(mergedAt, window)) return { cls: "blackout", green, notVerdict, red };
  return { cls: "bypass", green, notVerdict, red };
}

// ---------------------------------------------------------------------------
// self-test -- mutate the rules and prove each one is load-bearing
// ---------------------------------------------------------------------------

function selfTest() {
  const results = [];
  const check = (name, ok) => {
    results.push({ name, ok });
    console.log(`${ok ? "ok  " : "FAIL"} ${name}`);
  };
  const W = { start: "2026-07-26T15:25:00Z", end: null };
  const IN = "2026-07-26T16:49:24Z";
  const BEFORE = "2026-07-26T11:00:00Z";
  const req = ["unit tests", "secret scan"];
  const runs = (m) => new Map(Object.entries(m));

  const zero = { status: "completed", conclusion: "failure", executed_steps: 0 };
  const realRed = { status: "completed", conclusion: "failure", executed_steps: 14 };
  const ok = { status: "completed", conclusion: "success", executed_steps: 14 };

  check(
    "in-window merge whose checks executed nothing is `blackout`",
    classifyMerge({ mergedAt: IN, requiredChecks: req, runsByName: runs({ "unit tests": zero, "secret scan": zero }), window: W }).cls === "blackout",
  );
  check(
    "in-window merge with NO check runs at all is `blackout`",
    classifyMerge({ mergedAt: IN, requiredChecks: req, runsByName: runs({}), window: W }).cls === "blackout",
  );
  // The one that matters: the window must not excuse a check that really ran.
  check(
    "in-window merge over a check that RAN and failed is still `bypass`",
    classifyMerge({ mergedAt: IN, requiredChecks: req, runsByName: runs({ "unit tests": realRed, "secret scan": zero }), window: W }).cls === "bypass",
  );
  check(
    "same shape BEFORE the window is `bypass`, not `blackout`",
    classifyMerge({ mergedAt: BEFORE, requiredChecks: req, runsByName: runs({ "unit tests": zero, "secret scan": zero }), window: W }).cls === "bypass",
  );
  check(
    "all-green is `clean`",
    classifyMerge({ mergedAt: IN, requiredChecks: req, runsByName: runs({ "unit tests": ok, "secret scan": ok }), window: W }).cls === "clean",
  );
  // A closed window must stop classifying, or `blackout` never expires.
  check(
    "after a CLOSED window, an unverified merge is `bypass` again",
    classifyMerge({
      mergedAt: "2026-08-10T00:00:00Z", requiredChecks: req,
      runsByName: runs({}), window: { start: W.start, end: "2026-08-01T00:00:00Z" },
    }).cls === "bypass",
  );
  check(
    "a 0-step job is not green even when its conclusion says success",
    checkState({ status: "completed", conclusion: "success", executed_steps: 0 }).state === NEVER_EXECUTED,
  );
  // Timing must not be the signal.
  check(
    "a fast-but-real failure (steps > 0) stays `executed`",
    checkState(realRed).state === EXECUTED,
  );

  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n${results.length - failed}/${results.length} rules hold`);
  return failed ? 1 : 0;
}

// ---------------------------------------------------------------------------
// the sweep
// ---------------------------------------------------------------------------

const gh = (path) => JSON.parse(execFileSync("gh", ["api", "--paginate", path], {
  encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
}));

/** Step count for an Actions check run; null when it is not an Actions check. */
function executedSteps(run) {
  if (run.app?.slug !== "github-actions") return null;
  const jobId = String(run.details_url || "").match(/\/job\/(\d+)/)?.[1];
  if (!jobId) return null;
  try {
    return (gh(`repos/${REPO}/actions/jobs/${jobId}`).steps || []).length;
  } catch {
    return null; // unknown -- never assume it executed nothing
  }
}

function requiredFor(changedFiles, cfg) {
  const matchesPath = (file, pattern) => {
    if (pattern.endsWith("/")) return file.startsWith(pattern);
    if (/[*?]/.test(pattern)) {
      const rx = pattern.split("**")
        .map((s) => s.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]"))
        .join(".*");
      return new RegExp(`^${rx}$`).test(file);
    }
    return file === pattern || file.startsWith(`${pattern}/`);
  };
  const out = [...cfg.always];
  for (const c of cfg.conditional) {
    if (changedFiles.some((f) => c.when_paths_changed.some((p) => matchesPath(f, p)))) out.push(c.check);
  }
  return out;
}

/** Pull an `aim.ci-local.attestation/v1` blob out of the PR's comments. */
function findAttestation(prNumber, schema) {
  let comments = [];
  try {
    comments = gh(`repos/${REPO}/issues/${prNumber}/comments?per_page=100`);
  } catch { return null; }
  for (const c of [...comments].reverse()) {
    for (const m of String(c.body || "").matchAll(/\{[\s\S]*?"schema"[\s\S]*?\}/g)) {
      // The comment is prose around a JSON block; find the widest parse.
      const start = c.body.indexOf("{", c.body.indexOf(m[0]) === -1 ? 0 : 0);
      for (const cand of [m[0], c.body.slice(start)]) {
        try {
          const j = JSON.parse(cand);
          if (j.schema === schema) return { comment_url: c.html_url, attestation: j };
        } catch { /* not this slice */ }
      }
    }
  }
  return null;
}

function sweep(window) {
  const cfg = JSON.parse(readFileSync(".github/required-checks.json", "utf8").replace(/"_comment":\s*\[[^\]]*\],/, ""));
  const since = window.start;
  const until = window.end;

  const prs = gh(`repos/${REPO}/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=100`)
    .filter((p) => p.merged_at && inWindow(p.merged_at, window))
    .sort((a, b) => Date.parse(a.merged_at) - Date.parse(b.merged_at));

  const rows = [];
  for (const pr of prs) {
    const files = gh(`repos/${REPO}/pulls/${pr.number}/files?per_page=100`).map((f) => f.filename);
    const required = requiredFor(files, cfg);
    let runs = [];
    try {
      runs = gh(`repos/${REPO}/commits/${pr.head.sha}/check-runs?filter=latest&per_page=100`).check_runs || [];
    } catch { runs = []; }
    const runsByName = new Map(runs.map((r) => [r.name, { ...r, executed_steps: executedSteps(r) }]));
    const verdict = classifyMerge({ mergedAt: pr.merged_at, requiredChecks: required, runsByName, window });
    const att = findAttestation(pr.number, window.local_attestation_schema || "aim.ci-local.attestation/v1");
    rows.push({ pr, required, verdict, att });
  }

  // A sweep that found nothing to sweep is not a clean result. Say so.
  const scanned = rows.length;
  console.log(`\nblackout window ${since} .. ${until ?? "OPEN"} — ${scanned} merge(s) to main in scope\n`);
  if (!scanned) {
    console.log("NOTHING IN SCOPE. That is only 'clean' if no PR merged in the window;");
    console.log("verify against `git log --first-parent main` before believing it.");
  }

  for (const { pr, required, verdict, att } of rows) {
    const a = att
      ? `attested ${att.attestation.verdict} @ ${att.attestation.commit?.slice(0, 7)} (${att.comment_url})`
      : "NO local attestation";
    console.log(`#${pr.number} [${verdict.cls}] ${pr.merged_at} ${pr.title}`);
    console.log(`   ${verdict.green.length}/${required.length} required checks green · ${a}`);
    for (const n of verdict.notVerdict) console.log(`   - no verdict: ${n.name} (${n.why})`);
    for (const r of verdict.red) console.log(`   - RED: ${r.name} (${r.why})`);
  }

  const bypasses = rows.filter((r) => r.verdict.cls === "bypass");
  const blackout = rows.filter((r) => r.verdict.cls === "blackout");
  const unattested = blackout.filter((r) => !r.att);
  console.log(`\nblackout=${blackout.length} (${unattested.length} unattested) bypass=${bypasses.length} clean=${rows.filter((r) => r.verdict.cls === "clean").length}`);
  if (bypasses.length) {
    console.log("\nBYPASS inside the window — these merged over checks that actually ran and failed.");
    console.log("They are NOT excused by the blackout. Treat each as a real gate bypass.");
  }
  return { rows, bypasses, blackout, unattested };
}

// ---------------------------------------------------------------------------
// machine-readable reconciliation record (AIM-211)
//
// The audit (.github/scripts/merge-audit.cjs) defers to this artifact for any
// merge inside the closed window instead of re-deriving the verdict against
// TODAY's required-checks.json — re-checking a past decision against today's
// rule falsely accuses the merger. The artifact is therefore the adjudicated
// record: blackout stays blackout, bypass stays bypass, and an in-window merge
// MISSING from it is an audit finding (the record is incomplete).
// ---------------------------------------------------------------------------

function artifact(rows, window) {
  const record = (cls, e) => ({
    class: cls,
    ...(e.red.length ? { red_checks: e.red.map((r) => r.name) } : {}),
    ...(e.notVerdict.length ? { no_verdict_checks: e.notVerdict.map((n) => n.name) } : {}),
  });
  return {
    schema: "aim.blackout-reconciliation/v1",
    issue: "AIM-211",
    generated_at: new Date().toISOString(),
    window: { start: window.start, end: window.end },
    // Direct pushes to main with no PR. The sweep enumerates via the PR API
    // and cannot see these; they were found by walking `git log --first-parent
    // origin/main`. All three landed AFTER the window end, so the blackout
    // excuses none of them: no PR means no gate, and no gate outside the
    // window is a bypass.
    direct_pushes: [
      { sha: "9f44473b6042007867009d6c7ec53c7968fc59fd", committed_at: "2026-07-29T11:44:39Z", subject: "fix(AIM-364): restore AIM-319 ingest shared-token compose env after merge train", class: "bypass", direct_push: true },
      { sha: "882e7657a9e3ef7b5dddb337208cffb1202f59be", committed_at: "2026-07-29T11:48:03Z", subject: "fix(AIM-364): drop reintroduced dangling shadow-ai import", class: "bypass", direct_push: true },
      { sha: "f78e961003479e50cb0c17d1cde428fcf3ddae58", committed_at: "2026-07-29T11:56:55Z", subject: "fix(AIM-365): default local compose alert bus for api and guardrail", class: "bypass", direct_push: true },
    ],
    merges: rows.map(({ pr, verdict, att }) => ({
      pr: pr.number,
      head_sha: pr.head.sha,
      merged_at: pr.merged_at,
      title: pr.title,
      ...record(verdict.cls, verdict),
      attestation: att ? att.comment_url : null,
    })),
  };
}

// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);
if (argv.includes("--self-test")) process.exit(selfTest());

const WINDOW_FILE = ".github/blackout-window.json";
if (!existsSync(WINDOW_FILE)) {
  console.error(`${WINDOW_FILE} is missing — nothing defines the window.`);
  process.exit(3);
}
const window = JSON.parse(readFileSync(WINDOW_FILE, "utf8"));
const result = sweep(window);
const jsonIdx = argv.indexOf("--json");
if (jsonIdx !== -1 && argv[jsonIdx + 1]) {
  const { writeFileSync } = await import("node:fs");
  writeFileSync(argv[jsonIdx + 1], JSON.stringify(artifact(result.rows, window), null, 2) + "\n");
  console.log(`\nwrote ${argv[jsonIdx + 1]}`);
}

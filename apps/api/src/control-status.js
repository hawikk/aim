// Continuous control monitoring status (AIM-694).
//
// Each framework control is evaluated against live mapped guardrail rules and
// open findings in the report window. Weekly / on-demand snapshots store the
// full report (including these statuses) unchanged — this module only defines
// the live pass/fail/unknown semantics.
//
//   pass    — ≥1 live mapped rule and no open findings in the window
//   fail    — ≥1 live mapped rule and ≥1 open finding
//   unknown — no live mapped rules (control is catalogued but not monitored)

export const CONTROL_STATUSES = Object.freeze(['pass', 'fail', 'unknown']);

/**
 * @param {{ ruleIds?: string[], findings?: { open?: number } }} input
 * @returns {{ status: 'pass'|'fail'|'unknown', reason: string }}
 */
export function evaluateControlStatus({ ruleIds, findings } = {}) {
  const rules = Array.isArray(ruleIds) ? ruleIds : [];
  const open = Number(findings?.open ?? 0);
  if (rules.length === 0) {
    return { status: 'unknown', reason: 'no_mapped_rules' };
  }
  if (open > 0) {
    return { status: 'fail', reason: 'open_findings' };
  }
  return { status: 'pass', reason: 'no_open_findings' };
}

/**
 * Roll up per-control statuses across all frameworks for summary cards.
 * @param {Array<{ controls?: Array<{ status?: string }> }>} frameworks
 * @returns {{ pass: number, fail: number, unknown: number, total: number }}
 */
export function summarizeControlStatuses(frameworks = []) {
  const summary = { pass: 0, fail: 0, unknown: 0, total: 0 };
  for (const fw of frameworks) {
    for (const c of fw.controls ?? []) {
      summary.total += 1;
      const s = c.status;
      if (s === 'pass' || s === 'fail' || s === 'unknown') summary[s] += 1;
      else summary.unknown += 1;
    }
  }
  return summary;
}

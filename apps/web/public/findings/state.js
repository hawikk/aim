/* Shared view-private state for the Findings console (AIM-1140 split).
 * fctx is view-private: zero cross-view surface. The orchestrator
 * (public/findings.js) populates it during init() and every sibling module
 * imports it — never re-create it locally. resetFindingsCtx() runs at the top
 * of init() so a re-mounted module starts clean. */
import { api } from '../lib/api.js';
import { buildEvidenceIndexFromReport } from '../lib/compliance-evidence.js';

export const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
export const STATUS_LABEL = { new: 'new', acknowledged: 'acknowledged', resolved: 'resolved', false_positive: 'false positive' };
export const BULK_LABEL = { acknowledged: 'Acknowledge', resolved: 'Resolve', false_positive: 'False positive' };
export const POLL_MS = 45_000;

export const fctx = {};

export function resetFindingsCtx() {
  Object.assign(fctx, {
    section: null,
    list: null,
    btn: null,
    toast: null,
    loadFindings: null,
    pollCritical: null,
    // ruleId/days have no picker yet, but round-trip through saved views (AIM-94).
    state: { fstatus: 'open', fsev: 'all', ruleId: null, days: 30, activeViewId: null },
    /** AIM-702: historical closed outcomes (policy_hash + rule → disposition counts). */
    outcomeIndex: new Map(),
    // Bulk selection: ids of the currently loaded list the user has ticked.
    selected: new Set(),
    currentIds: [],
    // AIM-541: optional fixture fingerprint allowlist index (null = hints off).
    fixtureIndex: null,
    // AIM-925: rule → control index from compliance report (lazy, once per page).
    evidenceIndex: null,
    evidenceIndexPromise: null,
  });
  rulesCache = null;
}

/* ---------- Rule conditions (AIM-81): human-readable "why it fired" ----------
 * Lazy-loaded once from /api/guardrail/rules (same security gate). Findings
 * written under an older policy revision may reference rules no longer in
 * the file — those simply render without the extra block. */
let rulesCache = null;
export function ruleMap() {
  if (!rulesCache) {
    rulesCache = api('/api/guardrail/rules')
      .then((d) => new Map(d.rules.map((r) => [r.id, r])))
      .catch(() => new Map());
  }
  return rulesCache;
}

/* AIM-925: hydrate the rule→control index from the compliance report, once per
 * page. Failure is non-fatal — high-sev findings simply render without the
 * evidence links. */
export function ensureEvidenceIndex() {
  if (fctx.evidenceIndex) return Promise.resolve(fctx.evidenceIndex);
  if (!fctx.evidenceIndexPromise) {
    fctx.evidenceIndexPromise = api('/api/compliance/report')
      .then((report) => {
        fctx.evidenceIndex = buildEvidenceIndexFromReport(report);
        return fctx.evidenceIndex;
      })
      .catch(() => {
        fctx.evidenceIndex = { byRule: new Map(), mappingVersion: null, contentHash: null };
        return fctx.evidenceIndex;
      });
  }
  return fctx.evidenceIndexPromise;
}

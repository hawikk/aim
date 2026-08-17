/* Findings-console capability gate + severity-aware hops, split out
 * of views/security.js. Owns every Security → Findings link so the
 * severity filter and day window survive the hop. */
import { $ } from '../../lib/dom.js';
import { state } from '../../lib/runtime.js';
import { findingsHash } from '../../lib/view-filters.js';

/** Analyst+ gate for Findings console (same capability as /api/findings). */
export function canOpenFindings() {
  return Boolean(state.me?.capabilities?.findingsConsole);
}

/**
 * shareable Findings hop from Security.
 * When criticality is filtered (high/critical/…), carry that severity into triage
 * so "look at all the high ones" lands on the matching open findings list.
 */
export function findingsTriageHref(severity = 'all') {
  const fsev = severity && severity !== 'all' ? severity : 'all';
  return findingsHash({ fstatus: 'open', fsev, days: state.days });
}

/** Wire the always-visible View-all CTAs (controls row + panel header). */
export function wireFindingsCtas(severity = 'all') {
  const can = canOpenFindings();
  const href = findingsTriageHref(severity);
  const label = severity && severity !== 'all'
    ? `View all open ${severity} findings →`
    : 'View all open findings →';
  for (const id of ['#sec-findings-cta', '#sec-findings-panel-link']) {
    const el = $(id);
    if (!el) continue;
    if (!can) {
      el.hidden = true;
      continue;
    }
    el.hidden = false;
    el.href = href;
    el.textContent = label;
  }
}

/* AIM-796: fleet enforce coverage panel against GET /api/enforcement/coverage
 * (AIM-789). Analyst+ via capabilities.coverage || capabilities.fleet.
 * Pure render helpers live in lib/enforce-coverage.js; this module owns the
 * fetch, capability gate, and failure/unknown states (AIM-1135 split). */
import { $ } from '../../lib/dom.js';
import { state, api } from '../../lib/runtime.js';
import { skeletonCards, emptyState } from '../../lib/components.js';
import { setVerifiedStamp } from '../../lib/ui.js';
import { canViewEnforceCoverage, renderEnforceCoverage } from '../../lib/enforce-coverage.js';

function setEnforceStatement(d) {
  const el = $('#sec-enforce-statement');
  if (!el) return;
  if (!d?.statement) {
    el.textContent = '';
    el.className = 'sec-enforce-statement';
    return;
  }
  const alertable = Boolean(d.honor?.alertable);
  const uncovered = d.installPath?.covered === false;
  el.textContent = d.statement;
  el.className = 'sec-enforce-statement'
    + (uncovered || alertable ? ' tone-bad' : '')
    + (uncovered ? ' is-uncovered' : '');
  el.setAttribute('role', uncovered || alertable ? 'alert' : 'status');
}

export async function loadEnforceCoverage() {
  const panel = $('#sec-enforce-panel');
  const body = $('#sec-enforce-coverage');
  if (!panel || !body) return;

  if (!canViewEnforceCoverage(state.me)) {
    panel.hidden = true;
    body.innerHTML = '';
    return;
  }

  panel.hidden = false;
  body.innerHTML = skeletonCards(3);
  setEnforceStatement(null);

  try {
    const d = await api(`/api/enforcement/coverage?days=${state.days}`);
    setVerifiedStamp('#sec-enforce-asof', d.asOf);
    setEnforceStatement(d);
    body.innerHTML = renderEnforceCoverage(d);
  } catch (err) {
    // 403 = capability not granted server-side; hide rather than alarm.
    if (err.status === 403) {
      panel.hidden = true;
      body.innerHTML = '';
      return;
    }
    // 404 = API not deployed yet (AIM-789 still landing) — unknown, not clean.
    body.innerHTML = emptyState({
      reason: 'error',
      title: err.status === 404 ? 'Enforce coverage API not available' : 'Could not load enforce coverage',
      body: err.status === 404
        ? 'GET /api/enforcement/coverage is not on this stack yet. This is unknown, not a clean fleet — do not invent zeros.'
        : `${err.message}. This panel is unknown, not empty.`,
    });
    setEnforceStatement({
      statement: 'Enforce coverage unavailable — unknown, not clean.',
      installPath: { covered: false },
    });
  }
}

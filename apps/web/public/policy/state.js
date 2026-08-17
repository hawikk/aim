/* Shared view-private state for the Policy editor view (AIM-1177 split).
 * polCtx is view-private: zero cross-view surface. The orchestrator
 * (public/policy.js) calls resetPolicyCtx() at the top of init() and every
 * sibling module imports polCtx — never re-create it locally. */

import { esc } from '../lib/dom.js';
import { fmtInt } from '../lib/format.js';
import { card } from '../lib/components.js';

export const polCtx = {};

export function resetPolicyCtx(section, { mutate, advanced }) {
  Object.assign(polCtx, {
    section,
    mutate,
    advanced,
    toolsList: section.querySelector('#pol-tools-list'),
    modelsList: section.querySelector('#pol-models-list'),
    toolsForm: section.querySelector('#pol-tools-form'),
    modelsForm: section.querySelector('#pol-models-form'),
    cards: section.querySelector('#pol-cards'),
    ruleModes: section.querySelector('#pol-rule-modes'),
    lastSanctioned: [],
    lastAllowlist: [],
    lastAllowlistNote: '',
  });
}

/** observe|enforce mode badge, shared by the allowlist table and rule modes. */
export function modePill(mode) {
  const m = mode === 'enforce' ? 'enforce' : 'observe';
  return `<span class="mode-pill ${m}"><span class="sr-only">Mode: </span>${esc(m)}</span>`;
}

/** Summary cards — painted only after at least one panel loaded (see loadAll). */
export function renderCards() {
  const enforceN = polCtx.lastAllowlist.filter((e) => e.mode === 'enforce' && e.enabled !== false).length;
  const observeN = polCtx.lastAllowlist.filter((e) => e.mode === 'observe' && e.enabled !== false).length;
  polCtx.cards.innerHTML = [
    card({ label: 'Sanctioned tools', value: fmtInt(polCtx.lastSanctioned.length), role: 'listitem' }),
    card({ label: 'Allowlist entries', value: fmtInt(polCtx.lastAllowlist.length), role: 'listitem' }),
    card({ label: 'In enforce', value: fmtInt(enforceN), tone: enforceN > 0 ? '' : 'good', role: 'listitem' }),
    card({ label: 'In observe', value: fmtInt(observeN), role: 'listitem' }),
  ].join('');
}

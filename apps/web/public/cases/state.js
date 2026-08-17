/* Shared view-private state for the Cases view (split).
 * casesCtx is view-private: zero cross-view surface. The orchestrator
 * (public/cases.js) calls resetCasesCtx() at the top of init() and every
 * sibling module imports casesCtx — never re-create it locally. */

import { STATUS_LABEL } from '../lib/cases.js';
import { esc } from '../lib/dom.js';

export const casesCtx = {};

export function resetCasesCtx({ section }) {
  Object.assign(casesCtx, {
    section,
    listEl: section.querySelector('#cases-list'),
    cardsEl: section.querySelector('#case-cards'),
    listPane: section.querySelector('#case-list-pane'),
    detailPane: section.querySelector('#case-detail-pane'),
    createPane: section.querySelector('#case-create'),
    badge: document.querySelector('#cases-badge'),
    statusFilter: section.querySelector('#case-status-filter'),
    sevFilter: section.querySelector('#case-sev-filter'),
    ui: { status: 'active', severity: 'all' },
  });
}

/* Case status pill, shared by the list rows and the detail header. */
export function statusPill(status) {
  return `<span class="pill st-case-${esc(status)}">${esc(STATUS_LABEL[status] ?? status)}</span>`;
}

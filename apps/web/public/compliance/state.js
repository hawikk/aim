/* Shared view-private state for the Compliance evidence view (AIM-1172 split).
 * cmpCtx is view-private: zero cross-view surface. The orchestrator
 * (public/compliance.js) calls resetComplianceCtx() at the top of init() and
 * every sibling module imports cmpCtx — never re-create it locally. */

import { esc } from '../lib/dom.js';

export const cmpCtx = {};

export function resetComplianceCtx(section) {
  Object.assign(cmpCtx, {
    section,
    fromEl: section.querySelector('#cmp-from'),
    toEl: section.querySelector('#cmp-to'),
  });
}

/** Period pickers → `from`/`to` query string shared by every report fetch. */
export function periodQuery() {
  const p = new URLSearchParams();
  if (cmpCtx.fromEl.value) p.set('from', `${cmpCtx.fromEl.value}T00:00:00Z`);
  if (cmpCtx.toEl.value) p.set('to', `${cmpCtx.toEl.value}T23:59:59Z`);
  return p.toString();
}

export function showErr(err) {
  cmpCtx.section.querySelector('#cmp-frameworks').innerHTML = `<div class="err">${esc(err.message)}</div>`;
}

export function setPackStatus(html, tone = '') {
  const el = cmpCtx.section.querySelector('#cmp-pack-status');
  if (!el) return;
  el.dataset.tone = tone;
  el.innerHTML = html;
}

/* Alerts inbox data loading (AIM-1181 split): alert paging behind the
 * severity/pillar filters, shell-state fetch, and the AIM-702 closed-finding
 * outcome history. Rendering lives in ./render.js. */

import { api } from '../lib/api.js';
import { buildFilterParams } from '../lib/inbox.js';
import { indexFromFindingsPayload } from '../lib/auto-triage.js';
import { inboxCtx } from './state.js';
import { render, renderDropped } from './render.js';

const PAGE_LIMIT = 100;
/* Closed-finding history page size for AIM-702. Analyst+ already has this
 * endpoint; we only pull terminal dispositions (resolved / false_positive). */
const HISTORY_PAGE = 200;
const HISTORY_MAX_PAGES = 3;

/* AIM-702: load historical closed-finding dispositions once per inbox
 * session. Failures are non-fatal — cards simply omit the hint pill. */
export async function loadOutcomeHistory() {
  const { state } = inboxCtx;
  try {
    let index = new Map();
    for (let page = 0; page < HISTORY_MAX_PAGES; page += 1) {
      const offset = page * HISTORY_PAGE;
      const res = await api(
        `/api/findings?status=resolved,false_positive&limit=${HISTORY_PAGE}&offset=${offset}`,
      );
      index = indexFromFindingsPayload(res, index);
      const total = Number(res?.total ?? 0);
      const got = Array.isArray(res?.findings) ? res.findings.length : 0;
      if (got < HISTORY_PAGE || offset + got >= total) break;
    }
    state.outcomeIndex = index;
  } catch {
    // Keep whatever we had; first failure leaves null so we do not flash
    // empty-history as if the fleet has never triaged.
    if (!(state.outcomeIndex instanceof Map)) state.outcomeIndex = new Map();
  }
}

export function showProblem(err) {
  const { state } = inboxCtx;
  state.busProblem = err.message;
  state.exhausted = true;
  render();
}

async function fetchPage() {
  const { state } = inboxCtx;
  const params = buildFilterParams(state);
  params.set('limit', String(PAGE_LIMIT));
  if (state.nextCursor) params.set('after', state.nextCursor);
  return api(`/api/alerts?${params}`);
}

async function fetchStates(ids) {
  const { state } = inboxCtx;
  if (!ids.length) return;
  const res = await api(`/api/alerts/state?ids=${ids.map(encodeURIComponent).join(',')}`);
  Object.assign(state.states, res.states);
  // Unack of an alert on screen clears it locally too: the map only ever
  // gains keys from this endpoint, so re-asking for ids we already know
  // would otherwise leave a stale badge. Merge therefore means replace.
  for (const id of ids) if (!res.states[id]) delete state.states[id];
}

export async function loadMore() {
  const { state } = inboxCtx;
  const page = await fetchPage();
  state.nextCursor = page.exhausted ? null : page.nextCursor;
  state.exhausted = page.exhausted;
  state.alerts.push(...page.alerts);
  await fetchStates(page.alerts.map((a) => a.alert_id));
  renderDropped(page.dropped);
  render();
}

export async function reload() {
  const { state } = inboxCtx;
  state.alerts = [];
  state.states = {};
  state.nextCursor = null;
  state.exhausted = false;
  state.busProblem = null;
  // Refresh history in parallel with the first alert page. loadMore renders
  // when alerts arrive; we re-render after history so hint pills land even
  // when the outcome index finishes second.
  await Promise.all([loadMore(), loadOutcomeHistory()]);
  render();
}

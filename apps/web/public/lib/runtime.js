/* Shared runtime surface for dashboard views (pure move from app.js).
 *
 * Views import from here instead of reaching into app.js. The mutable surface
 * is intentional and enumerated — see docs/frontend-app-js-split-map.md.
 *
 * Cross-view state (after this split):
 *   - state.view / .entity / .days / .source — router-owned; views only read
 *   - state.me — session-owned, write-once at bootstrap
 *   - state.tools — the one genuine cross-view coupling: Overview writes it,
 *     Tools reads it (Tools also self-heals via /api/tools). Named here so it
 *     is no longer ambient and invisible.
 *
 * refresh() is late-bound by app.js to break the circular import (views need
 * refresh; refresh needs the loaders map of views).
 */
import { hashFor as buildHash } from './router.js';
import { $ } from './dom.js';
import { api, apiJson } from './api.js';

/* The fetch boundary lives in lib/api.js; re-exported here so
 * the established `import { api } from './lib/runtime.js'` surface keeps
 * working unchanged. */
export { api, apiJson };

export const state = { days: 30, view: 'overview', entity: null, source: 'all', tools: [], me: null };

/** Late-bound by app.js after loaders are wired. */
const hooks = {
  refresh: async () => {},
};

export function setRefresh(fn) {
  hooks.refresh = fn;
}

export function refresh() {
  return hooks.refresh();
}

export const hashFor = (view, entity = null) => buildHash(view, entity, state);

export const setStatus = (msg) => { $('#sr-status').textContent = msg; };

export function clearError(viewName) {
  $( `#view-${viewName}`).querySelector('.error-banner')?.remove();
}

export function showError(viewName, err) {
  const view = $(`#view-${viewName}`);
  clearError(viewName);
  const banner = document.createElement('div');
  banner.className = 'error-banner';
  banner.setAttribute('role', 'alert');
  const msg = document.createElement('div');
  const strong = document.createElement('strong');
  strong.textContent = 'Couldn’t load this view. ';
  const detail = document.createElement('span');
  detail.className = 'err-detail';
  detail.textContent = err.message;
  msg.append(strong, detail);
  const retry = document.createElement('button');
  retry.className = 'btn btn-danger btn-sm';
  retry.textContent = 'Retry';
  retry.addEventListener('click', () => refresh());
  banner.append(msg, retry);
  view.prepend(banner);
}

export const canManageTeams = () => Boolean(state.me?.capabilities?.admin);

export function canMutateSanctioned() {
  return Boolean(state.me?.capabilities?.admin);
}

export function promptReason(actionLabel, tool) {
  const reason = window.prompt(
    `${actionLabel} "${tool}"?\n\nReason (required — recorded in the audit trail with your identity):`,
    '',
  );
  if (reason == null) return null;
  const trimmed = reason.trim();
  if (!trimmed) {
    setStatus('A reason is required for sanction changes.');
    return null;
  }
  return trimmed;
}

export async function sanctionTool(tool, reason) {
  return api('/api/sanctioned', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tool, reason }),
  });
}

export async function unsanctionTool(tool, reason) {
  return api(`/api/sanctioned/${encodeURIComponent(tool)}/unsanction`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason }),
  });
}

export async function refreshSanctionedHint() {
  const el = $('#unapproved-sanctioned-hint');
  if (!el) return;
  try {
    const d = await api('/api/sanctioned');
    const labels = (d.labels && d.labels.length)
      ? d.labels.join(', ')
      : (d.tools || []).map((t) => t.tool).join(', ');
    el.textContent = labels
      ? `everything not on the sanctioned list (${labels}) — newest first`
      : 'everything not on the sanctioned list — newest first';
  } catch {
    // Non-fatal: leave the static placeholder.
  }
}

/* Underscore aliases for views/* pre-rename imports (→). */
export {
  state as _state,
  refresh as _refresh,
  hashFor as _hashFor,
  setStatus as _setStatus,
  showError as _showError,
  apiJson as _apiJson,
  canManageTeams as _canManageTeams,
  canMutateSanctioned as _canMutateSanctioned,
  promptReason as _promptReason,
  sanctionTool as _sanctionTool,
  unsanctionTool as _unsanctionTool,
  refreshSanctionedHint as _refreshSanctionedHint,
};

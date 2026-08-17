/* Cases list pane (AIM-1186 split): status/severity filters, summary cards,
 * the case list itself, and the nav-tab badge of active investigations.
 * List rows drill into the detail pane via nav.js goCase(). */

import { sortCases, openCaseCount } from '../lib/cases.js';
import { api } from '../lib/api.js';
import { esc } from '../lib/dom.js';
import { relTime } from '../lib/format.js';
import { sevPill, severityRowClass } from '../lib/severity.js';
import { card, emptyState } from '../lib/components.js';
import { casesCtx, statusPill } from './state.js';
import { goCase } from './nav.js';

export async function showList() {
  const { listPane, detailPane } = casesCtx;
  listPane.hidden = false;
  detailPane.hidden = true;
  detailPane.replaceChildren();
  await loadList();
}

function statusQuery() {
  const { ui } = casesCtx;
  if (ui.status === 'all') return '';
  if (ui.status === 'active') return 'status=open,investigating,contained';
  return `status=${encodeURIComponent(ui.status)}`;
}

function listQuery() {
  const { ui } = casesCtx;
  const parts = [];
  const sq = statusQuery();
  if (sq) parts.push(sq);
  if (ui.severity !== 'all') parts.push(`severity=${encodeURIComponent(ui.severity)}`);
  parts.push('limit=200');
  return parts.join('&');
}

export async function loadList() {
  const { section, listEl, cardsEl } = casesCtx;
  listEl.innerHTML = emptyState({ reason: 'loading', title: 'Loading cases…' });
  const qs = listQuery();
  section.querySelector('#case-export-list').href = `/api/cases?format=csv&${qs}`;
  try {
    const data = await api(`/api/cases?${qs}`);
    const openData = await api('/api/cases?status=open,investigating,contained&limit=200').catch(() => data);
    renderCards(openData.cases ?? []);
    renderList(data.cases ?? [], data.total ?? 0);
    updateBadge(openData.cases ?? []);
  } catch (err) {
    cardsEl.innerHTML = '';
    listEl.innerHTML = emptyState({ reason: 'error', title: 'Could not load cases', body: err.message });
  }
}

export function updateBadge(cases) {
  const { badge } = casesCtx;
  const n = openCaseCount(cases);
  if (!badge) return;
  if (n > 0) {
    badge.hidden = false;
    badge.textContent = String(n);
    badge.title = `${n} active investigation case${n === 1 ? '' : 's'}`;
  } else {
    badge.hidden = true;
    badge.textContent = '';
  }
}

function renderCards(cases) {
  const by = { open: 0, investigating: 0, contained: 0 };
  for (const c of cases) {
    if (by[c.status] != null) by[c.status] += 1;
  }
  const critical = cases.filter((c) => c.severity === 'critical' && c.status !== 'closed').length;
  casesCtx.cardsEl.innerHTML = [
    card('Open', by.open, by.open ? 'warn' : null),
    card('Investigating', by.investigating, by.investigating ? 'warn' : null),
    card('Contained', by.contained, null),
    card('Critical active', critical, critical ? 'bad' : null),
  ].join('');
}

function renderList(cases, total) {
  const { listEl, ui } = casesCtx;
  if (!cases.length) {
    const filtered = ui.status !== 'all' || ui.severity !== 'all';
    listEl.innerHTML = emptyState({
      reason: filtered ? 'filtered' : 'no-data',
      title: filtered ? 'No cases match these filters' : 'No investigation cases yet',
      body: filtered
        ? 'Cases exist outside the current filters, or none match this slice.'
        : 'Open a case to track an investigation across findings, users, and tools.',
    });
    return;
  }
  const sorted = sortCases(cases);
  listEl.innerHTML = `
    <div class="case-list-meta hint">${esc(String(sorted.length))} shown${total > sorted.length ? ` of ${esc(String(total))}` : ''}</div>
    <ul class="case-list" role="list">
      ${sorted.map((c) => caseRow(c)).join('')}
    </ul>`;
  listEl.querySelectorAll('[data-case-id]').forEach((el) => {
    el.addEventListener('click', () => goCase(el.dataset.caseId));
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        goCase(el.dataset.caseId);
      }
    });
  });
}

function caseRow(c) {
  const att = c.attachmentCount != null ? `${c.attachmentCount} attached` : '';
  return `
    <li>
      <button type="button" class="case-row ${severityRowClass(c.severity)}" data-case-id="${esc(c.caseId)}"
        aria-label="Open case ${esc(c.title)}">
        <span class="case-row-main">
          <span class="case-row-title">${esc(c.title)}</span>
          <span class="case-row-meta">
            ${statusPill(c.status)}
            ${sevPill(c.severity)}
            <span class="hint">${esc(c.createdBy ?? '')}${c.updatedAt ? ` · updated ${esc(relTime(c.updatedAt))}` : ''}${att ? ` · ${esc(att)}` : ''}</span>
          </span>
        </span>
        <span class="case-row-chevron" aria-hidden="true">→</span>
      </button>
    </li>`;
}

export function bindListFilters() {
  const { statusFilter, sevFilter, ui } = casesCtx;
  statusFilter.addEventListener('change', () => { ui.status = statusFilter.value; loadList().catch(() => {}); });
  sevFilter.addEventListener('change', () => { ui.severity = sevFilter.value; loadList().catch(() => {}); });
}

/* Nav-tab badge warms up before the view is first activated. */
export function initBadge() {
  api('/api/cases?status=open,investigating,contained&limit=200')
    .then((d) => updateBadge(d.cases ?? []))
    .catch(() => {});
}

/* MCP inventory panel (split): fleet catalogue table, KPI cards,
 * status/source filters, and the per-server installation drill-down.
 * The orchestrator (public/mcp.js) populates fctx before bind*() runs. */

import { entityHref } from '../lib/deeplinks.js';
import { fmtInt, fmtDay } from '../lib/format.js';
import { esc } from '../lib/dom.js';
import { table as dataTable, card, emptyState, skeletonCards } from '../lib/components.js';
import { state as dashState } from '../lib/runtime.js';
import { isOverrideCandidate } from '../lib/mcp-override.js';
import { api } from '../lib/api.js';
import { fctx } from './state.js';

export function statusPill(status) {
  if (status === 'approved') return '<span class="pill good">approved</span>';
  return '<span class="pill bad">unapproved</span>';
}

export function sourcePills(sources) {
  return (sources ?? [])
    .map((src) => {
      const tone = src === 'discovered' ? 'warn' : 'muted';
      return `<span class="pill ${tone}">${esc(src)}</span>`;
    })
    .join(' ');
}

function scopePills(scopes) {
  return (scopes ?? [])
    .map((sc) => `<span class="pill ${sc === 'user' ? 'warn' : 'muted'}">${esc(sc)}</span>`)
    .join(' ') || '—';
}

function mcpToolsCell(s) {
  const tools = s.mcpTools ?? [];
  if (!tools.length) return '—';
  return esc(tools.slice(0, 4).join(', ')) + (tools.length > 4 ? ` +${tools.length - 4}` : '');
}

/** Client-side inventory filter — same role as Security's criticality select. */
export function filterServers(servers, { status = 'all', source = 'all' } = {}) {
  const list = Array.isArray(servers) ? servers : [];
  return list.filter((s) => {
    if (status !== 'all' && s.status !== status) return false;
    if (source !== 'all') {
      const sources = s.sources ?? [];
      if (source === 'configured') {
        // Configured includes hybrid rows that also carry discovered traffic.
        // Legacy rows without a sources array are treated as configured inventory.
        if (sources.length > 0 && !sources.includes('configured')) return false;
      } else if (source === 'discovered') {
        if (!sources.includes('discovered')) return false;
      } else if (source === 'discovered_only') {
        if (!(sources.includes('discovered') && !sources.includes('configured'))) return false;
      }
    }
    return true;
  });
}

export function activeFilterLabels({ status = 'all', source = 'all' } = {}) {
  const labels = [];
  if (status !== 'all') labels.push(`status=${status}`);
  if (source !== 'all') labels.push(`source=${source}`);
  return labels;
}

/*: column specs feed the shared table() — no hand-rolled thead. */
const INVENTORY_COLS = [
  { key: 'name', label: 'MCP server', render: (s) => `<code>${esc(s.name)}</code>` },
  { key: 'status', label: 'Status', render: (s) => statusPill(s.status) },
  {
    key: 'override',
    label: 'Override',
    render: (s) => (isOverrideCandidate(s)
      ? `<button type="button" class="btn btn-sm btn-primary mcp-override-btn" data-server="${esc(s.name)}" aria-label="Override deny for ${esc(s.name)}">Override deny</button>`
      : '<span class="faint">—</span>'),
  },
  { key: 'sources', label: 'Sources', render: (s) => sourcePills(s.sources) },
  { key: 'scopes', label: 'Scope', render: (s) => scopePills(s.scopes) },
  { key: 'tools', label: 'AI tools', render: (s) => esc((s.tools ?? []).join(', ')) },
  { key: 'mcpTools', label: 'MCP tools', render: (s) => `<span class="mono muted">${mcpToolsCell(s)}</span>` },
  { key: 'users', label: 'Users', num: true, render: (s) => esc(fmtInt(s.users)) },
  { key: 'hosts', label: 'Hosts', num: true, render: (s) => esc(fmtInt(s.hosts)) },
  { key: 'callCount', label: 'Calls', num: true, render: (s) => esc(fmtInt(s.callCount ?? 0)) },
  { key: 'firstSeen', label: 'First seen', render: (s) => esc(fmtDay(s.firstSeen)) },
  { key: 'lastSeen', label: 'Last seen', render: (s) => esc(fmtDay(s.lastSeen)) },
];

/*: entity hops go through entityHref so the shared range survives. */
const installCtx = () => ({ days: dashState.days });
const INSTALL_COLS = [
  {
    key: 'user',
    label: 'User',
    render: (r) => (r.user
      ? `<a class="mono" href="${esc(entityHref('users', r.user, installCtx()))}">${esc(r.user.length > 11 ? `${r.user.slice(0, 10)}…` : r.user)}</a>`
      : '<span class="faint">(unattributed)</span>'),
  },
  {
    key: 'team',
    label: 'Team',
    render: (r) => (r.team
      ? `<a href="${esc(entityHref('teams', r.team, installCtx()))}">${esc(r.team)}</a>`
      : '—'),
  },
  {
    key: 'tool',
    label: 'Tool',
    render: (r) => (r.tool
      ? `<a href="${esc(entityHref('tools', r.tool, installCtx()))}">${esc(r.tool)}</a>`
      : '—'),
  },
  { key: 'host', label: 'Host', render: (r) => `<span class="mono">${esc(r.host ?? '—')}</span>` },
  {
    key: 'scope',
    label: 'Scope',
    render: (r) => `<span class="pill ${r.scope === 'user' ? 'warn' : 'muted'}">${esc(r.scope ?? '—')}</span>`,
  },
  { key: 'lastSeen', label: 'Snapshot', render: (r) => esc(fmtDay(r.lastSeen ?? r.snapshotAt)) },
];

const EMPTY_INVENTORY = {
  reason: 'no-data',
  needsEvents: true,
  title: 'No MCP servers configured fleet-wide',
  body: 'Inventory events arrive when a tool\'s MCP config changes; tool_use mcp_call events appear when agents invoke MCP tools. Widen the day range or check collector status.',
};

function currentFilters() {
  return {
    status: fctx.statusSel?.value || 'all',
    source: fctx.sourceSel?.value || 'all',
  };
}

export function setLoading() {
  const { cards, table } = fctx;
  cards.setAttribute('aria-busy', 'true');
  cards.innerHTML = skeletonCards(7);
  table.setAttribute('aria-busy', 'true');
  dataTable(table, INVENTORY_COLS, [], {
    caption: 'MCP server inventory — loading',
    empty: { reason: 'loading' },
  });
}

export function setError(err) {
  const { cards, table, filterHint } = fctx;
  cards.setAttribute('aria-busy', 'false');
  cards.innerHTML = emptyState({
    reason: 'error',
    body: err.message,
    retryKey: 'mcp',
    retryLabel: 'Retry',
  });
  table.setAttribute('aria-busy', 'false');
  dataTable(table, INVENTORY_COLS, [], {
    caption: 'MCP server inventory — failed to load',
    empty: { reason: 'error', body: err.message, retryKey: 'mcp' },
  });
  if (filterHint) filterHint.textContent = '';
}

export function renderInventory() {
  const { mcpState, table, filterHint } = fctx;
  if (!mcpState.servers) return;
  const filters = currentFilters();
  const all = mcpState.servers;
  const rows = filterServers(all, filters);
  const labels = activeFilterLabels(filters);
  if (filterHint) {
    filterHint.textContent = labels.length
      ? `${rows.length} of ${all.length} · ${labels.join(' · ')}`
      : `${all.length} server${all.length === 1 ? '' : 's'}`;
  }
  const empty = all.length === 0
    ? EMPTY_INVENTORY
    : {
      reason: 'filtered',
      title: 'No MCP servers match these filters',
      body: 'Widen Status or Source — the unfiltered inventory still has rows.',
      filters: labels,
    };
  dataTable(table, INVENTORY_COLS, rows, {
    caption: 'MCP server inventory with approval status, sources, and usage counts',
    empty,
    rowClass: () => 'is-clickable',
    rowAttrs: (s) => ({
      'data-server': s.name,
      tabindex: '0',
      role: 'button',
      'aria-label': `Open installations of ${s.name}`,
    }),
  });
  table.setAttribute('aria-busy', 'false');
}

function renderCards() {
  const { mcpState, cards } = fctx;
  const s = mcpState.summary ?? {};
  cards.setAttribute('aria-busy', 'false');
  cards.innerHTML = [
    card('Distinct MCP servers', fmtInt(s.servers)),
    card('Configured', fmtInt(s.configured ?? 0)),
    card('Discovered only', fmtInt(s.discoveredOnly ?? 0), (s.discoveredOnly ?? 0) > 0 ? 'warn' : undefined),
    card('Unapproved', fmtInt(s.unapproved ?? 0), (s.unapproved ?? 0) > 0 ? 'bad' : 'good'),
    card('Approved', fmtInt(s.approved ?? 0), (s.approved ?? 0) > 0 ? 'good' : undefined),
    card('Hosts reporting inventory', fmtInt(s.hostsReporting)),
    card('New in last 7 days', fmtInt(s.newLast7d), s.newLast7d > 0 ? 'bad' : 'good'),
  ].join('');
}

function renderRangeHint() {
  const { mcpState, section } = fctx;
  const discMode = mcpState.policy?.discoveryMode;
  const approvedN = mcpState.policy?.approvedServerCount ?? 0;
  const policyHint = discMode
    ? 'discovery mode (empty approved_mcp_servers — all unapproved)'
    : approvedN === 0
      ? 'deny-unlisted allowlist (empty — all MCP unapproved; discovery closed)'
      : `allowlist active (${fmtInt(approvedN)} approved) · policy_hash ${String(mcpState.policy?.contentHash ?? '').slice(0, 12) || '—'}…`;
  section.querySelector('#mcp-range').textContent =
    `last ${mcpState.rangeDays ?? dashState.days} days · ${policyHint} · click a row for who has it configured · Override deny for unapproved`;
}

export async function loadInventory() {
  const { mcpState } = fctx;
  setLoading();
  try {
    const days = Number(dashState.days) || 30;
    const d = await api(`/api/mcp-servers?days=${days}`);
    mcpState.servers = d.servers ?? [];
    mcpState.summary = d.summary ?? {};
    mcpState.policy = d.policy ?? null;
    mcpState.rangeDays = d.rangeDays ?? days;
    renderCards();
    renderRangeHint();
    renderInventory();
  } catch (err) {
    mcpState.servers = null;
    setError(err);
    throw err;
  }
}

async function drill(name) {
  const { detailPanel, detailTitle, detailBody } = fctx;
  detailPanel.hidden = false;
  detailTitle.innerHTML = `Who has <code>${esc(name)}</code> configured <span class="hint">per-user attribution (privacy-gated)</span>`;
  detailBody.innerHTML = emptyState({ reason: 'loading' });
  detailPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  try {
    const days = Number(dashState.days) || 30;
    const d = await api(`/api/mcp-servers?days=${days}&server=${encodeURIComponent(name)}`);
    const unapproved = d.status === 'unapproved';
    const statusLine = d.status
      ? `<p class="hint">Policy status: ${statusPill(d.status)}${
          d.policy?.discoveryMode ? ' · discovery mode' : ''
        }${
          unapproved
            ? ` · <button type="button" class="btn btn-sm btn-primary mcp-override-btn" data-server="${esc(name)}">Override deny</button>`
            : ''
        }</p>`
      : '';
    detailBody.innerHTML = `${statusLine}<div class="table-wrap" tabindex="0" role="region" aria-label="Installations of ${esc(name)}, scrollable"><table></table></div>`;
    dataTable(detailBody.querySelector('table'), INSTALL_COLS, d.installations, {
      caption: `Installations of ${name}`,
      empty: {
        reason: 'no-data',
        title: 'No current config installations',
        body: 'Server may be discovered-only (live mcp_call) or every host that had it has reported a newer snapshot without it.',
      },
    });
  } catch (err) {
    // 403 lands here for roles without user-level access: show the API's
    // privacy-gate explanation instead of data (same as other gated views).
    detailBody.innerHTML = emptyState({ reason: 'error', body: err.message });
  }
}

export function bindInventory() {
  const { statusSel, sourceSel, table, section, detailPanel, detailBody } = fctx;

  statusSel?.addEventListener('change', () => renderInventory());
  sourceSel?.addEventListener('change', () => renderInventory());

  table.addEventListener('click', (e) => {
    if (e.target.closest('a')) return;
    if (e.target.closest('.mcp-override-btn')) return;
    const tr = e.target.closest('tr[data-server]');
    if (tr) drill(tr.dataset.server);
  });
  table.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    if (e.target.closest('.mcp-override-btn')) return;
    const tr = e.target.closest('tr[data-server]');
    if (!tr) return;
    e.preventDefault();
    drill(tr.dataset.server);
  });
  section.querySelector('#mcp-detail-close').addEventListener('click', () => {
    detailPanel.hidden = true;
    detailBody.innerHTML = '';
  });
}

/* Shadow AI discovery — tools + IdP SaaS grant inventory.
 *
 * Self-contained module, same pattern as coverage.js / mcp.js: injects its nav
 * tab, view section and stylesheet at runtime, and activates only on the
 * server-computed `fleet` capability (analyst + security-admin).
 *
 * Data:
 *   GET /api/shadow-ai/summary — tool + grant headline counts
 *   GET /api/shadow-ai/tools   — aggregate AI tools (risk-ordered)
 *   GET /api/shadow-ai/grants  — who authorized which AI SaaS via corporate
 *                                IdP (user_ref pseudonym only)
 *
 * Honesty rules:
 *   * identityCount may be null → render "—". Never guessed.
 *   * sanctioned is THREE states: true / false / null.
 *   * grants list shows user_ref (HMAC) only; cleartext reveal is the
 *     identity-sync /reveal path (audited, separate capability).
 *   * finding_type unapproved_ai_saas_grant marks ChatGPT-class signals.
 *
 * loading skeletons, criticality-style risk filter + status filters
 * consistent with the Security module, shared empty/error states.
 */

import { registerModuleView } from './lib/router.js';
import { fmtDay, fmtInt, fmtTs } from './lib/format.js';
import { esc } from './lib/dom.js';
import { table as dataTable, tableHtml as sharedTableHtml, tableRowHtml, card, emptyState, skeletonCards } from './lib/components.js';
import { moduleTab, moduleSection } from './lib/a11y.js';
import { severityBadge } from './lib/severity.js';
import { api } from './lib/api.js';

/* ---------- Gate: server-computed capability (analyst + security-admin) ----------
 * Same gate as the Fleet view: /api/me.capabilities.fleet. Do not reintroduce
 * client-side group-name sniffing — role → capability is computed API-side. */
const me = await api('/api/me').catch((err) => {
  if (err.status === 401) window.location.assign('/auth/login');
  return null;
});
if (me?.capabilities?.fleet) {
  init().catch((err) => console.error('shadow ai view failed to start:', err));
}

/* ---------- Render helpers (pure string builders; unit-tested) ---------- */

const SOURCE_LABELS = { idp_oauth: 'IdP OAuth grant', proxy_domain: 'Proxy domain' };
const sourceLabel = (type) => SOURCE_LABELS[type] ?? type;
const BAND_ORDER = ['critical', 'high', 'medium', 'low'];

export function statusPill(tool) {
  if (tool.sanctioned === true) return '<span class="pill ok">Sanctioned</span>';
  if (tool.sanctioned === false) return '<span class="pill bad">Unsanctioned</span>';
  // null sanctioned: catalogued-but-unclassified or not catalogued at all —
  // three states, never collapsed into a boolean.
  return '<span class="pill warn">Unknown — not in catalogue</span>';
}

export function riskPill(tool) {
  const band = String(tool.riskBand ?? 'low');
  return severityBadge(band, { srLabel: 'Risk band: ' });
}

export function sourcesHtml(tool) {
  if (!tool.sources?.length) return '—';
  return tool.sources
    .map(
      (s) =>
        `<span class="pill muted" title="${esc(sourceLabel(s.type))}${s.attributed ? ' — identity-attributed' : ' — unattributed (identity count unknown)'}">${esc(sourceLabel(s.type))}</span>`,
    )
    .join(' ');
}

/* identityCount: null means unattributed → adoption unknown. Render "—",
 * never an invented zero. */
export function identitiesHtml(tool) {
  if (tool.identityCount == null) {
    return '<span class="sh-unknown" title="Unattributed — adoption unknown (no IdP identity signal)">—</span>';
  }
  return esc(fmtInt(tool.identityCount));
}

/** Client-side tools filter — risk band mirrors Security criticality. */
export function filterTools(tools, { band = 'all', status = 'all' } = {}) {
  const list = Array.isArray(tools) ? tools : [];
  return list.filter((t) => {
    if (band !== 'all' && String(t.riskBand ?? 'low') !== band) return false;
    if (status === 'sanctioned' && t.sanctioned !== true) return false;
    if (status === 'unsanctioned' && t.sanctioned !== false) return false;
    if (status === 'unknown' && t.sanctioned != null) return false;
    if (status === 'uncatalogued' && t.catalogued !== false) return false;
    return true;
  });
}

/** Client-side grants filter (sanction + finding presence). */
export function filterGrants(grants, { status = 'all', finding = 'all' } = {}) {
  const list = Array.isArray(grants) ? grants : [];
  return list.filter((g) => {
    if (status === 'sanctioned' && g.sanctioned !== true) return false;
    if (status === 'unsanctioned' && g.sanctioned !== false) return false;
    if (status === 'unknown' && g.sanctioned != null) return false;
    if (finding === 'with' && !g.findingType) return false;
    if (finding === 'without' && g.findingType) return false;
    return true;
  });
}

export function activeToolFilterLabels({ band = 'all', status = 'all' } = {}) {
  const labels = [];
  if (band !== 'all') labels.push(`risk=${band}`);
  if (status !== 'all') labels.push(`status=${status}`);
  return labels;
}

export function activeGrantFilterLabels({ status = 'all', finding = 'all' } = {}) {
  const labels = [];
  if (status !== 'all') labels.push(`status=${status}`);
  if (finding !== 'all') labels.push(`finding=${finding}`);
  return labels;
}

function detailHtml(tool) {
  const comps = tool.riskComponents?.length
    ? `<ul class="sh-components">${tool.riskComponents
        .map(
          (c) =>
            `<li><span class="sh-comp-name">${esc(c.name)}</span> <span class="sh-comp-points">+${esc(fmtInt(c.points))}</span>${c.detail ? ` <span class="hint">${esc(c.detail)}</span>` : ''}</li>`,
        )
        .join('')}</ul>`
    : emptyState({ reason: 'no-data', title: 'No risk components recorded', body: 'The discovery service scored this tool without recording contributing components.' });
  const scopes = tool.scopeClasses?.length
    ? tool.scopeClasses.map((sc) => `<span class="pill muted">${esc(sc)}</span>`).join(' ')
    : '<span class="sh-unknown">—</span>';
  return `<div class="sh-detail">
    <div class="sh-detail-block"><h3>Risk components <span class="hint">score ${esc(fmtInt(tool.riskScore))} · computed ${esc(fmtTs(tool.computedAt))}</span></h3>${comps}</div>
    <div class="sh-detail-block"><h3>OAuth scope classes</h3><div>${scopes}</div></div>
  </div>`;
}

const INVENTORY_COLS = [
  {
    key: 'name',
    label: 'Tool',
    render: (tool) => `<code>${esc(tool.name)}</code>${tool.catalogued ? '' : ' <span class="pill warn">New</span>'}${tool.vendor ? ` <span class="hint">${esc(tool.vendor)}</span>` : ''}`,
  },
  { key: 'status', label: 'Status', render: (tool) => statusPill(tool) },
  { key: 'dataAccessClass', label: 'Data access', render: (tool) => esc(tool.dataAccessClass ?? '—') },
  { key: 'sources', label: 'Discovered via', render: (tool) => sourcesHtml(tool) },
  { key: 'identityCount', label: 'Identities', num: true, render: (tool) => identitiesHtml(tool) },
  { key: 'firstSeen', label: 'First seen', render: (tool) => esc(fmtDay(tool.firstSeen)) },
  { key: 'lastSeen', label: 'Last seen', render: (tool) => esc(fmtDay(tool.lastSeen)) },
  { key: 'riskScore', label: 'Risk', num: true, render: (tool) => esc(fmtInt(tool.riskScore)) },
  { key: 'riskBand', label: 'Band', render: (tool) => riskPill(tool) },
];

const INVENTORY_OPTS = {
  caption: 'Discovered AI tools with sanction status, identity count and risk band',
  empty: {
    reason: 'no-data',
    needsEvents: true,
    title: 'No shadow AI tools discovered yet',
    body: 'The inventory is computed from IdP OAuth grants and proxy domain metadata by the shadow-ai discovery service.',
  },
  rowClass: (tool) => (tool.catalogued ? '' : 'sh-uncatalogued'),
  rowAttrs: (tool) => ({
    'data-tool': tool.toolId,
    tabindex: '0',
    role: 'button',
    title: 'Expand for risk components and scopes',
    'aria-label': `Expand risk detail for ${tool.name}`,
  }),
};

export function rowHtml(tool) {
  return tableRowHtml(INVENTORY_COLS, tool, INVENTORY_OPTS);
}

export function tableHtml(tools) {
  return sharedTableHtml(INVENTORY_COLS, tools, INVENTORY_OPTS);
}

export function cardsHtml(summary) {
  const bands = BAND_ORDER.map(
    (b) => `<span class="sh-band">${severityBadge(b)} ${esc(fmtInt(summary.by_band?.[b] ?? 0))}</span>`,
  ).join(' ');
  // per-IdP grant breakdown (Entra / Okta / Google / …).
  const byIdp = summary.grants_by_idp_source || {};
  const idpKeys = Object.keys(byIdp).sort();
  const idpBands = idpKeys.length
    ? idpKeys
        .map(
          (k) =>
            `<span class="sh-band"><span class="pill muted">${esc(k)}</span> ${esc(fmtInt(byIdp[k] ?? 0))}</span>`,
        )
        .join(' ')
    : '<span class="hint">no IdP grants yet</span>';
  return [
    card('Tools discovered', fmtInt(summary.total ?? 0)),
    card('IdP grants', fmtInt(summary.active_grants ?? 0)),
    card('unapproved_ai_saas_grant', fmtInt(summary.unapproved_ai_saas_grant_findings ?? 0), (summary.unapproved_ai_saas_grant_findings ?? 0) > 0 ? 'bad' : null),
    card('ChatGPT grants', fmtInt(summary.chatgpt_grants ?? 0), (summary.chatgpt_grants ?? 0) > 0 ? 'bad' : null),
    card('Sanctioned', fmtInt(summary.sanctioned ?? 0), 'good'),
    card('Unsanctioned', fmtInt(summary.unsanctioned ?? 0), summary.unsanctioned > 0 ? 'bad' : null),
    card('Not in catalogue', fmtInt(summary.uncatalogued ?? 0), summary.uncatalogued > 0 ? 'bad' : null),
    `<div class="card sh-bands"><div class="label">Risk bands</div><div class="sh-band-row">${bands}</div></div>`,
    `<div class="card sh-bands"><div class="label">Grants by IdP</div><div class="sh-band-row">${idpBands}</div></div>`,
  ].join('');
}

const GRANT_COLS = [
  {
    key: 'userRef',
    label: 'User (pseudonym)',
    render: (g) => `<code title="Pseudonym only — reveal via identity-sync /reveal (audited)">${esc(g.userRef)}</code>`,
  },
  {
    key: 'appName',
    label: 'AI SaaS app',
    render: (g) => `<code>${esc(g.appName)}</code>${g.toolId ? ` <span class="hint">${esc(g.toolId)}</span>` : ''}`,
  },
  { key: 'idpSource', label: 'IdP', render: (g) => `<span class="pill muted">${esc(g.idpSource)}</span>` },
  {
    key: 'sanctioned',
    label: 'Status',
    render: (g) => (g.sanctioned === true
      ? '<span class="pill ok">Sanctioned</span>'
      : g.sanctioned === false
        ? '<span class="pill bad">Unsanctioned</span>'
        : '<span class="pill warn">Unknown</span>'),
  },
  {
    key: 'findingType',
    label: 'Finding',
    render: (g) => (g.findingType
      ? `<span class="pill bad" title="${esc(g.findingId || '')}">${esc(g.findingType)}</span>`
      : '<span class="sh-unknown">—</span>'),
  },
  { key: 'scopes', label: 'Scopes', num: true, render: (g) => esc(fmtInt((g.scopes || []).length)) },
  { key: 'firstSeen', label: 'First seen', render: (g) => esc(fmtDay(g.firstSeen)) },
  { key: 'lastSeen', label: 'Last seen', render: (g) => esc(fmtDay(g.lastSeen)) },
];

const GRANT_OPTS = {
  caption: 'AI SaaS grants via corporate IdP, with sanction status and linked findings',
  empty: {
    reason: 'no-collector',
    title: 'No IdP AI SaaS grants yet',
    body: 'Run shadow-ai sync against fixture or a live Entra/Okta/Google connector. No collector install required for this path.',
    action: 'shadow-ai sync',
  },
};

export function grantRowHtml(g) {
  return tableRowHtml(GRANT_COLS, g, GRANT_OPTS);
}

export function grantsTableHtml(grants) {
  return sharedTableHtml(GRANT_COLS, grants, GRANT_OPTS);
}

async function init() {
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/shadow-ai.css';
  document.head.appendChild(link);

  // Nav tab: sits next to Fleet — both are analyst+ security surfaces.
  moduleTab({
    view: 'shadow-ai',
    label: 'Shadow AI',
    icon: '<svg class="ico" viewBox="0 0 16 16"><path d="M8 1.5 14 5v6l-6 3.5L2 11V5z" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/><path d="M8 5.5v3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/><circle cx="8" cy="11" r="0.9" fill="currentColor"/></svg>',
  });

  const section = moduleSection({ view: 'shadow-ai', html: `
    <div class="banner info">Shadow AI (Track 2) — <b>who authorized which AI SaaS with corporate identity</b> via IdP OAuth grants (Entra / Okta / Google), plus tool inventory from grants and proxy domain metadata. User column is a <b>pseudonym</b> only; cleartext reveal is the audited identity-sync path. No prompt content. Restricted to analyst + security-admin. <b>Read-only.</b></div>
    <div class="cards" id="sh-cards" aria-busy="true">${skeletonCards(8)}</div>
    <div class="controls-row" id="sh-filters">
      <label class="picker">Criticality: <select id="sh-band" aria-label="Filter discovered AI tools by risk band">
        <option value="all" selected>all</option>
        <option value="critical">critical</option>
        <option value="high">high</option>
        <option value="medium">medium</option>
        <option value="low">low</option>
      </select></label>
      <label class="picker">Tool status: <select id="sh-tool-status" aria-label="Filter discovered AI tools by sanction status">
        <option value="all" selected>all</option>
        <option value="unsanctioned">unsanctioned</option>
        <option value="sanctioned">sanctioned</option>
        <option value="unknown">unknown</option>
        <option value="uncatalogued">not in catalogue</option>
      </select></label>
      <label class="picker">Grant status: <select id="sh-grant-status" aria-label="Filter IdP grants by sanction status">
        <option value="all" selected>all</option>
        <option value="unsanctioned">unsanctioned</option>
        <option value="sanctioned">sanctioned</option>
        <option value="unknown">unknown</option>
      </select></label>
      <label class="picker">Finding: <select id="sh-grant-finding" aria-label="Filter IdP grants by linked finding">
        <option value="all" selected>all</option>
        <option value="with">with finding</option>
        <option value="without">no finding</option>
      </select></label>
      <span class="hint" id="sh-filter-hint"></span>
    </div>
    <div class="panel"><h2>AI SaaS grants via corporate IdP <span class="hint">pseudonyms · unapproved_ai_saas_grant when unsanctioned</span> <a class="btn-export" href="/api/shadow-ai/grants?format=csv" download>CSV</a></h2>
      <div class="table-wrap" tabindex="0" role="region" aria-label="AI SaaS IdP grants table, scrollable"><table id="sh-grants" aria-busy="true"></table></div></div>
    <div class="panel"><h2>Discovered AI tools <span class="hint" id="sh-freshness"></span> <a class="btn-export" id="exp-shadow-ai" href="/api/shadow-ai/tools?format=csv" download>CSV</a></h2>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Discovered AI tools table, scrollable"><table id="sh-table" aria-busy="true"></table></div></div>` });
  document.querySelector('main').appendChild(section);

  const cards = section.querySelector('#sh-cards');
  const table = section.querySelector('#sh-table');
  const grantsTable = section.querySelector('#sh-grants');
  const freshness = section.querySelector('#sh-freshness');
  const bandSel = section.querySelector('#sh-band');
  const toolStatusSel = section.querySelector('#sh-tool-status');
  const grantStatusSel = section.querySelector('#sh-grant-status');
  const grantFindingSel = section.querySelector('#sh-grant-finding');
  const filterHint = section.querySelector('#sh-filter-hint');

  // `#/shadow-ai` is a real route — the tab is an ordinary data-view
  // button handled by app.js, and route() calls this to render.
  registerModuleView('shadow-ai', {
    onActivate: () => load(),
  });

  /* Cached payloads so Criticality/status filters re-render without a round-trip
   * (Security secState pattern). */
  const shState = { tools: null, grants: null, summary: null };

  function toolFilters() {
    return {
      band: bandSel?.value || 'all',
      status: toolStatusSel?.value || 'all',
    };
  }

  function grantFilters() {
    return {
      status: grantStatusSel?.value || 'all',
      finding: grantFindingSel?.value || 'all',
    };
  }

  function setLoading() {
    cards.setAttribute('aria-busy', 'true');
    cards.innerHTML = skeletonCards(8);
    table.setAttribute('aria-busy', 'true');
    grantsTable.setAttribute('aria-busy', 'true');
    dataTable(table, INVENTORY_COLS, [], {
      caption: 'Discovered AI tools — loading',
      empty: { reason: 'loading' },
    });
    dataTable(grantsTable, GRANT_COLS, [], {
      caption: 'AI SaaS grants — loading',
      empty: { reason: 'loading' },
    });
  }

  function setError(err) {
    cards.setAttribute('aria-busy', 'false');
    cards.innerHTML = emptyState({
      reason: 'error',
      body: err.message,
      retryKey: 'shadow-ai',
      retryLabel: 'Retry',
    });
    table.setAttribute('aria-busy', 'false');
    grantsTable.setAttribute('aria-busy', 'false');
    dataTable(table, INVENTORY_COLS, [], {
      caption: 'Discovered AI tools — failed to load',
      empty: { reason: 'error', body: err.message, retryKey: 'shadow-ai' },
    });
    dataTable(grantsTable, GRANT_COLS, [], {
      caption: 'AI SaaS grants — failed to load',
      empty: { reason: 'error', body: err.message, retryKey: 'shadow-ai' },
    });
    if (filterHint) filterHint.textContent = '';
    if (freshness) freshness.textContent = '';
  }

  function renderFiltered() {
    const tFilters = toolFilters();
    const gFilters = grantFilters();
    const tools = filterTools(shState.tools ?? [], tFilters);
    const grants = filterGrants(shState.grants ?? [], gFilters);
    const tLabels = activeToolFilterLabels(tFilters);
    const gLabels = activeGrantFilterLabels(gFilters);
    const allTools = shState.tools ?? [];
    const allGrants = shState.grants ?? [];

    dataTable(table, INVENTORY_COLS, tools, {
      ...INVENTORY_OPTS,
      empty: allTools.length === 0
        ? INVENTORY_OPTS.empty
        : {
          reason: 'filtered',
          title: 'No discovered tools match these filters',
          body: 'Widen Criticality or Tool status — the unfiltered inventory still has rows.',
          filters: tLabels,
        },
    });
    dataTable(grantsTable, GRANT_COLS, grants, {
      ...GRANT_OPTS,
      empty: allGrants.length === 0
        ? GRANT_OPTS.empty
        : {
          reason: 'filtered',
          title: 'No IdP grants match these filters',
          body: 'Widen Grant status or Finding — the unfiltered grant list still has rows.',
          filters: gLabels,
        },
    });
    table.setAttribute('aria-busy', 'false');
    grantsTable.setAttribute('aria-busy', 'false');

    if (filterHint) {
      const toolPart = tLabels.length
        ? `tools ${tools.length}/${allTools.length} (${tLabels.join(', ')})`
        : `tools ${allTools.length}`;
      const grantPart = gLabels.length
        ? `grants ${grants.length}/${allGrants.length} (${gLabels.join(', ')})`
        : `grants ${allGrants.length}`;
      filterHint.textContent = `${toolPart} · ${grantPart}`;
    }
  }

  async function load() {
    setLoading();
    try {
      const [summary, inv, grantsResp] = await Promise.all([
        api('/api/shadow-ai/summary'),
        api('/api/shadow-ai/tools'),
        api('/api/shadow-ai/grants'),
      ]);
      shState.summary = summary;
      shState.tools = inv.tools ?? [];
      shState.grants = grantsResp.grants ?? [];
      cards.setAttribute('aria-busy', 'false');
      cards.innerHTML = cardsHtml(summary);
      freshness.textContent = `worst risk first · click a row for risk components · computed ${fmtTs(summary.computed_at)}`;
      renderFiltered();
    } catch (err) {
      shState.tools = null;
      shState.grants = null;
      setError(err);
      throw err;
    }
  }

  for (const el of [bandSel, toolStatusSel, grantStatusSel, grantFindingSel]) {
    el?.addEventListener('change', () => {
      if (shState.tools) renderFiltered();
    });
  }

  section.addEventListener('click', (e) => {
    const retry = e.target.closest('[data-empty-retry="shadow-ai"]');
    if (retry) {
      e.preventDefault();
      load().catch(() => {});
    }
  });

  function toggle(tr) {
    const next = tr.nextElementSibling;
    if (next?.classList.contains('sh-detail-row')) {
      next.remove();
      return;
    }
    const tool = (shState.tools ?? []).find((t) => String(t.toolId) === tr.dataset.tool);
    if (!tool) return;
    const detail = document.createElement('tr');
    detail.className = 'sh-detail-row';
    detail.innerHTML = `<td colspan="${INVENTORY_COLS.length}">${detailHtml(tool)}</td>`;
    tr.after(detail);
  }

  table.addEventListener('click', (e) => {
    if (e.target.closest('a')) return;
    const tr = e.target.closest('tr[data-tool]');
    if (tr) toggle(tr);
  });
  table.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const tr = e.target.closest('tr[data-tool]');
    if (!tr) return;
    e.preventDefault();
    toggle(tr);
  });

  // Initial loading skeleton is already in the DOM; pre-warm so first tab open is instant.
  load().catch(() => {});
}

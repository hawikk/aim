/* Coverage & Trust (AIM-278) — one screen that answers "what are we NOT
 * seeing?".
 *
 * Self-contained module, same pattern as mcp.js: injects its nav tab, view
 * section and stylesheet at runtime, and activates only on the
 * server-computed `coverage` capability (analyst + admin — coverage
 * gaps are an attacker's roadmap, so this is deliberately NOT an all-roles
 * surface).
 *
 * Everything rendered here comes from GET /api/coverage. The honesty rules
 * are load-bearing and mirrored from the API contract:
 *   * A source that is not wired renders an explicit "not wired: <endpoint>"
 *     state. Counts that are unknown render "—", never 0. Zero is a
 *     measurement; "—" is "we cannot see".
 *   * Stale is a state: a column whose freshness is stale is visually
 *     degraded (bad-tone freshness chip + Stale pill + a top banner), so the
 *     screen can never look healthy while the stack has ingested nothing.
 *   * Metadata only: tool names, repo pseudonyms/labels, account ids, counts,
 *     timestamps. No prompt or file content exists here to leak.
 */

import { registerModuleView } from './lib/router.js';
import { fmtInt, fmtTs } from './lib/format.js';
import { esc } from './lib/dom.js';
import { tableHtml } from './lib/components.js';
import { moduleTab, moduleSection } from './lib/a11y.js';
import { api } from './lib/api.js';

/* ---------- Gate: server-computed capability (analyst + admin) ---------- */
const me = await api('/api/me').catch((err) => {
  if (err.status === 401) window.location.assign('/auth/login');
  return null;
});
if (me?.capabilities?.coverage) {
  init().catch((err) => console.error('coverage & trust failed to start:', err));
}

function fmtAge(seconds) {
  if (seconds == null) return 'never';
  const s = Number(seconds);
  if (s < 90) return `${Math.round(s)}s ago`;
  if (s < 90 * 60) return `${Math.round(s / 60)}m ago`;
  if (s < 48 * 3600) return `${(s / 3600).toFixed(s < 10 * 3600 ? 1 : 0)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

const COLUMNS = [
  { key: 'aiTools', title: 'AI tools' },
  { key: 'cloudAccounts', title: 'Cloud accounts' },
  { key: 'repos', title: 'Repos' },
];

function statePill(col) {
  if (col.state === 'not_wired') return '<span class="pill muted">Not wired</span>';
  if (col.state === 'error') return '<span class="pill bad">Error</span>';
  if (col.freshness?.stale) return '<span class="pill bad">Stale</span>';
  if (col.state === 'partial') return '<span class="pill warn">Partial</span>';
  return '<span class="pill ok">Live</span>';
}

function freshnessHtml(col) {
  const f = col.freshness;
  if (!f) {
    return '<div class="cov-fresh unknown">Last event: unknown — source not wired</div>';
  }
  if (f.lastEventAt == null) {
    return '<div class="cov-fresh stale">Last event: never — nothing has ever reached this source</div>';
  }
  const cls = f.stale ? 'stale' : 'fresh';
  return `<div class="cov-fresh ${cls}">Last event: ${esc(fmtAge(f.ageSeconds))} (${esc(fmtTs(f.lastEventAt))})</div>`;
}

function statHtml(label, value, tone, unknownHint) {
  const unknown = value == null;
  const shown = unknown ? '—' : fmtInt(value);
  const cls = unknown ? 'tone-unknown' : tone ? `tone-${tone}` : '';
  return `<div class="cov-stat"><div class="label">${esc(label)}</div>` +
    `<div class="value ${cls}">${esc(shown)}</div>` +
    (unknown && unknownHint ? `<div class="unknown-hint">${esc(unknownHint)}</div>` : '') +
    `</div>`;
}

function darkReasonPill(reason) {
  if (!reason) return '';
  const tone = reason === 'policy_excluded' ? 'muted' : 'bad';
  return `<span class="pill ${tone}">${esc(reason)}</span>`;
}

const lastSeenCol = {
  key: 'lastEventAt',
  label: 'Last seen',
  render: (it) => (it.neverSeen ? '<span class="pill bad">never seen</span>' : esc(fmtTs(it.lastEventAt))),
};
const labelCol = (label) => ({ key: 'label', label, render: (it) => `<code>${esc(it.label ?? it.id)}</code>` });

const DARK_COLS = {
  cloudAccounts: [
    labelCol('Item'),
    { key: 'provider', label: 'Provider', render: (it) => esc(it.provider ?? '') },
    { key: 'costUsd30d', label: 'Cost 30d', num: true, render: (it) => (it.costUsd30d != null ? `$${fmtInt(it.costUsd30d)}` : '—') },
    lastSeenCol,
    { key: 'detail', label: 'Why dark', render: (it) => esc(it.detail ?? '') },
  ],
  repos: [
    labelCol('Repo'),
    {
      key: 'reason',
      label: 'Reason',
      render: (it) => `${darkReasonPill(it.reason)}${it.detail ? ` <span class="hint">${esc(it.detail)}</span>` : ''}`,
    },
    { ...lastSeenCol, label: 'Last gate' },
    { key: 'mode', label: 'Mode', render: (it) => esc(it.mode ?? '—') },
    { key: 'lastConclusion', label: 'Result', render: (it) => esc(it.lastConclusion ?? '—') },
  ],
  aiTools: [
    labelCol('Tool'),
    lastSeenCol,
    {
      key: 'lastVerifiedEndToEnd',
      label: 'Last verified e2e',
      render: (it) => (it.lastVerifiedEndToEnd
        ? esc(fmtTs(it.lastVerifiedEndToEnd))
        : '<span class="pill bad">never</span>'),
    },
    { key: 'hosts3d', label: 'Hosts 3d', num: true, render: (it) => fmtInt(it.hosts3d ?? 0) },
    { key: 'activeDays3d', label: 'Days 3d', num: true, render: (it) => fmtInt(it.activeDays3d ?? 0) },
    {
      key: 'alert',
      label: 'Alert',
      render: (it) => `${it.alert ? '<span class="pill bad">coverage alert</span>' : ''} ${esc(it.detail ?? '')}`.trim(),
    },
  ],
  default: [
    labelCol('Item'),
    lastSeenCol,
    { key: 'detail', label: 'Why dark', render: (it) => esc(it.detail ?? '') },
  ],
};

function darkTable(items, kind) {
  const cols = DARK_COLS[kind] ?? DARK_COLS.default;
  return `<div class="table-wrap" tabindex="0" role="region" aria-label="Dark items, scrollable"><table>${
    tableHtml(cols, items ?? [], {
      caption: `Items with no telemetry coverage${kind ? ` (${kind})` : ''}, with the reason each is dark`,
      empty: {
        reason: 'no-data',
        title: 'Nothing dark here',
        body: 'Every known item in this category is reporting telemetry.',
      },
    })
  }</table></div>`;
}

/** AIM-443: per-tool ledger with last-verified and sustained-coverage stats. */
const TOOL_LEDGER_COLS = [
  {
    key: 'tool',
    label: 'Tool',
    render: (it) => `<code>${esc(it.tool)}</code>${it.sanctioned ? ' <span class="pill muted">sanctioned</span>' : ''}`,
  },
  {
    key: 'covered',
    label: 'Status',
    render: (it) => (it.covered
      ? (it.sustained ? '<span class="pill ok">sustained</span>' : '<span class="pill warn">covered</span>')
      : (it.observed ? '<span class="pill bad">dark</span>' : '<span class="pill bad">never seen</span>')),
  },
  {
    key: 'lastVerifiedEndToEnd',
    label: 'Last verified e2e',
    render: (it) => (it.lastVerifiedEndToEnd
      ? esc(fmtTs(it.lastVerifiedEndToEnd))
      : '<span class="pill bad">never</span>'),
  },
  { key: 'events24h', label: 'Events 24h', num: true, render: (it) => fmtInt(it.events24h ?? 0) },
  { key: 'hosts24h', label: 'Hosts 24h', num: true, render: (it) => fmtInt(it.hosts24h ?? 0) },
  { key: 'hosts3d', label: 'Hosts 3d', num: true, render: (it) => fmtInt(it.hosts3d ?? 0) },
  { key: 'activeDays3d', label: 'Days 3d', num: true, render: (it) => fmtInt(it.activeDays3d ?? 0) },
  {
    key: 'coverageAlert',
    label: 'Alert',
    render: (it) => (it.coverageAlert
      ? `<span class="pill bad">${esc(it.coverageAlert.severity)}</span>`
      : '—'),
  },
];

function toolLedgerTable(items) {
  return `<div class="table-wrap" tabindex="0" role="region" aria-label="AI tool coverage ledger, scrollable"><table>${
    tableHtml(TOOL_LEDGER_COLS, items ?? [], {
      caption: 'AI tools with coverage status, last end-to-end verification, and host activity',
      empty: {
        reason: 'no-collector',
        title: 'No AI tools in the coverage ledger',
        body: 'Nothing is being scored for tool coverage yet.',
      },
    })
  }</table></div>`;
}

function conclusionPill(conclusion) {
  if (!conclusion) return '—';
  if (conclusion === 'success') return '<span class="pill ok">success</span>';
  if (conclusion === 'failure') return '<span class="pill bad">failure</span>';
  return `<span class="pill warn">${esc(conclusion)}</span>`;
}

/** AIM-332: full forge ledger — last gate run, mode, result, dark reason. */
const LEDGER_COLS = [
  { key: 'fullName', label: 'Repo', render: (r) => `<code>${esc(r.fullName || r.label || r.repoRef || '—')}</code>` },
  {
    key: 'covered',
    label: 'Status',
    render: (r) => (r.covered
      ? '<span class="pill ok">covered</span>'
      : darkReasonPill(r.darkReason) || '<span class="pill bad">dark</span>'),
  },
  {
    key: 'lastGateRunAt',
    label: 'Last gate run',
    render: (r) => (r.lastGateRunAt || r.lastEventAt
      ? esc(fmtTs(r.lastGateRunAt || r.lastEventAt))
      : '<span class="pill bad">never</span>')
      + (r.lastGateAgeSeconds != null ? ` <span class="hint">(${esc(fmtAge(r.lastGateAgeSeconds))})</span>` : ''),
  },
  { key: 'mode', label: 'Mode', render: (r) => esc(r.mode ?? '—') },
  { key: 'lastConclusion', label: 'Result', render: (r) => conclusionPill(r.lastConclusion) },
  { key: 'lastPr', label: 'PR', num: true, render: (r) => (r.lastPr != null ? esc(r.lastPr) : '—') },
  { key: 'detail', label: 'Detail', render: (r) => esc(r.detail ?? '') },
];

function repoLedgerTable(items) {
  const more = items.length > 100 ? `<p class="hint">Showing 100 of ${fmtInt(items.length)}.</p>` : '';
  return `<div class="table-wrap" tabindex="0" role="region" aria-label="Repo coverage ledger, scrollable"><table>${
    tableHtml(LEDGER_COLS, items.slice(0, 100), {
      caption: 'Forge repositories with gate coverage status, last gate run, mode and result',
      empty: {
        reason: 'no-collector',
        title: 'No repos from the forge ledger yet',
        body: 'Nobody has told us which repos exist, so coverage claims about repos are unproven.',
      },
    })
  }</table></div>${more}`;
}

function columnHtml(key, title, col) {
  const parts = [];
  parts.push(`<div class="cov-col-head"><h2>${esc(title)}</h2>${statePill(col)}</div>`);
  parts.push(freshnessHtml(col));

  if (col.state === 'not_wired') {
    parts.push(statRow(null, null, null));
    parts.push(`<div class="cov-notwired">Not wired: <code>${esc(col.notWired.endpoint)}</code> (${esc(col.notWired.awaiting)})<p>${esc(col.notWired.detail)}</p></div>`);
  } else if (col.state === 'error') {
    parts.push(statRow(null, null, null));
    parts.push(`<div class="cov-error">${esc(col.error)} — no numbers are shown because none were measured.</div>`);
  } else {
    parts.push(statRow(col.known, col.covered, col.dark));
    if (col.notWired) {
      parts.push(`<div class="cov-notwired">Not wired: <code>${esc(col.notWired.endpoint)}</code> (${esc(col.notWired.awaiting)})<p>${esc(col.notWired.detail)}</p></div>`);
    }
  }

  // Drill-through: dark items first; for repos also the full forge ledger
  // (AIM-332) so operators can see last gate run / mode / result per repo.
  if (col.darkItems && col.darkItems.length) {
    parts.push(`<button type="button" class="btn-control cov-toggle" data-col="${esc(key)}" data-kind="dark">Show ${esc(fmtInt(col.darkItems.length))} dark</button>`);
    parts.push(`<div class="cov-list" id="cov-list-${esc(key)}" hidden>${darkTable(col.darkItems, key)}</div>`);
  } else if (col.dark === 0 && col.state === 'ok') {
    parts.push('<div class="cov-fresh fresh">Nothing dark — everything known is covered.</div>');
  }
  if (key === 'repos' && col.items && col.items.length) {
    parts.push(`<button type="button" class="btn-control cov-toggle" data-col="${esc(key)}-ledger" data-kind="ledger">Show ${esc(fmtInt(col.items.length))} repo ledger</button>`);
    parts.push(`<div class="cov-list" id="cov-list-${esc(key)}-ledger" hidden>${repoLedgerTable(col.items)}</div>`);
  }
  if (key === 'aiTools' && col.items && col.items.length) {
    parts.push(`<button type="button" class="btn-control cov-toggle" data-col="${esc(key)}-ledger" data-kind="ledger">Show ${esc(fmtInt(col.items.length))} tool ledger</button>`);
    parts.push(`<div class="cov-list" id="cov-list-${esc(key)}-ledger" hidden>${toolLedgerTable(col.items)}</div>`);
  }

  if (col.note) parts.push(`<p class="hint">${esc(col.note)}</p>`);
  return `<div class="panel cov-col" data-col="${esc(key)}">${parts.join('')}</div>`;

  function statRow(known, covered, dark) {
    return `<div class="cov-stats">` +
      statHtml('Known', known, null, 'not measured') +
      statHtml('Covered', covered, null, 'unknown') +
      statHtml('Dark', dark, dark > 0 ? 'bad' : 'good', 'unknown') +
      `</div>`;
  }
}

async function init() {
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/coverage.css';
  document.head.appendChild(link);

  // Nav tab: this screen is the product's front door — it goes first, right
  // after Overview.
  moduleTab({
    view: 'coverage',
    label: 'Coverage',
    icon: '<svg class="ico" viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.5" fill="none" stroke="currentColor" stroke-width="1.3"/><circle cx="8" cy="8" r="1.6" fill="currentColor"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2" stroke="currentColor" stroke-width="1.3"/></svg>',
  });

  const section = moduleSection({ view: 'coverage', html: `
    <div class="banner info">Known vs covered vs dark, per surface — the answer to <b>"what are we NOT seeing?"</b> A count that is unknown shows <b>—</b> and says why; it never shows an invented zero. Metadata only: identifiers, counts and timestamps, never content. <b>Read-only.</b></div>
    <div id="cov-stale"></div>
    <div class="cov-grid" id="cov-grid"></div>
    <div class="cov-foot" id="cov-foot"></div>` });
  document.querySelector('main').appendChild(section);

  const grid = section.querySelector('#cov-grid');

  registerModuleView('coverage', {
    onActivate: () =>
      load().catch((err) => {
        grid.innerHTML = `<div class="err">${esc(err.message)}</div>`;
      }),
  });

  section.addEventListener('click', (e) => {
    const toggle = e.target.closest('.cov-toggle');
    if (!toggle) return;
    const list = section.querySelector(`#cov-list-${toggle.dataset.col}`);
    if (!list) return;
    list.hidden = !list.hidden;
    toggle.textContent = list.hidden
      ? toggle.textContent.replace(/^Hide/, 'Show')
      : toggle.textContent.replace(/^Show/, 'Hide');
  });

  async function load() {
    const d = await api('/api/coverage');
    const cols = d.columns;

    grid.innerHTML = COLUMNS.map(({ key, title }) => columnHtml(key, title, cols[key])).join('');

    // Staleness + AIM-443/596 sanctioned-tool coverage alerts (fireable only).
    const staleCols = COLUMNS.filter(({ key }) => cols[key].freshness?.stale && cols[key].state !== 'not_wired');
    const alerts = d.coverageAlerts || cols.aiTools?.alerts || [];
    const precision = d.coverageAlertPrecision || cols.aiTools?.alertPrecision || null;
    const banners = [];
    if (alerts.length) {
      banners.push(
        `<div class="banner warn" role="alert"><b>Sanctioned-tool coverage alert.</b> ` +
        `${alerts.map((a) => `<code>${esc(a.tool)}</code>: ${esc(a.message)}`).join(' · ')} ` +
        `Last verified e2e (response): ${esc(fmtTs(d.lastVerifiedEndToEnd))}. ` +
        `Absence of telemetry is not "no usage".</div>`
      );
    } else if (precision && precision.suppressed > 0) {
      // AIM-596: dark tools still on the ledger; suppressions are intentional, not silent.
      banners.push(
        `<div class="banner info"><b>Coverage alert precision.</b> ` +
        `${esc(fmtInt(precision.suppressed))} dark sanctioned-tool candidate(s) held under pilot gates ` +
        `(silence ≥${esc(String((precision.silenceThresholdSeconds || 0) / 3600))}h; ` +
        `never-seen needs ≥${esc(fmtInt(precision.neverSeenMinHealthyHosts))} healthy hosts; ` +
        `fleet healthy ${esc(fmtInt(precision.healthyHosts))}/${esc(fmtInt(precision.enrolledHosts))} enrolled). ` +
        `Dark ledger is unchanged — silence is still not "no usage".</div>`
      );
    }
    if (staleCols.length) {
      banners.push(
        `<div class="banner warn"><b>Stale data on this screen.</b> ${staleCols
          .map(({ key, title }) => `${esc(title)}: last event ${esc(fmtAge(cols[key].freshness.ageSeconds))}`)
          .join(' · ')}. Numbers below are history, not the current state — treat every "covered" count accordingly.</div>`
      );
    }
    section.querySelector('#cov-stale').innerHTML = banners.join('');

    // Only state what the payload actually carries (AIM-525). Include AIM-443
    // lastVerifiedEndToEnd + sustained window when present.
    const hours = (s) => (Number.isFinite(Number(s)) ? `${Number(s) / 3600}h` : null);
    section.querySelector('#cov-foot').textContent = [
      `Generated ${fmtTs(d.generatedAt)}`,
      d.lastVerifiedEndToEnd != null && `last verified e2e ${fmtTs(d.lastVerifiedEndToEnd)}`,
      hours(d.coverageWindowSeconds) && `coverage window ${hours(d.coverageWindowSeconds)}`,
      hours(d.sustainedWindowSeconds) && `sustained window ${hours(d.sustainedWindowSeconds)}`,
      hours(d.staleThresholdSeconds) && `stale threshold ${hours(d.staleThresholdSeconds)}`,
      d.note || null,
    ].filter(Boolean).join(' · ');
  }

  load().catch(() => {}); // pre-warm so first tab open is instant
}

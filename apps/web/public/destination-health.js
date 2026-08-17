/* — Destination health: failed delivery SLO for webhook/email/Slack.
 *
 * Self-contained module view (install-health pattern). Activates for
 * roles with capabilities.findingsConsole (analyst+), matching
 * GET /api/destination-health.
 */

import { registerModuleView } from './lib/router.js';
import { esc } from './lib/dom.js';
import { moduleTab, moduleSection } from './lib/a11y.js';
import { table as dataTable } from './lib/components.js';
import { fmtInt } from './lib/format.js';
import { api } from './lib/api.js';

const POLL_MS = 30_000;

const STATE_LABEL = {
  ok: 'ok',
  degraded: 'degraded',
  broken: 'broken',
  never_configured: 'never configured',
};

const ALERT_COLS = [
  { key: 'tileId', label: 'Tile', render: (a) => `<span class="mono">${esc(a.tileId || a.labels?.tile || '—')}</span>` },
  {
    key: 'severity',
    label: 'Severity',
    render: (a) => {
      const sev = a.severity || 'medium';
      const cls = sev === 'high' || sev === 'critical' ? 'bad' : 'warn';
      return `<span class="pill ${cls}">${esc(sev)}</span>`;
    },
  },
  {
    key: 'findingType',
    label: 'Finding type',
    render: (a) => `<span class="mono">${esc(a.findingType || a.finding_type || '—')}</span>`,
  },
  { key: 'title', label: 'Title', render: (a) => esc(a.title) },
];

const DEST_COLS = [
  {
    key: 'destination',
    label: 'Destination',
    render: (d) => {
      const name = d.destination || '—';
      const badge = d.primary ? ' <span class="dh-primary">primary</span>' : '';
      return `<b class="mono">${esc(name)}</b>${badge}`;
    },
  },
  {
    key: 'state',
    label: 'SLO',
    render: (d) => {
      const cls = d.state === 'broken' ? 'bad'
        : d.state === 'degraded' ? 'warn'
        : d.state === 'never_configured' ? 'muted'
        : 'ok';
      return `<span class="pill ${cls}"><span class="sr-only">State: </span>${esc(STATE_LABEL[d.state] || d.state)}</span>`;
    },
  },
  {
    key: 'successRatePct',
    label: 'Success',
    render: (d) => {
      if (d.successRatePct == null) return '<span class="muted">—</span>';
      return `<span class="mono">${esc(String(d.successRatePct))}%</span>`;
    },
  },
  {
    key: 'delivered',
    label: 'Delivered',
    render: (d) => `<span class="mono">${esc(fmtInt(d.delivered ?? 0))}</span>`,
  },
  {
    key: 'failed',
    label: 'Failed',
    render: (d) => {
      const n = d.failed ?? 0;
      if (n > 0) return `<span class="mono bad">${esc(fmtInt(n))}</span>`;
      return `<span class="mono">${esc(fmtInt(n))}</span>`;
    },
  },
  {
    key: 'lastError',
    label: 'Last error',
    render: (d) => {
      if (!d.lastError) return '<span class="muted">—</span>';
      return `<span class="mono dh-err-snip" title="${esc(d.lastError)}">${esc(truncate(d.lastError, 80))}</span>`;
    },
  },
];

function truncate(s, n) {
  const t = String(s);
  return t.length <= n ? t : `${t.slice(0, n - 1)}…`;
}

const me = await api('/api/me').catch((err) => {
  if (err.status === 401) window.location.assign('/auth/login');
  return null;
});

if (me?.capabilities?.findingsConsole) {
  init().catch((err) => console.error('destination health failed to start:', err));
}

async function init() {
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/destination-health.css';
  document.head.appendChild(link);

  moduleTab({
    view: 'destination-health',
    label: 'Destinations',
    icon: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
  });

  const main = document.querySelector('#main');
  const section = moduleSection({ view: 'destination-health', html: `
    <div class="dh-head">
      <div>
        <h2 class="dh-title">Destination health</h2>
        <p class="dh-sub">Failed delivery SLO for webhook, email, Slack, and other alert sinks. Green means the success rate is inside the window. Failures always surface — they are never silent.</p>
      </div>
      <div class="dh-overall" id="dh-overall" hidden></div>
    </div>
    <div class="dh-legend" aria-hidden="true">
      <span><i class="dh-dot ok"></i> ok — inside SLO, no failures</span>
      <span><i class="dh-dot degraded"></i> degraded — failures or rate under SLO</span>
      <span><i class="dh-dot broken"></i> broken — hard fail count or severe rate collapse</span>
      <span><i class="dh-dot never_configured"></i> never configured — no deliveries in window</span>
    </div>
    <div class="dh-grid" id="dh-grid" role="list"></div>
    <div class="panel">
      <h2>Destinations <span class="hint" id="dh-window-hint">delivery success rate</span></h2>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Destination delivery table, scrollable">
        <table id="dh-destinations"></table>
      </div>
    </div>
    <div class="panel dh-alerts-panel">
      <h2>Failed delivery alerts <span class="hint">candidates that would page — same shape as System status</span></h2>
      <div id="dh-alerts"></div>
    </div>
    <p class="dh-meta" id="dh-meta"></p>
    <div class="dh-err" id="dh-err" hidden role="alert"></div>
  ` });
  main.appendChild(section);

  let pollTimer = null;

  async function load() {
    const errEl = section.querySelector('#dh-err');
    errEl.hidden = true;
    errEl.textContent = '';
    try {
      const data = await api('/api/destination-health');
      render(data);
    } catch (err) {
      errEl.hidden = false;
      errEl.textContent = `Could not load destination health: ${err.message || err}`;
      if (!section.querySelector('#dh-overall')?.textContent) {
        section.querySelector('#dh-grid').innerHTML = '';
        section.querySelector('#dh-destinations').innerHTML = '';
        section.querySelector('#dh-alerts').innerHTML = '';
      }
    }
  }

  function render(data) {
    const overall = section.querySelector('#dh-overall');
    overall.hidden = false;
    overall.dataset.state = data.overall;
    const rate = data.summary?.successRatePct;
    overall.innerHTML =
      `<span class="dh-dot ${esc(data.overall)}"></span>` +
      `<span class="dh-overall-label">${esc(STATE_LABEL[data.overall] || data.overall)}</span>` +
      `<span class="dh-overall-count mono">${
        rate != null
          ? esc(`${rate}% success`)
          : esc(`${fmtInt(data.summary?.failed ?? 0)} failed`)
      }</span>`;

    const grid = section.querySelector('#dh-grid');
    grid.innerHTML = (data.tiles || []).map((t) => tileHtml(t)).join('');

    const hours = data.slo?.windowHours ?? data.summary?.windowHours ?? 24;
    const sloText = data.slo?.text || 'delivery success rate';
    section.querySelector('#dh-window-hint').textContent =
      `${sloText.split('(')[0].trim()} · last ${hours}h`;

    dataTable(section.querySelector('#dh-destinations'), DEST_COLS, data.destinations ?? [], {
      caption: 'Alert destination delivery outcomes',
      empty: {
        reason: 'no-data',
        title: 'No destinations',
        body: 'Configure webhook, email, or Slack under Rules → Alert destinations. Deliveries appear after the guardrail poller forwards a finding.',
      },
    });

    const alerts = section.querySelector('#dh-alerts');
    alerts.innerHTML = '<table class="dh-alert-table"></table>';
    dataTable(alerts.querySelector('table'), ALERT_COLS, data.alertCandidates ?? [], {
      caption: 'Destination delivery SLO breach alert candidates',
      empty: {
        reason: 'no-data',
        title: 'No failed-delivery alerts',
        body: 'Every measured destination is inside the SLO, or no destinations have delivered yet.',
      },
    });

    const verified = data.lastVerifiedAt || data.generatedAt;
    const bits = [
      verified ? `last verified ${new Date(verified).toLocaleString()}` : null,
      data.summary?.delivered != null ? `${fmtInt(data.summary.delivered)} delivered` : null,
      data.summary?.failed != null ? `${fmtInt(data.summary.failed)} failed` : null,
      data.summary?.measured != null ? `${fmtInt(data.summary.measured)} measured` : null,
    ].filter(Boolean);
    section.querySelector('#dh-meta').textContent = bits.join(' · ');
  }

  function tileHtml(t) {
    const valueBits = tileValues(t);
    return `
      <article class="dh-tile state-${esc(t.state)}" role="listitem" data-state="${esc(t.state)}" data-id="${esc(t.id)}">
        <header class="dh-tile-head">
          <span class="dh-tile-state">
            <i class="dh-dot ${esc(t.state)}"></i>
            ${esc(STATE_LABEL[t.state] || t.state)}
          </span>
          <span class="dh-tile-pillar mono">${esc(t.pillar || 'aim')}</span>
        </header>
        <h3 class="dh-tile-title">${esc(t.title)}</h3>
        <p class="dh-tile-msg">${esc(t.message)}</p>
        <dl class="dh-tile-meta">
          <div><dt>SLO</dt><dd>${esc(t.slo?.text || '—')}</dd></div>
          <div><dt>Breach</dt><dd class="mono">${t.breach ? 'yes' : 'no'}</dd></div>
          ${valueBits}
        </dl>
      </article>`;
  }

  function tileValues(t) {
    const v = t.value;
    if (!v || typeof v !== 'object') return '';
    const rows = [];
    if (v.successRatePct != null) rows.push(['Success', `${v.successRatePct}%`]);
    if (v.delivered != null) rows.push(['Delivered', fmtInt(v.delivered)]);
    if (v.failed != null) rows.push(['Failed', fmtInt(v.failed)]);
    if (v.total != null && v.delivered == null) rows.push(['Total', fmtInt(v.total)]);
    if (v.measured != null) rows.push(['Measured', fmtInt(v.measured)]);
    if (v.broken != null) rows.push(['Broken', fmtInt(v.broken)]);
    return rows.map(([k, val]) =>
      `<div><dt>${esc(k)}</dt><dd class="mono">${esc(String(val))}</dd></div>`).join('');
  }

  registerModuleView('destination-health', {
    onActivate: async () => {
      await load();
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = setInterval(() => {
        if (document.visibilityState === 'visible' &&
            document.querySelector('#view-destination-health')?.classList.contains('active')) {
          load().catch(() => {});
        }
      }, POLL_MS);
    },
  });
}

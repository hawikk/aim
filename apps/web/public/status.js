/* — one screen: "is it working and is it covering everything?"
 *
 * Self-contained module view (findings/inbox pattern). Activates for any
 * role that can see pipeline liveness (capabilities.userLevel — auditor+
 * in practice; the API enforces admin|analyst|auditor|viewer).
 *
 * Every tile comes from GET /api/system/status with an explicit SLO and a
 * state in {ok, degraded, broken, never_configured}. Green only means ok.
 */

import { registerModuleView } from './lib/router.js';
import { esc } from './lib/dom.js';
import { severityBadge } from './lib/severity.js';
import { moduleTab, moduleSection } from './lib/a11y.js';
import { table as dataTable } from './lib/components.js';
import { api } from './lib/api.js';

const ALERT_COLS = [
  { key: 'tileId', label: 'Tile', render: (a) => `<span class="mono">${esc(a.tileId)}</span>` },
  {
    key: 'severity',
    label: 'Severity',
    render: (a) => severityBadge(a.severity),
  },
  { key: 'findingType', label: 'Finding type', render: (a) => `<span class="mono">${esc(a.findingType)}</span>` },
  { key: 'title', label: 'Title', render: (a) => esc(a.title) },
];

const POLL_MS = 30_000;

const STATE_LABEL = {
  ok: 'ok',
  degraded: 'degraded',
  broken: 'broken',
  never_configured: 'never configured',
};

const me = await api('/api/me').catch((err) => {
  if (err.status === 401) window.location.assign('/auth/login');
  return null;
});

// Same population as GET /api/system/status (admin|analyst|auditor|viewer).
// dashboard capability is true for exactly those roles; employees stay out.
if (me?.capabilities?.dashboard) {
  init().catch((err) => console.error('system status failed to start:', err));
}

async function init() {
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/status.css';
  document.head.appendChild(link);

  moduleTab({
    view: 'status',
    label: 'Status',
    icon: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
  });

  const main = document.querySelector('#main');
  const section = moduleSection({ view: 'status', html: `
    <div class="status-head">
      <div>
        <h2 class="status-title">System status</h2>
        <p class="status-sub">Is it working, and is it covering everything? Every tile has an SLO. Green only means the SLO is met.</p>
      </div>
      <div class="status-overall" id="status-overall" hidden></div>
    </div>
    <div class="status-legend" aria-hidden="true">
      <span><i class="st-dot ok"></i> ok — SLO met</span>
      <span><i class="st-dot degraded"></i> degraded — works, outside SLO</span>
      <span><i class="st-dot broken"></i> broken — hard failure</span>
      <span><i class="st-dot never_configured"></i> never configured — not set up</span>
    </div>
    <div class="status-grid" id="status-grid" role="list"></div>
    <div class="panel status-alerts-panel">
      <h2>Alert candidates <span class="hint">same signals Sentinel would page — not a parallel mechanism</span></h2>
      <div id="status-alerts" class="status-alerts"></div>
    </div>
    <p class="status-meta" id="status-meta"></p>
  ` });
  main.appendChild(section);

  let pollTimer = null;

  async function load() {
    const data = await api('/api/system/status');
    render(data);
  }

  function render(data) {
    const overall = section.querySelector('#status-overall');
    overall.hidden = false;
    overall.dataset.state = data.overall;
    overall.innerHTML = `<span class="st-dot ${esc(data.overall)}"></span>` +
      `<span class="status-overall-label">${esc(STATE_LABEL[data.overall] || data.overall)}</span>` +
      `<span class="status-overall-count mono">${esc(data.tiles.length)} tiles</span>`;

    const grid = section.querySelector('#status-grid');
    grid.innerHTML = data.tiles.map((t) => tileHtml(t)).join('');

    const alerts = section.querySelector('#status-alerts');
    if (!data.alertCandidates?.length) {
      alerts.innerHTML = '<div class="status-alerts-empty">No breach alerts — nothing on this screen would page Sentinel right now.</div>';
    } else {
      alerts.innerHTML = `<table class="status-alert-table">
        <thead><tr><th>Tile</th><th>Severity</th><th>Finding type</th><th>Title</th></tr></thead>
        <tbody>${data.alertCandidates.map((a) => `
          <tr>
            <td class="mono">${esc(a.tileId)}</td>
            <td>${severityBadge(a.severity)}</td>
            <td class="mono">${esc(a.findingType)}</td>
            <td>${esc(a.title)}</td>
          </tr>`).join('')}
        </tbody></table>`;
    }
    alerts.innerHTML = '<table class="status-alert-table"></table>';
    dataTable(alerts.querySelector('table'), ALERT_COLS, data.alertCandidates ?? [], {
      caption: 'Status alert candidates with severity and finding type',
      empty: {
        reason: 'no-data',
        title: 'No breach alerts',
        body: 'Nothing on this screen would page Sentinel right now.',
      },
    });

    const verified = data.lastVerifiedAt || data.generatedAt;
    section.querySelector('#status-meta').textContent =
      `last verified ${new Date(verified).toLocaleString()} · gateway ${data.gatewayHost || '—'}`;
  }

  function tileHtml(t) {
    const valueBits = valueSummary(t);
    return `
      <article class="status-tile state-${esc(t.state)}" role="listitem" data-state="${esc(t.state)}" data-id="${esc(t.id)}">
        <header class="status-tile-head">
          <span class="status-tile-state">
            <i class="st-dot ${esc(t.state)}"></i>
            ${esc(STATE_LABEL[t.state] || t.state)}
          </span>
          <span class="status-tile-pillar mono">${esc(t.pillar)}</span>
        </header>
        <h3 class="status-tile-title">${esc(t.title)}</h3>
        <p class="status-tile-msg">${esc(t.message)}</p>
        <dl class="status-tile-meta">
          <div><dt>SLO</dt><dd>${esc(t.slo?.text || '—')}</dd></div>
          <div><dt>Breach</dt><dd class="mono">${t.breach ? 'yes' : 'no'}</dd></div>
          ${valueBits}
        </dl>
      </article>`;
  }

  function valueSummary(t) {
    const v = t.value;
    if (!v || typeof v !== 'object') return '';
    const rows = [];
    if (v.idleSeconds != null) rows.push(['Idle', `${v.idleSeconds}s`]);
    if (v.eventsLastHour != null) rows.push(['Events/h', String(v.eventsLastHour)]);
    if (v.total != null && t.id === 'dlq_depth') rows.push(['DLQ', String(v.total)]);
    if (v.enrolled != null) rows.push(['Enrolled', String(v.enrolled)]);
    if (v.healthy != null) rows.push(['Healthy', String(v.healthy)]);
    if (v.silent != null) rows.push(['Silent', String(v.silent)]);
    if (v.unattributedPct != null) rows.push(['Unattributed', `${v.unattributedPct}%`]);
    if (v.lastVerifiedAt) rows.push(['Last verified', new Date(v.lastVerifiedAt).toLocaleTimeString('en-US', { hour12: false })]);
    if (v.dark != null) rows.push(['Dark accounts', String(v.dark)]);
    if (v.known != null) rows.push(['Known', String(v.known)]);
    if (v.scanned != null) rows.push(['Scanned', String(v.scanned)]);
    if (v.latencyMs != null) rows.push(['Latency', `${v.latencyMs}ms`]);
    if (v.probe?.latencyMs != null) rows.push(['Latency', `${v.probe.latencyMs}ms`]);
    if (v.rulesLoaded != null) rows.push(['Rules', String(v.rulesLoaded)]);
    if (Array.isArray(v.channels)) rows.push(['Channels', v.channels.join(', ') || '(none)']);
    if (Array.isArray(v.scanFreshness) && v.scanFreshness.length) {
      rows.push(['Providers', v.scanFreshness.map((p) => p.provider).join(', ')]);
    }
    return rows.map(([k, val]) =>
      `<div><dt>${esc(k)}</dt><dd class="mono">${esc(val)}</dd></div>`).join('');
  }

  registerModuleView('status', {
    onActivate: async () => {
      await load();
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = setInterval(() => {
        if (document.visibilityState === 'visible' &&
            document.querySelector('#view-status')?.classList.contains('active')) {
          load().catch(() => {});
        }
      }, POLL_MS);
    },
  });
}

/* — Install health: enroll → first evidence SLO.
 *
 * Self-contained module view (status/onboarding pattern). Activates for
 * roles with capabilities.fleet (analyst+), matching GET /api/install-health.
 *
 * Answers for Ops:
 *   - How long from enroll to first server evidence (heartbeat) per device?
 *   - How long from first enroll to first usage event on the fleet?
 *   - Which OS cohorts (Windows / Linux / macOS) meet or miss the SLO?
 *   - Which enrollments are past the SLO with nothing back (breach alerts)?
 * - What is the Intune / Jamf / Linux zero-touch admin path?
 *   - What to do on delayed first evidence or missing collector?
 *
 * Metadata-only: hostnames, OS, latency, SLO state — never tokens/prompts.
 */

import { registerModuleView } from './lib/router.js';
import { esc } from './lib/dom.js';
import { moduleTab, moduleSection } from './lib/a11y.js';
import { table as dataTable } from './lib/components.js';
import { fmtInt, relTime } from './lib/format.js';
import {
  osFamily,
  OS_FAMILY_LABEL,
  sloTone,
  latencyTone,
  cohortByOs,
  devicesEmptySpec,
  alertsEmptySpec,
  recoveryCopy,
  formatDur,
} from './lib/install-health-ui.js';
import {
  listMdmAdminPaths,
  PRIVACY_FOOTER,
  MDM_DOCS,
} from './lib/mdm-enroll-runbook.js';
import { api } from './lib/api.js';

const POLL_MS = 30_000;

const STATE_LABEL = {
  ok: 'ok',
  degraded: 'degraded',
  broken: 'broken',
  never_configured: 'never configured',
  met: 'met',
  pending: 'pending',
  breached: 'breached',
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

function osBadge(os) {
  const family = osFamily(os);
  const label = OS_FAMILY_LABEL[family] || family;
  const raw = os ? String(os) : label;
  return `<span class="ih-os ih-os-${esc(family)}" title="${esc(raw)}">${esc(label)}</span>`;
}

function sloPill(state) {
  const tone = sloTone(state);
  const label = STATE_LABEL[state] || state || '—';
  return `<span class="pill ${esc(tone)}" data-slo-state="${esc(state || '')}"><span class="sr-only">SLO state: </span>${esc(label)}</span>`;
}

const DEVICE_COLS = [
  {
    key: 'hostname',
    label: 'Device',
    render: (d) => {
      const name = d.hostname || d.device_id || '—';
      const sub = [d.ring].filter(Boolean).join(' · ');
      return `<b>${esc(name)}</b>${sub ? `<div class="ih-sub mono">${esc(sub)}</div>` : ''}`;
    },
  },
  {
    key: 'os',
    label: 'OS',
    render: (d) => osBadge(d.os),
  },
  {
    key: 'state',
    label: 'SLO',
    render: (d) => sloPill(d.state),
  },
  {
    key: 'enrolled_at',
    label: 'Enrolled',
    render: (d) => esc(relTime(d.enrolled_at)),
  },
  {
    key: 'first_evidence_at',
    label: 'First evidence',
    render: (d) => {
      if (!d.first_evidence_at) {
        return d.state === 'pending'
          ? '<span class="muted">waiting…</span>'
          : '<span class="muted">none</span>';
      }
      const kind = d.evidence_kind ? ` <span class="ih-sub">(${esc(d.evidence_kind)})</span>` : '';
      return `${esc(relTime(d.first_evidence_at))}${kind}`;
    },
  },
  {
    key: 'latency_seconds',
    label: 'Latency',
    render: (d) => {
      const sloSec = d._sloSec;
      if (d.latency_seconds == null) {
        if (d.age_seconds != null && d.state !== 'met') {
          const tone = latencyTone(null, sloSec, d.state);
          return `<span class="mono tone-${esc(tone)}">${esc(formatDur(d.age_seconds))} waiting</span>`;
        }
        return '<span class="muted">—</span>';
      }
      const tone = latencyTone(d.latency_seconds, sloSec, d.state);
      return `<span class="mono tone-${esc(tone)}">${esc(formatDur(d.latency_seconds))}</span>`;
    },
  },
];

const me = await api('/api/me').catch((err) => {
  if (err.status === 401) window.location.assign('/auth/login');
  return null;
});

// Same population as GET /api/install-health (analyst|admin → capabilities.fleet).
if (me?.capabilities?.fleet) {
  init().catch((err) => console.error('install health failed to start:', err));
}

async function init() {
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/install-health.css';
  document.head.appendChild(link);

  moduleTab({
    view: 'install-health',
    label: 'Install health',
    icon: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>',
  });

  const main = document.querySelector('#main');
  const section = moduleSection({ view: 'install-health', html: `
    <div class="ih-head">
      <div>
        <h2 class="ih-title">Install health</h2>
        <p class="ih-sub">Enroll → first evidence latency. Green only means the SLO is met. Per-device evidence is the first heartbeat; fleet first usage event is measured separately. Windows and Linux share the same target — cohorts below show parity.</p>
      </div>
      <div class="ih-overall" id="ih-overall" hidden></div>
    </div>
    <div class="ih-legend" aria-label="SLO colour legend">
      <span><i class="ih-dot ok"></i> green / met — inside SLO</span>
      <span><i class="ih-dot degraded"></i> amber / pending — delayed, still inside window</span>
      <span><i class="ih-dot broken"></i> red / breached — past SLO, no evidence</span>
      <span><i class="ih-dot never_configured"></i> never configured — no enrollments</span>
    </div>
    <div class="ih-grid" id="ih-grid" role="list"></div>
    <div class="panel ih-cohort-panel">
      <h2>OS cohorts <span class="hint">Windows · Linux · macOS time-to-first-evidence</span></h2>
      <p class="ih-cohort-intro muted">Same enroll → first-evidence SLO for every OS. Use this when Intune (Windows) and script/Jamf (Linux/macOS) waves should track together.</p>
      <div class="ih-cohorts" id="ih-cohorts" role="list"></div>
    </div>
    <div class="panel ih-recovery-panel" id="ih-recovery" hidden></div>
    <div class="panel">
      <h2>Recent enrollments <span class="hint" id="ih-lookback-hint">enroll → first heartbeat</span></h2>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Recent enrollments table, scrollable">
        <table id="ih-devices"></table>
      </div>
    </div>
    <div class="panel ih-alerts-panel">
      <h2>SLO breach alerts <span class="hint">candidates that would page — same shape as System status</span></h2>
      <div id="ih-alerts"></div>
    </div>
    <div class="panel ih-runbook-panel" id="ih-runbook">
      <h2>Zero-touch / MDM admin path <span class="hint">Intune · Jamf · Linux parity — metadata only</span></h2>
      <p class="ih-runbook-lead">MDM “Installed” is not AIM enroll. Use the paths below for fleet zero-touch; use <a href="#/onboarding" data-view="onboarding">Onboarding</a> to mint a ring token and for engineer self-enroll (Windows and Linux tabs are equal). Full write-up: <code class="mono">${esc(MDM_DOCS.zeroTouch)}</code></p>
      <div class="ih-runbook-grid" id="ih-runbook-grid" role="list"></div>
      <p class="ih-privacy" id="ih-privacy">${esc(PRIVACY_FOOTER)}</p>
    </div>
    <p class="ih-meta" id="ih-meta"></p>
    <div class="ih-err" id="ih-err" hidden role="alert"></div>
  ` });
  main.appendChild(section);

  // Static runbook cards — no secrets, no live data required.
  section.querySelector('#ih-runbook-grid').innerHTML = listMdmAdminPaths()
    .map((path) => mdmPathHtml(path))
    .join('');

  let pollTimer = null;

  async function load() {
    const errEl = section.querySelector('#ih-err');
    errEl.hidden = true;
    errEl.textContent = '';
    try {
      const data = await api('/api/install-health');
      render(data);
    } catch (err) {
      errEl.hidden = false;
      errEl.textContent = `Could not load install health: ${err.message || err}`;
      // Keep last good paint if any; surface the error so this is never silent.
      if (!section.querySelector('#ih-overall')?.textContent) {
        section.querySelector('#ih-grid').innerHTML = '';
        section.querySelector('#ih-cohorts').innerHTML = '';
        section.querySelector('#ih-devices').innerHTML = '';
        section.querySelector('#ih-alerts').innerHTML = '';
        const recovery = section.querySelector('#ih-recovery');
        recovery.hidden = true;
        recovery.innerHTML = '';
      }
    }
  }

  function render(data) {
    const sloSec = data.slo?.targetSeconds ?? 300;
    const overall = section.querySelector('#ih-overall');
    overall.hidden = false;
    overall.dataset.state = data.overall;
    overall.innerHTML =
      `<span class="ih-dot ${esc(data.overall)}"></span>` +
      `<span class="ih-overall-label">${esc(STATE_LABEL[data.overall] || data.overall)}</span>` +
      `<span class="ih-overall-count mono">${esc(fmtInt(data.summary?.enrolled ?? 0))} enrolled</span>`;

    const grid = section.querySelector('#ih-grid');
    grid.innerHTML = (data.tiles || []).map((t) => tileHtml(t)).join('');

    renderCohorts(data, sloSec);
    renderRecovery(data);

    const lookback = data.summary?.lookbackDays ?? 7;
    const sloText = data.slo?.text || 'enroll → first evidence';
    section.querySelector('#ih-lookback-hint').textContent =
      `${sloText} · last ${lookback} day${lookback === 1 ? '' : 's'}`;

    // Stamp sloSec on rows so latency cells can RAG without a global.
    const devices = (data.devices ?? []).map((d) => ({ ...d, _sloSec: sloSec }));

    dataTable(section.querySelector('#ih-devices'), DEVICE_COLS, devices, {
      caption: 'Recent enrollments with enroll-to-first-evidence latency',
      empty: devicesEmptySpec(data.summary || {}),
    });

    const alerts = section.querySelector('#ih-alerts');
    alerts.innerHTML = '<table class="ih-alert-table"></table>';
    dataTable(alerts.querySelector('table'), ALERT_COLS, data.alertCandidates ?? [], {
      caption: 'Install-health SLO breach alert candidates',
      empty: alertsEmptySpec({ enrolled: data.summary?.enrolled ?? 0 }),
    });

    const verified = data.lastVerifiedAt || data.generatedAt;
    const p50 = data.summary?.p50Seconds;
    const p95 = data.summary?.p95Seconds;
    const fleetLat = data.summary?.fleetFirstEvent?.latency_seconds;
    const bits = [
      verified ? `last verified ${new Date(verified).toLocaleString()}` : null,
      p50 != null ? `p50 ${formatDur(p50)}` : null,
      p95 != null ? `p95 ${formatDur(p95)}` : null,
      fleetLat != null ? `fleet first event ${formatDur(Math.abs(fleetLat))}${fleetLat < 0 ? ' (events before enroll)' : ''}` : null,
    ].filter(Boolean);
    section.querySelector('#ih-meta').textContent = bits.join(' · ');
  }

  function renderCohorts(data, sloSec) {
    const el = section.querySelector('#ih-cohorts');
    // Prefer lookback devices for "recent wave" parity; fall back to allDevices.
    const source = (data.devices?.length ? data.devices : data.allDevices) || [];
    const cohorts = cohortByOs(source, sloSec);

    if (!cohorts.length) {
      el.innerHTML = `
        <div class="ih-cohort-empty empty-state empty-no-collector" role="status">
          <div class="empty-title">No OS cohorts yet</div>
          <div class="empty-body">Cohorts appear after the first device enrolls. Windows (Intune), Linux, and macOS share the same first-evidence SLO.</div>
          <div class="empty-cta"><a class="empty-link" href="#/onboarding">Open Onboarding</a></div>
        </div>`;
      return;
    }

    el.innerHTML = cohorts.map((c) => {
      const lat = c.p95Seconds != null
        ? `p95 ${formatDur(c.p95Seconds)}`
        : c.p50Seconds != null
          ? `p50 ${formatDur(c.p50Seconds)}`
          : c.pending
            ? 'waiting for first evidence'
            : c.breached
              ? 'no evidence past SLO'
              : '—';
      return `
        <article class="ih-cohort state-${esc(c.state)}" role="listitem" data-os-family="${esc(c.family)}" data-slo-state="${esc(c.state)}">
          <header class="ih-cohort-head">
            <span class="ih-os ih-os-${esc(c.family)}">${esc(c.label)}</span>
            ${sloPill(c.state)}
          </header>
          <div class="ih-cohort-stats mono">
            <span title="Enrolled">${esc(fmtInt(c.enrolled))} enrolled</span>
            <span class="tone-ok" title="Met">${esc(fmtInt(c.met))} met</span>
            <span class="tone-warn" title="Pending">${esc(fmtInt(c.pending))} pending</span>
            <span class="tone-bad" title="Breached">${esc(fmtInt(c.breached))} breached</span>
          </div>
          <div class="ih-cohort-lat mono tone-${esc(c.latencyTone)}">${esc(lat)}</div>
        </article>`;
    }).join('');
  }

  function renderRecovery(data) {
    const el = section.querySelector('#ih-recovery');
    const copy = recoveryCopy(data);
    if (!copy) {
      el.hidden = true;
      el.innerHTML = '';
      return;
    }
    el.hidden = false;
    el.dataset.tone = copy.tone;
    el.innerHTML = `
      <h2 class="ih-recovery-title">${esc(copy.title)}</h2>
      <p class="ih-recovery-body">${esc(copy.body)}</p>
      ${copy.steps?.length
        ? `<ol class="ih-recovery-steps">${copy.steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>`
        : ''}
      <div class="ih-recovery-actions">
        ${copy.href && copy.linkLabel
          ? `<a class="empty-link" href="${esc(copy.href)}">${esc(copy.linkLabel)}</a>`
          : ''}
        ${copy.doc
          ? `<span class="ih-recovery-doc muted">Setup: <code>${esc(copy.doc)}</code></span>`
          : ''}
      </div>`;
  }

  function mdmPathHtml(path) {
    const steps = (path.steps || [])
      .map((s, i) => `<li><span class="ih-step-n mono">${i + 1}.</span> ${esc(s)}</li>`)
      .join('');
    const docs = (path.docs || [])
      .map((d) => `<li><code class="mono">${esc(d)}</code></li>`)
      .join('');
    return `
      <article class="ih-mdm-card" role="listitem" data-path-id="${esc(path.id)}">
        <header class="ih-mdm-head">
          <span class="pill ${path.mdm === 'Intune' || path.mdm === 'Jamf' ? 'ok' : ''}">${esc(path.mdm)}</span>
          <span class="ih-mdm-plat mono">${esc(path.platform)}</span>
        </header>
        <h3 class="ih-mdm-title">${esc(path.title)}</h3>
        <p class="ih-mdm-sum">${esc(path.summary)}</p>
        <ol class="ih-mdm-steps">${steps}</ol>
        <p class="ih-mdm-verify"><b>Verify:</b> ${esc(path.verify)}</p>
        <ul class="ih-mdm-docs" aria-label="Related docs for ${esc(path.title)}">${docs}</ul>
      </article>`;
  }

  function tileHtml(t) {
    const valueBits = tileValues(t);
    return `
      <article class="ih-tile state-${esc(t.state)}" role="listitem" data-state="${esc(t.state)}" data-id="${esc(t.id)}">
        <header class="ih-tile-head">
          <span class="ih-tile-state">
            <i class="ih-dot ${esc(t.state)}"></i>
            ${esc(STATE_LABEL[t.state] || t.state)}
          </span>
          <span class="ih-tile-pillar mono">${esc(t.pillar || 'aim')}</span>
        </header>
        <h3 class="ih-tile-title">${esc(t.title)}</h3>
        <p class="ih-tile-msg">${esc(t.message)}</p>
        <dl class="ih-tile-meta">
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
    if (v.enrolled != null) rows.push(['Enrolled', fmtInt(v.enrolled)]);
    if (v.met != null) rows.push(['Met', fmtInt(v.met)]);
    if (v.pending != null) rows.push(['Pending', fmtInt(v.pending)]);
    if (v.breached != null) rows.push(['Breached', fmtInt(v.breached)]);
    if (v.p50Seconds != null) rows.push(['p50', formatDur(v.p50Seconds)]);
    if (v.p95Seconds != null) rows.push(['p95', formatDur(v.p95Seconds)]);
    if (v.latencySeconds != null) rows.push(['Latency', formatDur(Math.abs(v.latencySeconds))]);
    if (v.firstEventAt) rows.push(['First event', new Date(v.firstEventAt).toLocaleString()]);
    if (v.firstEnrolledAt) rows.push(['First enroll', new Date(v.firstEnrolledAt).toLocaleString()]);
    return rows.map(([k, val]) =>
      `<div><dt>${esc(k)}</dt><dd class="mono">${esc(String(val))}</dd></div>`).join('');
  }

  registerModuleView('install-health', {
    onActivate: async () => {
      await load();
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = setInterval(() => {
        if (document.visibilityState === 'visible' &&
            document.querySelector('#view-install-health')?.classList.contains('active')) {
          load().catch(() => {});
        }
      }, POLL_MS);
    },
  });
}

/* AIM-1007 — pure helpers for the live Attribution health panel.
 *
 * Epic A gate (AIM-487) re-measure shape from AIM-868:
 *   - windows 1h / 24h / 7d with pct_ok + n
 *   - 7d gate threshold ≥95%
 *   - last attributed timestamp with >15m stale warning
 *   - unbound / service-only host counts
 *
 * Pure so unit tests do not need a DOM. Markup builders use the same
 * esc() discipline as other shared components.
 */

import { esc } from '../lib/dom.js';

/** Fixed window order shown on the panel. */
export const ATTR_HEALTH_WINDOW_KEYS = Object.freeze(['1h', '24h', '7d']);

/** Epic A 7d gate threshold. */
export const EPIC_A_GATE_PCT = 95;

/** Stale threshold for last attributed event (seconds). */
export const ATTRIBUTED_STALE_SECONDS = 15 * 60;

/**
 * RAG tone for a window vs the gate threshold.
 * null pct → muted (no events); met → ok; below → bad.
 * @returns {'ok'|'warn'|'bad'|'muted'}
 */
export function windowTone(win, gatePct = EPIC_A_GATE_PCT) {
  if (!win || win.pctOk == null) return 'muted';
  if (win.pctOk >= gatePct) return 'ok';
  // Near miss: within 10 points of gate still amber so washout is readable.
  if (win.pctOk >= gatePct - 10) return 'warn';
  return 'bad';
}

/** Tone for the overall 7d gate tile. */
export function gateTone(gate) {
  if (!gate || gate.pctOk == null || gate.status === 'no_events') return 'muted';
  if (gate.met || gate.status === 'met') return 'ok';
  return 'bad';
}

/** Human duration for attributed age (largest sensible unit). */
export function formatAge(seconds) {
  if (seconds == null || !Number.isFinite(Number(seconds))) return '—';
  const n = Math.max(0, Math.floor(Number(seconds)));
  if (n < 90) return `${n}s`;
  if (n < 5400) return `${Math.round(n / 60)}m`;
  if (n < 172800) return `${(n / 3600).toFixed(1)}h`;
  return `${(n / 86400).toFixed(1)}d`;
}

/**
 * Format pct_ok for display — two decimals when present, else em dash.
 * Keeps rounding consistent with API (round to 2).
 */
export function formatPctOk(pct) {
  if (pct == null || !Number.isFinite(Number(pct))) return '—';
  return `${Number(pct).toFixed(2)}%`;
}

/**
 * Empty / error specs for the panel shell.
 * Distinguishes metrics-unavailable from empty windows.
 */
export function healthEmptySpec({ reason = 'no-data', detail } = {}) {
  if (reason === 'error') {
    return {
      reason: 'error',
      title: 'Attribution health unavailable',
      body: detail
        ? `Could not load live attribution metrics: ${detail}`
        : 'Could not load live attribution metrics. Check API / pipeline health and retry.',
      href: '#/status',
      linkLabel: 'Open Status',
    };
  }
  if (reason === 'forbidden') {
    return {
      reason: 'error',
      title: 'Attribution health restricted',
      body: 'Your role cannot read pipeline attribution metrics.',
    };
  }
  return {
    reason: 'no-data',
    title: 'No attribution events yet',
    body: '1h / 24h / 7d pct_ok appear once events land. Epic A gate requires ≥95% on trailing 7d.',
    href: '#/fleet',
    linkLabel: 'Open Fleet',
  };
}

/**
 * Build the compact panel body HTML from a GET /api/pipeline/attribution-health
 * payload (or null on empty). Caller wraps with panel chrome / verified stamp.
 *
 * @param {object|null} data
 * @param {{ error?: string|null, fmtInt?: (n:number)=>string, relTime?: (iso:string)=>string }} [opts]
 * @returns {string} HTML
 */
export function renderAttributionHealthHtml(data, opts = {}) {
  const fmtInt = opts.fmtInt || ((n) => String(n ?? 0));
  const relTime = opts.relTime || ((iso) => (iso ? String(iso) : '—'));

  if (opts.error) {
    const e = healthEmptySpec({ reason: 'error', detail: opts.error });
    return emptyBlock(e);
  }
  if (!data || !data.windows) {
    return emptyBlock(healthEmptySpec({ reason: 'no-data' }));
  }

  const gate = data.gate || {};
  const gatePct = gate.thresholdPct ?? EPIC_A_GATE_PCT;
  const windows = data.windows || {};
  const hosts = data.hosts || {};
  const unboundHref = safeHash(hosts.unboundHref) || '#/overview';
  const stale = Boolean(data.stale);
  const ageLabel = formatAge(data.lastAttributedAgeSeconds);
  const lastLabel = data.lastAttributedAt
    ? relTime(data.lastAttributedAt)
    : 'never';

  const windowCards = ATTR_HEALTH_WINDOW_KEYS.map((key) => {
    const w = windows[key] || {};
    const tone = windowTone(w, gatePct);
    const isGate = key === '7d';
    const met = w.pctOk != null && w.pctOk >= gatePct;
    const badge = w.pctOk == null
      ? '<span class="pill muted">no events</span>'
      : met
        ? `<span class="pill ok">${isGate ? 'gate met' : '≥' + gatePct + '%'}</span>`
        : `<span class="pill ${tone === 'warn' ? 'warn' : 'bad'}">${isGate ? 'gate open' : 'below ' + gatePct + '%'}</span>`;
    return `<div class="ah-window" data-window="${esc(key)}" data-tone="${esc(tone)}">`
      + `<div class="ah-window-label">${esc(key)}${isGate ? ' <span class="hint">Epic A</span>' : ''}</div>`
      + `<div class="ah-window-pct tone-${esc(tone)}">${esc(formatPctOk(w.pctOk))}</div>`
      + `<div class="ah-window-meta mono">n=${esc(fmtInt(w.n || 0))}`
      + (w.unbound != null ? ` · unbound ${esc(fmtInt(w.unbound))}` : '')
      + (w.service != null && w.service > 0 ? ` · service ${esc(fmtInt(w.service))}` : '')
      + `</div>`
      + `<div class="ah-window-badge">${badge}</div>`
      + `</div>`;
  }).join('');

  const gateBanner = gate.pctOk == null
    ? `<div class="banner info ah-gate" role="status" data-gate="no_events">Epic A 7d gate undefined — no events in the trailing week.</div>`
    : gate.met
      ? `<div class="banner ok ah-gate" role="status" data-gate="met">Epic A gate met: 7d pct_ok ${esc(formatPctOk(gate.pctOk))} ≥ ${esc(String(gatePct))}% (n=${esc(fmtInt(gate.n || 0))}).</div>`
      : `<div class="banner warn ah-gate" role="status" data-gate="breached">Epic A gate open: 7d pct_ok ${esc(formatPctOk(gate.pctOk))} &lt; ${esc(String(gatePct))}% (n=${esc(fmtInt(gate.n || 0))}). Live 1h/24h show washout vs regression.</div>`;

  const staleClass = stale ? 'ah-stale tone-bad' : 'ah-fresh';
  const stalePill = stale
    ? `<span class="pill bad">stale &gt;${esc(formatAge(data.staleThresholdSeconds || ATTRIBUTED_STALE_SECONDS))}</span>`
    : (data.lastAttributedAt
      ? '<span class="pill ok">fresh</span>'
      : '<span class="pill muted">none</span>');

  const unboundN = Number(hosts.unbound) || 0;
  const serviceOnlyN = Number(hosts.serviceOnly) || 0;
  const distinctN = Number(hosts.distinct) || 0;

  const spark = renderSparkline(data.trend24h);

  return gateBanner
    + `<div class="ah-windows" role="group" aria-label="Attribution pct_ok by window">${windowCards}</div>`
    + `<div class="ah-meta">`
    + `<div class="ah-meta-item ${staleClass}" data-stale="${stale ? '1' : '0'}">`
    + `<span class="ah-meta-label">Last attributed</span>`
    + `<span class="ah-meta-value mono" title="${esc(data.lastAttributedAt || '')}">${esc(lastLabel)}`
    + (data.lastAttributedAt ? ` <span class="faint">(${esc(ageLabel)} ago)</span>` : '')
    + `</span> ${stalePill}`
    + `</div>`
    + `<div class="ah-meta-item">`
    + `<span class="ah-meta-label">Unbound hosts (7d)</span>`
    + `<a class="ah-meta-value mono${unboundN > 0 ? ' tone-bad' : ''}" href="${esc(unboundHref)}" title="Open host list ranked by unattributed rate">${esc(fmtInt(unboundN))}</a>`
    + `<span class="faint"> of ${esc(fmtInt(distinctN))} distinct</span>`
    + `</div>`
    + `<div class="ah-meta-item">`
    + `<span class="ah-meta-label">Service-only hosts (7d)</span>`
    + `<span class="ah-meta-value mono">${esc(fmtInt(serviceOnlyN))}</span>`
    + `</div>`
    + `</div>`
    + spark;
}

function emptyBlock(spec) {
  const href = safeHash(spec.href);
  return `<div class="empty-state ah-empty" data-reason="${esc(spec.reason || 'no-data')}">`
    + `<div class="empty-title">${esc(spec.title || 'No data')}</div>`
    + `<div class="empty-body">${esc(spec.body || '')}</div>`
    + (href
      ? `<a class="empty-link" href="${esc(href)}">${esc(spec.linkLabel || 'Open')}</a>`
      : '')
    + `</div>`;
}

/** Tiny pure CSS sparkline from hourly pct_ok points (no Chart.js required). */
function renderSparkline(trend) {
  const pts = Array.isArray(trend) ? trend.filter((t) => t && t.pctOk != null) : [];
  if (pts.length < 2) {
    return `<div class="ah-spark muted" data-spark="empty">No 24h trend series yet — single-point window cards above.</div>`;
  }
  const w = 240;
  const h = 36;
  const max = 100;
  const step = (w - 2) / Math.max(pts.length - 1, 1);
  const coords = pts.map((p, i) => {
    const x = 1 + i * step;
    const y = h - 1 - ((Number(p.pctOk) / max) * (h - 2));
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const last = pts[pts.length - 1];
  const tone = windowTone(last);
  return `<div class="ah-spark" data-spark="series" aria-label="24h hourly pct_ok sparkline">`
    + `<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}" role="img" aria-hidden="true">`
    + `<polyline fill="none" stroke="currentColor" class="ah-spark-line tone-${esc(tone)}" stroke-width="1.5" points="${coords.join(' ')}" />`
    + `</svg>`
    + `<span class="ah-spark-caption faint">24h hourly pct_ok · last ${esc(formatPctOk(last.pctOk))}</span>`
    + `</div>`;
}

function safeHash(href) {
  if (typeof href !== 'string' || !href) return '';
  if (href.startsWith('#/')) return href;
  return '';
}

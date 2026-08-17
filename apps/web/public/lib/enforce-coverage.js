/* AIM-796 — fleet enforce coverage pure helpers.
 *
 * Renders GET /api/enforcement/coverage (AIM-789 contract) for the Security
 * panel. Honesty rules are load-bearing:
 *   * installPath.covered === false → explicit NO COVERAGE empty state
 *   * null rates → '—', never invented 0% / 100%
 *   * enrolled (host_id) is a footnote; rate is over event host_ref only
 *   * metadata only — never prompt / matched text / reason strings
 *
 * Own module so unit tests run without a DOM (same pattern as attribution-label).
 */
import { esc } from '../lib/dom.js';

import { fmtInt } from '../lib/format.js';

import { emptyState, tableHtml, card } from '../lib/components.js';

/** Analyst+ gate: same bar as /api/fleet and Coverage & Trust. */
export function canViewEnforceCoverage(me) {
  const caps = me?.capabilities;
  return Boolean(caps?.coverage || caps?.fleet);
}

/**
 * Format an API rate (0–1) as a percentage. Null/undefined/non-finite → '—'.
 * Never invents 0% or 100% when the API says the rate is undefined.
 */
export function fmtRate(rate) {
  if (rate == null) return '—';
  const n = Number(rate);
  if (!Number.isFinite(n)) return '—';
  const pct = n * 100;
  return Number.isInteger(pct) || Math.abs(pct - Math.round(pct)) < 0.05
    ? `${Math.round(pct)}%`
    : `${pct.toFixed(1)}%`;
}

/**
 * Install-path bar: hosts.policyLoaded / hosts.seen.
 * Enrolled is a footnote only — host_id (UUID) does not join host_ref (HMAC).
 */
export function installPathBar(hosts) {
  if (!hosts) return '';
  const seen = Number(hosts.seen) || 0;
  const loaded = Number(hosts.policyLoaded) || 0;
  const enrolled = hosts.enrolled == null ? null : Number(hosts.enrolled);
  const rate = hosts.coverageRate;

  if (seen === 0) {
    // No event hosts in window — unknown, not zero. Do not paint a green bar.
    return emptyState({
      reason: 'no-data',
      title: 'No event hosts in this window',
      body: 'Install-path coverage needs events with host_ref. Enrolled device count is not a substitute — host_id does not join host_ref.',
    });
  }

  const ratio = rate == null ? loaded / seen : Number(rate);
  const pct = ratio * 100;
  const gap = Math.max(0, seen - loaded);
  const loadedW = Math.min(100, Math.max(0, pct));
  const gapW = Math.max(0, 100 - loadedW);
  const tone = loadedW < 90 ? 'tone-bad' : '';
  const rateLabel = fmtRate(rate == null ? ratio : rate);
  const summary = `${rateLabel} of ${fmtInt(seen)} event-hosts report a loaded enforcement policy`
    + (gap > 0 ? `; ${fmtInt(gap)} without loaded policy` : '');
  const bar = `<span class="cov-seg cov-healthy" style="width:${loadedW.toFixed(2)}%" title="${esc(`policy loaded: ${loaded} of ${seen}`)}"></span>`
    + (gapW > 0
      ? `<span class="cov-seg cov-dead" style="width:${gapW.toFixed(2)}%" title="${esc(`no loaded policy: ${gap} of ${seen}`)}"></span>`
      : '');
  const legend = `<ul class="cov-legend">`
    + `<li class="cov-key cov-healthy"><span class="cov-dot"></span>policy loaded`
    + `<span class="cov-n">${fmtInt(loaded)}</span>`
    + `<span class="cov-pct">${esc(rateLabel)}</span></li>`
    + (gap > 0
      ? `<li class="cov-key cov-dead"><span class="cov-dot"></span>no loaded policy`
        + `<span class="cov-n">${fmtInt(gap)}</span></li>`
      : '')
    + `</ul>`;
  const enrolledNote = enrolled == null
    ? ''
    : `<div class="sec-enforce-footnote faint">`
      + `${fmtInt(enrolled)} enrolled device${enrolled === 1 ? '' : 's'} (host_id) — not joinable to event host_ref (HMAC). `
      + `Install-path rate is over event hosts only.`
      + `</div>`;

  return `<div class="cov-headline"><span class="cov-figure ${tone}">${esc(rateLabel)}</span>`
    + `<span class="cov-caption">of ${fmtInt(seen)} event-hosts with policy=loaded</span></div>`
    + `<div class="cov-bar" role="img" aria-label="${esc(summary)}">${bar}</div>`
    + legend
    + enrolledNote;
}

/** Mode / policy_hash distribution tables (metadata only). */
export function coverageDistTables(installPath) {
  if (!installPath) return '';
  const modeCols = [
    { key: 'mode', label: 'Mode', render: (r) => `<span class="pill muted">${esc(r.mode ?? '—')}</span>` },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'hosts', label: 'Hosts', num: true, render: (r) => fmtInt(r.hosts) },
  ];
  const hashCols = [
    { key: 'policyHash', label: 'Policy hash', render: (r) => `<span class="mono">${esc(r.policyHash ?? '—')}</span>` },
    { key: 'mode', label: 'Mode', render: (r) => `<span class="pill muted">${esc(r.mode ?? '—')}</span>` },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'hosts', label: 'Hosts', num: true, render: (r) => fmtInt(r.hosts) },
  ];
  const modeHtml = tableHtml(modeCols, installPath.byMode || [], {
    caption: 'Events and hosts with policy=loaded, by enforcement mode',
    empty: { title: 'No mode distribution', body: 'No loaded-policy events in this window.' },
  });
  const hashHtml = tableHtml(hashCols, installPath.byPolicyHash || [], {
    caption: 'Events and hosts with policy=loaded, by policy_hash and mode',
    empty: { title: 'No policy hash distribution', body: 'No loaded-policy events in this window.' },
  });
  return `<div class="sec-enforce-grid">`
    + `<div><h3>Mode distribution</h3><div class="table-wrap" tabindex="0" role="region" aria-label="Mode distribution table, scrollable"><table>${modeHtml}</table></div></div>`
    + `<div><h3>Policy hash distribution</h3><div class="table-wrap" tabindex="0" role="region" aria-label="Policy hash distribution table, scrollable"><table>${hashHtml}</table></div></div>`
    + `</div>`;
}

/**
 * Honor rate block + per-rule table.
 * Red flag when honor.alertable (would_block under mode=enforce).
 * Null rates stay '—' — never invent 1.0 / 0.0.
 */
export function honorBlock(honor) {
  if (!honor) return '';
  const totals = honor.totals || { blocked: 0, would_block: 0, confirmed: 0 };
  const alertable = Boolean(honor.alertable);
  const honorTone = alertable ? 'bad' : (honor.honorRate == null ? undefined : 'good');
  const cards = [
    card('Honor rate', fmtRate(honor.honorRate), honorTone),
    card('Break-glass rate', fmtRate(honor.breakGlassRate)),
    card('Blocked', fmtInt(totals.blocked)),
    card('Would-block', fmtInt(totals.would_block), totals.would_block > 0 ? 'bad' : 'good'),
    card('Confirmed (break-glass)', fmtInt(totals.confirmed)),
  ].join('');

  const alertBanner = alertable
    ? `<div class="banner warn sec-enforce-alert" role="alert">`
      + `<b>Honor alert.</b> would_block under mode=enforce — fail-open or delivery skew. `
      + `Honor rate is blocked/(blocked+would_block); a non-zero would_block is never a clean fleet.`
      + `</div>`
    : '';

  const ruleCols = [
    { key: 'ruleId', label: 'Rule', render: (r) => `<span class="mono">${esc(r.ruleId ?? '—')}</span>` },
    { key: 'policyHash', label: 'Policy hash', render: (r) => `<span class="mono">${esc(r.policyHash ?? '—')}</span>` },
    { key: 'blocked', label: 'Blocked', num: true, render: (r) => fmtInt(r.blocked) },
    {
      key: 'would_block',
      label: 'Would-block',
      num: true,
      render: (r) => {
        const n = Number(r.would_block) || 0;
        return n > 0 ? `<span class="tone-bad">${fmtInt(n)}</span>` : fmtInt(n);
      },
    },
    { key: 'confirmed', label: 'Confirmed', num: true, render: (r) => fmtInt(r.confirmed) },
    {
      key: 'honorRate',
      label: 'Honor',
      num: true,
      render: (r) => {
        const label = fmtRate(r.honorRate);
        return r.alertable
          ? `<span class="pill bad" title="would_block under enforce">${esc(label)}</span>`
          : esc(label);
      },
    },
    { key: 'breakGlassRate', label: 'Break-glass', num: true, render: (r) => esc(fmtRate(r.breakGlassRate)) },
  ];
  const rulesHtml = tableHtml(ruleCols, honor.byRule || [], {
    caption: 'Per-rule honor and break-glass under mode=enforce',
    empty: {
      title: 'No enforce decisions in this window',
      body: 'Honor rate has no denominator when no enforce-mode decisions fired — not 100%.',
    },
  });

  const note = honor.note
    ? `<p class="sec-enforce-note faint">${esc(honor.note)}</p>`
    : '';

  return alertBanner
    + `<div class="cards sec-enforce-honor-cards">${cards}</div>`
    + note
    + `<h3>Per-rule honor</h3>`
    + `<div class="table-wrap" tabindex="0" role="region" aria-label="Per-rule honor table, scrollable"><table>${rulesHtml}</table></div>`;
}

/**
 * Full panel body for GET /api/enforcement/coverage.
 * When installPath.covered === false, renders an explicit NO COVERAGE empty
 * state and does not invent zeros for honor rates.
 */
export function renderEnforceCoverage(d) {
  if (!d || !d.installPath) {
    return emptyState({
      reason: 'error',
      title: 'Could not load enforce coverage',
      body: 'This panel is unknown, not empty. Do not read it as a clean fleet.',
    });
  }

  const covered = d.installPath.covered === true;
  if (!covered) {
    // Honesty: NO COVERAGE is a coverage gap, not a quiet day. role=alert.
    const statement = d.statement || 'NO COVERAGE — no loaded enforcement_posture in window. Do not read zeros as clean.';
    return emptyState({
      reason: 'no-collector',
      title: 'NO COVERAGE',
      body: statement
        + (d.installPath.note ? ` ${d.installPath.note}` : '')
        + ' Zero blocks means no coverage, not a clean fleet.',
    });
  }

  const installNote = d.installPath.note
    ? `<p class="sec-enforce-note faint">${esc(d.installPath.note)}</p>`
    : '';

  return `<div class="sec-enforce-body">`
    + `<h3>Install path</h3>`
    + installPathBar(d.installPath.hosts)
    + installNote
    + coverageDistTables(d.installPath)
    + `<h3>Honor rate <span class="hint">under mode=enforce — blocked / (blocked + would_block)</span></h3>`
    + honorBlock(d.honor)
    + `</div>`;
}

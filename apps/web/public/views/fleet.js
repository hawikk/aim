/* Fleet view — pure-moved from app.js (AIM-527).
 * AIM-867: page enrolled devices at ≤100 rows; summary cards stay fleet-wide.
 * AIM-1007: live Attribution health panel (Epic A gate) for fleet operators. */
import { $, esc } from '../lib/dom.js';
import { fmtInt, fmtDay, relTime } from '../lib/format.js';
import { api, showError } from '../lib/runtime.js';
import { EMPTY, emptyState, table, card, skeletonCards } from '../lib/components.js';
import { refCell, verifiedStampHtml, setVerifiedStamp } from '../lib/ui.js';
import { lineChart, setChartState, chartSummary, fleetCoverageSeries } from '../lib/charts.js';
import { DEFAULT_PAGE_SIZE, pageRequest, withPageParams, resolvePage, pagerHtml, wirePager, truncationBannerHtml } from '../lib/list-page.js';
import { loadAttributionHealthPanel } from '../lib/attribution-health-panel.js';

/** 1-based page for the devices table. */
let fleetListPage = 1;

/* Health → pill tone: stale amber, dead red, healthy green, never_seen grey. */
export const FLEET_HEALTH_PILL = { healthy: 'ok', stale: 'warn', dead: 'bad', never_seen: 'muted' };
export const FLEET_HEALTH_LABEL = { healthy: 'healthy', stale: 'stale', dead: 'dead', never_seen: 'never seen' };

/* Devices needing attention sort first. A fleet table ordered by hostname
 * hides exactly the rows the view exists to surface: the ones that stopped
 * reporting. Active droppers first (AIM-439), then dead, never-seen, stale,
 * healthy. Lifetime drop counters alone do not reorder — only drop_active. */
export const FLEET_ATTENTION = { dead: 0, never_seen: 1, stale: 2, healthy: 3 };
export function fleetAttentionRank(d) {
  const dropBump = d?.drop_active ? -1 : 0;
  return dropBump + (FLEET_ATTENTION[d?.health] ?? 9);
}

/* Coverage as one stacked bar. The security question is "what fraction of the
 * fleet is actually reporting", and a bar answers it without arithmetic — the
 * gap is literally the non-green part. Counts stay in the legend because a
 * proportion alone is not actionable.
 *
 * AIM-645: headline prefers coverageSlo (SLO-healthy / in-scope with 24h grace)
 * and tones bad below the 99% target. */
export function coverageBar(d) {
  const total = Number(d.deployed) || 0;
  if (total === 0) {
    return emptyState(EMPTY.fleet);
  }
  const segs = [
    { key: 'healthy', label: 'healthy', n: Number(d.healthy) || 0 },
    { key: 'stale', label: 'stale (gap ≤3× interval)', n: Number(d.stale) || 0 },
    { key: 'dead', label: 'dead (gap >3× interval)', n: Number(d.dead) || 0 },
    { key: 'never_seen', label: 'never seen', n: Number(d.never_seen) || 0 },
  ].filter((s) => s.n > 0);
  const pct = (n) => (n / total) * 100;
  const reporting = pct(Number(d.healthy) || 0);
  // AIM-645: first-class SLO rollup when the API provides it.
  const slo = d.coverageSlo && typeof d.coverageSlo === 'object' ? d.coverageSlo : null;
  const sloTarget = Number(slo?.targetPct) > 0 ? Number(slo.targetPct) : 99;
  const sloPct = slo?.healthyPct != null && Number.isFinite(Number(slo.healthyPct))
    ? Number(slo.healthyPct)
    : reporting;
  const sloInScope = slo?.inScope != null ? Number(slo.inScope) : total;
  const sloBreached = slo
    ? Boolean(slo.alert) || (slo.status === 'breach')
    : sloPct < sloTarget;
  // AIM-452: silent + never_seen are coverage gaps, not vanishing devices.
  const gaps = Number(d.coverageGaps != null
    ? d.coverageGaps
    : (Number(d.stale) || 0) + (Number(d.dead) || 0) + (Number(d.never_seen) || 0));
  const silent = Number(d.silent != null
    ? d.silent
    : (Number(d.stale) || 0) + (Number(d.dead) || 0));
  const bar = segs
    .map((s) => `<span class="cov-seg cov-${s.key}" style="width:${pct(s.n).toFixed(2)}%" title="${esc(`${s.label}: ${s.n} of ${total}`)}"></span>`)
    .join('');
  const legend = segs
    .map((s) => `<li class="cov-key cov-${s.key}"><span class="cov-dot"></span>${esc(s.label)}`
      + `<span class="cov-n">${fmtInt(s.n)}</span>`
      + `<span class="cov-pct">${pct(s.n).toFixed(1)}%</span></li>`)
    .join('');
  const summary = slo
    ? `SLO coverage ${sloPct.toFixed(1)}% of ${sloInScope} in-scope enrolled devices (target ≥${sloTarget}%); ${gaps} coverage gap(s).`
    : `${reporting.toFixed(1)}% of ${total} enrolled devices are reporting normally; ${gaps} coverage gap(s).`;
  const verifiedHtml = verifiedStampHtml(d.lastVerifiedAt);
  const gapNote = gaps > 0
    ? `<div class="cov-gap-note tone-bad" role="status">${fmtInt(gaps)} coverage gap(s)`
      + (silent > 0 ? ` · ${fmtInt(silent)} enrolled-but-silent past one heartbeat interval` : '')
      + ' — silent hosts appear here; they do not vanish.</div>'
    : '';
  const sloPill = slo
    ? (sloBreached
      ? `<span class="pill bad" title="${esc(slo.message || 'Coverage SLO breached')}">SLO breach · target ≥${sloTarget}%</span>`
      : slo.status === 'pending_grace'
        ? `<span class="pill muted" title="${esc(slo.message || 'In grace window')}">SLO pending grace</span>`
        : `<span class="pill ok" title="${esc(slo.message || 'Coverage SLO met')}">SLO met · ≥${sloTarget}%</span>`)
    : '';
  const figureTone = sloBreached || sloPct < sloTarget ? ' tone-bad' : '';
  return `<div class="cov-headline"><span class="cov-figure${figureTone}">${sloPct.toFixed(1)}%</span>`
    + `<span class="cov-caption">of ${fmtInt(sloInScope)} in-scope enrolled devices SLO-healthy`
    + ` (heartbeat bucket ${reporting.toFixed(1)}% of ${fmtInt(total)}) · ${verifiedHtml}`
    + (sloPill ? ` · ${sloPill}` : '')
    + `</span></div>`
    + gapNote
    + `<div class="cov-bar" role="img" aria-label="${esc(summary)}">${bar}</div>`
    + `<ul class="cov-legend">${legend}</ul>`;
}

export function fleetDropCell(r) {
  const rejected = Number(r.events_rejected) || 0;
  const batches = Number(r.batches_fully_rejected) || 0;
  const spooled = Number(r.events_spooled) || 0;
  if (rejected === 0 && batches === 0 && spooled === 0) {
    return '<span class="faint" title="No client-side rejections or spool backlog reported on heartbeat.">—</span>';
  }
  const tone = r.drop_active ? 'bad' : (rejected > 0 || batches > 0 ? 'warn' : 'muted');
  const label = r.drop_active ? 'dropping now' : (rejected > 0 || batches > 0 ? 'lifetime drops' : 'spooled');
  const title = [
    `events_rejected=${rejected}`,
    `batches_fully_rejected=${batches}`,
    `events_spooled=${spooled}`,
    r.last_rejection_at ? `last_rejection_at=${r.last_rejection_at}` : null,
    r.drop_active ? 'ACTIVE within recent window' : 'not in active drop window',
  ].filter(Boolean).join(' · ');
  return `<span class="pill health ${tone}" title="${esc(title)}">${esc(label)}</span>`
    + ` <span class="mono" title="${esc(title)}">${fmtInt(rejected)} rej`
    + (batches ? ` / ${fmtInt(batches)} batch` : '')
    + (spooled ? ` / ${fmtInt(spooled)} spool` : '')
    + '</span>';
}

/** AIM-588: daily coverage trend when /api/fleet.trend is present. */
function renderFleetCoverageTrend(d) {
  const trend = d?.trend ?? [];
  if (trend.length === 0) {
    setChartState('#fleet-cov-trend', true, EMPTY.fleetCoverageTrend);
    return;
  }
  const { labels, series } = fleetCoverageSeries(trend, { labelDay: fmtDay });
  // Dual-scale mixed units (% + count) share one axis deliberately: gaps are
  // absolute device counts and stay scannable next to the healthy-% line.
  // suggestedMax keeps a flat 100% line from collapsing to a full-height wall.
  lineChart(
    '#fleet-cov-trend',
    labels,
    series,
    chartSummary('Fleet coverage', labels, series),
    { suggestedMax: 100 },
  );
}

export async function loadFleet() {
  $('#fleet-cards').innerHTML = skeletonCards(6);
  // AIM-1007: paint Epic A attribution health even if fleet list is slow/403.
  void loadAttributionHealthPanel('#fleet-attr-health', '#fleet-attr-health-verified');
  try {
    const req = pageRequest({ page: fleetListPage, pageSize: DEFAULT_PAGE_SIZE });
    const d = await api(withPageParams('/api/fleet', req));
    setVerifiedStamp('#fleet-verified', d.lastVerifiedAt);
    const silentN = Number(d.silent) || ((Number(d.stale) || 0) + (Number(d.dead) || 0));
    const gaps = Number(d.coverageGaps ?? (silentN + (Number(d.never_seen) || 0)));
    const slo = d.coverageSlo;
    const sloPct = slo?.healthyPct != null ? `${Number(slo.healthyPct).toFixed(1)}%` : '—';
    const sloTone = slo?.alert || slo?.status === 'breach' ? 'bad'
      : slo?.status === 'ok' ? 'good' : undefined;
    $('#fleet-cards').innerHTML = [
      card('Deployed', fmtInt(d.deployed)),
      card('Healthy', fmtInt(d.healthy), d.healthy > 0 ? 'good' : undefined),
      // AIM-645: ≥99% enrolled coverage SLO (grace-adjusted, version + event + errors).
      card(`Coverage SLO (≥${fmtInt(slo?.targetPct ?? 99)}%)`, sloPct, sloTone),
      // AIM-452: silent hosts are the coverage gap (past 1x heartbeat interval).
      card('Coverage gaps', fmtInt(gaps), gaps > 0 ? 'bad' : 'good'),
      card('Silent (missed heartbeat)', fmtInt(silentN), silentN > 0 ? 'bad' : undefined),
      card('Stale', fmtInt(d.stale), d.stale > 0 ? 'warn' : undefined),
      card('Dead', fmtInt(d.dead), d.dead > 0 ? 'bad' : undefined),
      card('Never seen', fmtInt(d.never_seen)),
      // AIM-439: client-side loss was previously invisible on this view.
      card('Dropping', fmtInt(d.dropping ?? 0), (d.dropping ?? 0) > 0 ? 'bad' : undefined),
    ].join('');
    $('#fleet-coverage').innerHTML = coverageBar(d);
    renderFleetCoverageTrend(d);

    // Pagination total comes only from the list contract (d.total). Do not
    // substitute d.deployed: summary cards can report fleet-wide counts while
    // the devices array is a page (or a small fixture), and a false total
    // would enable Next into empty pages.
    const page = resolvePage({
      rows: d.devices,
      total: d.total,
      limit: d.limit,
      offset: d.offset,
      requestedLimit: req.limit,
      requestedOffset: req.offset,
      truncated: d.truncated,
    });
    fleetListPage = page.page;

    // Attention sort applies within the current page. Global attention order
    // is a server concern once AIM-866 paginates (ORDER BY health/drop_active).
    const devices = [...page.rows].sort(
      (a, b) => fleetAttentionRank(a) - fleetAttentionRank(b),
    );

    const bannerHost = $('#fleet-page-banner');
    if (bannerHost) bannerHost.innerHTML = truncationBannerHtml(page, { noun: 'devices' });

    table($('#fleet-table'), [
      /* host_id is a salted-HMAC pseudonym like every other identity here, so
         it gets the same copy-on-click treatment. A hostname, where the device
         reported one, is the more useful label and wins. */
      { key: 'hostname', label: 'Device', render: (r) => (r.hostname ? `<span class="mono">${esc(r.hostname)}</span>` : refCell(r.host_id)) },
      {
        key: 'health',
        label: 'Health',
        render: (r) => {
          const gap = r.coverageGap || r.silent || r.health === 'stale' || r.health === 'dead' || r.health === 'never_seen';
          const pill = `<span class="pill health ${FLEET_HEALTH_PILL[r.health] ?? 'muted'}">${esc(FLEET_HEALTH_LABEL[r.health] ?? r.health)}</span>`;
          const sloPill = r.sloHealthy === false
            ? ' <span class="pill bad">SLO fail</span>'
            : (r.sloHealthy === true ? ' <span class="pill ok">SLO ok</span>' : '');
          const reasonMap = {
            missing_version: 'missing version',
            missing_last_event_at: 'no last_event_at',
            stale_last_event_at: 'stale last_event_at',
            active_errors: 'active errors',
          };
          const reasons = (r.unhealthyReasons ?? []).map((x) => reasonMap[x] || x).join(', ');
          const reasonHtml = reasons
            ? ` <span class="faint" title="${esc(reasons)}">(${esc(reasons)})</span>`
            : '';
          return (gap ? `${pill} <span class="pill bad">coverage gap</span>` : pill) + sloPill + reasonHtml;
        },
      },
      { key: 'events_rejected', label: 'Ingest health', render: fleetDropCell },
      {
        key: 'last_event_at',
        label: 'Last event / heartbeat',
        render: (r) => {
          const ts = r.last_event_at || r.last_heartbeat_at;
          return `<span class="mono" title="${esc(ts ?? 'never')}">${esc(relTime(ts))}</span>`;
        },
      },
      { key: 'collector_version', label: 'Collector', render: (r) => (r.collector_version ? `<span class="mono">${esc(r.collector_version)}</span>` : '<span class="faint">—</span>') },
      { key: 'os', label: 'OS', render: (r) => esc(r.os ?? '—') },
      { key: 'ring', label: 'Ring', render: (r) => esc(r.ring ?? '—') },
      { key: 'enrolled_at', label: 'Enrolled', render: (r) => fmtDay(r.enrolled_at) },
    ], devices, { caption: 'Enrolled collector devices with heartbeat health, SLO status (version + last_event_at + errors), and client-side drop counts; devices needing attention first (paged)', empty: EMPTY.fleet });

    const pagerHost = $('#fleet-pager');
    if (pagerHost) {
      pagerHost.innerHTML = pagerHtml(page, {
        idPrefix: 'fleet-page',
        noun: 'devices',
        label: 'Fleet devices table pagination',
      });
      wirePager(pagerHost, 'fleet-page', {
        onPrev: () => { if (fleetListPage > 1) { fleetListPage -= 1; loadFleet(); } },
        onNext: () => { if (page.hasNext) { fleetListPage += 1; loadFleet(); } },
      });
    }
    await loadEnforceCoverage();
  } catch (err) {
    /* Expected for non-security-group users (403) — surface as a retryable banner, not a broken table. */
    $('#fleet-cards').innerHTML = '';
    setChartState('#fleet-cov-trend', true, EMPTY.fleetCoverageTrend);
    showError('fleet', err);
  }
}

/* ---- AIM-781 fleet enforce coverage --------------------------------------
 * Install-path coverage + honor rate + fail-open inventory. SOC answers
 * "who can enforce today?" without SQL. Data: GET /api/enforcement/fleet-coverage.
 */

export const FAIL_OPEN_REASON_LABEL = {
  no_bundle: 'no bundle',
  shadow_mode: 'shadow mode',
  stale_shadow_bake: 'stale shadow bake',
  stale_bundle: 'stale hash',
  pre_aim110: 'pre-AIM-110',
};

function shortRef(ref) {
  if (!ref) return '—';
  const s = String(ref);
  return s.length <= 16 ? s : `${s.slice(0, 12)}…`;
}

function pctLabel(n) {
  if (n == null || !Number.isFinite(Number(n))) return '—';
  return `${Number(n).toFixed(1)}%`;
}

function rateLabel(n) {
  if (n == null || !Number.isFinite(Number(n))) return '—';
  return `${(Number(n) * 100).toFixed(1)}%`;
}

export function enforceCoverageCards(d) {
  const inst = d.install ?? {};
  const honor = d.honorRate ?? {};
  const cov = inst.coveragePct;
  const covTone = cov == null ? undefined
    : (inst.slo?.met === false ? 'bad' : (inst.slo?.met === true ? 'good' : undefined));
  const honorTone = honor.slo?.met === false ? 'bad'
    : (honor.slo?.met === true ? 'good' : undefined);
  const failN = Number(inst.failOpenHosts) || 0;
  return [
    card('Can enforce', fmtInt(inst.canEnforceHosts ?? 0),
      (inst.canEnforceHosts ?? 0) > 0 ? 'good' : 'bad'),
    card('Install coverage', pctLabel(cov), covTone),
    card('Fail-open hosts', fmtInt(failN), failN > 0 ? 'bad' : 'good'),
    card('Honor rate', rateLabel(honor.honorRate), honorTone),
    card('Blocked', fmtInt(honor.blocked ?? 0)),
    card('Would-block', fmtInt(honor.wouldBlock ?? 0),
      (honor.wouldBlock ?? 0) > 0 ? 'warn' : undefined),
    card('Break-glass', rateLabel(honor.breakGlassRate)),
    card('Reporting hosts', fmtInt(inst.reportingHosts ?? 0)),
  ].join('');
}

export function enforceCoverageSummaryHtml(d) {
  const inst = d.install ?? {};
  const desired = d.desiredPolicy ?? {};
  const cov = inst.coveragePct;
  const slo = inst.slo?.minCoveragePct;
  const figureTone = cov != null && inst.slo?.met === false ? ' tone-bad' : '';
  const figure = cov == null ? '—' : `${Number(cov).toFixed(1)}%`;
  const hash = desired.policyHash
    ? `<span class="mono" title="${esc(desired.source ?? '')}">${esc(String(desired.policyHash).slice(0, 24))}${String(desired.policyHash).length > 24 ? '…' : ''}</span>`
    : '<span class="faint">desired hash unconfigured</span>';
  return `<div class="cov-headline"><span class="cov-figure${figureTone}">${esc(figure)}</span>`
    + `<span class="cov-caption">of ${fmtInt(inst.reportingHosts ?? 0)} reporting hosts can enforce`
    + (slo != null ? ` · pilot SLO ≥${fmtInt(slo)}%` : '')
    + ` · desired policy ${hash}</span></div>`
    + `<p class="hint" style="margin:0.5rem 0 0">${esc(inst.note ?? d.note ?? '')}</p>`;
}

export function enforceAlertsHtml(alerts) {
  if (!alerts?.length) return '';
  return alerts.map((a) => {
    const sev = a.severity === 'high' ? 'bad' : 'warn';
    return `<div class="banner ${sev}" role="alert"><strong>${esc(a.kind)}</strong> — ${esc(a.message)}</div>`;
  }).join('');
}

async function loadEnforceCoverage() {
  const cardsEl = $('#fleet-enforce-cards');
  const alertsEl = $('#fleet-enforce-alerts');
  const summaryEl = $('#fleet-enforce-summary');
  if (!cardsEl) return;
  cardsEl.innerHTML = skeletonCards(4);
  try {
    const d = await api('/api/enforcement/fleet-coverage');
    setVerifiedStamp('#fleet-enforce-verified', d.lastVerifiedAt ?? d.generatedAt);
    cardsEl.innerHTML = enforceCoverageCards(d);
    if (summaryEl) summaryEl.innerHTML = enforceCoverageSummaryHtml(d);
    if (alertsEl) {
      if (d.alerts?.length) {
        alertsEl.hidden = false;
        alertsEl.className = 'banner warn';
        alertsEl.innerHTML = enforceAlertsHtml(d.alerts);
      } else {
        alertsEl.hidden = true;
        alertsEl.innerHTML = '';
      }
    }
    table($('#fleet-enforce-who-table'), [
      { key: 'hostRef', label: 'Host', render: (r) => `<span class="mono" title="${esc(r.hostRef)}">${esc(shortRef(r.hostRef))}</span>` },
      {
        key: 'current',
        label: 'Bundle',
        render: (r) => r.current
          ? '<span class="pill health ok">current</span>'
          : '<span class="pill health warn">stale hash</span>',
      },
      { key: 'mode', label: 'Mode', render: (r) => `<span class="pill muted">${esc(r.mode ?? '—')}</span>` },
      {
        key: 'policyHash',
        label: 'policy_hash',
        render: (r) => r.policyHash
          ? `<span class="mono" title="${esc(r.policyHash)}">${esc(String(r.policyHash).slice(0, 20))}${String(r.policyHash).length > 20 ? '…' : ''}</span>`
          : '<span class="faint">—</span>',
      },
      { key: 'blocked', label: 'Blocked', num: true, render: (r) => fmtInt(r.blocked ?? 0) },
      { key: 'wouldBlock', label: 'Would-block', num: true, render: (r) => fmtInt(r.wouldBlock ?? 0) },
      { key: 'lastEventAt', label: 'Last event', render: (r) => `<span class="mono" title="${esc(r.lastEventAt ?? '')}">${esc(relTime(r.lastEventAt))}</span>` },
    ], d.whoCanEnforce ?? [], {
      caption: 'Hosts with loaded enforce enforcement.json — can block today',
      empty: {
        title: 'No hosts can enforce',
        body: 'No reporting host has a loaded enforce bundle in this window. Zero blocks means no coverage, not a clean fleet. Deliver enforcement.json (AIM-440) and confirm with aim doctor --fix.',
      },
    });
    table($('#fleet-enforce-failopen-table'), [
      { key: 'hostRef', label: 'Host', render: (r) => `<span class="mono" title="${esc(r.hostRef)}">${esc(shortRef(r.hostRef))}</span>` },
      {
        key: 'reason',
        label: 'Reason',
        render: (r) => {
          const label = FAIL_OPEN_REASON_LABEL[r.reason] ?? r.reason ?? 'fail-open';
          return `<span class="pill bad" title="${esc(r.label ?? '')}">${esc(label)}</span>`;
        },
      },
      { key: 'policy', label: 'Posture', render: (r) => esc(r.policy ?? '—') },
      { key: 'mode', label: 'Mode', render: (r) => esc(r.mode ?? '—') },
      {
        key: 'policyHash',
        label: 'policy_hash',
        render: (r) => r.policyHash
          ? `<span class="mono" title="${esc(r.policyHash)}">${esc(String(r.policyHash).slice(0, 16))}…</span>`
          : '<span class="faint">—</span>',
      },
      { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events ?? 0) },
      { key: 'lastEventAt', label: 'Last event', render: (r) => `<span class="mono" title="${esc(r.lastEventAt ?? '')}">${esc(relTime(r.lastEventAt))}</span>` },
    ], d.failOpenInventory ?? [], {
      caption: 'Reporting hosts that cannot enforce — fail-open inventory',
      empty: {
        title: 'No fail-open hosts',
        body: 'Every reporting host in the window has a loaded enforce bundle.',
      },
    });
    table($('#fleet-enforce-honor-table'), [
      { key: 'ruleId', label: 'Rule', render: (r) => `<span class="mono">${esc(r.ruleId)}</span>` },
      {
        key: 'policyHash',
        label: 'policy_hash',
        render: (r) => r.policyHash
          ? `<span class="mono" title="${esc(r.policyHash)}">${esc(String(r.policyHash).slice(0, 16))}…</span>`
          : '<span class="faint">—</span>',
      },
      { key: 'blocked', label: 'Blocked', num: true, render: (r) => fmtInt(r.blocked ?? 0) },
      { key: 'wouldBlock', label: 'Would-block', num: true, render: (r) => fmtInt(r.wouldBlock ?? 0) },
      { key: 'confirmed', label: 'Confirmed', num: true, render: (r) => fmtInt(r.confirmed ?? 0) },
      {
        key: 'honorRate',
        label: 'Honor rate',
        render: (r) => {
          const v = r.honorRate;
          if (v == null) return '<span class="faint">—</span>';
          const tone = v < 0.95 ? 'bad' : 'ok';
          return `<span class="pill health ${tone}">${esc(rateLabel(v))}</span>`;
        },
      },
      {
        key: 'breakGlassRate',
        label: 'Break-glass',
        render: (r) => r.breakGlassRate == null
          ? '<span class="faint">—</span>'
          : esc(rateLabel(r.breakGlassRate)),
      },
    ], d.honorRate?.byRule ?? [], {
      caption: 'Per-rule honor rate from endpoint enforcement audit records',
      empty: {
        title: 'No enforcement decisions',
        body: 'No blocked/would_block/confirmed records in the window. If install coverage is high, the fleet is quiet; if coverage is low, this is not evidence of a clean fleet.',
      },
    });
  } catch (err) {
    cardsEl.innerHTML = '';
    if (summaryEl) summaryEl.innerHTML = '';
    if (alertsEl) {
      alertsEl.hidden = false;
      alertsEl.className = 'banner warn';
      alertsEl.textContent = `Enforce coverage unavailable: ${err.message || err}`;
    }
  }
}

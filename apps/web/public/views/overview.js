/* Overview view (AIM-481) — pure-moved from app.js (AIM-527).
 * AIM-707: widget order + KPI emphasis follow the active home persona.
 * AIM-1007: live Attribution health panel (1h/24h/7d Epic A gate). */
import { $, esc } from '../lib/dom.js';
import { fmtInt, fmtTok, fmtDay, relTime, fmtUsd } from '../lib/format.js';
import { state, hashFor, api } from '../lib/runtime.js';
import { EMPTY, emptyState, table, card, skeletonCards } from '../lib/components.js';
import { lineChart, setChartState, chartSummary, ACCENT, GOOD, PALETTE } from '../lib/charts.js';
import { delta, refCell, setVerifiedStamp, sevPill, compareSeverity } from '../lib/ui.js';
import { resolveHomeRole, applyHomeWidgets, HOME_TITLES, HOME_LABELS } from '../lib/home-role.js';
import { findingsHash } from '../lib/view-filters.js';
import { loadAttributionHealthPanel } from '../lib/attribution-health-panel.js';
import { mergeVendorTools, renderVendorFeedBanner, vendorFeedEmpty } from '../lib/vendor-feeds.js';

/* AIM-481 Overview helpers: tool columns shared by the sanctioned / unapproved
 * split tables. Severity ordering comes from lib/severity.js (AIM-524). */
const OV_TOOL_COLS = [
  { key: 'tool', label: 'Tool', render: (r) => `<a href="${hashFor('tools', r.tool)}">${esc(r.tool)}</a>` },
  { key: 'users', label: 'Users', num: true, render: (r) => fmtInt(r.users) },
  { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
  { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
  { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => fmtUsd(r.costUsd) },
];

function renderOverviewAlerts(openFindings, canFindings) {
  const panel = $('#ov-alerts-panel');
  const el = $('#ov-alerts');
  if (!panel || !el) return;
  if (!canFindings) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  /* openFindings is already the union of the critical + high API pulls —
   * do not re-filter on the raw label. The alert corpus ships labels like
   * "catastrophic" that only band via severity_id; dropping them here is how
   * a real critical vanishes from the front page (AIM-524). */
  const rows = [...(openFindings?.findings ?? [])]
    .sort((a, b) => compareSeverity(a.severity ?? a.band, b.severity ?? b.band)
      || new Date(b.detectedAt) - new Date(a.detectedAt))
    .slice(0, 6);
  if (rows.length === 0) {
    el.innerHTML = emptyState({
      title: 'No open critical or high findings',
      body: 'Nothing in triage needs attention at critical/high severity right now.',
    });
    return;
  }
  el.innerHTML = rows.map((f) => {
    const title = esc(f.title || f.ruleId || 'Finding');
    const when = f.detectedAt ? relTime(f.detectedAt) : '';
    const href = findingsHash({ fstatus: 'open', fsev: f.severity || 'all', days: state.days });
    return `<a class="ov-alert" role="listitem" href="${esc(href)}">`
      + sevPill(f.severity || 'unknown')
      + `<span class="ov-alert-title">${title}</span>`
      + (when ? `<span class="ov-alert-when">${esc(when)}</span>` : '')
      + `</a>`;
  }).join('');
}

function renderHomeBanner(persona) {
  const el = $('#ov-home-banner');
  if (!el) return;
  if (!persona) {
    el.hidden = true;
    el.textContent = '';
    return;
  }
  el.hidden = false;
  el.textContent = HOME_TITLES[persona] || `${HOME_LABELS[persona] || persona} home`;
}

/** KPI row ordered for the active persona — same data, different lead questions. */
function overviewKpis(d, { persona, canFindings, canUsers, critCount, prev }) {
  const usersHref = canUsers ? hashFor('users') : hashFor('teams');
  // AIM-589: keep shared range via hashFor — bare '#/activity' drops ?days=.
  const eventsHref = canUsers ? hashFor('activity') : hashFor('tools');
  const critTone = critCount > 0 ? 'bad' : null;
  const critDelta = canFindings
    ? `<div class="delta"><span class="base">${critCount === 0 ? 'none open' : 'open in triage'}</span></div>`
    : `<div class="delta"><span class="base">requires analyst+</span></div>`;
  const unapproved = (d.tools || []).filter((t) => !t.sanctioned).length;
  const unappTone = unapproved > 0 ? 'warn' : 'good';
  const attrPct = d.attribution?.unattributedPct;
  const attrTone = d.attribution?.alert || (attrPct != null && attrPct > (d.attribution?.targetPct ?? 5))
    ? 'bad'
    : (attrPct != null && attrPct > 0 ? 'warn' : 'good');
  // AIM-551 / AIM-589: critical KPI must land on open+critical with range, not bare #/findings.
  const critHref = canFindings
    ? findingsHash({ fstatus: 'open', fsev: 'critical', days: state.days })
    : null;

  const cards = {
    users: card('Active users', fmtInt(d.totals.activeUsers), null, delta(d.totals.activeUsers, prev.activeUsers), usersHref),
    events: card('Events in range', fmtInt(d.totals.events), null, delta(d.totals.events, prev.events), eventsHref),
    critical: card(
      'Open critical findings',
      canFindings ? fmtInt(critCount) : '—',
      critTone,
      critDelta,
      critHref,
    ),
    spend: card('Est. spend', fmtUsd(d.totals.costUsd), null, delta(d.totals.costUsd, prev.costUsd, { badWhen: 'up' }), hashFor('teams')),
    unapproved: card(
      'Unapproved tools',
      fmtInt(unapproved),
      unappTone,
      `<div class="delta"><span class="base">${unapproved === 0 ? 'none in range' : 'in use now'}</span></div>`,
      hashFor('security'),
    ),
    attribution: card(
      'Unattributed',
      attrPct == null ? '—' : `${attrPct}%`,
      attrPct == null ? null : attrTone,
      `<div class="delta"><span class="base">${d.attribution?.alert ? 'above threshold' : 'fleet identity'}</span></div>`,
      null,
    ),
  };

  // Persona answerability: SOC = what is on fire; SecEng = what is unsanctioned;
  // Admin = is the fleet covered. Viewer/null keeps the AIM-481 default set.
  if (persona === 'soc') {
    return [cards.critical, cards.events, cards.users, cards.unapproved].join('');
  }
  if (persona === 'seceng') {
    return [cards.unapproved, cards.attribution, cards.events, cards.spend].join('');
  }
  if (persona === 'admin') {
    return [cards.attribution, cards.critical, cards.users, cards.events].join('');
  }
  return [cards.users, cards.events, cards.critical, cards.spend].join('');
}

export async function loadOverview() {
  // AIM-481 front page: four honest KPIs (each links to its backing view),
  // an events sparkline, a top-alerts strip into Findings, and a sanctioned vs
  // unapproved tool split. No vanity hosts/sessions/tokens tiles.
  // AIM-707: persona reorders widgets and KPI emphasis; never blanks the page.
  const persona = resolveHomeRole(state.me);
  applyHomeWidgets($('#view-overview'), persona);
  renderHomeBanner(persona);

  $('#ov-cards').innerHTML = skeletonCards(4);
  const canFindings = Boolean(state.me?.capabilities?.findingsConsole);
  const canUsers = Boolean(state.me?.capabilities?.userLevel);
  const activityLink = $('#ov-activity-link');
  if (activityLink) {
    // Live trail is user-level; everyone else drills into tools as the nearest
    // volume view rather than a dead #/activity link. hashFor keeps ?days=.
    activityLink.href = canUsers ? hashFor('activity') : hashFor('tools');
    activityLink.textContent = canUsers ? 'Open Live →' : 'Open Tools →';
  }
  const alertsLink = $('#ov-alerts-link');
  if (alertsLink && canFindings) {
    alertsLink.href = hashFor('findings');
  }

  const fetches = [
    api(`/api/overview?days=${state.days}`),
    api(`/api/repos?days=${state.days}`),
    api(`/api/vendor-admin/feeds?days=${state.days}`).catch(() => null),
  ];
  if (canFindings) {
    // Severity filter is single-value server-side; pull critical + high in
    // parallel so the strip matches the KPI (a bare limit=50 of all open
    // findings can bury criticals under medium noise).
    fetches.push(
      api('/api/findings?status=new,acknowledged&severity=critical&limit=1').catch(() => null),
      api('/api/findings?status=new,acknowledged&severity=critical&limit=25').catch(() => null),
      api('/api/findings?status=new,acknowledged&severity=high&limit=25').catch(() => null),
    );
  }
  const [d, repos, vendorFeeds, crit, critFindings, highFindings] = await Promise.all(fetches);
  const feeds = vendorFeeds?.feeds ?? d.vendorFeeds ?? [];
  renderVendorFeedBanner($('#ov-vendor-feeds'), feeds);
  const openFindings = canFindings
    ? { findings: [...(critFindings?.findings ?? []), ...(highFindings?.findings ?? [])] }
    : null;
  const prev = d.previousTotals ?? {};
  const critCount = canFindings ? (crit?.total ?? 0) : null;

  $('#ov-cards').innerHTML = overviewKpis(d, { persona, canFindings, canUsers, critCount, prev });
  // AIM-1007: Epic A multi-window panel — fire-and-forget so Overview KPIs
  // still paint if attribution-health is slow or missing on older backends.
  void loadAttributionHealthPanel('#ov-attr-health', '#ov-attr-health-verified');
  renderOverviewAttribution(d.attribution, d.lastVerifiedAt);
  if (d.trend.length === 0) {
    setChartState('#ov-trend', true, EMPTY.overviewTrend);
  } else {
    // Prefer events when the API supplies them (AIM-481); fall back to sessions
    // on older backends so a partial deploy never blanks the sparkline.
    const spark = d.trend.map((t) => (t.events != null ? t.events : t.sessions));
    const series = [{ label: 'Events', data: spark, token: ACCENT }];
    lineChart('#ov-trend', d.trend.map((t) => fmtDay(t.day)), series, chartSummary('Sparkline', d.trend, series));
  }

  renderOverviewAlerts(openFindings, canFindings);

  const tools = mergeVendorTools(d.tools, feeds);
  const sanctioned = tools.filter((t) => t.sanctioned);
  const unapproved = tools.filter((t) => !t.sanctioned);
  table($('#ov-tools-sanctioned'), OV_TOOL_COLS, sanctioned, {
    caption: 'Sanctioned AI tools in use',
    empty: vendorFeedEmpty(EMPTY.overviewTools, feeds),
  });
  table($('#ov-tools-unapproved'), OV_TOOL_COLS, unapproved, {
    caption: 'Unapproved AI tools in use',
    empty: vendorFeedEmpty(EMPTY.unapproved, feeds),
  });

  table($('#ov-repos'), [
    { key: 'repo', label: 'Repo', render: (r) => refCell(r.repo, { href: hashFor('repos', r.repo) }) },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'users', label: 'Users', num: true },
    { key: 'hosts', label: 'Hosts', num: true },
    { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
    { key: 'tools', label: 'Tools', num: true },
    { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
    { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => fmtUsd(r.costUsd) },
    { key: 'lastSeen', label: 'Last seen', render: (r) => fmtDay(r.lastSeen) },
  ], repos.repos, { caption: 'Repositories with AI tool activity, pseudonymous identifiers', empty: EMPTY.repos });
  state.tools = d.tools.map((t) => t.tool);
}

/* AIM-452: first-class attributed vs unattributed rate on Overview.
 * Threshold breach is already an alert-bus candidate on the API; this panel
 * is the operator-facing trend and the by-tool / by-host split. */
function renderOverviewAttribution(att, fallbackVerified) {
  const panel = $('#ov-attribution-panel');
  if (!panel) return;
  const verified = att?.lastVerifiedAt || fallbackVerified || null;
  setVerifiedStamp('#ov-attr-verified', verified);
  const emptyAttr = {
    needsEvents: true,
    title: 'No attribution data',
    body: 'Attributed vs unattributed rates appear once events land in this range.',
  };
  if (!att || att.unattributedPct == null) {
    $('#ov-attr-cards').innerHTML = [
      card('Attributed', '—'),
      card('Unattributed', '—'),
      card('Events in window', fmtInt(att?.events ?? 0)),
      card('Alert threshold', `≤${att?.targetPct ?? 5}% unattributed`),
    ].join('');
    setChartState('#ov-attr-trend', true, emptyAttr);
    table($('#ov-attr-tools'), [
      { key: 'tool', label: 'Tool' },
      { key: 'events', label: 'Events', num: true },
    ], [], { caption: 'By tool', empty: emptyAttr });
    table($('#ov-attr-hosts'), [
      { key: 'hostRef', label: 'Host' },
      { key: 'events', label: 'Events', num: true },
    ], [], { caption: 'By host', empty: emptyAttr });
    return;
  }
  const pct = att.unattributedPct;
  const tone = att.status === 'ok' ? 'good'
    : (att.status === 'degraded' || att.status === 'none_attributed' || att.alert ? 'bad' : undefined);
  const target = att.targetPct ?? 5;
  const attrPct = att.attributedPct != null
    ? att.attributedPct
    : (pct == null ? null : Math.round((1000 - pct * 10)) / 10);
  $('#ov-attr-cards').innerHTML = [
    card('Attributed', attrPct == null ? 'n/a' : `${attrPct}%`, att.status === 'ok' ? 'good' : undefined),
    card('Unattributed', `${pct}%`, tone),
    card('Unattributed events', fmtInt(att.unattributedEvents ?? 0),
      (att.unattributedEvents ?? 0) > 0 ? 'warn' : undefined),
    card('Alert', att.alert ? `OPEN — above ${target}%` : `ok ≤${target}%`, att.alert ? 'bad' : 'good'),
  ].join('');
  const trend = att.trend ?? [];
  if (trend.length === 0) {
    setChartState('#ov-attr-trend', true, emptyAttr);
  } else {
    const series = [
      {
        label: 'Attributed %',
        data: trend.map((t) => t.attributedPct ?? (t.events ? Math.round(((t.attributedEvents || 0) / t.events) * 1000) / 10 : 0)),
        token: GOOD,
      },
      {
        label: 'Unattributed %',
        data: trend.map((t) => t.unattributedPct ?? 0),
        token: PALETTE[3],
      },
    ];
    lineChart('#ov-attr-trend', trend.map((t) => fmtDay(t.day)), series,
      chartSummary('Line', trend, series));
  }
  const ratePill = (r) => {
    if (r.unattributedPct == null) return '—';
    const bad = r.unattributedPct > target;
    const pill = bad ? 'bad' : (r.unattributedPct > 0 ? 'warn' : 'ok');
    return `<span class="pill ${pill}">${esc(String(r.unattributedPct))}%</span>`;
  };
  table($('#ov-attr-tools'), [
    { key: 'tool', label: 'Tool', render: (r) => {
      const name = r.tool ?? r.key ?? '—';
      return name === '—' ? '—' : `<a href="${hashFor('tools', name)}">${esc(name)}</a>`;
    } },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'unattributedEvents', label: 'Unattributed', num: true, render: (r) => fmtInt(r.unattributedEvents) },
    { key: 'unattributedPct', label: 'Rate', num: true, render: ratePill },
  ], att.byTool ?? [], { caption: 'Unattributed rate by tool (worst first)', empty: emptyAttr });
  table($('#ov-attr-hosts'), [
    { key: 'hostRef', label: 'Host', render: (r) => refCell(r.hostRef ?? r.key) },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'unattributedEvents', label: 'Unattributed', num: true, render: (r) => fmtInt(r.unattributedEvents) },
    { key: 'unattributedPct', label: 'Rate', num: true, render: ratePill },
  ], att.byHost ?? [], {
    caption: 'Unattributed rate by host_ref (pseudonym, worst first)',
    empty: { needsEvents: true, title: 'No host breakdown', body: 'Hosts appear once events include host_ref.' },
  });
}

/* Users view (AIM-79) — pure-moved from app.js (AIM-527).
 * AIM-867: page the list at ≤100 rows; never re-assemble multi-MB full lists. */
import { $, esc } from '../lib/dom.js';
import { fmtInt, fmtTok, fmtDay, fmtMs, fmtUsd, fmtTs } from '../lib/format.js';
import { state, hashFor, api, showError } from '../lib/runtime.js';
import { entityHref } from '../lib/deeplinks.js';
import { EMPTY, table, card } from '../lib/components.js';
import { lineChart, chartSummary, charts, ACCENT, GOOD } from '../lib/charts.js';
import { hideEntityDetail, entityDetailError, entityDetailShell } from '../lib/entity-detail.js';
import { refCell, sevPill } from '../lib/ui.js';
import { navigateToView, setHash } from '../lib/router.js';
import { DEFAULT_PAGE_SIZE, pageRequest, withPageParams, resolvePage, pagerHtml, wirePager, truncationBannerHtml } from '../lib/list-page.js';
import { usersListTruncation, usersTruncationBannerCopy } from '../lib/users-list.js';

/** 1-based page for the users table; reset when the days window changes. */
let usersListPage = 1;
let usersListDays = null;

/** Paint or clear the LIMIT-cap honesty banner (AIM-865). */
export function renderUsersTruncationBanner(payload) {
  const el = $('#users-truncation-banner');
  if (!el) return;
  const copy = usersTruncationBannerCopy(usersListTruncation(payload));
  if (!copy) {
    el.hidden = true;
    el.textContent = '';
    return;
  }
  el.hidden = false;
  el.innerHTML = `<b>Incomplete user list.</b> ${esc(copy)}`;
}

export async function loadUsers() {
  try {
    if (usersListDays !== state.days) {
      usersListPage = 1;
      usersListDays = state.days;
    }
    const req = pageRequest({ page: usersListPage, pageSize: DEFAULT_PAGE_SIZE });
    const d = await api(withPageParams(`/api/users?days=${state.days}`, req));
    // AIM-865: fleet-wide hard cap honesty (separate from AIM-867 page banner).
    renderUsersTruncationBanner(d);
    const page = resolvePage({
      rows: d.users,
      total: d.total,
      limit: d.limit,
      offset: d.offset,
      requestedLimit: req.limit,
      requestedOffset: req.offset,
      truncated: d.truncated,
    });
    // Keep page index in sync if the server snapped offset (e.g. past end).
    usersListPage = page.page;

    const bannerHost = $('#users-page-banner');
    if (bannerHost) bannerHost.innerHTML = truncationBannerHtml(page, { noun: 'users' });

    table($('#users-table'), [
      { key: 'pseudonym', label: 'Pseudonym', render: (r) => refCell(r.pseudonym, { href: hashFor('users', r.pseudonym) }) },
      { key: 'team', label: 'Team', render: (r) => (r.team ? `<a href="${hashFor('teams', r.team)}">${esc(r.team)}</a>` : '(unattributed)') },
      { key: 'tools', label: 'Tools', num: true },
      { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
      { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
      { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => fmtUsd(r.costUsd) },
      { key: 'flagHits', label: 'Flags', num: true, render: (r) => (r.flagHits > 0 ? `<span class="pill bad">${esc(r.flagHits)}</span>` : '0') },
      { key: 'lastActive', label: 'Last active', render: (r) => fmtDay(r.lastActive) },
    ], page.rows, { caption: 'Per-user AI usage, pseudonymous identifiers (paged)', empty: EMPTY.users });

    const pagerHost = $('#users-pager');
    if (pagerHost) {
      pagerHost.innerHTML = pagerHtml(page, {
        idPrefix: 'users-page',
        noun: 'users',
        label: 'Users table pagination',
      });
      wirePager(pagerHost, 'users-page', {
        onPrev: () => { if (usersListPage > 1) { usersListPage -= 1; loadUsers(); } },
        onNext: () => { if (page.hasNext) { usersListPage += 1; loadUsers(); } },
      });
    }
    await renderUserDetail();
  } catch (err) {
    /* Expected for non-security-group users (403) — surface as a retryable banner, not a broken table. */
    showError('users', err);
  }
}

export async function renderUserDetail() {
  const box = $('#user-detail');
  if (!state.entity) {
    hideEntityDetail(box, () => {
      charts['#user-detail-trend']?.destroy();
      delete charts['#user-detail-trend'];
    });
    return;
  }
  let d, tc;
  try {
    [d, tc] = await Promise.all([
      api(`/api/users/${encodeURIComponent(state.entity)}?days=${state.days}`),
      api(`/api/tool-calls?days=${state.days}&user=${encodeURIComponent(state.entity)}`),
    ]);
  } catch (err) {
    entityDetailError(box, { view: 'users', backLabel: 'Users', message: err.message });
    return;
  }
  const s = d.summary;
  const teamLabel = s.team ?? '(unattributed)';
  const teamCard = s.team
    ? `<a href="${hashFor('teams', s.team)}">${esc(teamLabel)}</a>`
    : esc(teamLabel);
  entityDetailShell(box, {
    view: 'users',
    backLabel: 'Users',
    title: d.pseudonym,
    cards: [
      card('Team', teamLabel),
      card('Sessions', fmtInt(s.sessions)),
      card('Tools', fmtInt(s.tools)),
      card('Hosts', fmtInt(s.hosts)),
      card('Events', fmtInt(s.events)),
      card('Tokens', fmtTok(s.tokensInput + s.tokensOutput)),
      card('Est. cost', fmtUsd(s.costUsd)),
      card('Flag hits', fmtInt(s.flagHits), s.flagHits > 0 ? 'bad' : 'good'),
      card('Findings', fmtInt(d.findings.length), d.findings.length > 0 ? 'bad' : 'good'),
      card('Last active', fmtDay(s.lastActive)),
    ],
    body: `
    <p class="hint">Team: ${teamCard}</p>
    <div class="chart-box"><canvas id="user-detail-trend" role="img" aria-label="Line chart of daily events and flag hits for this user"></canvas></div>
    <h2>Tools used</h2><div class="table-wrap" tabindex="0" role="region" aria-label="Tools used by this user, scrollable"><table id="user-detail-tools"></table></div>
    <h2>Tool-call mix <span class="hint">agent tool invocations by action class — metadata only, arguments are never stored</span></h2><div class="table-wrap" tabindex="0" role="region" aria-label="Tool-call mix for this user, scrollable"><table id="user-detail-mix"></table></div>
    <h2>Top tools <span class="hint">most-invoked agent tools, top 20</span></h2><div class="table-wrap" tabindex="0" role="region" aria-label="Top tools for this user, scrollable"><table id="user-detail-toptools"></table></div>
    <h2>Recent sessions <span class="hint">latest 50</span></h2><div class="table-wrap" tabindex="0" role="region" aria-label="Recent sessions for this user, scrollable"><table id="user-detail-sessions"></table></div>
    <h2>Flag hits <span class="hint">latest 100 — detector names only, matched content is never stored</span></h2><div class="table-wrap" tabindex="0" role="region" aria-label="Flag hit timeline for this user, scrollable"><table id="user-detail-flags"></table></div>
    <h2>Linked findings</h2><div class="table-wrap" tabindex="0" role="region" aria-label="Findings linked to this user, scrollable"><table id="user-detail-findings"></table></div>
    <p><a class="btn btn-ghost btn-sm" id="open-findings-console" href="${esc(entityHref('findings', null, { days: state.days }))}">Triage in findings console →</a></p>`,
  });
  // AIM-589: navigate via the hash (preserves days) instead of a synthetic tab click.
  box.querySelector('#open-findings-console')?.addEventListener('click', (ev) => {
    const href = entityHref('findings', null, { days: state.days });
    if (!setHash(location, href)) navigateToView('findings');
    ev.preventDefault();
  });
  const userSeries = [
    { label: 'Events', data: d.trend.map((t) => t.events), token: ACCENT },
    { label: 'Sessions', data: d.trend.map((t) => t.sessions), token: GOOD },
    { label: 'Flag hits', data: d.trend.map((t) => t.flagHits), token: '--bad' },
  ];
  lineChart('#user-detail-trend', d.trend.map((t) => fmtDay(t.day)), userSeries, chartSummary('Line', d.trend, userSeries));
  table($('#user-detail-tools'), [
    { key: 'tool', label: 'Tool', render: (r) => `<a href="${hashFor('tools', r.tool)}">${esc(r.tool)}</a>` },
    { key: 'sanctioned', label: 'Status', render: (r) => (r.sanctioned ? '<span class="pill ok">sanctioned</span>' : '<span class="pill bad">unapproved</span>') },
    { key: 'models', label: 'Models', render: (r) => esc(r.models.join(', ') || '—') },
    { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
    { key: 'flagHits', label: 'Flags', num: true, render: (r) => (r.flagHits > 0 ? `<span class="pill bad">${esc(r.flagHits)}</span>` : '0') },
    { key: 'lastSeen', label: 'Last seen', render: (r) => fmtDay(r.lastSeen) },
  ], d.tools, { caption: 'Tools used by this user', empty: EMPTY.userTools });
  table($('#user-detail-mix'), [
    { key: 'actionClass', label: 'Action class', render: (r) => `<span class="pill muted">${esc(r.actionClass)}</span>` },
    { key: 'calls', label: 'Calls', num: true, render: (r) => fmtInt(r.calls) },
    { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
    { key: 'durationMs', label: 'Duration', num: true, render: (r) => fmtMs(r.durationMs) },
  ], tc.byActionClass, { caption: 'Tool-call mix by action class for this user', empty: EMPTY.userToolCalls });
  table($('#user-detail-toptools'), [
    { key: 'tool', label: 'Tool', render: (r) => (r.tool ? `<a href="${hashFor('tools', r.tool)}">${esc(r.tool)}</a>` : '—') },
    { key: 'actionClass', label: 'Action class' },
    { key: 'mcpServer', label: 'MCP server', render: (r) => esc(r.mcpServer ?? '—') },
    { key: 'calls', label: 'Calls', num: true, render: (r) => fmtInt(r.calls) },
    { key: 'durationMs', label: 'Duration', num: true, render: (r) => fmtMs(r.durationMs) },
  ], tc.topTools, { caption: 'Most-invoked agent tools for this user', empty: EMPTY.userToolCalls });
  table($('#user-detail-sessions'), [
    { key: 'sessionId', label: 'Session', render: (r) => `<span class="mono">${esc(r.sessionId)}</span>` },
    { key: 'started', label: 'Started', render: (r) => fmtTs(r.started) },
    { key: 'ended', label: 'Ended', render: (r) => fmtTs(r.ended) },
    {
      key: 'tools', label: 'Tools',
      render: (r) => (r.tools ?? []).map((t) => `<a href="${hashFor('tools', t)}">${esc(t)}</a>`).join(', ') || '—',
    },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
    { key: 'flagHits', label: 'Flags', num: true, render: (r) => (r.flagHits > 0 ? `<span class="pill bad">${esc(r.flagHits)}</span>` : '0') },
  ], d.sessions, { caption: 'Recent sessions for this user', empty: EMPTY.userSessions });
  table($('#user-detail-flags'), [
    { key: 'ts', label: 'Time', render: (r) => fmtTs(r.ts) },
    { key: 'detector', label: 'Detector' },
    { key: 'category', label: 'Category', render: (r) => `<span class="pill ${r.category === 'secret' ? 'bad' : 'warn'}">${esc(r.category)}</span>` },
    { key: 'tool', label: 'Tool', render: (r) => (r.tool ? `<a href="${hashFor('tools', r.tool)}">${esc(r.tool)}</a>` : '—') },
    { key: 'sessionId', label: 'Session', render: (r) => `<span class="mono">${esc(r.sessionId)}</span>` },
  ], d.flags, { caption: 'Match-flag timeline for this user', empty: EMPTY.userFlags });
  table($('#user-detail-findings'), [
    { key: 'severity', label: 'Severity', render: (r) => sevPill(r.severity) },
    { key: 'title', label: 'Finding' },
    { key: 'ruleId', label: 'Rule' },
    { key: 'status', label: 'Status' },
    { key: 'detectedAt', label: 'Detected', render: (r) => fmtTs(r.detectedAt) },
  ], d.findings, { caption: 'Findings linked to this user', empty: EMPTY.userFindings });
}

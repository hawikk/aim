/* Repos view — pure-moved from app.js. */
import { $, esc } from '../lib/dom.js';
import { fmtInt, fmtTok, fmtDay, fmtUsd } from '../lib/format.js';
import { state, hashFor, api } from '../lib/runtime.js';
import { EMPTY, table, card } from '../lib/components.js';
import { lineChart, chartSummary, ACCENT, GOOD } from '../lib/charts.js';
import { hideEntityDetail, entityDetailError, entityDetailShell } from '../lib/entity-detail.js';

/* ---------- Repos view ---------- */
export const fmtRepoRef = (r) => (r.label ? r.label : `${String(r.repo).slice(0, 12)}…`);

export async function loadRepos() {
  const d = await api(`/api/repos?days=${state.days}`);
  renderRepoTable(d);
  await renderRepoDetail();
}

export function renderRepoTable(d) {
  // The label column exists only when the API joined repo_labels in — i.e.
  // the caller is in the security group (de-pseudonymization is role-gated).
  const hasLabels = d.repos.some((r) => 'label' in r);
  const cols = [
    {
      key: 'repo', label: 'Repo',
      render: (r) => `<a href="${hashFor('repos', r.repo)}" title="${esc(r.repo)}"><span class="mono">${esc(fmtRepoRef(r))}</span></a>`,
    },
    ...(hasLabels ? [{ key: 'label', label: 'Label', render: (r) => (r.label ? esc(r.label) : '—') }] : []),
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
    { key: 'tools', label: 'Tools', num: true },
    { key: 'users', label: 'Users', num: true },
    { key: 'hosts', label: 'Hosts', num: true },
    { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
    { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => fmtUsd(r.costUsd) },
    { key: 'flagHits', label: 'Flags', num: true, render: (r) => (r.flagHits > 0 ? `<span class="pill bad">${esc(r.flagHits)}</span>` : '0') },
    { key: 'lastSeen', label: 'Last seen', render: (r) => fmtDay(r.lastSeen) },
  ];
  table($('#repos-table'), cols, d.repos, { caption: 'Repositories with AI tool activity, pseudonymous identifiers', empty: EMPTY.repos });
}

// Drill-down panel for a single repo: aggregate cards, per-tool breakdown,
// daily trend, and flag hits by detector — from /api/repos/:repoRef.
export async function renderRepoDetail() {
  const box = $('#repo-detail');
  if (!state.entity) {
    hideEntityDetail(box);
    return;
  }
  let d;
  try {
    d = await api(`/api/repos/${encodeURIComponent(state.entity)}?days=${state.days}`);
  } catch (err) {
    entityDetailError(box, { view: 'repos', backLabel: 'Repos', message: err.message });
    return;
  }
  const name = d.label ?? `${String(d.repo).slice(0, 12)}…`;
  entityDetailShell(box, {
    view: 'repos',
    backLabel: 'Repos',
    titleHtml: `<span class="mono" title="${esc(d.repo)}">${esc(name)}</span>`,
    cards: [
      card('Events', fmtInt(d.summary.events)),
      card('Sessions', fmtInt(d.summary.sessions)),
      card('Tools', fmtInt(d.summary.tools)),
      card('Users', fmtInt(d.summary.users)),
      card('Hosts', fmtInt(d.summary.hosts)),
      card('Tokens', fmtTok(d.summary.tokens)),
      card('Est. cost', fmtUsd(d.summary.costUsd)),
      card('Flag hits', fmtInt(d.summary.flagHits), d.summary.flagHits > 0 ? 'bad' : 'good'),
      card('First seen', fmtDay(d.summary.firstSeen)),
      card('Last seen', fmtDay(d.summary.lastSeen)),
    ],
    body: `
    <div class="chart-box"><canvas id="repo-detail-trend" role="img" aria-label="Line chart of daily events and tokens for this repo"></canvas></div>
    <div class="table-wrap" tabindex="0" role="region" aria-label="Per-tool usage in this repo, scrollable"><table id="repo-detail-tools"></table></div>
    <div class="table-wrap" tabindex="0" role="region" aria-label="Guardrail flag hits in this repo, scrollable"><table id="repo-detail-flags"></table></div>`,
  });
  const detSeries = [
    { label: 'Events', data: d.trend.map((t) => t.events), token: ACCENT },
    { label: 'Tokens', data: d.trend.map((t) => t.tokens), token: GOOD },
  ];
  lineChart('#repo-detail-trend', d.trend.map((t) => fmtDay(t.day)), detSeries, chartSummary('Line', d.trend, detSeries));
  table($('#repo-detail-tools'), [
    { key: 'tool', label: 'Tool', render: (r) => `<a href="${hashFor('tools', r.tool)}">${esc(r.tool)}</a>` },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
    { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
    { key: 'flagHits', label: 'Flags', num: true, render: (r) => (r.flagHits > 0 ? `<span class="pill bad">${esc(r.flagHits)}</span>` : '0') },
    { key: 'lastSeen', label: 'Last seen', render: (r) => fmtDay(r.lastSeen) },
  ], d.byTool, { caption: 'Per-tool usage in this repo', empty: EMPTY.repos });
  table($('#repo-detail-flags'), [
    { key: 'detector', label: 'Detector' },
    { key: 'category', label: 'Category', render: (r) => `<span class="pill ${r.category === 'secret' ? 'bad' : 'warn'}">${esc(r.category)}</span>` },
    { key: 'hits', label: 'Hits', num: true, render: (r) => fmtInt(r.hits) },
    { key: 'firstSeen', label: 'First seen', render: (r) => fmtDay(r.firstSeen) },
    { key: 'lastSeen', label: 'Last seen', render: (r) => fmtDay(r.lastSeen) },
  ], d.flags, { caption: 'Guardrail flag hits in this repo by detector', empty: EMPTY.flags });
}

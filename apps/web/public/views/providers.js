/* Providers view — pure-moved from app.js (AIM-527). */
import { $, esc } from '../lib/dom.js';
import { fmtInt, fmtTok, fmtDay, fmtUsd } from '../lib/format.js';
import { state, hashFor, api } from '../lib/runtime.js';
import { EMPTY, table, card, skeletonCards } from '../lib/components.js';
import { lineChart, barChart, setChartState, chartSummary, ACCENT, GOOD, PALETTE } from '../lib/charts.js';
import { hideEntityDetail, entityDetailError, entityDetailShell } from '../lib/entity-detail.js';

export async function loadProviders() {
  $('#prov-cards').innerHTML = skeletonCards(6);
  const src = state.source === 'all' ? '' : `&source=${state.source}`;
  const d = await api(`/api/providers?days=${state.days}${src}`);
  renderProviderDetail(d);
  const bySrc = Object.fromEntries(d.bySource.map((s) => [s.source, s]));
  $('#prov-cards').innerHTML = [
    card('Providers seen', fmtInt(d.providers.length)),
    card('Proxy events', fmtInt(bySrc.proxy?.events ?? 0)),
    card('Endpoint events', fmtInt(bySrc.endpoint?.events ?? 0)),
    card('Proxy hosts', fmtInt(bySrc.proxy?.hosts ?? 0)),
    card('Total tokens', fmtTok(d.providers.reduce((a, p) => a + p.tokens, 0))),
    card('Est. cost', fmtUsd(d.providers.reduce((a, p) => a + p.costUsd, 0))),
  ].join('');
  table($('#prov-table'), [
    { key: 'provider', label: 'Provider', render: (r) => `<a href="${hashFor('providers', r.provider)}">${esc(r.provider)}</a>` },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'tools', label: 'Tools', num: true },
    { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
    { key: 'hosts', label: 'Hosts', num: true, render: (r) => fmtInt(r.hosts) },
    { key: 'users', label: 'Users', num: true, render: (r) => fmtInt(r.users) },
    { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
    { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => fmtUsd(r.costUsd) },
    { key: 'firstSeen', label: 'First seen', render: (r) => fmtDay(r.firstSeen) },
    { key: 'lastSeen', label: 'Last seen', render: (r) => fmtDay(r.lastSeen) },
  ], d.providers, { caption: 'AI providers with usage volumes', empty: EMPTY.providers });
  if (d.providers.length === 0) {
    setChartState('#prov-chart', true, EMPTY.providers);
    setChartState('#prov-trend', true, EMPTY.provTrend);
    return;
  }
  barChart('#prov-chart', d.providers.map((p) => p.provider), d.providers.map((p) => p.events), 'Events',
    `Bar chart of events by provider. ${d.providers.map((p) => `${p.provider}: ${fmtInt(p.events)}`).join('; ')}.`);
  const days = [...new Set(d.trend.map((t) => fmtDay(t.day)))];
  const providers = [...new Set(d.trend.map((t) => t.provider))];
  const provSeries = providers.map((p, i) => ({
    label: p,
    data: days.map((day) => d.trend.find((t) => fmtDay(t.day) === day && t.provider === p)?.events ?? 0),
    token: PALETTE[i % PALETTE.length],
  }));
  lineChart('#prov-trend', days, provSeries, chartSummary('Line', days, provSeries));
}

// Drill-down panel for a single provider: aggregate cards + its daily trend,
// sliced client-side from the /api/providers payload (no dedicated endpoint yet).
export function renderProviderDetail(d) {
  const box = $('#prov-detail');
  if (!state.entity) {
    hideEntityDetail(box);
    return;
  }
  const p = d.providers.find((x) => x.provider === state.entity);
  if (!p) {
    entityDetailError(box, { view: 'providers', backLabel: 'Providers', message: `No provider “${state.entity}” in this range/source filter.` });
    return;
  }
  entityDetailShell(box, {
    view: 'providers',
    backLabel: 'Providers',
    title: p.provider,
    cards: [
      card('Events', fmtInt(p.events)),
      card('Tools', fmtInt(p.tools)),
      card('Sessions', fmtInt(p.sessions)),
      card('Hosts', fmtInt(p.hosts)),
      card('Users', fmtInt(p.users)),
      card('Tokens', fmtTok(p.tokens)),
      card('Est. cost', fmtUsd(p.costUsd)),
      card('First seen', fmtDay(p.firstSeen)),
      card('Last seen', fmtDay(p.lastSeen)),
    ],
    body: `<div class="chart-box"><canvas id="prov-detail-trend" role="img" aria-label="Line chart of daily events and tokens for this provider"></canvas></div>`,
  });
  const rows = d.trend.filter((t) => t.provider === p.provider);
  const detSeries = [
    { label: 'Events', data: rows.map((t) => t.events), token: ACCENT },
    { label: 'Tokens', data: rows.map((t) => t.tokens), token: GOOD },
  ];
  lineChart('#prov-detail-trend', rows.map((t) => fmtDay(t.day)), detSeries, chartSummary('Line', rows, detSeries));
}

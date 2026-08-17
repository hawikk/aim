/* Apps view (AIM-105 / AIM-574 / AIM-737) — pure-moved from app.js (AIM-527).
 *
 * OTel GenAI application telemetry: model distribution, token metering (in/out),
 * estimated cost by service and by model, exportable CSV. Metadata only —
 * deliberately no employee/user dimension. Complements App-LLM (proxy metering). */
import { $, esc } from '../lib/dom.js';
import { fmtInt, fmtTok, fmtDay, fmtMs, fmtUsd } from '../lib/format.js';
import { state, hashFor, api } from '../lib/runtime.js';
import { EMPTY, table, card, skeletonCards } from '../lib/components.js';
import { renderVendorFeedBanner, vendorFeedEmpty } from '../lib/vendor-feeds.js';
import { lineChart, barChart, setChartState, chartSummary, ACCENT, GOOD } from '../lib/charts.js';
import { hideEntityDetail, entityDetailError, entityDetailShell } from '../lib/entity-detail.js';

function modelTokens(m) {
  if (m.tokens != null) return m.tokens;
  return (m.tokensInput ?? 0) + (m.tokensOutput ?? 0);
}

/** Prefer API fleet rollup; fall back to client merge of per-app models. */
export function fleetModels(d) {
  if (Array.isArray(d.models) && d.models.length > 0) return d.models;
  const byKey = new Map();
  for (const app of d.apps ?? []) {
    for (const m of app.models ?? []) {
      const key = `${m.model}\0${m.provider ?? ''}`;
      const cur = byKey.get(key) ?? {
        model: m.model,
        provider: m.provider,
        services: 0,
        requests: 0,
        tokensInput: 0,
        tokensOutput: 0,
        tokens: 0,
        costUsd: 0,
        errors: 0,
      };
      cur.services += 1;
      cur.requests += m.requests ?? 0;
      cur.tokensInput += m.tokensInput ?? 0;
      cur.tokensOutput += m.tokensOutput ?? 0;
      cur.tokens += modelTokens(m);
      cur.costUsd += m.costUsd ?? 0;
      cur.errors += m.errors ?? 0;
      byKey.set(key, cur);
    }
  }
  return [...byKey.values()].sort((a, b) => modelTokens(b) - modelTokens(a));
}

function topModelsCell(r) {
  const models = r.models ?? [];
  if (models.length === 0) return '—';
  const ranked = [...models].sort((a, b) => modelTokens(b) - modelTokens(a));
  const top = ranked.slice(0, 2).map((m) => m.model).join(', ');
  const more = ranked.length > 2 ? ` +${ranked.length - 2}` : '';
  return `<span title="${esc(ranked.map((m) => m.model).join(', '))}">${esc(top)}${esc(more)}</span>`;
}

export async function loadApps() {
  $('#apps-cards').innerHTML = skeletonCards(6);
  const [d, vendorFeeds] = await Promise.all([
    api(`/api/apps/llm?days=${state.days}`),
    api(`/api/vendor-admin/feeds?days=${state.days}`).catch(() => null),
  ]);
  const feeds = vendorFeeds?.feeds ?? d.vendorFeeds ?? [];
  renderVendorFeedBanner($('#apps-vendor-feeds'), feeds);
  renderAppsDetail(d);
  const totRequests = d.apps.reduce((a, p) => a + p.requests, 0);
  const totErrors = d.apps.reduce((a, p) => a + p.errors, 0);
  const totCost = d.apps.reduce((a, p) => a + (p.costUsd ?? 0), 0);
  const totTokens = d.apps.reduce((a, p) => a + p.tokensInput + p.tokensOutput, 0);
  $('#apps-cards').innerHTML = [
    card('Instrumented services', fmtInt(d.services)),
    card('Providers seen', fmtInt(d.providersSeen.length)),
    card('Requests', fmtInt(totRequests)),
    card('Tokens', fmtTok(totTokens)),
    card('Est. cost', fmtUsd(totCost)),
    card('Errors', fmtInt(totErrors), totErrors > 0 ? 'bad' : 'good'),
  ].join('');
  table($('#apps-table'), [
    { key: 'service', label: 'Service', render: (r) => `<a href="${hashFor('apps', r.service)}">${esc(r.service)}</a>` },
    { key: 'providers', label: 'Providers', num: true, render: (r) => fmtInt(r.providers) },
    { key: 'models', label: 'Top models', render: (r) => topModelsCell(r) },
    { key: 'requests', label: 'Requests', num: true, render: (r) => fmtInt(r.requests) },
    { key: 'tokensInput', label: 'Tokens in', num: true, render: (r) => fmtTok(r.tokensInput) },
    { key: 'tokensOutput', label: 'Tokens out', num: true, render: (r) => fmtTok(r.tokensOutput) },
    { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => fmtUsd(r.costUsd) },
    { key: 'errors', label: 'Errors', num: true, render: (r) => (r.errors > 0 ? `<span class="pill bad">${esc(fmtInt(r.errors))} · ${(r.errorRate * 100).toFixed(1)}%</span>` : '0') },
    { key: 'avgDurationMs', label: 'Avg', num: true, render: (r) => fmtMs(r.avgDurationMs) },
    { key: 'p95DurationMs', label: 'p95', num: true, render: (r) => fmtMs(r.p95DurationMs) },
    { key: 'firstSeen', label: 'First seen', render: (r) => fmtDay(r.firstSeen) },
    { key: 'lastSeen', label: 'Last seen', render: (r) => fmtDay(r.lastSeen) },
  ], d.apps, { caption: 'Per-application LLM telemetry from OTel GenAI instrumentation', empty: vendorFeedEmpty(EMPTY.apps, feeds) });
  renderFleetModels(d);
}

/** Fleet-wide model distribution: table + cost + bar chart (AIM-574 / AIM-737). */
export function renderFleetModels(d) {
  return renderAppsModelDistribution(d);
}

/** Alias kept for AIM-574 static contract tests and callers. */
export function renderAppsModelDistribution(d) {
  const models = fleetModels(d);
  const totTokens = models.reduce((sum, m) => sum + modelTokens(m), 0);
  const totCost = models.reduce((sum, m) => sum + (m.costUsd ?? 0), 0);
  const tableEl = $('#apps-models-table');
  if (!tableEl) return;
  table(tableEl, [
    { key: 'model', label: 'Model' },
    { key: 'provider', label: 'Provider', render: (r) => esc(r.provider || '—') },
    { key: 'services', label: 'Services', num: true, render: (r) => fmtInt(r.services ?? 0) },
    { key: 'requests', label: 'Requests', num: true, render: (r) => fmtInt(r.requests) },
    { key: 'tokensInput', label: 'Tokens in', num: true, render: (r) => fmtTok(r.tokensInput ?? 0) },
    { key: 'tokensOutput', label: 'Tokens out', num: true, render: (r) => fmtTok(r.tokensOutput ?? 0) },
    {
      key: 'tokens',
      label: 'Share',
      num: true,
      render: (r) => {
        const t = modelTokens(r);
        const pct = totTokens > 0 ? ((t / totTokens) * 100).toFixed(1) : '0.0';
        return `${fmtTok(t)} · ${pct}%`;
      },
    },
    {
      key: 'costUsd',
      label: 'Est. cost',
      num: true,
      render: (r) => {
        const c = r.costUsd ?? 0;
        const pct = totCost > 0 ? ((c / totCost) * 100).toFixed(1) : '0.0';
        return `${fmtUsd(c)} · ${pct}%`;
      },
    },
    { key: 'errors', label: 'Errors', num: true, render: (r) => (r.errors > 0 ? `<span class="pill bad">${esc(fmtInt(r.errors))}</span>` : '0') },
  ], models, {
    caption: 'Model distribution across instrumented apps (metadata only — no prompt content)',
    empty: EMPTY.appsModelsFleet,
  });

  const chartEl = $('#apps-models-chart');
  if (!chartEl) return;
  if (models.length === 0) {
    setChartState('#apps-models-chart', true, EMPTY.appsModelsFleet);
    return;
  }
  // Top N by total tokens so a long tail stays legible.
  const top = models.slice(0, 12);
  barChart(
    '#apps-models-chart',
    top.map((m) => m.model),
    top.map((m) => modelTokens(m)),
    'Tokens',
    `Bar chart of total tokens by model across ${models.length} model(s). Top ${top.length} shown. Fleet est. cost ${fmtUsd(totCost)}.`,
  );
}

// Drill-down panel for a single service: aggregate cards, model inventory and
// its daily requests/tokens trend, sliced from the /api/apps/llm payload.
export function renderAppsDetail(d) {
  const box = $('#apps-detail');
  if (!state.entity) {
    hideEntityDetail(box);
    return;
  }
  const a = d.apps.find((x) => x.service === state.entity);
  if (!a) {
    entityDetailError(box, { view: 'apps', backLabel: 'Apps', message: `No app “${state.entity}” in this range.` });
    return;
  }
  entityDetailShell(box, {
    view: 'apps',
    backLabel: 'Apps',
    title: a.service,
    cards: [
      card('Requests', fmtInt(a.requests)),
      card('Tokens in', fmtTok(a.tokensInput)),
      card('Tokens out', fmtTok(a.tokensOutput)),
      card('Models', fmtInt((a.models ?? []).length)),
      card('Est. cost', fmtUsd(a.costUsd)),
      card('Errors', fmtInt(a.errors), a.errors > 0 ? 'bad' : 'good'),
      card('Error rate', `${(a.errorRate * 100).toFixed(1)}%`, a.errorRate > 0 ? 'warn' : undefined),
      card('Avg latency', fmtMs(a.avgDurationMs)),
      card('p95 latency', fmtMs(a.p95DurationMs)),
      card('First seen', fmtDay(a.firstSeen)),
      card('Last seen', fmtDay(a.lastSeen)),
    ],
    body: `
    <div class="chart-box"><canvas id="apps-detail-trend" role="img" aria-label="Line chart of daily requests and tokens for this app"></canvas></div>
    <h2>Model distribution <span class="hint">which models this service called, with tokens and est. cost (metadata only)</span></h2>
    <div class="chart-box"><canvas id="apps-detail-models-chart" role="img" aria-label="Bar chart of tokens by model for this app"></canvas></div>
    <div class="table-wrap" tabindex="0" role="region" aria-label="Model inventory for this app, scrollable"><table id="apps-detail-models"></table></div>`,
  });
  const rows = a.trend ?? [];
  if (rows.length === 0) {
    setChartState('#apps-detail-trend', true, EMPTY.appsTrend);
  } else {
    const detSeries = [
      { label: 'Requests', data: rows.map((t) => t.requests), token: ACCENT },
      { label: 'Tokens', data: rows.map((t) => t.tokens), token: GOOD },
    ];
    lineChart('#apps-detail-trend', rows.map((t) => fmtDay(t.day)), detSeries, chartSummary('Line', rows, detSeries));
  }
  const models = a.models ?? [];
  const totTokens = models.reduce((sum, m) => sum + modelTokens(m), 0);
  const totCost = models.reduce((sum, m) => sum + (m.costUsd ?? 0), 0);
  table($('#apps-detail-models'), [
    { key: 'model', label: 'Model' },
    { key: 'provider', label: 'Provider', render: (r) => esc(r.provider || '—') },
    { key: 'requests', label: 'Requests', num: true, render: (r) => fmtInt(r.requests) },
    { key: 'tokensInput', label: 'Tokens in', num: true, render: (r) => fmtTok(r.tokensInput ?? 0) },
    { key: 'tokensOutput', label: 'Tokens out', num: true, render: (r) => fmtTok(r.tokensOutput ?? 0) },
    {
      key: 'tokens',
      label: 'Share',
      num: true,
      render: (r) => {
        const t = modelTokens(r);
        const pct = totTokens > 0 ? ((t / totTokens) * 100).toFixed(1) : '0.0';
        return `${fmtTok(t)} · ${pct}%`;
      },
    },
    {
      key: 'costUsd',
      label: 'Est. cost',
      num: true,
      render: (r) => {
        const c = r.costUsd ?? 0;
        const pct = totCost > 0 ? ((c / totCost) * 100).toFixed(1) : '0.0';
        return `${fmtUsd(c)}${totCost > 0 ? ` · ${pct}%` : ''}`;
      },
    },
    { key: 'errors', label: 'Errors', num: true, render: (r) => (r.errors > 0 ? `<span class="pill bad">${esc(fmtInt(r.errors))}</span>` : '0') },
  ], models, { caption: `Models called by ${a.service}`, empty: EMPTY.appsModels });
  if (models.length === 0) {
    setChartState('#apps-detail-models-chart', true, EMPTY.appsModels);
  } else {
    barChart(
      '#apps-detail-models-chart',
      models.map((m) => m.model),
      models.map((m) => modelTokens(m)),
      'Tokens',
      `Bar chart of tokens by model for ${a.service}. ${models.length} model(s). Est. cost ${fmtUsd(a.costUsd)}.`,
    );
  }
}

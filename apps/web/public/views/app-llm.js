/* App-LLM view — pure-moved from app.js. */
import { $, esc } from '../lib/dom.js';
import { fmtInt, fmtTok, fmtDay, fmtUsd, fmtTs } from '../lib/format.js';
import { state, hashFor, api } from '../lib/runtime.js';
import { EMPTY, table, card, skeletonCards } from '../lib/components.js';
import { lineChart, setChartState, chartSummary, PALETTE } from '../lib/charts.js';
import { refCell } from '../lib/ui.js';

/* ---------- App-LLM view: provider-API metering by source class ----------
 * Per-provider volume/bytes/status split application vs employee vs unknown,
 * plus the shadow-AI signal: sources whose first-ever LLM API call is recent.
 *
 * when OTel sources exist, surface a compact model/token/cost
 * summary that deep-links to Apps (where full distribution lives). Proxy path
 * still has no tokens/models by design — we never invent them here. */
export const CLASS_PILL = { application: 'ok', employee: 'muted', unknown: 'warn' };

export async function loadAppLlm() {
  $('#al-cards').innerHTML = skeletonCards(4);
  const [d, otel] = await Promise.all([
    api(`/api/app-llm?days=${state.days}`),
    api(`/api/apps/llm?days=${state.days}`).catch(() => null),
  ]);
  const byClass = {};
  for (const r of d.byProviderClass) {
    const c = byClass[r.trafficClass] ?? { events: 0, bytesDown: 0, hosts: 0 };
    c.events += r.events;
    c.bytesDown += r.bytesDown;
    c.hosts = Math.max(c.hosts, r.hosts);
    byClass[r.trafficClass] = c;
  }
  $('#al-cards').innerHTML = [
    card('Application events', fmtInt(byClass.application?.events ?? 0)),
    card('Employee events', fmtInt(byClass.employee?.events ?? 0)),
    card('Unknown-class events', fmtInt(byClass.unknown?.events ?? 0), byClass.unknown?.events > 0 ? 'warn' : undefined),
    card('New sources', fmtInt(d.newSources.length), d.newSources.length > 0 ? 'bad' : 'good'),
  ].join('');
  renderAppLlmOtelSummary(otel);
  table($('#al-table'), [
    { key: 'provider', label: 'Provider' },
    { key: 'trafficClass', label: 'Source class', render: (r) => `<span class="pill ${CLASS_PILL[r.trafficClass] ?? 'muted'}">${esc(r.trafficClass)}</span>` },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'hosts', label: 'Hosts', num: true, render: (r) => fmtInt(r.hosts) },
    { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
    { key: 'bytesDown', label: 'Bytes down', num: true, render: (r) => fmtTok(r.bytesDown) },
    { key: 'status2xx', label: '2xx', num: true, render: (r) => fmtInt(r.status2xx) },
    { key: 'status4xx', label: '4xx', num: true, render: (r) => (r.status4xx > 0 ? `<span class="pill warn">${esc(r.status4xx)}</span>` : '0') },
    { key: 'status5xx', label: '5xx', num: true, render: (r) => (r.status5xx > 0 ? `<span class="pill bad">${esc(r.status5xx)}</span>` : '0') },
    { key: 'firstSeen', label: 'First seen', render: (r) => fmtDay(r.firstSeen) },
    { key: 'lastSeen', label: 'Last seen', render: (r) => fmtDay(r.lastSeen) },
  ], d.byProviderClass, { caption: 'Provider API metering by source class', empty: EMPTY.appLlm });
  table($('#al-new'), [
    { key: 'hostRef', label: 'Source (pseudonym)', render: (r) => refCell(r.hostRef) },
    { key: 'provider', label: 'Provider' },
    { key: 'firstSeen', label: 'First seen', render: (r) => fmtTs(r.firstSeen) },
  ], d.newSources, { caption: 'Sources whose first-ever LLM API call falls inside the window', empty: EMPTY.appLlmNew });
  if (d.trend.length === 0) {
    setChartState('#al-trend', true, EMPTY.appLlm);
    return;
  }
  const days = [...new Set(d.trend.map((t) => fmtDay(t.day)))];
  const seriesKeys = [...new Set(d.trend.map((t) => `${t.provider} · ${t.trafficClass}`))];
  const alSeries = seriesKeys.map((k, i) => ({
    label: k,
    data: days.map((day) => d.trend.find((t) => fmtDay(t.day) === day && `${t.provider} · ${t.trafficClass}` === k)?.events ?? 0),
    token: PALETTE[i % PALETTE.length],
  }));
  lineChart('#al-trend', days, alSeries, chartSummary('Line', days, alSeries));
}

/** Compact OTel model/token/cost teaser when instrumented apps exist. */
export function renderAppLlmOtelSummary(otel) {
  const panel = $('#al-otel-panel');
  const cards = $('#al-otel-cards');
  const hint = $('#al-otel-hint');
  if (!panel || !cards || !hint) return;
  const apps = otel?.apps ?? [];
  if (apps.length === 0) {
    panel.hidden = true;
    cards.innerHTML = '';
    hint.textContent = '';
    return;
  }
  panel.hidden = false;
  const models = otel.models?.length
    ? otel.models
    : [...new Map(apps.flatMap((a) => (a.models ?? []).map((m) => [m.model, m]))).values()];
  const tokensIn = apps.reduce((n, a) => n + (a.tokensInput ?? 0), 0);
  const tokensOut = apps.reduce((n, a) => n + (a.tokensOutput ?? 0), 0);
  const cost = apps.reduce((n, a) => n + (a.costUsd ?? 0), 0);
  const topModel = models[0];
  const pilot = apps[0];
  cards.innerHTML = [
    card('Instrumented services', fmtInt(apps.length)),
    card('Models', fmtInt(models.length)),
    card('Tokens in', fmtTok(tokensIn)),
    card('Tokens out', fmtTok(tokensOut)),
    card('Est. cost', fmtUsd(cost)),
    card('Top model', topModel ? topModel.model : '—'),
  ].join('');
  const pilotLink = pilot
    ? `<a href="${hashFor('apps', pilot.service)}">${esc(pilot.service)}</a>`
    : 'Apps';
  const modelBits = topModel
    ? ` Top model <b>${esc(topModel.model)}</b> · ${fmtTok(topModel.tokens ?? ((topModel.tokensInput ?? 0) + (topModel.tokensOutput ?? 0)))} tokens${topModel.costUsd != null ? ` · ${fmtUsd(topModel.costUsd)}` : ''}.`
    : '';
  hint.innerHTML = `OTel sources report model + token + cost metadata the proxy cannot see. Open ${pilotLink} (or <a href="${hashFor('apps')}">Apps</a>) for full model distribution and CSV export.${modelBits}`;
}

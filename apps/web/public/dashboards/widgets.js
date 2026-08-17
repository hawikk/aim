/* Widget renderers for the custom dashboards builder (split).
 * KPI tiles, charts, and tables — each re-fetches via loadSource under the
 * active time range. Gated findings widgets surface an empty/gated card when
 * the operator lacks findingsConsole. */
import { esc } from '../lib/dom.js';
import { fmtInt, fmtTok, fmtUsd, fmtDay, relTime } from '../lib/format.js';
import { emptyState, table as dataTable, card, skeletonCards } from '../lib/components.js';
import { lineChart, barChart, setChartState, chartSummary, ACCENT } from '../lib/charts.js';
import { sevPill } from '../lib/severity.js';
import { catalogEntry } from '../lib/dashboards.js';
import { loadSource } from './data.js';

export function kpiCard(widgetId, data) {
  switch (widgetId) {
    case 'kpi.activeUsers':
      return card('Active users', fmtInt(data?.totals?.activeUsers), null, null, '#/users');
    case 'kpi.events':
      return card('Events in range', fmtInt(data?.totals?.events), null, null, '#/activity');
    case 'kpi.costUsd':
      return card('Est. spend', fmtUsd(data?.totals?.costUsd), null, null, '#/teams');
    case 'kpi.openCritical': {
      if (data?.gated) {
        return card('Open critical findings', '—', null,
          '<div class="delta"><span class="base">requires analyst+</span></div>', null);
      }
      const n = data?.total ?? 0;
      return card('Open critical findings', fmtInt(n), n > 0 ? 'bad' : null,
        `<div class="delta"><span class="base">${n === 0 ? 'none open' : 'open in triage'}</span></div>`,
        '#/findings');
    }
    case 'kpi.unapproved': {
      const n = Array.isArray(data) ? data.length : 0;
      return card('Unapproved tools', fmtInt(n), n > 0 ? 'warn' : null,
        `<div class="delta"><span class="base">${n === 0 ? 'all sanctioned' : 'outside list'}</span></div>`,
        '#/security');
    }
    default:
      return card(catalogEntry(widgetId)?.label || widgetId, '—');
  }
}

export async function renderKpi(host, placement, days) {
  const entry = catalogEntry(placement.widgetId);
  host.innerHTML = skeletonCards(1);
  try {
    const data = await loadSource(entry.source, days);
    host.innerHTML = kpiCard(placement.widgetId, data);
  } catch (err) {
    host.innerHTML = emptyState({
      reason: 'error',
      title: 'Could not load KPI',
      body: err.message || 'Request failed',
    });
  }
}

export async function renderChart(host, placement, days) {
  const entry = catalogEntry(placement.widgetId);
  const canvasId = `db-chart-${placement.instanceId}`;
  host.innerHTML = `
    <div class="panel">
      <h2>${esc(entry.label)}</h2>
      <div class="chart-box"><canvas id="${esc(canvasId)}"></canvas></div>
    </div>`;
  try {
    const data = await loadSource(entry.source, days);
    if (placement.widgetId === 'chart.eventsTrend') {
      const trend = data?.trend ?? [];
      if (!trend.length) {
        setChartState(`#${canvasId}`, true, {
          reason: 'no-data',
          title: 'No activity in this range',
          body: 'Daily events will appear here once collectors report.',
          needsEvents: true,
        });
        return;
      }
      const spark = trend.map((t) => (t.events != null ? t.events : t.sessions));
      const series = [{ label: 'Events', data: spark, token: ACCENT }];
      lineChart(`#${canvasId}`, trend.map((t) => fmtDay(t.day)), series, chartSummary('Events', trend, series));
    } else if (placement.widgetId === 'chart.flagsTrend') {
      // /api/flags trend is per day×detector; sum hits per day for the sparkline.
      const raw = data?.trend ?? [];
      const byDay = new Map();
      for (const t of raw) {
        const day = t.day;
        if (!day) continue;
        byDay.set(day, (byDay.get(day) || 0) + (t.hits ?? t.count ?? 0));
      }
      const daysList = [...byDay.keys()].sort();
      if (!daysList.length) {
        setChartState(`#${canvasId}`, true, {
          reason: 'no-data',
          title: 'No flag hits',
          body: 'Guardrail hits per day will appear here if detectors trigger.',
          needsEvents: true,
        });
        return;
      }
      const vals = daysList.map((d) => byDay.get(d));
      const series = [{ label: 'Hits', data: vals, token: '--bad' }];
      lineChart(`#${canvasId}`, daysList.map((d) => fmtDay(d)), series, chartSummary('Flags', daysList, series));
    } else if (placement.widgetId === 'chart.toolsBar') {
      const tools = (Array.isArray(data) ? data : []).slice(0, 10);
      if (!tools.length) {
        setChartState(`#${canvasId}`, true, {
          reason: 'no-data',
          title: 'No tools to show',
          body: 'No tools observed yet in this range.',
          needsEvents: true,
        });
        return;
      }
      barChart(
        `#${canvasId}`,
        tools.map((t) => t.tool || t.name),
        tools.map((t) => t.tokens ?? 0),
        'Tokens',
        `Top ${tools.length} tools by tokens.`,
      );
    }
  } catch (err) {
    host.innerHTML = `
      <div class="panel">${emptyState({
        reason: 'error',
        title: 'Could not load chart',
        body: err.message || 'Request failed',
      })}</div>`;
  }
}

export async function renderTable(host, placement, days) {
  const entry = catalogEntry(placement.widgetId);
  host.innerHTML = `
    <div class="panel">
      <h2>${esc(entry.label)}</h2>
      <div class="table-wrap" tabindex="0" role="region" aria-label="${esc(entry.label)} table, scrollable">
        <table id="db-table-${esc(placement.instanceId)}"></table>
      </div>
    </div>`;
  const tableEl = host.querySelector('table');
  try {
    const data = await loadSource(entry.source, days);
    if (placement.widgetId === 'table.topTools') {
      const rows = (Array.isArray(data) ? data : []).slice(0, 15);
      dataTable(tableEl, [
        { key: 'tool', label: 'Tool', render: (r) => `<a href="#/tools/${encodeURIComponent(r.tool || r.name)}">${esc(r.tool || r.name)}</a>` },
        { key: 'users', label: 'Users', num: true, render: (r) => fmtInt(r.users) },
        { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
        { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
        { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => fmtUsd(r.costUsd) },
      ], rows, {
        caption: 'Top tools by tokens',
        empty: { reason: 'no-data', title: 'No tools to show', body: 'No tools observed yet.', needsEvents: true },
      });
    } else if (placement.widgetId === 'table.unapproved') {
      const rows = (Array.isArray(data) ? data : []).slice(0, 20);
      dataTable(tableEl, [
        { key: 'tool', label: 'Tool', render: (r) => esc(r.tool || r.name) },
        { key: 'users', label: 'Users', num: true, render: (r) => fmtInt(r.users) },
        { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
        { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
      ], rows, {
        caption: 'Unapproved tools',
        empty: { reason: 'no-data', title: 'No unapproved tools discovered', body: 'Every observed tool is on the sanctioned list for this range.', needsEvents: true },
      });
    } else if (placement.widgetId === 'table.openFindings') {
      if (data?.gated) {
        tableEl.innerHTML = '';
        host.querySelector('.panel').innerHTML = emptyState({
          title: 'Findings require analyst+',
          body: 'Your role cannot open the findings console.',
        });
        return;
      }
      const SEV = { critical: 0, high: 1, medium: 2, low: 3 };
      const rows = [...(data?.findings ?? [])]
        .sort((a, b) => (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9)
          || new Date(b.detectedAt) - new Date(a.detectedAt))
        .slice(0, 15);
      dataTable(tableEl, [
        { key: 'severity', label: 'Sev', render: (r) => sevPill(r.severity || 'unknown') },
        { key: 'title', label: 'Finding', render: (r) => `<a href="#/findings">${esc(r.title || r.ruleId || 'Finding')}</a>` },
        { key: 'status', label: 'Status', render: (r) => esc(r.status || '') },
        { key: 'detectedAt', label: 'Detected', render: (r) => esc(r.detectedAt ? relTime(r.detectedAt) : '') },
      ], rows, {
        caption: 'Open critical and high findings',
        empty: { reason: 'no-data', title: 'No open critical or high findings', body: 'Nothing in triage needs attention at critical/high severity right now.' },
      });
    } else if (placement.widgetId === 'table.teams') {
      const rows = (Array.isArray(data) ? data : []).slice(0, 15);
      dataTable(tableEl, [
        {
          key: 'team',
          label: 'Team',
          render: (r) => {
            const label = r.displayName && r.displayName !== r.team
              ? r.displayName
              : (r.team || r.name || '');
            return `<a href="#/teams/${encodeURIComponent(r.team || r.name)}">${esc(label)}</a>`;
          },
        },
        { key: 'activeUsers', label: 'Users', num: true, render: (r) => fmtInt(r.activeUsers ?? r.users) },
        { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
        { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => fmtUsd(r.costUsd) },
      ], rows, {
        caption: 'Team usage',
        empty: { reason: 'no-data', title: 'No team usage', body: 'No usage could be attributed to teams in this range.', needsEvents: true },
      });
    }
  } catch (err) {
    host.querySelector('.panel').innerHTML = emptyState({
      reason: 'error',
      title: 'Could not load table',
      body: err.message || 'Request failed',
    });
  }
}

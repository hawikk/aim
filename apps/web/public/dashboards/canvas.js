/* Canvas layout for the custom dashboards builder (AIM-1162 split).
 * Paints the active dashboard's widgets (KPI rows + full/half blocks) and
 * dispatches each placement to the widget renderer for its kind. */
import { esc } from '../lib/dom.js';
import { emptyState } from '../lib/components.js';
import {
  catalogEntry,
  getActive,
  layoutRows,
} from '../lib/dashboards.js';
import { dctx } from './state.js';
import { currentDays } from './data.js';
import { renderKpi, renderChart, renderTable } from './widgets.js';
import { fillSelect } from './shell.js';

function chromeFor(placement, index, total) {
  if (!dctx.editing) return '';
  const entry = catalogEntry(placement.widgetId);
  return `
    <div class="db-widget-chrome">
      <span class="db-widget-name">${esc(entry?.label || placement.widgetId)}</span>
      <span class="db-widget-actions">
        <button type="button" class="btn-control db-size" data-instance="${esc(placement.instanceId)}" data-size="${placement.size === 'full' ? 'half' : 'full'}" title="Toggle half/full width">
          ${placement.size === 'full' ? 'Half width' : 'Full width'}
        </button>
        <button type="button" class="btn-control" data-move="up" data-instance="${esc(placement.instanceId)}" ${index === 0 ? 'disabled' : ''} aria-label="Move up">↑</button>
        <button type="button" class="btn-control" data-move="down" data-instance="${esc(placement.instanceId)}" ${index === total - 1 ? 'disabled' : ''} aria-label="Move down">↓</button>
        <button type="button" class="btn-control db-remove" data-instance="${esc(placement.instanceId)}" aria-label="Remove widget">Remove</button>
      </span>
    </div>`;
}

export async function renderCanvas() {
  const gen = ++dctx.loadGen;
  dctx.dataCache = new Map();
  const { store, canvasEl, editing } = dctx;
  const active = getActive(store);
  fillSelect();

  if (!active) {
    canvasEl.innerHTML = emptyState({
      title: 'No dashboards yet',
      body: 'Create a named dashboard, then add KPI, chart, and table widgets from the catalog.',
    });
    return;
  }

  if (!active.widgets.length) {
    canvasEl.innerHTML = emptyState({
      title: editing ? 'Empty dashboard' : 'This dashboard has no widgets',
      body: editing
        ? 'Add a widget from the catalog above.'
        : 'Click “Edit layout” to compose KPIs, charts, and tables.',
    });
    return;
  }

  const days = currentDays();
  const rows = layoutRows(active.widgets);
  const indexById = new Map(active.widgets.map((w, i) => [w.instanceId, i]));
  const total = active.widgets.length;

  canvasEl.innerHTML = rows.map((row) => {
    if (row.type === 'kpi-row') {
      return `<div class="db-kpi-row cards">${row.widgets.map((w) => `
        <div class="db-widget db-widget-kpi" data-instance="${esc(w.instanceId)}">
          ${chromeFor(w, indexById.get(w.instanceId), total)}
          <div class="db-widget-body" data-body="${esc(w.instanceId)}"></div>
        </div>`).join('')}</div>`;
    }
    const w = row.widget;
    const size = row.size || 'full';
    return `<div class="db-block db-size-${esc(size)}">
      <div class="db-widget" data-instance="${esc(w.instanceId)}">
        ${chromeFor(w, indexById.get(w.instanceId), total)}
        <div class="db-widget-body" data-body="${esc(w.instanceId)}"></div>
      </div>
    </div>`;
  }).join('');

  await Promise.all(active.widgets.map(async (w) => {
    if (gen !== dctx.loadGen) return;
    const host = canvasEl.querySelector(`[data-body="${CSS.escape(w.instanceId)}"]`);
    if (!host) return;
    const entry = catalogEntry(w.widgetId);
    if (!entry) {
      host.innerHTML = emptyState({ title: 'Unknown widget', body: w.widgetId });
      return;
    }
    if (entry.kind === 'kpi') await renderKpi(host, w, days);
    else if (entry.kind === 'chart') await renderChart(host, w, days);
    else if (entry.kind === 'table') await renderTable(host, w, days);
  }));
}

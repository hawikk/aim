/* — Custom dashboard builder. Orchestrator only.
 *
 * Beyond saved views (filter presets): operators compose widgets — KPIs,
 * charts, tables — into named dashboards. Self-contained module view that
 * activates for any role with capabilities.dashboard (same population as the
 * rest of the read dashboards).
 *
 * Persistence is browser-local for the frontend MVP. Layout only — no
 * telemetry content is stored. Widget data is always re-fetched from the
 * existing read APIs under the current time range.
 *
 * Split (mirroring the findings rules /
 * mcp splits) — the panels live in sibling modules with clear
 * ownership:
 *   ./dashboards/state.js    shared view-private dctx + reset
 *   ./dashboards/data.js     range parse + per-source data loaders (cached)
 *   ./dashboards/widgets.js  KPI / chart / table widget renderers
 *   ./dashboards/shell.js    select fill, catalog, edit mode, error banner
 *   ./dashboards/canvas.js   layout rows + chrome + canvas paint
 *   ./dashboards/controls.js toolbar / catalog / canvas chrome event binders
 *
 * This file wires the capability gate, tab/section injection, element refs,
 * the router activation, and the control binder. Keep it thin — new panel
 * code goes in a sibling module.
 */

import { registerModuleView } from './lib/router.js';
import { moduleTab, moduleSection } from './lib/a11y.js';
import {
  loadStore,
} from './lib/dashboards.js';
import { api } from './lib/api.js';
import { dctx, resetDashboardsCtx } from './dashboards/state.js';
import { fillSelect, renderCatalog } from './dashboards/shell.js';
import { renderCanvas } from './dashboards/canvas.js';
import { bindDashboardControls } from './dashboards/controls.js';

const me = await api('/api/me').catch((err) => {
  if (err.status === 401) window.location.assign('/auth/login');
  return null;
});

if (me?.capabilities?.dashboard) {
  init().catch((err) => console.error('custom dashboards failed to start:', err));
}

async function init() {
  resetDashboardsCtx();
  dctx.caps = me.capabilities || {};
  dctx.store = loadStore();

  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/dashboards.css';
  document.head.appendChild(link);

  moduleTab({
    view: 'dashboards',
    label: 'Dashboards',
    icon: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg>',
  });

  const main = document.querySelector('#main');
  const section = moduleSection({
    view: 'dashboards',
    className: 'dashboards-view',
    html: `
    <div class="banner info">
      Compose charts, tables, and KPIs into named dashboards. Layout is saved in this browser;
      every widget re-fetches live data under the current time range. This is beyond saved
      views (filter presets) — it is a full builder.
    </div>
    <div class="db-toolbar" role="toolbar" aria-label="Dashboard controls">
      <label class="picker">Dashboard:
        <select id="db-select" aria-label="Select dashboard"></select>
      </label>
      <button type="button" class="btn-control" id="db-new">New…</button>
      <button type="button" class="btn-control" id="db-rename">Rename…</button>
      <button type="button" class="btn-control" id="db-delete">Delete</button>
      <button type="button" class="btn-control db-delete-confirm" id="db-delete-confirm" hidden>Confirm delete</button>
      <button type="button" class="btn-control" id="db-delete-cancel" hidden>Cancel</button>
      <span class="db-toolbar-spacer"></span>
      <button type="button" class="btn-control" id="db-edit" aria-pressed="false">Edit layout</button>
    </div>
    <div class="db-err" id="db-err" role="alert" hidden></div>
    <div class="db-builder" id="db-builder" hidden>
      <div class="db-builder-head">
        <h2>Add widget</h2>
        <p class="hint">Pick a KPI, chart, or table. Reorder and resize on the canvas below.</p>
      </div>
      <div class="db-catalog" id="db-catalog" role="list" aria-label="Widget catalog"></div>
    </div>
    <div id="db-canvas" class="db-canvas" aria-live="polite"></div>
  `,
  });
  main?.appendChild(section);

  Object.assign(dctx, {
    section,
    selectEl: section.querySelector('#db-select'),
    builderEl: section.querySelector('#db-builder'),
    catalogEl: section.querySelector('#db-catalog'),
    canvasEl: section.querySelector('#db-canvas'),
    editBtn: section.querySelector('#db-edit'),
  });

  bindDashboardControls();

  registerModuleView('dashboards', {
    onActivate: async () => {
      // Re-read store in case another tab mutated localStorage.
      dctx.store = loadStore();
      fillSelect();
      if (dctx.editing) renderCatalog();
      await renderCanvas();
    },
  });
}

/* Shell helpers for the custom dashboards builder (AIM-1162 split).
 * Shared by canvas paint and toolbar controls without a circular import:
 * select fill, error banner, two-step delete arming, catalog, edit mode. */
import { esc } from '../lib/dom.js';
import { emptyState } from '../lib/components.js';
import {
  catalogForCapabilities,
  getActive,
  saveStore,
  WIDGET_KINDS,
} from '../lib/dashboards.js';
import { dctx } from './state.js';

export function persist(next) {
  dctx.store = next;
  saveStore(dctx.store);
}

export function showErr(msg) {
  const el = dctx.section.querySelector('#db-err');
  if (!msg) {
    el.hidden = true;
    el.textContent = '';
    return;
  }
  el.hidden = false;
  el.textContent = msg;
}

export function setDeleteArmed(armed) {
  dctx.section.querySelector('#db-delete').hidden = armed;
  dctx.section.querySelector('#db-delete-confirm').hidden = !armed;
  dctx.section.querySelector('#db-delete-cancel').hidden = !armed;
}

export function fillSelect() {
  const { store, selectEl, editBtn } = dctx;
  const active = getActive(store);
  selectEl.innerHTML = store.dashboards
    .map((d) => `<option value="${esc(d.id)}"${d.id === active?.id ? ' selected' : ''}>${esc(d.name)}</option>`)
    .join('');
  const empty = store.dashboards.length === 0;
  dctx.section.querySelector('#db-rename').disabled = empty;
  dctx.section.querySelector('#db-delete').disabled = empty;
  editBtn.disabled = empty;
  setDeleteArmed(false);
}

export function renderCatalog() {
  const { caps, catalogEl } = dctx;
  const available = catalogForCapabilities(caps);
  if (available.length === 0) {
    catalogEl.innerHTML = emptyState({
      title: 'No widgets available',
      body: 'Your role cannot see any of the widget data sources.',
    });
    return;
  }
  const byKind = WIDGET_KINDS.map((kind) => ({
    kind,
    items: available.filter((w) => w.kind === kind),
  })).filter((g) => g.items.length);
  const kindLabel = { kpi: 'KPI tiles', chart: 'Charts', table: 'Tables' };
  catalogEl.innerHTML = byKind.map((g) => `
    <div class="db-catalog-group">
      <h3 class="db-catalog-kind">${esc(kindLabel[g.kind] || g.kind)}</h3>
      <ul class="db-catalog-list">
        ${g.items.map((w) => `
          <li role="listitem">
            <button type="button" class="db-catalog-item" data-widget-id="${esc(w.id)}">
              <span class="db-catalog-label">${esc(w.label)}</span>
              <span class="db-catalog-desc">${esc(w.description || '')}</span>
            </button>
          </li>`).join('')}
      </ul>
    </div>`).join('');
}

export function setEditing(on) {
  dctx.editing = Boolean(on);
  dctx.builderEl.hidden = !dctx.editing;
  dctx.editBtn.setAttribute('aria-pressed', dctx.editing ? 'true' : 'false');
  dctx.editBtn.textContent = dctx.editing ? 'Done editing' : 'Edit layout';
  dctx.section.classList.toggle('is-editing', dctx.editing);
  if (dctx.editing) renderCatalog();
}

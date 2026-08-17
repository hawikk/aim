/* Toolbar + catalog + mutation controls for the custom dashboards builder
 * (AIM-1162 split). Owns the dashboard picker, two-step delete (AIM-151),
 * edit-layout toggle, widget catalog, and canvas chrome event handlers. */
import { announce } from '../lib/a11y.js';
import {
  catalogEntry,
  getActive,
  createDashboard,
  renameDashboard,
  deleteDashboard,
  setActiveDashboard,
  addWidget,
  removeWidget,
  moveWidget,
  setWidgetSize,
} from '../lib/dashboards.js';
import { dctx } from './state.js';
import { renderCanvas } from './canvas.js';
import {
  persist,
  showErr,
  setDeleteArmed,
  fillSelect,
  setEditing,
} from './shell.js';

/** Wire toolbar, catalog, and canvas chrome interactions. Call once after
 * the shell is mounted and dctx element refs are populated. */
export function bindDashboardControls() {
  const { section, selectEl, catalogEl, canvasEl, editBtn } = dctx;

  selectEl.addEventListener('change', () => {
    showErr('');
    const r = setActiveDashboard(dctx.store, selectEl.value);
    if (!r.ok) return;
    persist(r.store);
    renderCanvas();
    announce(`Switched to ${getActive(dctx.store)?.name || 'dashboard'}`);
  });

  section.querySelector('#db-new').addEventListener('click', () => {
    showErr('');
    const name = window.prompt('Name for the new dashboard');
    if (name == null) return;
    const r = createDashboard(dctx.store, name);
    if (!r.ok) {
      showErr(r.error);
      return;
    }
    persist(r.store);
    setEditing(true);
    renderCanvas();
    announce(`Created dashboard ${r.dashboard.name}`);
  });

  section.querySelector('#db-rename').addEventListener('click', () => {
    showErr('');
    const active = getActive(dctx.store);
    if (!active) return;
    const name = window.prompt('Rename dashboard', active.name);
    if (name == null) return;
    const r = renameDashboard(dctx.store, active.id, name);
    if (!r.ok) {
      showErr(r.error);
      return;
    }
    persist(r.store);
    fillSelect();
    announce(`Renamed dashboard to ${String(name || '').trim() || 'dashboard'}`);
  });

  // Two-step delete (AIM-151): no native confirm() — second click is the deliberate action.
  section.querySelector('#db-delete').addEventListener('click', () => {
    showErr('');
    if (!getActive(dctx.store)) return;
    setDeleteArmed(true);
  });
  section.querySelector('#db-delete-cancel').addEventListener('click', () => setDeleteArmed(false));
  section.querySelector('#db-delete-confirm').addEventListener('click', () => {
    const active = getActive(dctx.store);
    if (!active) return;
    const r = deleteDashboard(dctx.store, active.id);
    if (!r.ok) {
      showErr(r.error);
      setDeleteArmed(false);
      return;
    }
    persist(r.store);
    if (!getActive(dctx.store)) setEditing(false);
    renderCanvas();
    announce(`Deleted dashboard ${active.name}`);
  });

  editBtn.addEventListener('click', () => {
    showErr('');
    setEditing(!dctx.editing);
    renderCanvas();
    announce(dctx.editing ? 'Editing dashboard layout' : 'Finished editing layout');
  });

  catalogEl.addEventListener('click', (e) => {
    const btnEl = e.target.closest('[data-widget-id]');
    if (!btnEl) return;
    const active = getActive(dctx.store);
    if (!active) return;
    const r = addWidget(dctx.store, active.id, btnEl.dataset.widgetId, { capabilities: dctx.caps });
    if (!r.ok) {
      showErr(r.error);
      return;
    }
    showErr('');
    persist(r.store);
    renderCanvas();
    announce(`Added ${catalogEntry(btnEl.dataset.widgetId)?.label || 'widget'}`);
  });

  canvasEl.addEventListener('click', (e) => {
    const active = getActive(dctx.store);
    if (!active || !dctx.editing) return;

    const removeBtn = e.target.closest('.db-remove');
    if (removeBtn) {
      const r = removeWidget(dctx.store, active.id, removeBtn.dataset.instance);
      if (!r.ok) return;
      persist(r.store);
      renderCanvas();
      announce('Removed widget');
      return;
    }

    const moveBtn = e.target.closest('[data-move]');
    if (moveBtn) {
      const r = moveWidget(dctx.store, active.id, moveBtn.dataset.instance, moveBtn.dataset.move);
      if (!r.ok) return;
      persist(r.store);
      renderCanvas();
      return;
    }

    const sizeBtn = e.target.closest('.db-size');
    if (sizeBtn) {
      const r = setWidgetSize(dctx.store, active.id, sizeBtn.dataset.instance, sizeBtn.dataset.size);
      if (!r.ok) return;
      persist(r.store);
      renderCanvas();
    }
  });
}

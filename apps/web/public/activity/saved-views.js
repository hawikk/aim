/* Saved views panel for the Activity trail (split, extracted
 * from activity.js): /api/views CRUD for activity filter sets — save, rename,
 * update filters, two-step delete, and the select that applies a saved view.
 *
 * bindSavedViews() wires every control and returns the handle the orchestrator
 * needs: syncViewUI() for the clear-filters handoff and loadViews() for the
 * pre-warm. */

import { esc } from '../lib/dom.js';
import { api } from '../lib/runtime.js';
import { activityFiltersFromState, activityStateFromFilters, validateFilters } from '../lib/view-filters.js';
import { actx } from './state.js';
import { resetAndLoad, setHint } from './feed.js';

const $ = (sel, ctx = document) => ctx.querySelector(sel);

export function bindSavedViews() {
  const viewSelect = $('#act-view-select');
  const viewRename = $('#act-view-rename');
  const viewUpdate = $('#act-view-update');
  const viewDelete = $('#act-view-delete');
  const viewHint = $('#act-view-hint');
  const viewForm = $('#act-view-form');
  const viewName = $('#act-view-name');
  const viewConfirm = $('#act-view-confirm');
  const viewErr = $('#act-view-err');
  let savedViews = [];
  let formMode = 'create';

  function readFilterState() {
    return {
      tool: $('#act-filter-tool')?.value ?? '',
      event_type: $('#act-filter-event-type')?.value ?? '',
      user: $('#act-filter-user')?.value ?? '',
      minScore: $('#act-filter-min-score')?.value ?? '',
    };
  }

  function writeFilterState(st) {
    const map = {
      '#act-filter-tool': st.tool,
      '#act-filter-event-type': st.event_type,
      '#act-filter-user': st.user,
      '#act-filter-min-score': st.minScore,
    };
    for (const [sel, val] of Object.entries(map)) {
      const el = $(sel);
      if (el) el.value = val ?? '';
    }
  }

  function syncViewUI() {
    if (!viewSelect) return;
    viewSelect.innerHTML =
      '<option value="">Custom filters</option>' +
      savedViews.map((v) => `<option value="${esc(v.viewId)}">${esc(v.name)}</option>`).join('');
    viewSelect.value = actx.activeViewId ?? '';
    const active = Boolean(actx.activeViewId);
    if (viewRename) viewRename.hidden = !active;
    if (viewUpdate) viewUpdate.hidden = !active;
    if (viewDelete) viewDelete.hidden = !active;
    if (viewHint) viewHint.hidden = savedViews.length > 0;
  }

  async function loadViews(selectId) {
    try {
      const d = await api('/api/views');
      savedViews = (d.views ?? []).filter((v) => v.filters?.view === 'activity');
    } catch {
      savedViews = [];
    }
    if (selectId && savedViews.some((v) => v.viewId === selectId)) actx.activeViewId = selectId;
    syncViewUI();
  }

  function applySavedFilters(filters, viewId) {
    const st = activityStateFromFilters(filters);
    writeFilterState(st);
    actx.activeViewId = viewId ?? null;
    syncViewUI();
    resetAndLoad();
  }

  function markCustom() {
    if (!actx.activeViewId) return;
    actx.activeViewId = null;
    syncViewUI();
  }

  function openViewForm(mode) {
    if (!viewForm || !viewName || !viewConfirm) return;
    formMode = mode;
    if (viewErr) viewErr.textContent = '';
    if (mode === 'rename') {
      const current = savedViews.find((v) => v.viewId === actx.activeViewId);
      viewName.value = current?.name ?? '';
      viewConfirm.textContent = 'Rename view';
    } else {
      viewName.value = '';
      viewConfirm.textContent = 'Save view';
    }
    viewForm.hidden = false;
    viewName.focus();
    viewName.select?.();
  }

  function toastMsg(msg, kind = 'info') {
    // Prefer a light-weight status in the hint; no dedicated toast stack here.
    setHint(msg);
    if (kind === 'bad') console.warn('[activity saved views]', msg);
  }

  viewSelect?.addEventListener('change', () => {
    const v = savedViews.find((x) => x.viewId === viewSelect.value);
    if (v) applySavedFilters(v.filters, v.viewId);
    else {
      actx.activeViewId = null;
      syncViewUI();
    }
  });

  for (const id of ['#act-filter-tool', '#act-filter-event-type', '#act-filter-user', '#act-filter-min-score']) {
    $(id)?.addEventListener('input', markCustom);
  }

  $('#act-view-save')?.addEventListener('click', () => openViewForm('create'));
  viewRename?.addEventListener('click', () => {
    if (!actx.activeViewId) return;
    openViewForm('rename');
  });
  $('#act-view-cancel')?.addEventListener('click', () => {
    if (viewForm) viewForm.hidden = true;
    formMode = 'create';
    if (viewConfirm) viewConfirm.textContent = 'Save view';
  });
  viewConfirm?.addEventListener('click', async () => {
    const name = (viewName?.value ?? '').trim();
    if (!name) {
      if (viewErr) viewErr.textContent = 'Name is required (1–80 chars).';
      return;
    }
    if (formMode === 'rename') {
      if (!actx.activeViewId) {
        if (viewErr) viewErr.textContent = 'No active view to rename.';
        return;
      }
      try {
        await api(`/api/views/${encodeURIComponent(actx.activeViewId)}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name }),
        });
        if (viewForm) viewForm.hidden = true;
        formMode = 'create';
        if (viewConfirm) viewConfirm.textContent = 'Save view';
        toastMsg(`View renamed to “${name}”`);
        await loadViews(actx.activeViewId);
      } catch (err) {
        if (viewErr) viewErr.textContent = err.status === 409 ? 'A view with that name already exists.' : err.message;
      }
      return;
    }
    const filters = activityFiltersFromState(readFilterState());
    const check = validateFilters(filters);
    if (!check.ok) {
      if (viewErr) viewErr.textContent = check.errors.join('; ');
      return;
    }
    try {
      const v = await api('/api/views', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, filters }),
      });
      if (viewForm) viewForm.hidden = true;
      toastMsg(`View “${name}” saved`);
      await loadViews(v.viewId);
    } catch (err) {
      if (viewErr) viewErr.textContent = err.status === 409 ? 'A view with that name already exists.' : err.message;
    }
  });

  viewUpdate?.addEventListener('click', async () => {
    if (!actx.activeViewId) return;
    const filters = activityFiltersFromState(readFilterState());
    const check = validateFilters(filters);
    if (!check.ok) {
      toastMsg(`Cannot save these filters: ${check.errors.join('; ')}`, 'bad');
      return;
    }
    try {
      await api(`/api/views/${encodeURIComponent(actx.activeViewId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filters }),
      });
      toastMsg('View filters updated');
      await loadViews(actx.activeViewId);
    } catch (err) {
      toastMsg(`Update failed: ${err.message}`, 'bad');
    }
  });

  let deleteArmed = false;
  viewDelete?.addEventListener('click', async () => {
    if (!actx.activeViewId) return;
    if (!deleteArmed) {
      deleteArmed = true;
      if (viewDelete) viewDelete.textContent = 'Confirm delete';
      setTimeout(() => {
        deleteArmed = false;
        if (viewDelete) viewDelete.textContent = 'Delete';
      }, 4000);
      return;
    }
    deleteArmed = false;
    if (viewDelete) viewDelete.textContent = 'Delete';
    try {
      await api(`/api/views/${encodeURIComponent(actx.activeViewId)}`, { method: 'DELETE' });
      toastMsg('View deleted');
      actx.activeViewId = null;
      await loadViews();
    } catch (err) {
      toastMsg(`Delete failed: ${err.message}`, 'bad');
    }
  });

  // Clear-filters action should also detach from a saved view.
  // markCustom is already wired on filter input; clear path resets values then reloads.

  return { syncViewUI, loadViews };
}

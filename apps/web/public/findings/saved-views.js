/* Findings saved views (AIM-94 / AIM-587) + hash filter round-trip
 * (AIM-1140 split of findings.js). Per-user filter presets via /api/views and
 * the #/findings?status=&severity= URL contract the rest of the dashboard
 * hops into. setupSavedViews() wires the controls and returns the entry
 * points the orchestrator needs (activate on route, mark-custom on manual
 * filter edits, pre-warm). */
import { fctx } from './state.js';
import {
  filtersFromState,
  stateFromFilters,
  validateFilters,
  parseFindingsHash,
  findingsHash,
  findingsHashHasFilters,
} from '../lib/view-filters.js';
import { esc } from '../lib/dom.js';
import { api } from '../lib/api.js';
import { withBusy, showFieldError, clearFieldError } from '../lib/form.js';

export function setupSavedViews() {
  const { section, state, toast } = fctx;
  const viewSelect = section.querySelector('#find-view-select');
  const viewRename = section.querySelector('#find-view-rename');
  const viewUpdate = section.querySelector('#find-view-update');
  const viewDelete = section.querySelector('#find-view-delete');
  const viewHint = section.querySelector('#find-view-hint');
  const viewForm = section.querySelector('#find-view-form');
  const viewName = section.querySelector('#find-view-name');
  const viewConfirm = section.querySelector('#find-view-confirm');
  const viewErr = section.querySelector('#find-view-err');
  let savedViews = [];
  // Form dual-purpose: "create" (POST) or "rename" (PUT name only).
  let formMode = 'create';

  function syncViewUI() {
    viewSelect.innerHTML =
      '<option value="">Custom filters</option>' +
      savedViews.map((v) => `<option value="${esc(v.viewId)}">${esc(v.name)}</option>`).join('');
    viewSelect.value = state.activeViewId ?? '';
    const active = Boolean(state.activeViewId);
    viewRename.hidden = !active;
    viewUpdate.hidden = !active;
    viewDelete.hidden = !active;
    viewHint.hidden = savedViews.length > 0;
  }

  function syncFindingsUrl() {
    const next = findingsHash({
      viewId: state.activeViewId,
      fstatus: state.fstatus,
      fsev: state.fsev,
    });
    if (typeof location === 'undefined' || location.hash === next) return;
    if (typeof history !== 'undefined' && history.replaceState) {
      history.replaceState(null, '', next);
    } else {
      location.hash = next;
    }
  }

  async function loadViews(selectId) {
    try {
      const d = await api('/api/views');
      // Defensive: only findings-view filters are meaningful in this console.
      savedViews = (d.views ?? []).filter((v) => v.filters?.view === 'findings');
    } catch {
      // Silent: the select simply shows "Custom filters" (the save/update/delete
      // flows surface their own errors via toast or the inline form error).
      savedViews = [];
    }
    if (selectId && savedViews.some((v) => v.viewId === selectId)) state.activeViewId = selectId;
    syncViewUI();
  }

  function applyFilters(filters, viewId, { load = true, syncUrl = true } = {}) {
    const st = stateFromFilters(filters);
    state.fstatus = st.fstatus;
    state.fsev = st.fsev;
    state.ruleId = st.ruleId;
    state.days = st.days;
    state.activeViewId = viewId ?? null;
    section.querySelector('#find-status').value = state.fstatus;
    section.querySelector('#find-severity').value = state.fsev;
    syncViewUI();
    if (syncUrl) syncFindingsUrl();
    if (load) {
      return fctx.loadFindings().catch((err) => {
        fctx.list.innerHTML = `<div class="err">${esc(err.message)}</div>`;
      });
    }
    return Promise.resolve();
  }

  function applyQueryFilters({ status, severity }, opts) {
    return applyFilters(
      {
        view: 'findings',
        status: status ?? state.fstatus,
        severity: severity ?? state.fsev,
        ruleId: state.ruleId,
        days: state.days,
      },
      null,
      opts,
    );
  }

  async function activateFindings() {
    await loadViews(state.activeViewId);
    const q = parseFindingsHash(typeof location !== 'undefined' ? location.hash : '');
    if (q.viewId) {
      const v = savedViews.find((x) => x.viewId === q.viewId);
      if (v) await applyFilters(v.filters, v.viewId, { load: false, syncUrl: true });
      else {
        state.activeViewId = null;
        if (q.status || q.severity) await applyQueryFilters(q, { load: false, syncUrl: true });
        else syncViewUI();
      }
    } else if (findingsHashHasFilters(typeof location !== 'undefined' ? location.hash : '')) {
      await applyQueryFilters(q, { load: false, syncUrl: true });
    }
    await fctx.loadFindings();
  }

  viewSelect.addEventListener('change', () => {
    const v = savedViews.find((x) => x.viewId === viewSelect.value);
    if (v) applyFilters(v.filters, v.viewId);
    else {
      state.activeViewId = null; // "Custom filters" — keep the current filter set
      syncViewUI();
      syncFindingsUrl();
    }
  });

  // Manual filter changes detach from the active saved view.
  function markCustom() {
    state.activeViewId = null;
    syncViewUI();
    syncFindingsUrl();
  }

  function openViewForm(mode) {
    formMode = mode;
    clearFieldError(viewErr);
    if (mode === 'rename') {
      const current = savedViews.find((v) => v.viewId === state.activeViewId);
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

  section.querySelector('#find-view-save').addEventListener('click', () => openViewForm('create'));
  viewRename.addEventListener('click', () => {
    if (!state.activeViewId) return;
    openViewForm('rename');
  });
  section.querySelector('#find-view-cancel').addEventListener('click', () => {
    viewForm.hidden = true;
    formMode = 'create';
    viewConfirm.textContent = 'Save view';
  });
  viewConfirm.addEventListener('click', async () => {
    const name = viewName.value.trim();
    if (!name) {
      showFieldError(viewErr, 'Name is required (1–80 chars).', viewName);
      return;
    }
    if (formMode === 'rename') {
      if (!state.activeViewId) {
        showFieldError(viewErr, 'No active view to rename.');
        return;
      }
      await withBusy(viewConfirm, async () => {
        await api(`/api/views/${encodeURIComponent(state.activeViewId)}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name }),
        });
        viewForm.hidden = true;
        formMode = 'create';
        viewConfirm.textContent = 'Save view';
        toast(`View renamed to “${name}”`, 'ok');
        await loadViews(state.activeViewId);
      }, { reenable: 'always' }).catch((err) => {
        showFieldError(viewErr, err.status === 409 ? 'A view with that name already exists.' : err.message);
      });
      return;
    }
    const filters = filtersFromState(state);
    const check = validateFilters(filters); // client-side mirror of the API contract
    if (!check.ok) {
      showFieldError(viewErr, check.errors.join('; '));
      return;
    }
    await withBusy(viewConfirm, async () => {
      const v = await api('/api/views', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, filters }),
      });
      viewForm.hidden = true;
      toast(`View “${name}” saved`, 'ok');
      await loadViews(v.viewId);
      syncFindingsUrl();
    }, { reenable: 'always' }).catch((err) => {
      showFieldError(viewErr, err.status === 409 ? 'A view with that name already exists.' : err.message);
    });
  });

  viewUpdate.addEventListener('click', async () => {
    const filters = filtersFromState(state);
    const check = validateFilters(filters);
    if (!check.ok) {
      toast(`Cannot save these filters: ${check.errors.join('; ')}`, 'bad');
      return;
    }
    try {
      await api(`/api/views/${encodeURIComponent(state.activeViewId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filters }),
      });
      toast('View filters updated', 'ok');
      await loadViews(state.activeViewId);
    } catch (err) {
      toast(`Update failed: ${err.message}`, 'bad');
    }
  });

  // Inline confirm: first click arms, second click deletes.
  let deleteArmed = false;
  viewDelete.addEventListener('click', async () => {
    if (!deleteArmed) {
      deleteArmed = true;
      viewDelete.textContent = 'Confirm delete';
      setTimeout(() => {
        deleteArmed = false;
        viewDelete.textContent = 'Delete';
      }, 4000);
      return;
    }
    deleteArmed = false;
    viewDelete.textContent = 'Delete';
    try {
      await api(`/api/views/${encodeURIComponent(state.activeViewId)}`, { method: 'DELETE' });
      toast('View deleted', 'ok');
      state.activeViewId = null;
      await loadViews();
    } catch (err) {
      toast(`Delete failed: ${err.message}`, 'bad');
    }
  });

  return { loadViews, activateFindings, markCustom };
}

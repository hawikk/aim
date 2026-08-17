/* Findings triage + list interactions (split of findings.js).
 * Owns the disclosure open/close path (keyboard investigation), the
 * single-finding triage mutation (reason enforcement), and bulk
 * selection / bulk triage. Row markup lives in ./row.js, shared
 * state in ./state.js. */
import { STATUS_LABEL, fctx } from './state.js';
import { renderHistory } from './row.js';
import { buildTriagePayload, buildBulkPayload, triageBlocker } from '../lib/triage.js';
import { announce, focusInto, setExpanded } from '../lib/a11y.js';
import { api } from '../lib/api.js';
import { withBusy } from '../lib/form.js';

/* ---------- Bulk selection ---------- */

export function syncBulkUI() {
  const { section, list, selected, currentIds } = fctx;
  const bulkbar = section.querySelector('#find-bulkbar');
  const selectAll = section.querySelector('#find-select-all');
  bulkbar.hidden = selected.size === 0;
  section.querySelector('#find-bulk-count').textContent = `${selected.size} selected`;
  selectAll.checked = currentIds.length > 0 && currentIds.every((id) => selected.has(id));
  selectAll.indeterminate = selected.size > 0 && !selectAll.checked;
  selectAll.disabled = currentIds.length === 0;
  list.querySelectorAll('.finding').forEach((el) => {
    const on = selected.has(el.dataset.id);
    el.classList.toggle('selected', on);
    const box = el.querySelector('.f-check');
    if (box) box.checked = on;
  });
}

export function bindBulkBar() {
  const { section, selected, toast } = fctx;
  const bulkbar = section.querySelector('#find-bulkbar');
  const selectAll = section.querySelector('#find-select-all');

  selectAll.addEventListener('change', () => {
    // fctx.currentIds is re-read per event: loadFindings replaces the array.
    if (selectAll.checked) fctx.currentIds.forEach((id) => selected.add(id));
    else selected.clear();
    syncBulkUI();
  });

  section.querySelector('#find-bulk-clear').addEventListener('click', () => {
    selected.clear();
    syncBulkUI();
  });

  bulkbar.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-bulk]');
    if (!btn || selected.size === 0) return;
    const status = btn.dataset.bulk;
    const note = section.querySelector('#find-bulk-note').value;
    // refuse early rather than round-trip the API's 400.
    const blocker = triageBlocker(status, note);
    if (blocker) {
      toast(blocker, 'bad');
      return;
    }
    const buttons = [...bulkbar.querySelectorAll('button')];
    await withBusy(buttons, async () => {
      const r = await api('/api/findings/triage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(buildBulkPayload([...selected], status, note)),
      });
      toast(`${r.updated} finding${r.updated === 1 ? '' : 's'} ${STATUS_LABEL[status] ?? status}`, 'ok');
      selected.clear();
      section.querySelector('#find-bulk-note').value = '';
      await fctx.loadFindings();
      fctx.pollCritical(true); // keep the nav badge honest after a transition
    }, { reenable: 'always' }).catch((err) => {
      // Keep the selection so the batch can be retried or trimmed.
      toast(`Bulk triage failed: ${err.message}`, 'bad');
      syncBulkUI();
    });
  });
}

/* ---------- Disclosure + triage ---------- */

/*: open/close a finding disclosure without stranding the keyboard.
 * setExpanded owns aria-expanded / aria-controls / hidden; we own focus and
 * the live-region announcement (rules.js uses the same pattern). */
export function findingTitle(el) {
  return el.querySelector('.f-title')?.textContent?.trim() || el.dataset.id || 'finding';
}

export function setFindingOpen(el, open, { focus = true } = {}) {
  const { section } = fctx;
  const rowBtn = el.querySelector('.f-row');
  const detail = el.querySelector('.f-detail');
  if (!rowBtn || !detail) return;
  setExpanded(rowBtn, detail, open);
  el.classList.toggle('open', open);
  if (open) {
    renderHistory(el); // fresh trail on expand
    announce(`Finding detail open: ${findingTitle(el)}. Escape closes.`);
    if (focus) {
      // Prefer the triage note — the SOC path is read evidence → act.
      const note = detail.querySelector('.f-note');
      if (note) note.focus();
      else focusInto(detail, section);
    }
  } else {
    announce(`Finding detail closed: ${findingTitle(el)}.`);
    if (focus) rowBtn.focus();
  }
}

export function closeOpenFindings({ except = null, focus = false } = {}) {
  fctx.list.querySelectorAll('.finding.open').forEach((el) => {
    if (except && el === except) return;
    setFindingOpen(el, false, { focus: false });
  });
  if (focus && except) except.querySelector('.f-row')?.focus();
}

export async function triage(id, status, el) {
  const { toast, list, section } = fctx;
  const note = el.querySelector('.f-note')?.value;
  // refuse early rather than round-trip the API's 400.
  const blocker = triageBlocker(status, note);
  if (blocker) {
    toast(blocker, 'bad');
    announce(blocker);
    el.querySelector('.f-note')?.focus();
    return;
  }
  const title = findingTitle(el);
  let okMsg = null;
  try {
    const f = await api(`/api/findings/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildTriagePayload(status, note)),
    });
    okMsg = `Finding ${STATUS_LABEL[status] ?? status}${f.triagedBy ? ` — ${f.triagedBy}` : ''}`;
    toast(okMsg, 'ok');
    announce(`${title}: ${okMsg}`);
  } catch (err) {
    toast(`Triage failed: ${err.message}`, 'bad');
    announce(`Triage failed for ${title}: ${err.message}`);
  }
  // Re-render destroys the open row (status filter may drop it). Put focus
  // back on the list so the keyboard does not reset to <body>.
  await fctx.loadFindings();
  // Prefer the same finding's row when it is still in the filter; otherwise
  // land on the tabpanel (moduleSection sets tabindex=0) so focus does not
  // silently reset to <body>.
  const idSel = typeof CSS !== 'undefined' && CSS.escape ? CSS.escape(id) : id.replace(/"/g, '');
  const stillThere = list.querySelector(`.finding[data-id="${idSel}"] .f-row`);
  if (stillThere) stillThere.focus();
  else section.focus();
  fctx.pollCritical(true); // keep the nav badge honest after a transition
}

export function bindFindingsList() {
  const { section, list, selected } = fctx;

  list.addEventListener('click', async (e) => {
    const el = e.target.closest('.finding');
    if (!el) return;
    if (e.target.closest('.f-check')) {
      // Checkbox toggles bulk selection only — never expands the row.
      if (e.target.checked) selected.add(el.dataset.id);
      else selected.delete(el.dataset.id);
      syncBulkUI();
      return;
    }
    // Links inside the detail (runbook, entity deep-links, session chain)
    // must navigate — do not treat them as a row toggle.
    if (e.target.closest('a[href]')) return;
    const action = e.target.closest('[data-action]');
    if (action) {
      // reenable 'connected': a blocker / early return leaves the row in
      // place — re-enable so the keyboard operator can correct the note and
      // try again; a successful triage re-renders the row away.
      await withBusy(action, () => triage(el.dataset.id, action.dataset.action, el), { reenable: 'connected' });
      return;
    }
    if (e.target.closest('.f-row')) {
      const open = el.classList.contains('open');
      if (!open) closeOpenFindings({ except: el });
      setFindingOpen(el, !open);
    }
  });

  // Escape collapses the open finding and returns focus to its row.
  // Scoped to the findings panel so it does not fight other modals/editors.
  section.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const open = list.querySelector('.finding.open');
    if (!open) return;
    // Don't steal Escape from a nested disclosure if we add one later —
    // only close when focus is inside this finding (or still on the row).
    if (!open.contains(e.target) && e.target !== section) return;
    e.preventDefault();
    setFindingOpen(open, false, { focus: true });
  });
}

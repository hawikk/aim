/* Threshold rule editor interactions (AIM-1147) — pure-moved from rules.js.
 *
 * The AIM-94 inline tuning surface for threshold rules: open/close the
 * editor, validate, PATCH /api/guardrail/rules/:id, reset to the policy
 * default. Match rules stay policy-as-code and have no editor.
 *
 * AIM-515 focus management: a successful PATCH re-renders the entire list,
 * which destroys the node the operator was standing on — focus is restored to
 * the same rule's edit button and the result is announced on the shared live
 * region. Cancel moves focus back to the trigger *before* tearing the form
 * down, for the same reason.
 */
import { esc } from '../lib/dom.js';
import { api } from '../lib/api.js';
import { announce, focusInto, setExpanded, preservingFocus } from '../lib/a11y.js';
import { withBusy, showFieldError, clearFieldError } from '../lib/form.js';
import { editFormHtml, setLabel, renderRules } from './rule-list.js';
import { rulesState } from './state.js';

/* AIM-515: a successful PATCH re-renders the entire list, which destroys the
 * node the operator was standing on and drops focus to <body> — mid-edit,
 * with no announcement that anything happened. Focus is restored to the same
 * rule's edit button (the editor itself is gone, having been saved) and the
 * result is announced on the shared live region. */
async function patchRule(id, body) {
  const list = rulesState.list;
  let updated;
  await preservingFocus(list, `[data-edit="${CSS.escape(id)}"]`, async () => {
    updated = await api(`/api/guardrail/rules/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const i = rulesState.lastRules.findIndex((r) => r.id === id);
    if (i !== -1) rulesState.lastRules[i] = updated; // response is the effective rule object
    renderRules();
  });
  const title = updated?.title ?? id;
  announce(body.reset ? `${title} reset to the policy default.` : `${title} thresholds saved.`);
  return updated;
}

export function bindThresholdEditor() {
  const list = rulesState.list;

  list.addEventListener('change', (e) => {
    if (e.target.closest('.re-window')) {
      const form = e.target.closest('.rule-edit');
      form.querySelector('.re-custom').hidden = e.target.value !== 'custom';
    }
  });

  list.addEventListener('click', async (e) => {
    const editBtn = e.target.closest('[data-edit]');
    if (editBtn) {
      const id = editBtn.dataset.edit;
      const form = list.querySelector(`[data-form="${CSS.escape(id)}"]`);
      const rule = rulesState.lastRules.find((r) => r.id === id);
      const label = rule?.title ?? id;
      if (form.hidden) {
        form.innerHTML = editFormHtml(rule);
        setExpanded(editBtn, form, true);
        setLabel(editBtn, 'Close editor', label);
        // The editor is useless if the keyboard is still parked on the trigger.
        focusInto(form);
        announce(`Threshold editor open for ${label}.`);
      } else {
        setExpanded(editBtn, form, false);
        form.innerHTML = '';
        setLabel(editBtn, 'Edit thresholds', label);
        announce(`Threshold editor closed for ${label}.`);
      }
      return;
    }
    const cancelBtn = e.target.closest('[data-cancel]');
    if (cancelBtn) {
      const form = cancelBtn.closest('.rule-edit');
      const ruleEl = cancelBtn.closest('.rule');
      const editBtnForRule = ruleEl.querySelector('[data-edit]');
      const label = rulesState.lastRules.find((r) => r.id === form.dataset.form)?.title ?? form.dataset.form;
      /* Focus first, then tear down. Removing the subtree the active element
       * lives in drops focus to <body>; the operator who pressed Cancel with the
       * keyboard would land back at the top of the document. */
      editBtnForRule.focus();
      setExpanded(editBtnForRule, form, false);
      form.innerHTML = '';
      setLabel(editBtnForRule, 'Edit thresholds', label);
      announce(`Threshold edit cancelled for ${label}.`);
      return;
    }
    const saveBtn = e.target.closest('[data-save]');
    if (saveBtn) {
      const form = saveBtn.closest('.rule-edit');
      const errEl = form.querySelector('.re-err');
      clearFieldError(errEl);
      const id = form.dataset.form;
      const rule = rulesState.lastRules.find((r) => r.id === id);
      const op = rule.threshold.gt !== null && rule.threshold.gt !== undefined ? 'gt' : 'gte';
      const value = Number(form.querySelector('.re-value').value);
      const winSel = form.querySelector('.re-window').value;
      const windowSeconds = winSel === 'custom' ? Number(form.querySelector('.re-window-custom').value) : Number(winSel);
      // AIM-515: showFieldError sends focus to the field that failed.
      // role="alert" speaks the message, but without this the operator has to
      // hunt for which input it is about.
      if (!Number.isFinite(value) || value < 0) {
        showFieldError(errEl, 'Threshold value must be a number ≥ 0.', form.querySelector('.re-value'));
        return;
      }
      if (!Number.isInteger(windowSeconds) || windowSeconds < 1) {
        showFieldError(errEl, 'Window must be a positive whole number of seconds.',
          form.querySelector(winSel === 'custom' ? '.re-window-custom' : '.re-window'));
        return;
      }
      try {
        await withBusy(saveBtn, () => patchRule(id, {
          [op]: value,
          windowSeconds,
          severity: form.querySelector('.re-severity').value,
        }));
      } catch (err) {
        errEl.textContent = err.message; // 400 detail from the API lands here
      }
      return;
    }
    const resetBtn = e.target.closest('[data-reset]');
    if (resetBtn) {
      try {
        await withBusy(resetBtn, () => patchRule(resetBtn.dataset.reset, { reset: true }));
      } catch (err) {
        resetBtn.insertAdjacentHTML('afterend', `<span class="re-err" role="alert">${esc(err.message)}</span>`);
      }
    }
  });
}

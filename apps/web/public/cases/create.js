/* "Open case" create form (split): toggle, cancel, validated submit.
 * A successful create drills straight into the new case via nav.js goCase(). */

import { validateCreate } from '../lib/cases.js';
import { api } from '../lib/api.js';
import { casesCtx } from './state.js';
import { goCase } from './nav.js';

export function bindCreateForm() {
  const { section, createPane } = casesCtx;

  section.querySelector('#case-new-btn').addEventListener('click', () => {
    createPane.hidden = false;
    section.querySelector('#case-title').focus();
  });
  section.querySelector('#case-create-cancel').addEventListener('click', () => {
    createPane.hidden = true;
    section.querySelector('#case-create-err').textContent = '';
  });
  section.querySelector('#case-create-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errEl = section.querySelector('#case-create-err');
    errEl.textContent = '';
    const split = (sel) =>
      section.querySelector(sel).value.split(',').map((s) => s.trim()).filter(Boolean);
    const body = {
      title: section.querySelector('#case-title').value,
      severity: section.querySelector('#case-severity').value,
      description: section.querySelector('#case-desc').value || null,
      findingIds: split('#case-seed-findings'),
      userRefs: split('#case-seed-users'),
      tools: split('#case-seed-tools'),
    };
    const parsed = validateCreate(body);
    if (!parsed.ok) { errEl.textContent = parsed.detail; return; }
    try {
      const created = await api('/api/cases', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(parsed.value),
      });
      createPane.hidden = true;
      section.querySelector('#case-create-form').reset();
      goCase(created.caseId);
    } catch (err) { errEl.textContent = err.message; }
  });
}

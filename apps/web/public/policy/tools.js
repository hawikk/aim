/* Sanctioned-tools panel for the Policy editor view (AIM-1177 split).
 * Owns the add-tool form (admin only), the allowlist table render, and the
 * load + sanction/unsanction mutations against GET/POST /api/sanctioned. */

import { esc } from '../lib/dom.js';
import { emptyState } from '../lib/components.js';
import { announce, preservingFocus } from '../lib/a11y.js';
import { api } from '../lib/api.js';
import { validateSanctioned } from '../lib/policy-editor.js';
import { polCtx, renderCards } from './state.js';

/** Admin-only add form. Called by the orchestrator when polCtx.mutate. */
export function mountToolsForm() {
  polCtx.toolsForm.innerHTML = `
    <form class="pol-toolbar" id="pol-tool-add" novalidate>
      <label class="pol-grow">Tool id
        <input name="tool" type="text" required autocomplete="off" placeholder="e.g. windsurf" pattern="[A-Za-z0-9][A-Za-z0-9._+-]{0,127}" />
      </label>
      <label class="pol-grow">Reason (audit)
        <input name="reason" type="text" required autocomplete="off" placeholder="why this tool is sanctioned" maxlength="2000" />
      </label>
      <button type="submit" class="btn btn-sm btn-primary">Add tool</button>
    </form>
    <p class="pol-err" id="pol-tool-err" role="alert"></p>
    <p class="pol-ok" id="pol-tool-ok" role="status"></p>`;
}

export async function loadSanctioned() {
  const d = await api('/api/sanctioned');
  polCtx.lastSanctioned = d.tools ?? [];
  renderTools();
}

export function renderTools() {
  const { toolsList, mutate, lastSanctioned } = polCtx;
  toolsList.setAttribute('aria-busy', 'false');
  if (!lastSanctioned.length) {
    toolsList.innerHTML = emptyState({
      reason: 'no-data',
      title: 'No sanctioned tools',
      body: 'The fleet tool allowlist is empty — every observed tool will be treated as unapproved until tools are added.',
    });
    return;
  }
  const rows = lastSanctioned.map((t) => {
    const name = typeof t === 'string' ? t : t.tool;
    const note = typeof t === 'object' && t.note ? esc(t.note) : '—';
    const by = typeof t === 'object' && t.updatedBy ? esc(t.updatedBy) : (typeof t === 'object' && t.createdBy ? esc(t.createdBy) : '—');
    const actions = mutate
      ? `<div class="pol-actions">
          <button type="button" class="danger" data-unsanction="${esc(name)}">Remove</button>
        </div>`
      : '<span class="hint">read-only</span>';
    return `<tr>
      <td><code>${esc(name)}</code></td>
      <td>${note}</td>
      <td>${by}</td>
      <td>${actions}</td>
    </tr>`;
  }).join('');
  toolsList.innerHTML = `<table class="pol-table">
    <caption class="sr-only">Sanctioned tools allowlist</caption>
    <thead><tr>
      <th scope="col">Tool</th>
      <th scope="col">Note</th>
      <th scope="col">Last actor</th>
      <th scope="col">Actions</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

/** Admin-only mutations: add-tool submit + delegated unsanction clicks. */
export function bindToolHandlers() {
  const { section, toolsForm, toolsList } = polCtx;

  toolsForm.querySelector('#pol-tool-add')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const errEl = section.querySelector('#pol-tool-err');
    const okEl = section.querySelector('#pol-tool-ok');
    errEl.textContent = '';
    okEl.textContent = '';
    const fd = new FormData(form);
    const v = validateSanctioned({
      tool: fd.get('tool'),
      reason: fd.get('reason'),
    });
    if (!v.ok) {
      errEl.textContent = v.error;
      form.querySelector(`[name="${v.field || 'tool'}"]`)?.focus();
      return;
    }
    const submit = form.querySelector('[type="submit"]');
    submit.disabled = true;
    try {
      await api('/api/sanctioned', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(v.value),
      });
      form.reset();
      await loadSanctioned();
      renderCards();
      okEl.textContent = `Sanctioned ${v.value.tool}.`;
      announce(`Sanctioned ${v.value.tool}.`);
    } catch (err) {
      errEl.textContent = err.message;
    } finally {
      submit.disabled = false;
    }
  });

  toolsList.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-unsanction]');
    if (!btn) return;
    const tool = btn.dataset.unsanction;
    const reason = window.prompt(
      `Remove "${tool}" from the sanctioned list?\n\nReason (required — audit trail):`,
      '',
    );
    if (reason == null) return;
    const v = validateSanctioned({ tool, reason });
    if (!v.ok) {
      announce(v.error);
      return;
    }
    btn.disabled = true;
    try {
      await preservingFocus(toolsList, `[data-unsanction="${CSS.escape(tool)}"]`, async () => {
        await api(`/api/sanctioned/${encodeURIComponent(tool)}/unsanction`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: v.value.reason }),
        });
        await loadSanctioned();
        renderCards();
      });
      announce(`Removed ${tool} from the sanctioned list.`);
    } catch (err) {
      btn.disabled = false;
      announce(`Remove failed: ${err.message}`);
    }
  });
}

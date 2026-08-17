/* Model/provider allowlist panel for the Policy editor view (split).
 * Owns the add-entry form (admin only), the allowlist table render, and the
 * load + add/flip/delete mutations against
 * GET/POST/DELETE /api/governance/model-allowlist. */

import { esc } from '../lib/dom.js';
import { emptyState } from '../lib/components.js';
import { announce, preservingFocus } from '../lib/a11y.js';
import { api } from '../lib/api.js';
import {
  validateModelAllowlist,
  flipMode,
  rebuildAllowlistBody,
  allowlistLabel,
  MODES,
} from '../lib/policy-editor.js';
import { polCtx, renderCards, modePill } from './state.js';

/** Admin-only add form + team-scope toggle. Called when polCtx.mutate. */
export function mountModelsForm() {
  polCtx.modelsForm.innerHTML = `
    <form class="pol-toolbar" id="pol-model-add" novalidate>
      <label>Scope
        <select name="scope_type">
          <option value="global" selected>global</option>
          <option value="team">team</option>
        </select>
      </label>
      <label class="pol-grow" id="pol-scope-id-wrap" hidden>Team id
        <input name="scope_id" type="text" autocomplete="off" placeholder="Engineering" maxlength="128" />
      </label>
      <label class="pol-grow">Provider
        <input name="provider" type="text" autocomplete="off" placeholder="anthropic" maxlength="256" />
      </label>
      <label class="pol-grow">Model
        <input name="model" type="text" autocomplete="off" placeholder="claude-sonnet-4" maxlength="256" />
      </label>
      <label>Mode
        <select name="mode">
          ${MODES.map((m) => `<option value="${m}"${m === 'observe' ? ' selected' : ''}>${m}</option>`).join('')}
        </select>
      </label>
      <button type="submit" class="btn btn-sm btn-primary">Add entry</button>
    </form>
    <p class="pol-err" id="pol-model-err" role="alert"></p>
    <p class="pol-ok" id="pol-model-ok" role="status"></p>`;

  const scopeSel = polCtx.modelsForm.querySelector('[name="scope_type"]');
  const scopeWrap = polCtx.modelsForm.querySelector('#pol-scope-id-wrap');
  scopeSel.addEventListener('change', () => {
    scopeWrap.hidden = scopeSel.value !== 'team';
  });
}

export async function loadAllowlist() {
  const d = await api('/api/governance/model-allowlist');
  polCtx.lastAllowlist = d.entries ?? [];
  polCtx.lastAllowlistNote = d.note ?? '';
  renderModels();
}

export function renderModels() {
  const { modelsList, mutate, lastAllowlist, lastAllowlistNote } = polCtx;
  modelsList.setAttribute('aria-busy', 'false');
  if (!lastAllowlist.length) {
    modelsList.innerHTML = emptyState({
      reason: 'no-data',
      title: 'No model/provider allowlist entries',
      body: lastAllowlistNote
        || 'Empty allowlist = unrestricted (fail-open). Add global or team rows to start an observe→enforce rollout.',
    });
    return;
  }
  const rows = lastAllowlist.map((e) => {
    const id = e.id;
    const scope = e.scope_type === 'team'
      ? `team:<code>${esc(e.scope_id ?? '')}</code>`
      : '<span class="pill muted">global</span>';
    const enabled = e.enabled === false
      ? '<span class="pill muted">disabled</span>'
      : '<span class="pill good">enabled</span>';
    const actions = mutate
      ? `<div class="pol-actions">
          <button type="button" class="primary" data-flip-mode="${esc(String(id))}"
            aria-label="Toggle mode for ${esc(allowlistLabel(e))}">
            Set ${esc(flipMode(e.mode) ?? 'observe')}
          </button>
          <button type="button" class="danger" data-delete-allow="${esc(String(id))}"
            aria-label="Remove ${esc(allowlistLabel(e))}">Remove</button>
        </div>`
      : '<span class="hint">read-only</span>';
    return `<tr data-allow-id="${esc(String(id))}">
      <td>${scope}</td>
      <td>${e.provider ? `<code>${esc(e.provider)}</code>` : '—'}</td>
      <td>${e.model ? `<code>${esc(e.model)}</code>` : '—'}</td>
      <td>${modePill(e.mode)}</td>
      <td>${enabled}</td>
      <td>${e.note ? esc(e.note) : '—'}</td>
      <td>${actions}</td>
    </tr>`;
  }).join('');
  modelsList.innerHTML = `<table class="pol-table">
    <caption class="sr-only">Model and provider allowlist</caption>
    <thead><tr>
      <th scope="col">Scope</th>
      <th scope="col">Provider</th>
      <th scope="col">Model</th>
      <th scope="col">Mode</th>
      <th scope="col">Enabled</th>
      <th scope="col">Note</th>
      <th scope="col">Actions</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

/** Admin-only mutations: add-entry submit + delegated flip/delete clicks. */
export function bindModelHandlers() {
  const { section, modelsForm, modelsList } = polCtx;

  modelsForm.querySelector('#pol-model-add')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const errEl = section.querySelector('#pol-model-err');
    const okEl = section.querySelector('#pol-model-ok');
    errEl.textContent = '';
    okEl.textContent = '';
    const fd = new FormData(form);
    const v = validateModelAllowlist({
      scope_type: fd.get('scope_type'),
      scope_id: fd.get('scope_id'),
      provider: fd.get('provider'),
      model: fd.get('model'),
      mode: fd.get('mode'),
      enabled: true,
    });
    if (!v.ok) {
      errEl.textContent = v.error;
      form.querySelector(`[name="${v.field || 'provider'}"]`)?.focus();
      return;
    }
    const submit = form.querySelector('[type="submit"]');
    submit.disabled = true;
    try {
      await api('/api/governance/model-allowlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(v.value),
      });
      form.reset();
      form.querySelector('[name="scope_type"]').value = 'global';
      form.querySelector('#pol-scope-id-wrap').hidden = true;
      form.querySelector('[name="mode"]').value = 'observe';
      await loadAllowlist();
      renderCards();
      okEl.textContent = `Added ${allowlistLabel(v.value)}.`;
      announce(`Allowlist entry added: ${allowlistLabel(v.value)}.`);
    } catch (err) {
      errEl.textContent = err.message;
    } finally {
      submit.disabled = false;
    }
  });

  modelsList.addEventListener('click', async (e) => {
    const flipBtn = e.target.closest('[data-flip-mode]');
    if (flipBtn) {
      const id = Number(flipBtn.dataset.flipMode);
      const entry = polCtx.lastAllowlist.find((row) => Number(row.id) === id);
      if (!entry) return;
      const next = flipMode(entry.mode);
      if (!next) {
        announce(`Unknown mode ${entry.mode}`);
        return;
      }
      const rebuilt = rebuildAllowlistBody(entry, next);
      if (!rebuilt.ok) {
        announce(rebuilt.error);
        return;
      }
      flipBtn.disabled = true;
      try {
        // Existing API has no PATCH — mode toggle is delete + re-create.
        await preservingFocus(modelsList, `[data-flip-mode="${CSS.escape(String(id))}"]`, async () => {
          await api(`/api/governance/model-allowlist/${encodeURIComponent(id)}`, { method: 'DELETE' });
          await api('/api/governance/model-allowlist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(rebuilt.value),
          });
          await loadAllowlist();
          renderCards();
        });
        announce(`${allowlistLabel(entry)} mode set to ${next}.`);
      } catch (err) {
        flipBtn.disabled = false;
        // Best-effort recovery: reload so UI matches server after a partial toggle.
        await loadAllowlist().catch(() => {});
        renderCards();
        announce(`Mode toggle failed: ${err.message}`);
      }
      return;
    }

    const delBtn = e.target.closest('[data-delete-allow]');
    if (delBtn) {
      const id = Number(delBtn.dataset.deleteAllow);
      const entry = polCtx.lastAllowlist.find((row) => Number(row.id) === id);
      const label = entry ? allowlistLabel(entry) : String(id);
      // no confirm() — reason prompt is the deliberate second step.
      const reason = window.prompt(
        `Remove allowlist entry "${label}"?\n\nReason (required — audit trail):`,
        '',
      );
      if (reason == null) return;
      if (!String(reason).trim()) {
        announce('A reason is required to remove an allowlist entry.');
        return;
      }
      delBtn.disabled = true;
      try {
        await preservingFocus(modelsList, 'table', async () => {
          await api(`/api/governance/model-allowlist/${encodeURIComponent(id)}`, { method: 'DELETE' });
          await loadAllowlist();
          renderCards();
        });
        announce(`Removed allowlist entry ${label}.`);
      } catch (err) {
        delBtn.disabled = false;
        announce(`Remove failed: ${err.message}`);
      }
    }
  });
}

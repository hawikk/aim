/* Case detail pane (split): header, status transitions, evidence
 * attach/detach, notes, and the event timeline. Matched content and cleartext
 * identity are never rendered — attachments are refs only. The back button
 * returns to the list via nav.js goList(). */

import {
  STATUS_LABEL,
  ATTACH_KINDS,
  ATTACH_LABEL,
  nextActions,
  groupAttachments,
  validateAttachment,
  validateNote,
} from '../lib/cases.js';
import { api } from '../lib/api.js';
import { esc } from '../lib/dom.js';
import { fmtTs, relTime, shortRef } from '../lib/format.js';
import { sevPill } from '../lib/severity.js';
import { emptyState } from '../lib/components.js';
import { casesCtx, statusPill } from './state.js';
import { goList } from './nav.js';

export async function showDetail(caseId) {
  const { listPane, detailPane } = casesCtx;
  listPane.hidden = true;
  detailPane.hidden = false;
  detailPane.innerHTML = emptyState({ reason: 'loading', title: 'Loading case…' });
  try {
    const data = await api(`/api/cases/${encodeURIComponent(caseId)}`);
    renderDetail(data);
  } catch (err) {
    detailPane.innerHTML = emptyState({ reason: 'error', title: 'Could not load this case', body: err.message });
  }
}

function renderDetail(data) {
  const { detailPane } = casesCtx;
  const c = data.case;
  const groups = groupAttachments(data.attachments ?? []);
  const actions = nextActions(c.status);
  detailPane.innerHTML = `
    <div class="case-detail-head">
      <button type="button" class="btn" id="case-back">← All cases</button>
      <div class="case-detail-titleblock">
        <h2 class="case-detail-title">${esc(c.title)}</h2>
        <div class="case-detail-pills">
          ${statusPill(c.status)}
          ${sevPill(c.severity)}
          <span class="hint">opened by ${esc(c.createdBy)} · ${esc(fmtTs(c.createdAt))}</span>
        </div>
      </div>
      <div class="case-detail-exports">
        <a class="btn-export" href="/api/cases/${esc(c.caseId)}/export" download>JSON</a>
        <a class="btn-export" href="/api/cases/${esc(c.caseId)}/export?format=csv" download>CSV</a>
      </div>
    </div>
    ${c.description ? `<div class="panel case-desc"><p>${esc(c.description)}</p></div>` : ''}
    <div class="case-detail-grid">
      <div class="panel">
        <h3>Status</h3>
        <div class="case-status-actions" id="case-status-actions">
          ${actions.length
            ? actions.map((s) => `<button type="button" class="btn ${s === 'closed' ? '' : 'primary'}" data-status="${esc(s)}">Mark ${esc(STATUS_LABEL[s])}</button>`).join('')
            : '<span class="hint">No transitions available</span>'}
        </div>
        ${c.closedAt ? `<p class="hint">Closed ${esc(fmtTs(c.closedAt))}${c.closedBy ? ` by ${esc(c.closedBy)}` : ''}</p>` : ''}
      </div>
      <div class="panel">
        <h3>Attach evidence</h3>
        <form id="case-attach-form" class="case-form case-form-compact">
          <label>Kind
            <select id="case-attach-kind" name="kind">
              ${ATTACH_KINDS.map((k) => `<option value="${k}">${ATTACH_LABEL[k]}</option>`).join('')}
            </select>
          </label>
          <label class="case-form-full">Ref <span class="hint">finding id · user_ref · tool name</span>
            <input type="text" id="case-attach-ref" name="ref" maxlength="200" required autocomplete="off" />
          </label>
          <label class="case-form-full">Label <span class="hint">optional display hint</span>
            <input type="text" id="case-attach-label" name="label" maxlength="200" autocomplete="off" />
          </label>
          <div class="case-form-actions">
            <button type="submit" class="btn primary">Attach</button>
            <span class="case-form-err" id="case-attach-err" role="alert"></span>
          </div>
        </form>
      </div>
    </div>
    <div class="panel">
      <h3>Attachments</h3>
      <div id="case-attachments">${renderAttachments(groups)}</div>
    </div>
    <div class="panel">
      <h3>Notes & timeline</h3>
      <form id="case-note-form" class="case-form case-form-compact">
        <label class="case-form-full">Add note
          <textarea id="case-note-body" maxlength="4000" rows="2" required placeholder="Investigation note (no secrets / no prompt content)"></textarea>
        </label>
        <div class="case-form-actions">
          <button type="submit" class="btn primary">Add note</button>
          <span class="case-form-err" id="case-note-err" role="alert"></span>
        </div>
      </form>
      <ol class="case-timeline" id="case-timeline">
        ${(data.events ?? []).slice().reverse().map(eventItem).join('') || '<li class="hint">No events yet</li>'}
      </ol>
    </div>`;

  detailPane.querySelector('#case-back').addEventListener('click', goList);
  detailPane.querySelectorAll('[data-status]').forEach((b) => {
    b.addEventListener('click', () => transitionStatus(c.caseId, b.dataset.status));
  });
  detailPane.querySelector('#case-attach-form').addEventListener('submit', (e) => {
    e.preventDefault();
    submitAttach(c.caseId);
  });
  detailPane.querySelector('#case-note-form').addEventListener('submit', (e) => {
    e.preventDefault();
    submitNote(c.caseId);
  });
  detailPane.querySelectorAll('[data-detach]').forEach((b) => {
    b.addEventListener('click', () => detach(c.caseId, b.dataset.detach));
  });
}

function renderAttachments(groups) {
  return ATTACH_KINDS.map((kind) => {
    const items = groups[kind] ?? [];
    if (!items.length) {
      return `<div class="case-attach-group"><h4>${esc(ATTACH_LABEL[kind])}s</h4><p class="hint">None attached</p></div>`;
    }
    return `<div class="case-attach-group"><h4>${esc(ATTACH_LABEL[kind])}s</h4>
      <ul class="case-attach-list">${items.map((a) => attachItem(a, kind)).join('')}</ul></div>`;
  }).join('');
}

function attachItem(a, kind) {
  let link = '';
  if (kind === 'finding') link = `<a href="#/findings" class="hint">findings inbox</a>`;
  else if (kind === 'user') link = `<a href="#/users/${encodeURIComponent(a.ref)}">user timeline →</a>`;
  else if (kind === 'tool') link = `<a href="#/tools/${encodeURIComponent(a.ref)}">tool →</a>`;
  const display = a.label || (kind === 'user' ? shortRef(a.ref) : a.ref);
  return `<li class="case-attach-item">
    <code class="mono" title="${esc(a.ref)}">${esc(display)}</code>
    ${link}
    <button type="button" class="btn btn-sm" data-detach="${esc(a.attachmentId)}" aria-label="Detach ${esc(display)}">Detach</button>
  </li>`;
}

function eventItem(e) {
  return `<li class="case-event case-event-${esc(e.kind)}">
    <span class="case-event-when" title="${esc(e.createdAt ?? '')}">${esc(relTime(e.createdAt))}</span>
    <span class="case-event-kind pill muted">${esc(e.kind)}</span>
    <span class="case-event-body">${esc(e.body ?? '')}</span>
    <span class="hint">${esc(e.actor ?? '')}</span>
  </li>`;
}

async function transitionStatus(caseId, status) {
  const { detailPane } = casesCtx;
  try {
    await api(`/api/cases/${encodeURIComponent(caseId)}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    await showDetail(caseId);
  } catch (err) {
    detailPane.insertAdjacentHTML('afterbegin', `<div class="err" role="alert">${esc(err.message)}</div>`);
  }
}

async function submitAttach(caseId) {
  const { detailPane } = casesCtx;
  const errEl = detailPane.querySelector('#case-attach-err');
  errEl.textContent = '';
  const body = {
    kind: detailPane.querySelector('#case-attach-kind').value,
    ref: detailPane.querySelector('#case-attach-ref').value,
    label: detailPane.querySelector('#case-attach-label').value || null,
  };
  const parsed = validateAttachment(body);
  if (!parsed.ok) { errEl.textContent = parsed.detail; return; }
  try {
    await api(`/api/cases/${encodeURIComponent(caseId)}/attachments`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(parsed.value),
    });
    await showDetail(caseId);
  } catch (err) { errEl.textContent = err.message; }
}

async function detach(caseId, attachmentId) {
  const { detailPane } = casesCtx;
  try {
    await api(`/api/cases/${encodeURIComponent(caseId)}/attachments/${encodeURIComponent(attachmentId)}`, {
      method: 'DELETE',
    });
    await showDetail(caseId);
  } catch (err) {
    detailPane.insertAdjacentHTML('afterbegin', `<div class="err" role="alert">${esc(err.message)}</div>`);
  }
}

async function submitNote(caseId) {
  const { detailPane } = casesCtx;
  const errEl = detailPane.querySelector('#case-note-err');
  errEl.textContent = '';
  const parsed = validateNote({ body: detailPane.querySelector('#case-note-body').value });
  if (!parsed.ok) { errEl.textContent = parsed.detail; return; }
  try {
    await api(`/api/cases/${encodeURIComponent(caseId)}/notes`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(parsed.value),
    });
    await showDetail(caseId);
  } catch (err) { errEl.textContent = err.message; }
}

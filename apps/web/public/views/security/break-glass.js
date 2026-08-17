/* Break-glass panels (split of views/security.js):
 *: analyst surface for secret break-glass (and other confirmed
 *    overrides) in the selected pilot window. Metadata only — no prompt or
 *    secret content. Failures must not blank the rest of Security — the panel
 *    degrades to an error empty state.
 *: break-glass grants (request → manager approve/deny → revoke),
 *    admin-gated via canMutateSanctioned(). */
import { $, esc } from '../../lib/dom.js';
import { fmtInt, fmtTs } from '../../lib/format.js';
import { state, hashFor, api, setStatus, canMutateSanctioned, apiJson, showError } from '../../lib/runtime.js';
import { EMPTY, table, card, skeletonCards } from '../../lib/components.js';
import { refCell } from '../../lib/ui.js';

const KIND_LABEL = {
  break_glass: 'secret break-glass',
  pii_confirm: 'PII confirm',
  override: 'override',
  blocked: 'blocked',
  would_block: 'would_block',
};

export async function loadBreakGlass() {
  const cardsEl = $('#break-glass-cards');
  const hint = $('#break-glass-hint');
  const exp = $('#exp-break-glass');
  if (exp) exp.href = `/api/enforcement/break-glass?days=${state.days}&action=confirmed&format=csv`;
  if (cardsEl) cardsEl.innerHTML = skeletonCards(3);
  try {
    const d = await api(`/api/enforcement/break-glass?days=${state.days}&action=confirmed&limit=100`);
    const by = d.summary?.byAction ?? {};
    if (cardsEl) {
      cardsEl.innerHTML = [
        card('Secret break-glass', fmtInt(d.breakGlassCount ?? 0), (d.breakGlassCount ?? 0) > 0 ? 'warn' : 'good'),
        card('All confirmed overrides', fmtInt(by.confirmed ?? 0)),
        card('Secret blocks (window)', fmtInt(by.blocked ?? 0), (by.blocked ?? 0) > 0 ? 'bad' : 'good'),
      ].join('');
    }
    if (hint) {
      const listed = d.summary?.listed ?? d.events?.length ?? 0;
      const trunc = d.summary?.truncated ? ' (truncated at limit)' : '';
      hint.textContent = `${listed} override event${listed === 1 ? '' : 's'} listed for last ${d.days}d${trunc}. Metadata only — no prompt or secret content.`;
    }
    table($('#break-glass-table'), [
      { key: 'ts', label: 'Time', render: (r) => fmtTs(r.ts) },
      {
        key: 'kind',
        label: 'Kind',
        render: (r) => `<span class="pill ${r.kind === 'break_glass' ? 'warn' : 'muted'}">${esc(KIND_LABEL[r.kind] ?? r.kind ?? '—')}</span>`,
      },
      {
        key: 'ruleId',
        label: 'Rule',
        render: (r) => `<span class="mono">${esc(r.ruleId ?? '—')}</span>`,
      },
      {
        key: 'pseudonym',
        label: 'User',
        render: (r) => (r.pseudonym
          ? refCell(r.pseudonym, { href: hashFor('users', r.pseudonym) })
          : '<span class="faint">—</span>'),
      },
      { key: 'team', label: 'Team', render: (r) => esc(r.team ?? '—') },
      { key: 'tool', label: 'Tool', render: (r) => (r.tool ? `<a href="${hashFor('tools', r.tool)}">${esc(r.tool)}</a>` : '—') },
      {
        key: 'policyHash',
        label: 'Policy',
        render: (r) => `<span class="mono faint" title="${esc(r.policyHash ?? '')}">${esc((r.policyHash ?? '—').slice(0, 20))}</span>`,
      },
      {
        key: 'hostRef',
        label: 'Host',
        render: (r) => `<span class="mono faint">${esc((r.hostRef ?? '—').slice(0, 12))}</span>`,
      },
    ], d.events ?? [], {
      caption: 'Endpoint break-glass and confirmed overrides (pilot window)',
      empty: EMPTY.breakGlass,
    });
  } catch (err) {
    if (cardsEl) cardsEl.innerHTML = '';
    if (hint) hint.textContent = `Could not load break-glass trail: ${err.message}`;
    table($('#break-glass-table'), [
      { key: 'ts', label: 'Time' },
      { key: 'kind', label: 'Kind' },
      { key: 'ruleId', label: 'Rule' },
    ], [], {
      caption: 'Endpoint break-glass and confirmed overrides (pilot window)',
      empty: { reason: 'error', title: 'Could not load break-glass trail', body: err.message || 'Request failed.' },
    });
  }
}

/* ---------- break-glass grants (manager approval + expiry) ---------- */

const GRANT_STATUS_CLASS = {
  pending: 'warn',
  approved: 'good',
  denied: 'bad',
  revoked: 'muted',
  expired: 'muted',
};

export async function loadBreakGlassGrants() {
  const cardsEl = $('#break-glass-grants-cards');
  const hint = $('#break-glass-grants-hint');
  const expG = $('#exp-break-glass-grants');
  const expA = $('#exp-break-glass-audit');
  if (expG) expG.href = `/api/enforcement/break-glass/grants?days=${state.days}&format=csv`;
  if (expA) expA.href = `/api/enforcement/break-glass/audit-export?days=${state.days}&format=bundle`;
  if (cardsEl) cardsEl.innerHTML = skeletonCards(4);
  bindGrantControls();
  try {
    const d = await api(`/api/enforcement/break-glass/grants?days=${state.days}&limit=100`);
    const s = d.summary ?? {};
    if (cardsEl) {
      cardsEl.innerHTML = [
        card('Pending approval', fmtInt(s.pending ?? 0), (s.pending ?? 0) > 0 ? 'warn' : null),
        card('Active grants', fmtInt(s.active ?? 0), (s.active ?? 0) > 0 ? 'good' : null),
        card('Revoked', fmtInt(s.revoked ?? 0)),
        card('Expired / denied', fmtInt((s.expired ?? 0) + (s.denied ?? 0))),
      ].join('');
    }
    if (hint) {
      const n = d.grants?.length ?? 0;
      hint.textContent = `${n} grant${n === 1 ? '' : 's'} in last ${d.days}d. `
        + 'Manager approval is optional (policy default off). Admin approves/revokes; export the audit pack for compliance.';
    }
    const canAdmin = canMutateSanctioned();
    table($('#break-glass-grants-table'), [
      { key: 'requestedAt', label: 'Requested', render: (r) => fmtTs(r.requestedAt) },
      {
        key: 'status',
        label: 'Status',
        render: (r) => `<span class="pill ${GRANT_STATUS_CLASS[r.status] ?? 'muted'}">${esc(r.status)}</span>`,
      },
      {
        key: 'subjectUserRef',
        label: 'Subject',
        render: (r) => (r.subjectUserRef
          ? refCell(r.subjectUserRef, { href: hashFor('users', r.subjectUserRef) })
          : '—'),
      },
      { key: 'reason', label: 'Reason', render: (r) => esc((r.reason ?? '').slice(0, 80)) },
      { key: 'ticketRef', label: 'Ticket', render: (r) => esc(r.ticketRef ?? '—') },
      {
        key: 'expiresAt',
        label: 'Expires',
        render: (r) => (r.expiresAt ? fmtTs(r.expiresAt) : '<span class="faint">—</span>'),
      },
      {
        key: 'actions',
        label: 'Actions',
        render: (r) => {
          if (!canAdmin) return '<span class="faint">admin only</span>';
          const bits = [];
          if (r.status === 'pending') {
            bits.push(`<button type="button" class="btn-control btn-sm bg-approve" data-id="${esc(r.id)}">Approve</button>`);
            bits.push(`<button type="button" class="btn-control btn-sm bg-deny" data-id="${esc(r.id)}">Deny</button>`);
          }
          if (r.status === 'approved') {
            bits.push(`<button type="button" class="btn-control btn-sm bg-revoke" data-id="${esc(r.id)}">Revoke</button>`);
          }
          return bits.join(' ') || '<span class="faint">—</span>';
        },
      },
    ], d.grants ?? [], {
      caption: 'Break-glass grants — request, approve, expire, revoke',
      empty: EMPTY.breakGlassGrants,
    });
    $('#break-glass-grants-table')?.querySelectorAll('.bg-approve').forEach((btn) => {
      btn.addEventListener('click', () => approveGrant(btn.dataset.id));
    });
    $('#break-glass-grants-table')?.querySelectorAll('.bg-deny').forEach((btn) => {
      btn.addEventListener('click', () => denyGrant(btn.dataset.id));
    });
    $('#break-glass-grants-table')?.querySelectorAll('.bg-revoke').forEach((btn) => {
      btn.addEventListener('click', () => revokeGrant(btn.dataset.id));
    });
  } catch (err) {
    if (cardsEl) cardsEl.innerHTML = '';
    if (hint) hint.textContent = `Could not load grants: ${err.message}`;
    table($('#break-glass-grants-table'), [
      { key: 'status', label: 'Status' },
      { key: 'subjectUserRef', label: 'Subject' },
    ], [], {
      caption: 'Break-glass grants',
      empty: { reason: 'error', title: 'Could not load grants', body: err.message || 'Request failed.' },
    });
  }
}

let _grantControlsBound = false;
function bindGrantControls() {
  if (_grantControlsBound) return;
  _grantControlsBound = true;
  $('#bg-grant-refresh')?.addEventListener('click', () => { loadBreakGlassGrants(); });
  $('#bg-grant-request')?.addEventListener('click', requestGrant);
}

async function requestGrant() {
  const subject = window.prompt('Subject user_ref / pseudonym for the grant (required):', '');
  if (subject == null) return;
  const subjectUserRef = subject.trim();
  if (!subjectUserRef) {
    setStatus('subjectUserRef is required');
    return;
  }
  const reason = window.prompt('Reason for break-glass grant (required, audited — no secrets):', '');
  if (reason == null) return;
  if (!reason.trim()) {
    setStatus('A reason is required');
    return;
  }
  const ticket = window.prompt('Optional ticket ref (e.g. SEC-1234):', '') ?? '';
  // no window.confirm(). Leave pending for manager approval; admins
  // use the grant-table Approve action for immediate approval.
  const auto = false;
  try {
    await apiJson('/api/enforcement/break-glass/grants', 'POST', {
      subjectUserRef,
      reason: reason.trim(),
      ticketRef: ticket.trim() || undefined,
      requestedTtlHours: 4,
      autoApprove: auto || undefined,
      ttlHours: auto ? 4 : undefined,
    });
    setStatus(auto ? 'Grant approved.' : 'Grant requested (pending approval).');
    await loadBreakGlassGrants();
  } catch (err) {
    showError(err);
  }
}

async function approveGrant(id) {
  const note = window.prompt('Approval note (optional):', 'Approved') ?? '';
  const ttlRaw = window.prompt('TTL hours (1–168, default 4):', '4');
  if (ttlRaw == null) return;
  const ttlHours = Number(ttlRaw) || 4;
  try {
    await apiJson(`/api/enforcement/break-glass/grants/${encodeURIComponent(id)}/approve`, 'POST', {
      ttlHours,
      decisionNote: note.trim() || undefined,
    });
    setStatus('Grant approved.');
    await loadBreakGlassGrants();
  } catch (err) {
    showError(err);
  }
}

async function denyGrant(id) {
  const note = window.prompt('Denial reason (required):', '');
  if (note == null || !note.trim()) {
    setStatus('Denial reason required');
    return;
  }
  try {
    await apiJson(`/api/enforcement/break-glass/grants/${encodeURIComponent(id)}/deny`, 'POST', {
      decisionNote: note.trim(),
    });
    setStatus('Grant denied.');
    await loadBreakGlassGrants();
  } catch (err) {
    showError(err);
  }
}

async function revokeGrant(id) {
  const reason = window.prompt('Revoke reason (required):', '');
  if (reason == null || !reason.trim()) {
    setStatus('Revoke reason required');
    return;
  }
  try {
    await apiJson(`/api/enforcement/break-glass/grants/${encodeURIComponent(id)}/revoke`, 'POST', {
      reason: reason.trim(),
    });
    setStatus('Grant revoked.');
    await loadBreakGlassGrants();
  } catch (err) {
    showError(err);
  }
}

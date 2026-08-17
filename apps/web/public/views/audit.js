/* Audit trail view (AIM-95) — pure-moved from app.js (AIM-527).
 * AIM-989: JIT first-login failure + SLA breach surfaces on this tab so
 * auditors see identity.jit_* without digging raw logs. */
import { $, esc } from '../lib/dom.js';
import { fmtTs } from '../lib/format.js';
import { api } from '../lib/runtime.js';
import { EMPTY, table, emptyState } from '../lib/components.js';
import { parseAuditFiltersFromHash } from '../lib/audit-filters.js';
import {
  JIT_ACTIONS,
  JIT_RUNBOOK_PATH,
  formatJitDetail,
  jitAuditQueryPath,
  summarizeJitStatus,
} from '../lib/jit-status.js';

let jitFiltersWired = false;

function wireJitFilters() {
  if (jitFiltersWired) return;
  const host = $('#jit-quick-filters');
  if (!host) return;
  jitFiltersWired = true;
  host.addEventListener('click', (ev) => {
    const btn = ev.target.closest('[data-jit-filter]');
    if (!btn) return;
    const actionInput = $('#audit-filter-action');
    if (!actionInput) return;
    const value = btn.getAttribute('data-jit-filter') ?? '';
    actionInput.value = value;
    // Re-use the existing refresh path so filters + main table stay in sync.
    $('#audit-refresh')?.click();
  });
}

function renderJitTable(el, events, { caption, emptyTitle, emptyBody }) {
  if (!el) return;
  if (!events.length) {
    el.innerHTML = emptyState({
      reason: 'no-data',
      title: emptyTitle,
      body: emptyBody,
      doc: JIT_RUNBOOK_PATH,
    });
    return;
  }
  // Newest first for operator scan order.
  const rows = events.slice().reverse();
  el.innerHTML = `<div class="table-wrap" tabindex="0" role="region" aria-label="${esc(caption)}, scrollable"><table></table></div>`;
  const tbl = el.querySelector('table');
  table(tbl, [
    { key: 'ts', label: 'Time', render: (r) => fmtTs(r.ts) },
    { key: 'actor', label: 'Principal', render: (r) => esc(r.actor ?? '—') },
    {
      key: 'detail',
      label: 'Detail',
      render: (r) => `<span class="mono">${esc(formatJitDetail(r.detail))}</span>`,
    },
    {
      key: 'resource',
      label: 'Resource',
      render: (r) => `<span class="mono">${esc(r.resource ?? '—')}</span>`,
    },
  ], rows, { caption });
}

async function loadJitStatus() {
  const panel = $('#jit-status-panel');
  const failHost = $('#jit-failures');
  const breachHost = $('#jit-breaches');
  if (!panel || !failHost || !breachHost) return;

  wireJitFilters();

  const runbook = $('#jit-runbook-link');
  if (runbook) runbook.textContent = JIT_RUNBOOK_PATH;

  try {
    const [failRes, breachRes] = await Promise.all([
      api(jitAuditQueryPath(JIT_ACTIONS.FAILED, { limit: 25 })),
      api(jitAuditQueryPath(JIT_ACTIONS.SLA_BREACH, { limit: 25 })),
    ]);
    const failures = failRes?.events ?? [];
    const breaches = breachRes?.events ?? [];
    const summary = summarizeJitStatus({ failures, breaches });

    const failCount = $('#jit-fail-count');
    const breachCount = $('#jit-breach-count');
    if (failCount) failCount.textContent = summary.failureCount ? `(${summary.failureCount})` : '';
    if (breachCount) breachCount.textContent = summary.breachCount ? `(${summary.breachCount})` : '';

    panel.dataset.jitHasIssues = summary.hasIssues ? '1' : '0';
    const banner = $('#jit-status-banner');
    if (banner) {
      if (summary.hasIssues) {
        banner.hidden = false;
        banner.className = 'banner warn';
        banner.textContent = summary.failureCount
          ? `${summary.failureCount} recent JIT provision failure(s)${summary.breachCount ? ` · ${summary.breachCount} SLA breach(es)` : ''}. Filter the full trail below or open the runbook.`
          : `${summary.breachCount} recent JIT SLA breach(es). Login may still succeed; investigate latency.`;
      } else {
        banner.hidden = false;
        banner.className = 'banner info';
        banner.textContent = 'No recent JIT provision failures or SLA breaches in the audit trail.';
      }
    }

    renderJitTable(failHost, failures, {
      caption: 'Recent JIT provision failures',
      emptyTitle: 'No JIT provision failures',
      emptyBody: 'identity.jit_provision_failed events appear here when first-login directory upsert fails or a deprovisioned user is blocked.',
    });
    renderJitTable(breachHost, breaches, {
      caption: 'Recent JIT SLA breaches',
      emptyTitle: 'No JIT SLA breaches',
      emptyBody: 'identity.jit_sla_breach fires when AIM-side JIT duration exceeds AIM_JIT_SLA_MS (default 1s). Login can still succeed.',
    });
  } catch (err) {
    panel.dataset.jitHasIssues = '';
    const banner = $('#jit-status-banner');
    if (banner) {
      banner.hidden = false;
      banner.className = 'banner warn';
      banner.textContent = err?.message
        ? `Could not load JIT status: ${err.message}`
        : 'Could not load JIT status.';
    }
    failHost.innerHTML = emptyState({
      reason: 'error',
      title: 'JIT failures unavailable',
      body: err?.message || 'Audit query failed.',
      retryKey: 'audit',
    });
    breachHost.innerHTML = emptyState({
      reason: 'error',
      title: 'SLA breaches unavailable',
      body: err?.message || 'Audit query failed.',
      retryKey: 'audit',
    });
    throw err;
  }
}


/* ---------- Audit trail view (AIM-95) ----------
 * Server-gated to auditor + admin; the tab only renders with
 * capabilities.auditTrail, so a 403 here means the role changed mid-session —
 * refresh() already surfaces that as a retryable banner.
 *
 * AIM-998: `#/audit?action=guardrail.alerts_update` (and optional actor/since)
 * pre-fills the filter bar so Rules can deep-link destination config changes. */
export function applyAuditFiltersFromHash(hash = typeof location !== 'undefined' ? location.hash : '') {
  const filters = parseAuditFiltersFromHash(hash);
  const actionEl = $('#audit-filter-action');
  const actorEl = $('#audit-filter-actor');
  const sinceEl = $('#audit-filter-since');
  if (filters.action != null && actionEl) actionEl.value = filters.action;
  if (filters.actor != null && actorEl) actorEl.value = filters.actor;
  if (filters.since != null && sinceEl) sinceEl.value = filters.since;
  return filters;
}

export async function loadAudit() {
  applyAuditFiltersFromHash();
  const p = new URLSearchParams();
  const action = $('#audit-filter-action').value.trim();
  const actor = $('#audit-filter-actor').value.trim();
  const since = $('#audit-filter-since').value;
  if (action) p.set('action', action);
  if (actor) p.set('actor', actor);
  if (since) p.set('since', `${since}T00:00:00Z`);
  p.set('limit', '200');

  // Load main trail + JIT status in parallel. JIT failure must not blank the
  // full audit table if only one query fails — Promise.allSettled.
  const mainP = api(`/api/audit/events?${p}`);
  const jitP = loadJitStatus().catch(() => null);
  const d = await mainP;
  await jitP;

  table($('#audit-table'), [
    { key: 'ts', label: 'Time', render: (r) => fmtTs(r.ts) },
    { key: 'actor', label: 'Actor', render: (r) => esc(r.actor ?? '—') },
    { key: 'action', label: 'Action', render: (r) => esc(r.action ?? '—') },
    { key: 'resource', label: 'Resource', render: (r) => `<span class="mono">${esc(r.resource ?? '—')}</span>` },
    { key: 'detail', label: 'Detail', render: (r) => `<span class="mono">${esc(JSON.stringify(r.detail ?? {}))}</span>` },
  ], d.events, { caption: 'Audit trail events', empty: EMPTY.audit });
}

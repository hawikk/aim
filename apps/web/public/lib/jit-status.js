/* — JIT first-login failure + SLA status helpers (pure, no DOM).
 *
 * Operators should see identity.jit_provision_failed and identity.jit_sla_breach
 * without digging raw audit JSONL. Data still comes from GET /api/audit/events.
 */

export const JIT_RUNBOOK_PATH = 'docs/security/jit-provisioning-sla.md';

export const JIT_ACTIONS = Object.freeze({
  FAILED: 'identity.jit_provision_failed',
  SLA_BREACH: 'identity.jit_sla_breach',
  PROVISIONED: 'identity.user_provisioned',
  UPDATED: 'identity.user_updated',
});

/**
 * @param {{ failures?: object[], breaches?: object[] }} input
 */
export function summarizeJitStatus({ failures = [], breaches = [] } = {}) {
  const failureCount = failures.length;
  const breachCount = breaches.length;
  return {
    failureCount,
    breachCount,
    hasIssues: failureCount > 0 || breachCount > 0,
    /** AuditLog.query returns chronological order; last = most recent. */
    latestFailure: failureCount ? failures[failureCount - 1] : null,
    latestBreach: breachCount ? breaches[breachCount - 1] : null,
  };
}

/**
 * Compact one-line detail for tables (not full JSON dump).
 * @param {unknown} detail
 */
export function formatJitDetail(detail) {
  if (detail == null) return '—';
  if (typeof detail !== 'object') return String(detail);
  const d = /** @type {Record<string, unknown>} */ (detail);
  const bits = [];
  if (d.error) bits.push(String(d.error));
  if (d.reason && d.reason !== d.error) bits.push(String(d.reason));
  if (d.durationMs != null && Number.isFinite(Number(d.durationMs))) {
    bits.push(`${Number(d.durationMs)}ms`);
  }
  if (d.slaMs != null && Number.isFinite(Number(d.slaMs))) {
    bits.push(`SLA ${Number(d.slaMs)}ms`);
  }
  if (d.slaBreached === true) bits.push('slaBreached');
  if (d.idp) bits.push(`idp:${d.idp}`);
  if (d.source) bits.push(String(d.source));
  if (bits.length) return bits.join(' · ');
  try {
    return JSON.stringify(d);
  } catch {
    return '—';
  }
}

/** Query path for a single JIT audit action (exact match). */
export function jitAuditQueryPath(action, { limit = 25 } = {}) {
  const p = new URLSearchParams();
  p.set('action', action);
  p.set('limit', String(Math.min(Math.max(Number(limit) || 25, 1), 200)));
  return `/api/audit/events?${p}`;
}

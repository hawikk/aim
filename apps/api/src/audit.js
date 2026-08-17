// Immutable audit trail wiring (AIM-27). Appends dashboard/data access records
// to the hash-chained, HMAC-sealed audit log from @aim/audit.
//
// Config (both required to enable; missing config = no-op with a startup warn):
//   AUDIT_LOG_PATH  — append-only JSONL path (single writer per path)
//   AUDIT_HMAC_KEY  — HMAC-SHA256 sealing key (from KMS/secret store in prod)
import { AuditLog } from '../../../packages/audit/src/audit-log.ts';

let log = null;

export function initAudit(fastify) {
  const path = process.env.AUDIT_LOG_PATH;
  const key = process.env.AUDIT_HMAC_KEY;
  if (!path || !key) {
    fastify.log.warn('audit trail disabled — set AUDIT_LOG_PATH and AUDIT_HMAC_KEY to enable');
    return;
  }
  log = new AuditLog({ path, key });
  fastify.log.info({ path }, 'immutable audit trail enabled');
}

// Full-chain verification for the compliance evidence report (AIM-87).
// Re-reads env so it works even when initAudit was never called; never
// throws — a broken chain is a reportable result, not a request failure.
// Returns { enabled, ok, records, reason? }.
export function verifyAuditChain() {
  const path = process.env.AUDIT_LOG_PATH;
  const key = process.env.AUDIT_HMAC_KEY;
  if (!path || !key) return { enabled: false, ok: null, records: 0, reason: 'audit trail not configured (AUDIT_LOG_PATH/AUDIT_HMAC_KEY unset)' };
  try {
    const r = AuditLog.verify({ path, key });
    return { enabled: true, ok: r.ok, records: r.count, ...(r.ok ? {} : { reason: `${r.reason} at seq ${r.failedSeq}` }) };
  } catch (err) {
    return { enabled: true, ok: false, records: 0, reason: `verification error: ${err.message}` };
  }
}

// Chain head for evidence bundles (AIM-99): the current tail seq + seal an
// exported artifact anchors to. Never throws; mirrors verifyAuditChain's
// enabled/disabled contract. Returns { enabled, records, headSeq, headSeal }.
export function auditHead() {
  const path = process.env.AUDIT_LOG_PATH;
  const key = process.env.AUDIT_HMAC_KEY;
  if (!path || !key) return { enabled: false, records: 0, headSeq: 0, headSeal: null };
  try {
    const records = AuditLog.readAll(path);
    const tail = records[records.length - 1];
    return { enabled: true, records: records.length, headSeq: tail?.seq ?? 0, headSeal: tail?.seal ?? null };
  } catch {
    return { enabled: true, records: 0, headSeq: 0, headSeal: null };
  }
}

// Never let auditing break the request path. Returns the appended record
// (or null when the trail is not configured) so callers can hash-link
// artifacts to the chain (AIM-99 evidence bundles/snapshots).
export function audit(actor, action, resource, detail = {}) {
  if (!log) return null;
  try {
    return log.append({ actor, action, resource, detail });
  } catch (err) {
    console.error('audit append failed:', err);
    return null;
  }
}

/* AIM-998 — Audit trail deep-link helpers.
 *
 * Destination config writes audit as `guardrail.alerts_update`. Rules links
 * here with `#/audit?action=guardrail.alerts_update` so an admin can see who
 * changed enable/recipients/floors without retyping the action filter.
 *
 * Pure URL helpers only — views apply the parsed filters to the Audit form.
 */

/** Action recorded by PUT /api/guardrail/alerts (apps/api guardrail.js). */
export const GUARDRAIL_ALERTS_UPDATE_ACTION = 'guardrail.alerts_update';

/**
 * Build a shareable Audit hash with optional filters.
 * @param {{ action?: string|null, actor?: string|null, since?: string|null }} [opts]
 * @returns {string}
 */
export function auditHash({ action = null, actor = null, since = null } = {}) {
  const q = new URLSearchParams();
  if (action) q.set('action', String(action));
  if (actor) q.set('actor', String(actor));
  if (since) q.set('since', String(since));
  const qs = q.toString();
  return qs ? `#/audit?${qs}` : '#/audit';
}

/**
 * Parse Audit filter query params from a location hash.
 * Unknown / empty values become null (callers leave form fields alone).
 * @param {string} [hash]
 * @returns {{ action: string|null, actor: string|null, since: string|null }}
 */
export function parseAuditFiltersFromHash(hash = '') {
  const raw = String(hash || '').replace(/^#\/?/, '');
  const qIdx = raw.indexOf('?');
  if (qIdx < 0) return { action: null, actor: null, since: null };
  const q = new URLSearchParams(raw.slice(qIdx + 1));
  const trim = (k) => {
    const v = (q.get(k) || '').trim();
    return v || null;
  };
  return {
    action: trim('action'),
    actor: trim('actor'),
    since: trim('since'),
  };
}

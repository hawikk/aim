/* Canonical /api/findings item shape (AIM-532).
 *
 * Pure module — no db/auth deps — so web DOM fixtures can import the same
 * key list the API response builder uses. If a rename lands on either side
 * without the other, the fixture-contract test fails the build.
 */

/** Keys of one finding as returned by GET /api/findings and PATCH triage. */
export const FINDING_RESPONSE_KEYS = Object.freeze([
  'findingId',
  'ts',
  'detectedAt',
  'ruleId',
  'severity',
  'title',
  'subject',
  'evidence',
  'policyHash',
  'decision',
  'eventId',
  'status',
  'triageNote',
  'triagedBy',
  'triagedAt',
]);

/** Map a findings table row (snake_case) to the public API object (camelCase). */
export function toFinding(r) {
  return {
    findingId: r.finding_id,
    ts: r.ts,
    detectedAt: r.detected_at,
    ruleId: r.rule_id,
    severity: r.severity,
    title: r.title,
    subject: r.subject,
    evidence: r.evidence,
    policyHash: r.policy_hash,
    decision: r.decision,
    eventId: r.event_id,
    status: r.status,
    triageNote: r.triage_note,
    triagedBy: r.triaged_by,
    triagedAt: r.triaged_at,
  };
}

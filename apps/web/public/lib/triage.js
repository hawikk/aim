/* — pure triage logic shared by findings.js and the node:test suite.
 * DOM-free by design: findings.js renders and fetches; this module decides.
 * Kept dependency-free so node:test can import it without a browser. */

// Valid finding statuses, in lifecycle order. The vocabulary maps onto the
// Costa-style disposition lifecycle: new = Open, acknowledged =
// Under Review, resolved + false_positive = Resolved (with an explicit
// false-positive category).
export const TRIAGE_STATUSES = ['new', 'acknowledged', 'resolved', 'false_positive'];

// Statuses the bulk-triage endpoint accepts as a target.
export const BULK_TARGETS = ['acknowledged', 'resolved', 'false_positive'];

// Acknowledge doubles as "assign to me": the API sets triaged_by to the
// caller on any transition, so acknowledging claims the finding.
// Shape: current status → [[target status, button label, css class], ...].
export const STATUS_FLOW = {
  new: [
    ['acknowledged', 'Acknowledge & assign to me', 'primary'],
    ['resolved', 'Resolve', ''],
    ['false_positive', 'False positive', ''],
  ],
  acknowledged: [
    ['resolved', 'Resolve', 'primary'],
    ['false_positive', 'False positive', ''],
    ['new', 'Reopen', ''],
  ],
  resolved: [['new', 'Reopen', '']],
  false_positive: [['new', 'Reopen', '']],
};

// Allowed transitions for a finding currently in `status` ([] when unknown).
export function nextActions(status) {
  return STATUS_FLOW[status] ?? [];
}

// Body for PATCH /api/findings/:id — the note is trimmed and omitted when empty.
export function buildTriagePayload(status, note) {
  const payload = { status };
  const trimmed = String(note ?? '').trim();
  if (trimmed) payload.note = trimmed;
  return payload;
}

// Body for POST /api/findings/triage (bulk) — same note rule, ids copied.
export function buildBulkPayload(ids, status, note) {
  return { ids: [...ids], ...buildTriagePayload(status, note) };
}

/*: transitions that REQUIRE a non-empty reason — client-side mirror
 * of REASON_REQUIRED in apps/api/src/routes/findings.js. The API is the
 * enforcement point; this exists so the UI can refuse early with a clear
 * message instead of round-tripping a 400. */
export const REASON_REQUIRED = ['resolved'];

// Error string when a transition must not be attempted, else null.
export function triageBlocker(status, note) {
  if (REASON_REQUIRED.includes(status) && !String(note ?? '').trim()) {
    return 'A reason is required to resolve a finding — add a note first.';
  }
  return null;
}

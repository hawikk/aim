/* Attribution pill label.
 *
 * Two numbers, one pill, and the second one exists to stop the first from
 * lying. "Unattributed %" is the share of events we cannot pin to any
 * principal. A declared agent host or CI runner IS a principal, so enrolling
 * one pushes that share down without adding a single engineer of coverage —
 * an all-machine fleet would read a comfortable "0% unattributed" while the
 * directory still knows nobody. So whenever machine activity is nonzero, its
 * share is rendered beside the rate rather than folded into it.
 *
 * Own module so it is unit-testable without a DOM (see test/attribution.test.js).
 */

/** Percentage with one decimal, floored at 0.1 so a real nonzero share never
 *  rounds down to a reassuring 0%. Mirrors the API's rule for the same reason. */
export function sharePct(part, whole) {
  if (!whole || !part) return 0;
  return Math.max(Math.round((part / whole) * 1000) / 10, 0.1);
}

/** Pill text for an attribution block, or null when the rate is undefined
 *  (empty window — the liveness pill is already explaining the silence). */
export function attributionLabel(att) {
  if (!att || att.unattributedPct == null) return null;
  const base = `◑ ${att.unattributedPct}% unattributed`;
  const machine = sharePct(Number(att.serviceAttributedEvents || 0), Number(att.events || 0));
  return machine > 0 ? `${base} · ${machine}% machine` : base;
}

/** Compact "verified <time>" stamp for coverage claims. */
export function verifiedStamp(iso) {
  if (!iso) return '';
  const t = new Date(iso);
  if (!Number.isFinite(t.getTime())) return '';
  return `verified ${t.toLocaleTimeString('en-US', { hour12: false })}`;
}

/** Title attribute with full ISO last-verified time. */
export function verifiedTitle(iso) {
  if (!iso) return 'Last verified time unavailable';
  return `Last verified end-to-end: ${iso}`;
}

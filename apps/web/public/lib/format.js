/* Shared display formatters for the dashboard (AIM-479).
 *
 * Keep cost / timestamp / subject rendering consistent across app.js,
 * findings.js and activity.js so a security analyst correlating views
 * sees one language, not three.
 */

/** Truncate a long pseudonym/HMAC ref for list rows; full value stays in title. */
export function shortRef(ref, keep = 10) {
  if (ref == null || ref === '') return null;
  const s = String(ref);
  return s.length > keep + 1 ? `${s.slice(0, keep)}…` : s;
}

/**
 * Finding subject → human label.
 * Subjects are JSON objects in the event store (`{user_ref, host_ref, …}`).
 * Never dump raw JSON into the inbox meta line or detail Subject field.
 *
 * @param {unknown} s
 * @param {{ full?: boolean }} [opts] full=true keeps untruncated refs (detail pane)
 */
export function fmtSubject(s, opts = {}) {
  const full = Boolean(opts.full);
  if (s == null || s === '') return '';
  if (typeof s !== 'object' || Array.isArray(s)) return String(s);

  const clip = (v) => (full ? String(v) : shortRef(v));
  const parts = [];

  const user = s.user_ref ?? s.userRef ?? s.pseudonym ?? undefined;
  const host = s.host_ref ?? s.hostRef ?? undefined;
  const repo = s.repo_ref ?? s.repoRef ?? undefined;

  // Explicit null user_ref means the engine had no identity — say so, do not
  // silently omit and leave only a host hash.
  if (typeof user === 'string' && user.length) parts.push(`user ${clip(user)}`);
  else if (Object.prototype.hasOwnProperty.call(s, 'user_ref') || Object.prototype.hasOwnProperty.call(s, 'userRef')) {
    parts.push('unattributed');
  }

  if (typeof host === 'string' && host.length) parts.push(`host ${clip(host)}`);
  if (typeof repo === 'string' && repo.length) parts.push(`repo ${clip(repo)}`);

  const known = new Set(['user_ref', 'userRef', 'host_ref', 'hostRef', 'repo_ref', 'repoRef', 'pseudonym']);
  for (const [k, v] of Object.entries(s)) {
    if (known.has(k) || v == null || v === '') continue;
    if (typeof v === 'object') continue; // nested blobs stay in evidence, not the subject line
    parts.push(`${k} ${typeof v === 'string' ? clip(v) : String(v)}`);
  }

  return parts.length ? parts.join(' · ') : 'unknown subject';
}

/**
 * Estimated cost in USD. Always `$…` — never mix ¢ and $ in the same column.
 * Sub-cent values collapse to `<$0.01` so a stream of $0.00035 events stays scannable.
 */
export function fmtCost(usd) {
  if (usd == null || usd === '') return '—';
  const n = Number(usd);
  if (!Number.isFinite(n)) return '—';
  if (n === 0) return '$0';
  const abs = Math.abs(n);
  if (abs < 0.01) return n < 0 ? '−<$0.01' : '<$0.01';
  if (abs < 100) {
    return (n < 0 ? '−' : '') + '$' + abs.toLocaleString('en-US', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    });
  }
  return (n < 0 ? '−' : '') + '$' + abs.toLocaleString('en-US', { maximumFractionDigits: 0 });
}

/** Alias used by the overview cards / aggregate tables. */
export const fmtUsd = fmtCost;

/**
 * Timestamps for analyst tables: ISO-8601 UTC, second precision, explicit Z.
 * Shape: `2026-07-30 00:00:00Z` (space separator, no millis, trailing Z).
 *
 * Second precision correlates cleanly with SIEM / collector logs when an
 * analyst pastes into Splunk; the trailing Z makes the UTC claim explicit
 * so readers never have to know "we always store UTC". One vocabulary
 * across every view — do not reimplement locally (AIM-533).
 *
 * Full original value belongs in the cell title attribute.
 */
export function fmtTs(iso) {
  if (iso == null || iso === '') return '—';
  const d = iso instanceof Date ? iso : new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
}

/* ---------------------------------------------------------------------------
 * AIM-525: helpers that used to be re-declared per view (fmtInt in 9 files,
 * relTime in 5). One definition each, one set of edge-case rules:
 * missing → '—', unparseable → '—', never a literal "NaN" in a stat tile.
 * ------------------------------------------------------------------------- */

/** Coerce to a finite number, or null if the value is missing/unparseable. */
function finite(n) {
  if (n == null || n === '' || typeof n === 'boolean') return null;
  const v = Number(n);
  return Number.isFinite(v) ? v : null;
}

/** Parse to a valid Date, or null. Accepts Date, ISO string, epoch millis. */
function parseDate(d) {
  if (d == null || d === '') return null;
  const dt = d instanceof Date ? d : new Date(d);
  return Number.isNaN(dt.getTime()) ? null : dt;
}

/**
 * Whole counts for stat tiles and table cells: `1,234`.
 * Missing or unparseable input renders '—', not '0' and never 'NaN' —
 * "no data" and "zero" are different answers in a security dashboard.
 */
export function fmtInt(n) {
  const v = finite(n);
  if (v === null) return '—';
  return Math.round(v).toLocaleString('en-US');
}

/**
 * Token counts, abbreviated so a 1.2B-token column stays scannable.
 * Thresholds match the original app.js implementation: 2dp at B, 1dp at M/K.
 */
export function fmtTok(n) {
  const v = finite(n);
  if (v === null) return '—';
  const abs = Math.abs(v);
  const sign = v < 0 ? '−' : '';
  if (abs >= 1e9) return `${sign}${(abs / 1e9).toFixed(2)}B`;
  if (abs >= 1e6) return `${sign}${(abs / 1e6).toFixed(1)}M`;
  if (abs >= 1e3) return `${sign}${(abs / 1e3).toFixed(1)}K`;
  return `${sign}${Math.round(abs)}`;
}

/** Calendar day in UTC (`2026-07-31`) for day buckets and chart axis labels. */
export function fmtDay(d) {
  const dt = parseDate(d);
  return dt ? dt.toISOString().slice(0, 10) : '—';
}

/**
 * Relative age for heartbeat / last-seen timestamps.
 *
 * Rules (the five prior copies disagreed on all three — see AIM-525):
 *  - missing → 'never'. A null last-seen is "this collector has never
 *    reported", not "56 years ago" from the epoch.
 *  - unparseable → '—'.
 *  - under a minute → 'just now'. The string is baked at render time and
 *    never ticks, so second-level precision goes stale immediately.
 *  - future timestamps clamp to 'just now' (all prior copies agreed).
 */
export function relTime(d) {
  if (d == null || d === '') return 'never';
  const dt = parseDate(d);
  if (!dt) return '—';
  const s = Math.max(0, (Date.now() - dt.getTime()) / 1000);
  if (s < 60) return 'just now';
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

/* ---------- AIM-527 surface used by split view modules ----------
 * fmtDay already returns '—' for missing/unparseable dates (AIM-525), so
 * fmtDaySafe is a stable alias for call sites that predated that hardening.
 * fmtMs remains the duration helper formerly local to app.js. */

/** Alias of fmtDay — kept so views can name the null-safe intent explicitly. */
export const fmtDaySafe = fmtDay;

/** Duration cells: tool_calls.duration_ms is nullable per schema v1.1. */
export function fmtMs(ms) {
  const v = finite(ms);
  if (v === null || v <= 0) return '—';
  return `${fmtInt(v)} ms`;
}

/* Underscore aliases for views/* pre-rename imports (AIM-527 → AIM-782). */
export {
  fmtDay as _fmtDay,
  fmtDaySafe as _fmtDaySafe,
  fmtInt as _fmtInt,
  fmtMs as _fmtMs,
  fmtTok as _fmtTok,
  fmtTs as _fmtTs,
  fmtUsd as _fmtUsd,
  relTime as _relTime,
};

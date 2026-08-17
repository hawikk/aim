/* AIM-94 / AIM-587 — saved-view filter mapping, pure and DOM-free.
 * findings.js and activity.js own UI state; these functions translate between
 * that state and the /api/views filters contract, and validate a filters object
 * client-side before it is POSTed. Dependency-free so node:test can import it
 * without a browser.
 *
 * Supported kinds:
 *   findings — { view, status?, severity?, ruleId?, days? }
 *   activity — { view, tool?, event_type?, user?, minScore? }
 */

export const VIEW_KINDS = ['findings', 'activity'];

export const FILTER_STATUSES = ['open', 'new', 'acknowledged', 'resolved', 'false_positive', 'all'];
export const FILTER_SEVERITIES = ['all', 'critical', 'high', 'medium', 'low'];
export const FILTER_DAYS = [7, 30, 90];

export const FINDINGS_FILTER_KEYS = Object.freeze(['view', 'status', 'severity', 'ruleId', 'days']);
export const ACTIVITY_FILTER_KEYS = Object.freeze(['view', 'tool', 'event_type', 'user', 'minScore']);
export const FILTER_STRING_MAX = 200;

export const DEFAULT_FILTERS = Object.freeze({
  view: 'findings',
  status: 'open',
  severity: 'all',
  ruleId: null,
  days: 30,
});

export const ACTIVITY_DEFAULT_FILTERS = Object.freeze({
  view: 'activity',
  tool: null,
  event_type: null,
  user: null,
  minScore: null,
});

function cleanOptionalString(value) {
  if (value == null || value === '') return null;
  if (typeof value !== 'string') return undefined; // signal invalid
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > FILTER_STRING_MAX) return undefined;
  return trimmed;
}

function cleanMinScore(value) {
  if (value == null || value === '') return null;
  const n = typeof value === 'number' ? value : Number(String(value).trim());
  if (!Number.isInteger(n) || n < 1 || n > 10) return undefined;
  return n;
}

// UI state → filters object for /api/views (findings). Unknown/missing values
// fall back to the defaults, so the result always passes validateFilters.
export function filtersFromState(state = {}) {
  const days = Number(state.days);
  return {
    view: 'findings',
    status: FILTER_STATUSES.includes(state.fstatus) ? state.fstatus : DEFAULT_FILTERS.status,
    severity: FILTER_SEVERITIES.includes(state.fsev) ? state.fsev : DEFAULT_FILTERS.severity,
    ruleId: typeof state.ruleId === 'string' && state.ruleId ? state.ruleId : null,
    days: FILTER_DAYS.includes(days) ? days : DEFAULT_FILTERS.days,
  };
}

// Saved filters → UI state (findings), with defaults for anything absent/unknown.
export function stateFromFilters(filters = {}) {
  const days = Number(filters.days);
  return {
    fstatus: FILTER_STATUSES.includes(filters.status) ? filters.status : DEFAULT_FILTERS.status,
    fsev: FILTER_SEVERITIES.includes(filters.severity) ? filters.severity : DEFAULT_FILTERS.severity,
    ruleId: typeof filters.ruleId === 'string' && filters.ruleId ? filters.ruleId : null,
    days: FILTER_DAYS.includes(days) ? days : DEFAULT_FILTERS.days,
  };
}

// Activity DOM/state → filters object. Invalid strings fall back to null so
// a mistyped field never blocks a save.
export function activityFiltersFromState(state = {}) {
  const tool = cleanOptionalString(state.tool);
  const eventType = cleanOptionalString(state.event_type);
  const user = cleanOptionalString(state.user);
  const minScore = cleanMinScore(state.minScore);
  return {
    view: 'activity',
    tool: tool === undefined ? null : tool,
    event_type: eventType === undefined ? null : eventType,
    user: user === undefined ? null : user,
    minScore: minScore === undefined ? null : minScore,
  };
}

// Saved activity filters → form field values (always strings for inputs).
export function activityStateFromFilters(filters = {}) {
  const tool = cleanOptionalString(filters.tool);
  const eventType = cleanOptionalString(filters.event_type);
  const user = cleanOptionalString(filters.user);
  const minScore = cleanMinScore(filters.minScore);
  return {
    tool: tool || '',
    event_type: eventType || '',
    user: user || '',
    minScore: minScore == null ? '' : String(minScore),
  };
}

// Mirror of the /api/views filters contract. Returns {ok, errors[]} and never throws.
export function validateFilters(obj) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    return { ok: false, errors: ['filters must be an object'] };
  }
  const errors = [];
  if (!VIEW_KINDS.includes(obj.view)) {
    errors.push(`view must be one of: ${VIEW_KINDS.join(', ')}`);
    return { ok: false, errors };
  }

  if (obj.view === 'findings') {
    for (const key of Object.keys(obj)) {
      if (!FINDINGS_FILTER_KEYS.includes(key)) {
        errors.push(`unknown filters key '${key}'`);
      }
    }
    if (obj.status !== undefined && !FILTER_STATUSES.includes(obj.status)) {
      errors.push(`status must be one of: ${FILTER_STATUSES.join(', ')}`);
    }
    if (obj.severity !== undefined && !FILTER_SEVERITIES.includes(obj.severity)) {
      errors.push(`severity must be one of: ${FILTER_SEVERITIES.join(', ')}`);
    }
    if (obj.ruleId !== undefined && obj.ruleId !== null && typeof obj.ruleId !== 'string') {
      errors.push('ruleId must be a string or null');
    }
    if (obj.days !== undefined && !FILTER_DAYS.includes(obj.days)) {
      errors.push('days must be 7, 30 or 90');
    }
  } else if (obj.view === 'activity') {
    for (const key of Object.keys(obj)) {
      if (!ACTIVITY_FILTER_KEYS.includes(key)) {
        errors.push(`unknown filters key '${key}'`);
      }
    }
    for (const key of ['tool', 'event_type', 'user']) {
      if (obj[key] === undefined || obj[key] === null) continue;
      if (typeof obj[key] !== 'string') {
        errors.push(`${key} must be a string or null`);
      } else if (obj[key].length > FILTER_STRING_MAX) {
        errors.push(`${key} must be at most ${FILTER_STRING_MAX} chars`);
      }
    }
    if (obj.minScore !== undefined && obj.minScore !== null) {
      const n = obj.minScore;
      if (!Number.isInteger(n) || n < 1 || n > 10) {
        errors.push('minScore must be an integer 1–10 or null');
      }
    }
  }

  return { ok: errors.length === 0, errors };
}

/* ---------- AIM-587: shareable findings deep-links ----------
 * Query keys owned by the findings console:
 *   view      — saved-view id (wins over status/severity)
 *   status    — findings status filter
 *   severity  — findings severity filter
 * The app router owns days/source; those are ignored here.
 */

function hashQueryPart(hash = '') {
  const raw = String(hash).replace(/^#\/?/, '');
  const qIdx = raw.indexOf('?');
  return qIdx === -1 ? '' : raw.slice(qIdx + 1);
}

/** Read findings deep-link params from a location hash. Unknown enums → null. */
export function parseFindingsHash(hash = '') {
  const q = new URLSearchParams(hashQueryPart(hash));
  const viewRaw = q.get('view');
  const statusRaw = q.get('status');
  const severityRaw = q.get('severity');
  return {
    viewId: viewRaw && viewRaw.trim() ? viewRaw.trim() : null,
    status: FILTER_STATUSES.includes(statusRaw) ? statusRaw : null,
    severity: FILTER_SEVERITIES.includes(severityRaw) ? severityRaw : null,
  };
}

/**
 * Build a shareable findings hash. Defaults (status=open, severity=all, days=30) omitted.
 * When viewId is set it alone is written — the saved view owns the filter set.
 * Optional `days` keeps the global range on cross-module hops (AIM-589 + AIM-587).
 */
export function findingsHash({ viewId = null, fstatus = null, fsev = null, days = null } = {}) {
  const q = new URLSearchParams();
  if (viewId) {
    q.set('view', String(viewId));
  } else {
    if (fstatus && FILTER_STATUSES.includes(fstatus) && fstatus !== DEFAULT_FILTERS.status) {
      q.set('status', fstatus);
    }
    if (fsev && FILTER_SEVERITIES.includes(fsev) && fsev !== DEFAULT_FILTERS.severity) {
      q.set('severity', fsev);
    }
  }
  // Number(null) === 0 — only encode when the caller actually passed days.
  if (days != null && days !== '') {
    const d = Number(days);
    if (Number.isFinite(d) && d !== 30) q.set('days', String(d));
  }
  const qs = q.toString();
  return qs ? `#/findings?${qs}` : '#/findings';
}

/** True when a findings-owned query key is present. */
export function findingsHashHasFilters(hash = '') {
  const { viewId, status, severity } = parseFindingsHash(hash);
  return Boolean(viewId || status || severity);
}

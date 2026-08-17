/**
 * AIM-702 — auto-triage hints from policy_hash + historical outcomes.
 *
 * ML-light, metadata-only. Never reads prompt/response/matched content.
 * Pure + DOM-free so node:test can exercise the heuristic without a browser.
 *
 * Inputs are closed-finding dispositions (resolved / false_positive) keyed by
 * rule_id and optional policy_hash. Outputs a suggested disposition with a
 * confidence in [0, 1] and a short human-readable basis.
 *
 * Matching order (most specific first):
 *   1. exact (ruleId + policyHash)
 *   2. ruleId only (any policy)
 *   3. no hint
 *
 * Confidence uses additive (Laplace) smoothing over the terminal dispositions
 * and a sample-size dampener so n=3 cannot claim "high confidence".
 */

// XSS boundary: import even when callers pass their own esc (AIM-523 guard).
import { esc as defaultEsc } from './dom.js';

/** Terminal dispositions we treat as historical outcomes. */
export const TERMINAL_DISPOSITIONS = ['resolved', 'false_positive'];

/** Open / in-progress statuses — counted for context, never suggested. */
export const NON_TERMINAL = ['new', 'acknowledged'];

/** Friendly labels for UI chrome (never invent new statuses). */
export const DISPOSITION_LABEL = {
  resolved: 'resolve',
  false_positive: 'false positive',
  acknowledged: 'acknowledge',
  new: 'reopen',
};

/** Default knobs — override via opts for tests. */
export const DEFAULTS = {
  /** Minimum terminal outcomes before a hint is shown. */
  minSamples: 3,
  /** Sample size at which the dampener reaches 1.0. */
  fullConfidenceAt: 20,
  /** Laplace prior mass per class (α). */
  alpha: 1,
  /** Max confidence returned (never claim certainty). */
  maxConfidence: 0.95,
  /** Confidence floor below which we suppress the pill entirely. */
  minConfidence: 0.45,
};

/**
 * Normalize a rule id for lookup (engine rules use kebab-case; some alert
 * labels use snake_case). Metadata only — no content.
 * @param {unknown} ruleId
 * @returns {string|null}
 */
export function normalizeRuleId(ruleId) {
  if (ruleId == null) return null;
  const s = String(ruleId).trim().toLowerCase();
  if (!s) return null;
  return s.replace(/_/g, '-');
}

/**
 * Normalize policy hash for lookup. Truncation is NOT applied — exact match
 * only; partial hashes would invent false history.
 * @param {unknown} policyHash
 * @returns {string|null}
 */
export function normalizePolicyHash(policyHash) {
  if (policyHash == null) return null;
  const s = String(policyHash).trim().toLowerCase();
  return s || null;
}

/**
 * Extract the auto-triage key fields from an alert or finding row.
 * Accepts both bus alerts (snake_case labels) and API findings (camelCase).
 * Never reads content-bearing fields.
 *
 * @param {object} item
 * @returns {{ ruleId: string|null, policyHash: string|null }}
 */
export function triageKeyOf(item) {
  if (!item || typeof item !== 'object') return { ruleId: null, policyHash: null };

  const labels = item.labels && typeof item.labels === 'object' ? item.labels : {};

  const ruleRaw =
    item.ruleId
    ?? item.rule_id
    ?? labels.rule_id
    ?? labels.rule
    ?? labels.detector
    ?? (typeof item.finding_type === 'string' && item.finding_type.includes('.')
      ? item.finding_type.split('.').slice(1).join('.')
      : item.finding_type)
    ?? null;

  const policyRaw =
    item.policyHash
    ?? item.policy_hash
    ?? labels.policy_hash
    ?? labels.policyHash
    ?? null;

  return {
    ruleId: normalizeRuleId(ruleRaw),
    policyHash: normalizePolicyHash(policyRaw),
  };
}

/**
 * Build an outcome index from closed finding rows.
 *
 * Each finding contributes one count under its (ruleId, policyHash) and under
 * its (ruleId, null) rollup. Open findings (new / acknowledged) are ignored —
 * they are not outcomes.
 *
 * @param {Iterable<object>} findings — shape: { ruleId, policyHash?, status }
 * @returns {Map<string, { resolved: number, false_positive: number, n: number }>}
 */
export function buildOutcomeIndex(findings) {
  /** @type {Map<string, { resolved: number, false_positive: number, n: number }>} */
  const index = new Map();

  const bump = (key, status) => {
    let bucket = index.get(key);
    if (!bucket) {
      bucket = { resolved: 0, false_positive: 0, n: 0 };
      index.set(key, bucket);
    }
    if (status === 'resolved') bucket.resolved += 1;
    else if (status === 'false_positive') bucket.false_positive += 1;
    else return;
    bucket.n += 1;
  };

  for (const f of findings ?? []) {
    if (!f || typeof f !== 'object') continue;
    const status = String(f.status ?? '');
    if (!TERMINAL_DISPOSITIONS.includes(status)) continue;
    const { ruleId, policyHash } = triageKeyOf(f);
    if (!ruleId) continue;
    // Exact policy+rule key when hash is known.
    if (policyHash) bump(indexKey(ruleId, policyHash), status);
    // Always roll up to rule-only so sparse policy_hash still yields a hint.
    bump(indexKey(ruleId, null), status);
  }
  return index;
}

/**
 * @param {string} ruleId
 * @param {string|null} policyHash
 */
export function indexKey(ruleId, policyHash) {
  return policyHash ? `${ruleId}\0${policyHash}` : `${ruleId}\0*`;
}

/**
 * Score a bucket into a hint, or null when evidence is too thin.
 *
 * @param {{ resolved: number, false_positive: number, n: number }} bucket
 * @param {'policy+rule'|'rule'} match
 * @param {Partial<typeof DEFAULTS>} [opts]
 * @returns {null | {
 *   disposition: 'resolved'|'false_positive',
 *   confidence: number,
 *   sampleSize: number,
 *   match: 'policy+rule'|'rule',
 *   counts: { resolved: number, false_positive: number },
 * }}
 */
export function scoreBucket(bucket, match, opts = {}) {
  const cfg = { ...DEFAULTS, ...opts };
  if (!bucket || bucket.n < cfg.minSamples) return null;

  const classes = TERMINAL_DISPOSITIONS;
  let best = null;
  let bestScore = -1;
  const smoothed = {};
  let denom = 0;
  for (const d of classes) {
    const c = Number(bucket[d] ?? 0);
    const s = c + cfg.alpha;
    smoothed[d] = s;
    denom += s;
    if (s > bestScore) {
      bestScore = s;
      best = d;
    }
  }
  if (!best || denom <= 0) return null;

  // Require a strict plurality — ties suppress the hint (analyst decides).
  const sorted = classes.map((d) => smoothed[d]).sort((a, b) => b - a);
  if (sorted.length > 1 && sorted[0] === sorted[1]) return null;

  const raw = smoothed[best] / denom;
  const damp = Math.min(1, bucket.n / cfg.fullConfidenceAt);
  // Rule-only matches pay a small specificity tax vs policy+rule.
  const specificity = match === 'policy+rule' ? 1 : 0.9;
  const confidence = Math.min(cfg.maxConfidence, raw * damp * specificity);

  if (confidence < cfg.minConfidence) return null;

  return {
    disposition: best,
    confidence,
    sampleSize: bucket.n,
    match,
    counts: {
      resolved: bucket.resolved,
      false_positive: bucket.false_positive,
    },
  };
}

/**
 * Suggest a disposition for one alert/finding against a prebuilt outcome index.
 *
 * @param {object} item — alert or finding (metadata fields only)
 * @param {Map<string, { resolved: number, false_positive: number, n: number }>} index
 * @param {Partial<typeof DEFAULTS>} [opts]
 * @returns {null | {
 *   disposition: 'resolved'|'false_positive',
 *   confidence: number,
 *   sampleSize: number,
 *   match: 'policy+rule'|'rule',
 *   counts: { resolved: number, false_positive: number },
 *   ruleId: string,
 *   policyHash: string|null,
 * }}
 */
export function suggestDisposition(item, index, opts = {}) {
  if (!(index instanceof Map) || index.size === 0) return null;
  const { ruleId, policyHash } = triageKeyOf(item);
  if (!ruleId) return null;

  if (policyHash) {
    const exact = scoreBucket(index.get(indexKey(ruleId, policyHash)), 'policy+rule', opts);
    if (exact) {
      return { ...exact, ruleId, policyHash };
    }
  }

  const rollup = scoreBucket(index.get(indexKey(ruleId, null)), 'rule', opts);
  if (rollup) {
    return { ...rollup, ruleId, policyHash };
  }
  return null;
}

/**
 * Format confidence as a whole-percent string for chrome (no locale).
 * @param {number} confidence 0..1
 * @returns {string}
 */
export function formatConfidence(confidence) {
  const n = Number(confidence);
  if (!Number.isFinite(n)) return '—';
  return `${Math.round(Math.max(0, Math.min(1, n)) * 100)}%`;
}

/**
 * Short label for the disposition pill.
 * @param {'resolved'|'false_positive'|string} disposition
 * @returns {string}
 */
export function formatDisposition(disposition) {
  return DISPOSITION_LABEL[disposition] ?? String(disposition ?? '—');
}

/**
 * Accessible title / tooltip for a hint.
 * @param {NonNullable<ReturnType<typeof suggestDisposition>>} hint
 * @returns {string}
 */
export function hintTitle(hint) {
  if (!hint) return '';
  const label = formatDisposition(hint.disposition);
  const conf = formatConfidence(hint.confidence);
  const match = hint.match === 'policy+rule'
    ? `policy_hash + rule ${hint.ruleId}`
    : `rule ${hint.ruleId} (any policy)`;
  const counts = `history: ${hint.counts.false_positive} false_positive, ${hint.counts.resolved} resolved (n=${hint.sampleSize})`;
  return `Auto-triage hint (AIM-702): likely ${label} · ${conf} confidence from ${match}. ${counts}. Metadata-only — no content.`;
}

/**
 * Compact pill HTML fragment. Caller may supply esc(); defaults to lib/dom.js.
 * Does not auto-apply the disposition — analyst remains the decision maker.
 *
 * @param {ReturnType<typeof suggestDisposition>} hint
 * @param {(s: string) => string} [esc]
 * @returns {string} empty string when no hint
 */
export function hintPillHtml(hint, esc = defaultEsc) {
  if (!hint || typeof esc !== 'function') return '';
  const label = formatDisposition(hint.disposition);
  const conf = formatConfidence(hint.confidence);
  const matchTag = hint.match === 'policy+rule' ? 'policy+rule' : 'rule';
  const title = hintTitle(hint);
  return (
    `<span class="pill auto-triage auto-triage-${esc(hint.disposition)}"`
    + ` title="${esc(title)}"`
    + ` data-disposition="${esc(hint.disposition)}"`
    + ` data-confidence="${esc(String(hint.confidence))}"`
    + ` data-match="${esc(hint.match)}"`
    + ` data-n="${esc(String(hint.sampleSize))}"`
    + ` aria-label="${esc(title)}">`
    + `suggest ${esc(label)} · ${esc(conf)} · n=${esc(String(hint.sampleSize))} · ${esc(matchTag)}`
    + `</span>`
  );
}

/**
 * Ingest a findings list API payload into an outcome index.
 * Tolerates missing/empty arrays so callers can merge pages.
 *
 * @param {object|null|undefined} payload — { findings: [...] }
 * @param {Map} [into] — optional existing index to merge into
 * @returns {Map}
 */
export function indexFromFindingsPayload(payload, into) {
  const index = into instanceof Map ? into : new Map();
  const rows = Array.isArray(payload?.findings) ? payload.findings : [];
  // Rebuild is simpler and correct for a fresh map; for merge, rebuild from
  // both would require storing raw rows — instead re-bump via buildOutcomeIndex
  // into a temporary and union counts.
  const next = buildOutcomeIndex(rows);
  if (index.size === 0) return next;
  for (const [k, v] of next) {
    const cur = index.get(k) ?? { resolved: 0, false_positive: 0, n: 0 };
    index.set(k, {
      resolved: cur.resolved + v.resolved,
      false_positive: cur.false_positive + v.false_positive,
      n: cur.n + v.n,
    });
  }
  return index;
}

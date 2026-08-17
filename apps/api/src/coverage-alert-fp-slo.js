// — Pageable dark-tool / coverage-alert false-positive precision SLO.
//
// Scope is the **pageable / banner** channel only (`coverageAlerts[]` after
// precision gates). The Coverage ledger (darkItems) is honesty, not
// paging — ledger rows are never counted as FPs.
//
// This module is pure measurement. It does not change fire-on-dark defaults
// or the precision knobs in routes/coverage.js.

/** Published SLO: pageable dark-tool alert FP rate over labeled 14-day window. */
export const DARK_TOOL_PAGEABLE_ALERT_FP_SLO = Object.freeze({
  /** Max labeled false-positive rate among fired pageable alerts. */
  maxFpRate: 0.1,
  /** Rolling measurement window in days. */
  windowDays: 14,
  /** Measurement scope — never the ledger. */
  scope: 'pageable',
  /** Alert kind under measurement. */
  alertKind: 'sanctioned_tool_dark',
});

const DAY_MS = 24 * 60 * 60 * 1000;

const FP_LABELS = new Set(['fp', 'false_positive', 'false-positive']);
const TP_LABELS = new Set(['tp', 'true_positive', 'true-positive']);

/**
 * Map free-form analyst label to fp | tp | null.
 * @param {unknown} label
 * @returns {'fp'|'tp'|null}
 */
export function normalizeAnalystLabel(label) {
  if (label == null || label === '') return null;
  const s = String(label).trim().toLowerCase();
  if (FP_LABELS.has(s)) return 'fp';
  if (TP_LABELS.has(s)) return 'tp';
  return null;
}

/**
 * Normalize one alert sample for measurement.
 *
 * Required: `at` (ISO or epoch ms), `outcome` ∈ {fired, suppressed}.
 * Optional: `tool`, `kind`, `suppressReason`, `label` / `analystLabel`, `id`.
 *
 * @param {object} row
 * @returns {object|null} null when the row cannot enter the harness
 */
export function normalizeAlertSample(row) {
  if (!row || typeof row !== 'object') return null;

  const outcomeRaw = String(row.outcome ?? '').toLowerCase();
  if (outcomeRaw !== 'fired' && outcomeRaw !== 'suppressed') return null;

  const atMs = parseTimeMs(row.at ?? row.ts ?? row.classifiedAt);
  if (atMs == null) return null;

  const kind = row.kind ?? row.alertKind ?? DARK_TOOL_PAGEABLE_ALERT_FP_SLO.alertKind;
  // Only pageable dark-tool / coverage alerts. Ledger-only rows have no outcome.
  if (kind && kind !== DARK_TOOL_PAGEABLE_ALERT_FP_SLO.alertKind) return null;

  const label = normalizeAnalystLabel(row.label ?? row.analystLabel ?? row.disposition);

  return {
    id: row.id != null ? String(row.id) : `${row.tool ?? 'unknown'}:${atMs}:${outcomeRaw}`,
    tool: row.tool != null ? String(row.tool) : null,
    kind: DARK_TOOL_PAGEABLE_ALERT_FP_SLO.alertKind,
    outcome: outcomeRaw,
    suppressReason: row.suppressReason != null ? String(row.suppressReason) : null,
    atMs,
    at: new Date(atMs).toISOString(),
    label,
  };
}

/**
 * Build a sample from classifySanctionedToolCoverage() + optional analyst label.
 * Pure; does not call the classifier.
 *
 * @param {object} args
 * @param {string} args.tool
 * @param {{ fireable: boolean, alert?: object|null, candidate?: object|null, suppressReason?: string|null }} args.classification
 * @param {string|number|Date} [args.at]
 * @param {string|null} [args.label]
 * @param {string} [args.id]
 * @returns {object|null} null when there was no candidate (covered / unsanctioned)
 */
export function sampleFromClassification({
  tool,
  classification,
  at = Date.now(),
  label = null,
  id,
} = {}) {
  if (!classification || typeof classification !== 'object') return null;
  const candidate = classification.alert ?? classification.candidate;
  if (!candidate && !classification.fireable && !classification.suppressReason) {
    // No pageable candidate (covered / unsanctioned) — out of scope.
    return null;
  }
  const outcome = classification.fireable ? 'fired' : 'suppressed';
  if (!classification.fireable && !classification.suppressReason) return null;

  return normalizeAlertSample({
    id,
    tool: tool ?? candidate?.tool,
    kind: candidate?.kind ?? DARK_TOOL_PAGEABLE_ALERT_FP_SLO.alertKind,
    outcome,
    suppressReason: classification.suppressReason ?? null,
    at,
    label,
  });
}

/**
 * Measure pageable dark-tool alert precision over a rolling window.
 *
 * Counts (acceptance harness):
 *  - fired       — pageable alerts that fired in the window
 *  - suppressed  — precision-held candidates in the window
 *  - labeled_fp  — fired + analyst FP label
 *  - labeled_tp  — fired + analyst TP label
 *
 * FP rate = labeled_fp / (labeled_fp + labeled_tp) when any labels exist;
 * otherwise null (insufficient labels — SLO not evaluable).
 *
 * @param {Iterable<object>} samples raw or normalized samples
 * @param {object} [opts]
 * @param {number} [opts.nowMs]
 * @param {number} [opts.windowDays]
 * @param {number} [opts.maxFpRate]
 * @returns {object}
 */
export function measurePageableDarkToolAlertPrecision(samples, opts = {}) {
  const windowDays = positiveInt(opts.windowDays, DARK_TOOL_PAGEABLE_ALERT_FP_SLO.windowDays);
  const maxFpRate = clamp01(
    opts.maxFpRate != null ? Number(opts.maxFpRate) : DARK_TOOL_PAGEABLE_ALERT_FP_SLO.maxFpRate,
  );
  const nowMs = Number.isFinite(opts.nowMs) ? opts.nowMs : Date.now();
  const windowStartMs = nowMs - windowDays * DAY_MS;

  let fired = 0;
  let suppressed = 0;
  let labeled_fp = 0;
  let labeled_tp = 0;
  let unlabeled_fired = 0;
  let labeled_suppressed = 0;
  const byTool = new Map();
  const bySuppressReason = new Map();

  const list = Array.isArray(samples) ? samples : [...(samples ?? [])];
  for (const raw of list) {
    const s = raw?.atMs != null && raw?.outcome
      ? raw
      : normalizeAlertSample(raw);
    if (!s) continue;
    if (s.atMs < windowStartMs || s.atMs > nowMs) continue;

    if (s.outcome === 'fired') {
      fired += 1;
      if (s.label === 'fp') labeled_fp += 1;
      else if (s.label === 'tp') labeled_tp += 1;
      else unlabeled_fired += 1;
    } else {
      suppressed += 1;
      if (s.label) labeled_suppressed += 1;
      if (s.suppressReason) {
        bySuppressReason.set(
          s.suppressReason,
          (bySuppressReason.get(s.suppressReason) ?? 0) + 1,
        );
      }
    }

    if (s.tool) {
      const t = byTool.get(s.tool) ?? {
        tool: s.tool,
        fired: 0,
        suppressed: 0,
        labeled_fp: 0,
        labeled_tp: 0,
      };
      if (s.outcome === 'fired') {
        t.fired += 1;
        if (s.label === 'fp') t.labeled_fp += 1;
        if (s.label === 'tp') t.labeled_tp += 1;
      } else {
        t.suppressed += 1;
      }
      byTool.set(s.tool, t);
    }
  }

  const labeled = labeled_fp + labeled_tp;
  const fp_rate = labeled > 0 ? labeled_fp / labeled : null;
  const precision = labeled > 0 ? labeled_tp / labeled : null;

  const slo = evaluatePageableDarkToolAlertFpSlo({
    fp_rate,
    labeled_fp,
    labeled_tp,
    maxFpRate,
  });

  return {
    scope: DARK_TOOL_PAGEABLE_ALERT_FP_SLO.scope,
    alertKind: DARK_TOOL_PAGEABLE_ALERT_FP_SLO.alertKind,
    windowDays,
    windowStart: new Date(windowStartMs).toISOString(),
    windowEnd: new Date(nowMs).toISOString(),
    fired,
    suppressed,
    labeled_fp,
    labeled_tp,
    labeled,
    unlabeled_fired,
    labeled_suppressed,
    fp_rate,
    precision,
    maxFpRate,
    slo,
    bySuppressReason: Object.fromEntries(bySuppressReason),
    byTool: [...byTool.values()].sort((a, b) => a.tool.localeCompare(b.tool)),
    note:
      'FP rate is labeled_fp / (labeled_fp + labeled_tp) among **fired** pageable ' +
      'dark-tool alerts only. Suppressed candidates and ledger-only dark rows are ' +
      'excluded from the rate. Insufficient labels → slo.status = insufficient_labels.',
  };
}

/**
 * Evaluate the published SLO against a measurement (or partial counts).
 *
 * @param {object} m
 * @returns {{ status: 'met'|'breached'|'insufficient_labels', met: boolean|null, maxFpRate: number, fp_rate: number|null, labeled: number }}
 */
export function evaluatePageableDarkToolAlertFpSlo(m = {}) {
  const maxFpRate = clamp01(
    m.maxFpRate != null ? Number(m.maxFpRate) : DARK_TOOL_PAGEABLE_ALERT_FP_SLO.maxFpRate,
  );
  const labeled_fp = Math.max(0, Math.floor(Number(m.labeled_fp) || 0));
  const labeled_tp = Math.max(0, Math.floor(Number(m.labeled_tp) || 0));
  const labeled = labeled_fp + labeled_tp;
  const fp_rate =
    m.fp_rate != null && Number.isFinite(Number(m.fp_rate))
      ? Number(m.fp_rate)
      : labeled > 0
        ? labeled_fp / labeled
        : null;

  if (labeled === 0 || fp_rate == null) {
    return {
      status: 'insufficient_labels',
      met: null,
      maxFpRate,
      fp_rate: null,
      labeled: 0,
    };
  }

  const met = fp_rate <= maxFpRate;
  return {
    status: met ? 'met' : 'breached',
    met,
    maxFpRate,
    fp_rate,
    labeled,
  };
}

function parseTimeMs(v) {
  if (v == null || v === '') return null;
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (v instanceof Date) {
    const t = v.getTime();
    return Number.isFinite(t) ? t : null;
  }
  const t = Date.parse(String(v));
  return Number.isFinite(t) ? t : null;
}

function positiveInt(v, fallback) {
  const n = Number(v);
  if (Number.isFinite(n) && n > 0) return Math.floor(n);
  return fallback;
}

function clamp01(v) {
  if (!Number.isFinite(v)) return DARK_TOOL_PAGEABLE_ALERT_FP_SLO.maxFpRate;
  if (v < 0) return 0;
  if (v > 1) return 1;
  return v;
}

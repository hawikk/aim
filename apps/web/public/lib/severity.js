/* Severity — the product's primary axis, in exactly one place.
 *
 * Before this module, severity pill markup was hand-written at seven sites with
 * three competing variants inside app.js alone (`severityBadge`, `sevPill`, and
 * inline markup on Overview). A "critical" looked the same on Overview,
 * Security and the Alerts inbox by luck, not by construction. Everything that
 * ranks risk now goes through `severityBadge()`.
 *
 * ---------------------------------------------------------------------------
 * Why severity never rides on hue alone
 * ---------------------------------------------------------------------------
 * The band colours are red → orange → amber → gray. Run that ramp through the
 * dataviz palette validator (Machado-2009 CVD simulation) and it does not clear
 * the ΔE 12 target, or even the ΔE 8 floor, in either mode:
 *
 *   dark  (panel #141416): worst all-pairs medium↔high  ΔE  9.7 (deuteranopia)
 *   light (panel #fafafa): worst all-pairs medium↔critical ΔE 4.9 (deuteranopia)
 *
 * That is not a bad colour pick — it is structural. Any red/orange/amber ordinal
 * ramp collapses toward the same yellow-brown under deuteranopia, and pushing
 * the steps apart runs into the AA text-contrast floor these pills need. A ramp
 * built from unrelated hues would validate, but it would stop reading as an
 * ordinal risk scale to everyone else, and that is a design-system call above
 * this refactor (noted in docs/frontend-design-system.md for review).
 *
 * So the mitigation is structural too, and it is not optional: every badge this
 * module emits carries TWO non-colour channels —
 *   1. the band name as visible text, always;
 *   2. a per-band shape marker (`[data-sev]::before` in styles.css): triangle
 *      critical, diamond high, square medium, dot low, hollow ring
 *      informational.
 * Colour is the third channel, never the only one. Do not build a severity
 * affordance that drops both of the first two.
 * ---------------------------------------------------------------------------
 */

import { esc } from './dom.js';
import { t } from './i18n.js';

/** Every band the UI can render, loudest first. This is also display order. */
export const SEVERITY_BANDS = Object.freeze(['critical', 'high', 'medium', 'low', 'informational']);

/** The four bands the API filters and sorts on (§7.4 rev 6). `informational`
 *  is renderable but is not a filter facet — the inbox never files by it. */
export const SEVERITY_FILTER_BANDS = Object.freeze(['critical', 'high', 'medium', 'low']);

/** One ordering for sorts, "worst of" reductions and threshold comparisons.
 *  Higher is worse. Note `informational` is 0 and therefore falsy — compare
 *  with `in`/`??`, never with a truthiness test. */
export const SEVERITY_RANK = Object.freeze({ informational: 0, low: 1, medium: 2, high: 3, critical: 4 });

/** Alert contracts carry a numeric severity_id alongside the label. The label
 *  is open vocabulary (the corpus ships "catastrophic", severity_id 5), so the
 *  id wins for banding: burying a critical-band alert in gray because nobody
 *  taught the UI a new word is the same failure as ranking it wrong. */
const BAND_BY_ID = { 5: 'critical', 4: 'high', 3: 'medium', 2: 'low', 1: 'informational' };

/**
 * Resolve anything the API can hand us to one of SEVERITY_BANDS.
 *
 * @param {unknown} value      severity label, e.g. 'critical' or 'catastrophic'
 * @param {object}  [opts]
 * @param {number}  [opts.id]  numeric severity_id, authoritative when present
 * @param {string}  [opts.fallback='medium'] band for an unrecognisable input.
 *   Defaults to 'medium', not 'low': an unreadable severity is an unknown risk,
 *   and rounding unknown risk down is how a real critical goes unlooked-at.
 * @returns {string} a band from SEVERITY_BANDS
 */
export function severityBand(value, { id, fallback = 'medium' } = {}) {
  const byId = BAND_BY_ID[id];
  if (byId) return byId;
  const label = String(value ?? '').trim().toLowerCase();
  if (SEVERITY_BANDS.includes(label)) return label;
  return SEVERITY_BANDS.includes(fallback) ? fallback : 'medium';
}

/** Band for an alert-shaped object ({ severity, severity_id }). */
export function severityBandOf(alert) {
  return severityBand(alert?.severity, { id: alert?.severity_id });
}

/** Sort comparator, worst first. Use everywhere a list ranks by risk. */
export function compareSeverity(a, b) {
  return (SEVERITY_RANK[severityBand(b)] ?? 0) - (SEVERITY_RANK[severityBand(a)] ?? 0);
}

/** The worst band in a collection, or null for an empty one. Unrecognisable
 *  entries band like everywhere else (medium) rather than being skipped —
 *  dropping a severity nobody could read is how a "Highest severity: none"
 *  card gets rendered over real risk. */
export function worstSeverity(values) {
  let worst = null;
  for (const v of values ?? []) {
    const band = severityBand(v);
    if (worst === null || SEVERITY_RANK[band] > SEVERITY_RANK[worst]) worst = band;
  }
  return worst;
}

/* An inferred severity is one nothing measured — it was defaulted from the
 * detection category, or came from an API predating the severity field. It
 * renders dashed (styles.css .pill.inferred) and says so on hover. A badge that
 * looks measured but was guessed is exactly the number this product must not
 * ship, so the test is fail-safe: only an explicit 'reported' counts. */
/**
 * THE severity badge. Every site that shows a severity calls this.
 *
 * Visible band text and provenance titles go through i18n. The
 * `data-sev` attribute and `sev-*` class stay on the English band key forever
 * so CSS shape markers and DOM tests remain stable across locales.
 *
 * @param {unknown} severity   severity label from the API
 * @param {object}  [opts]
 * @param {number}  [opts.id]     numeric severity_id; wins over the label
 * @param {string}  [opts.label]  visible text, when the raw label is worth
 *   showing verbatim even though it bands elsewhere ("catastrophic" in the
 *   critical band). Defaults to the localized band name.
 * @param {string}  [opts.source] 'reported' → measured; anything else → inferred
 * @param {string}  [opts.title]  overrides the hover text entirely
 * @param {boolean|string} [opts.srLabel]
 *   Screen-reader role prefix inside the pill so severity is never announced
 * as colour alone. Defaults to t('severity.srPrefix'). Pass `false`
 *   when the visible label is not a severity word (e.g. an SLA chip that
 *   reuses the critical band look).
 * @returns {string} trusted HTML; every interpolated value is escaped here
 */
export function severityBadge(severity, opts = {}) {
  /* call sites still pass source as a positional string:
   *   severityBadge(r.severity, r.severitySource)
   * Accept that shape without forcing every view to re-wrap. */
  if (typeof opts === 'string' || opts == null) {
    opts = opts == null ? {} : { source: opts };
  }
  const {
    id,
    label,
    source,
    title,
    srLabel = t('severity.srPrefix'),
  } = opts;
  const band = severityBand(severity, { id });
  /* `source` is opt-in: a site that has no provenance to show passes nothing
   * and gets a plain badge, rather than every pill in the app going dashed. */
  const inferred = source !== undefined && source !== 'reported';
  const text = label === undefined || label === null || label === ''
    ? t(`severity.band.${band}`)
    : label;
  const hover = title ?? (source === undefined
    ? null
    : inferred
      ? t('severity.title.inferred')
      : t('severity.title.reported'));
  const sr = srLabel === false || srLabel === ''
    ? ''
    : `<span class="sr-only">${esc(srLabel)}</span>`;
  return `<span class="pill sev-${band}${inferred ? ' inferred' : ''}" data-sev="${band}"`
    + (hover ? ` title="${esc(hover)}"` : '')
    + `>${sr}${esc(text)}</span>`;
}

/** Class for a container that carries a band edge (.finding, .inbox-alert,
 *  .rule). Same band vocabulary as the badge, so the row and its pill can
 *  never disagree. */
export function severityRowClass(severity, opts = {}) {
  return `sev-${severityBand(severity, opts)}`;
}

/* ---------- Chart colours ----------
 * A critical slice in a chart and a critical pill in a table are the same
 * colour because they read the same CSS custom property, not because someone
 * copied a hex. The fallbacks below matter only outside a browser (tests, SSR)
 * and mirror the dark-mode token values in styles.css. */
const FALLBACK_COLOR = {
  critical: '#f85149',
  high: '#db6d28',
  medium: '#d29922',
  low: '#9a9aa2',
  informational: '#9a9aa2',
};

/** Resolved colour for a band, straight off the --sev-* tokens. Re-read on
 * every call so a theme switch repaints charts without a reload. */
export function severityColor(severity) {
  const band = severityBand(severity);
  if (typeof getComputedStyle !== 'function' || typeof document === 'undefined') return FALLBACK_COLOR[band];
  const v = getComputedStyle(document.documentElement).getPropertyValue(`--sev-${band}`).trim();
  return v || FALLBACK_COLOR[band];
}

/** Colours for a series of bands, in the order given — for Chart.js datasets. */
export function severityColors(bands) {
  return (bands ?? []).map((b) => severityColor(b));
}

/* ---------- Exposure (reach, not severity) ----------
 * Deliberately NOT severity: wide/moderate/contained describe observed reach.
 * The pill reuses the sev-* tint scale as a reach language the operator already
 * knows, but the labels are different words so the two axes cannot be confused. */

/** Operator-facing reach thresholds. Kept as an exported constant so
 *  the rule stays discoverable in source / smoke guards — not colour alone. */
export const EXPOSURE_RULE =
  'wide: ≥10 users or ≥3 teams; moderate: ≥3 users; contained: otherwise; unknown when both zero';

export function exposureBadge(r) {
  const users = Number(r.users) || 0;
  const teams = Number(r.teams) || 0;
  if (users === 0 && teams === 0) {
    return `<span class="pill muted inferred" title="${esc(t('exposure.unknownTitle'))}">${esc(t('exposure.unknown'))}</span>`;
  }
  const [key, band] = users >= 10 || teams >= 3
    ? ['wide', 'sev-high']
    : users >= 3
      ? ['moderate', 'sev-medium']
      : ['contained', 'sev-low'];
  return `<span class="pill ${band}" title="${esc(t('exposure.rule') || EXPOSURE_RULE)}">${esc(t(`exposure.${key}`))}</span>`;
}

/** @deprecated — use severityBadge(). Kept as a thin alias so any
 *  transitional import fails closed on the shared markup rather than a 404. */
export function sevPill(sev) {
  return severityBadge(sev);
}

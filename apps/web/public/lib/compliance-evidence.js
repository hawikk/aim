/**
 * Compliance control evidence links for high-severity findings.
 *
 * High/critical findings should surface the framework controls they evidence
 * (EU AI Act, OWASP LLM, NIST AI RMF, ISO 42001) so an analyst can jump from
 * triage to the compliance map without re-deriving the mapping.
 *
 * Resolution order:
 *   1. `finding.complianceEvidence` (or snake_case) when the API auto-attaches
 *   2. Rule → control index built from GET /api/compliance/report (interim glue)
 *
 * Metadata / control ids only — never prompt or matched content.
 */

// XSS boundary: import even when callers pass their own esc (guard).
import { esc as defaultEsc } from './dom.js';

/** Severities that always get the compliance evidence block when links exist. */
export const HIGH_SEV_FOR_EVIDENCE = Object.freeze(['critical', 'high']);

/**
 * @param {string|null|undefined} severity
 * @returns {boolean}
 */
export function isHighSeverityForEvidence(severity) {
  return HIGH_SEV_FOR_EVIDENCE.includes(String(severity ?? '').toLowerCase());
}

/**
 * Deep-link into Compliance. Query params are reserved for a future control
 * highlight; today the Compliance view loads the full report at `#/compliance`.
 *
 * @param {string|null|undefined} frameworkId
 * @param {string|null|undefined} controlId
 * @returns {string}
 */
export function controlHash(frameworkId, controlId) {
  const params = new URLSearchParams();
  if (frameworkId) params.set('fw', String(frameworkId));
  if (controlId) params.set('ctrl', String(controlId));
  const q = params.toString();
  return q ? `#/compliance?${q}` : '#/compliance';
}

/**
 * Inverse of controlHash — parse framework/control ids from a location.hash.
 * Accepts both `fw`/`ctrl` (chips) and legacy `framework`/`control` keys.
 * Used by the Compliance view to scroll to a control deep-linked from findings.
 *
 * @param {string|null|undefined} hash
 * @returns {{ framework: string|null, control: string|null }}
 */
export function parseComplianceControlFromHash(hash) {
  const raw = String(hash ?? '');
  const qIdx = raw.indexOf('?');
  if (qIdx < 0) return { framework: null, control: null };
  const params = new URLSearchParams(raw.slice(qIdx + 1));
  const framework = (params.get('fw') || params.get('framework') || '').trim() || null;
  const control = (params.get('ctrl') || params.get('control') || '').trim() || null;
  return { framework, control };
}

/**
 * Normalize a single evidence link object from API or index.
 * @param {unknown} raw
 * @returns {{ frameworkId: string, frameworkName: string, controlId: string, ref: string, title: string, href: string } | null}
 */
export function normalizeEvidenceLink(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const o = /** @type {Record<string, unknown>} */ (raw);
  const frameworkId = String(o.frameworkId ?? o.framework_id ?? o.framework ?? '').trim();
  const controlId = String(o.controlId ?? o.control_id ?? o.id ?? '').trim();
  if (!frameworkId && !controlId) return null;
  const frameworkName = String(o.frameworkName ?? o.framework_name ?? o.frameworkLabel ?? frameworkId).trim();
  const ref = String(o.ref ?? o.controlRef ?? o.control_ref ?? controlId).trim();
  const title = String(o.title ?? o.controlTitle ?? o.control_title ?? '').trim();
  const hrefRaw = o.href ?? o.url ?? o.link;
  const href =
    typeof hrefRaw === 'string' && hrefRaw.trim()
      ? hrefRaw.trim()
      : controlHash(frameworkId, controlId);
  return {
    frameworkId: frameworkId || 'unknown',
    frameworkName: frameworkName || frameworkId || 'unknown',
    controlId: controlId || ref || 'unknown',
    ref: ref || controlId || '—',
    title,
    href,
  };
}

/**
 * @param {unknown} raw
 * @returns {ReturnType<typeof normalizeEvidenceLink>[]}
 */
export function normalizeEvidenceLinks(raw) {
  if (!raw) return [];
  const list = Array.isArray(raw) ? raw : [raw];
  const out = [];
  const seen = new Set();
  for (const item of list) {
    const link = normalizeEvidenceLink(item);
    if (!link) continue;
    const key = `${link.frameworkId}::${link.controlId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(link);
  }
  return out;
}

/**
 * Build a rule → evidence-link index from a compliance report payload.
 *
 * @param {{ frameworks?: Array<{ id: string, name?: string, controls?: Array<{ id: string, ref?: string, title?: string }> }>, rules?: Array<{ id: string, mappings?: Record<string, { controls?: string[], na?: string|null }> }> } | null | undefined} report
 * @returns {{ byRule: Map<string, ReturnType<typeof normalizeEvidenceLink>[]>, mappingVersion: string|null, contentHash: string|null }}
 */
export function buildEvidenceIndexFromReport(report) {
  /** @type {Map<string, ReturnType<typeof normalizeEvidenceLink>[]>} */
  const byRule = new Map();
  if (!report || typeof report !== 'object') {
    return { byRule, mappingVersion: null, contentHash: null };
  }

  /** @type {Map<string, { id: string, name: string, controls: Map<string, { id: string, ref: string, title: string }> }>} */
  const frameworks = new Map();
  for (const fw of report.frameworks ?? []) {
    if (!fw?.id) continue;
    const controls = new Map();
    for (const c of fw.controls ?? []) {
      if (!c?.id) continue;
      controls.set(c.id, {
        id: c.id,
        ref: c.ref ?? c.id,
        title: c.title ?? '',
      });
    }
    frameworks.set(fw.id, {
      id: fw.id,
      name: fw.name ?? fw.id,
      controls,
    });
  }

  for (const rule of report.rules ?? []) {
    if (!rule?.id || !rule.mappings) continue;
    const links = [];
    const seen = new Set();
    for (const [fwId, mapping] of Object.entries(rule.mappings)) {
      if (!mapping || typeof mapping !== 'object') continue;
      const controlIds = Array.isArray(mapping.controls) ? mapping.controls : [];
      const fw = frameworks.get(fwId);
      for (const ctrlId of controlIds) {
        const key = `${fwId}::${ctrlId}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const ctrl = fw?.controls.get(ctrlId);
        links.push({
          frameworkId: fwId,
          frameworkName: fw?.name ?? fwId,
          controlId: ctrlId,
          ref: ctrl?.ref ?? ctrlId,
          title: ctrl?.title ?? '',
          href: controlHash(fwId, ctrlId),
        });
      }
    }
    if (links.length) byRule.set(rule.id, links);
  }

  const mapping = report.mapping && typeof report.mapping === 'object' ? report.mapping : null;
  return {
    byRule,
    mappingVersion: mapping?.version != null ? String(mapping.version) : null,
    contentHash: mapping?.contentHash != null ? String(mapping.contentHash) : null,
  };
}

/**
 * @param {string|null|undefined} ruleId
 * @param {{ byRule?: Map<string, ReturnType<typeof normalizeEvidenceLink>[]> } | null | undefined} index
 * @returns {ReturnType<typeof normalizeEvidenceLink>[]}
 */
export function linksForRule(ruleId, index) {
  if (!ruleId || !index?.byRule) return [];
  return index.byRule.get(ruleId) ?? [];
}

/**
 * Resolve evidence links for a finding. Non-high severities always return [].
 *
 * @param {{ severity?: string, ruleId?: string, complianceEvidence?: unknown, compliance_evidence?: unknown } | null | undefined} finding
 * @param {{ byRule?: Map<string, ReturnType<typeof normalizeEvidenceLink>[]> } | null | undefined} index
 * @returns {ReturnType<typeof normalizeEvidenceLink>[]}
 */
export function resolveComplianceEvidence(finding, index) {
  if (!finding || !isHighSeverityForEvidence(finding.severity)) return [];
  const attached = normalizeEvidenceLinks(
    finding.complianceEvidence ?? finding.compliance_evidence
  );
  if (attached.length) return attached;
  return linksForRule(finding.ruleId, index);
}

/**
 * Render the compliance evidence block for finding detail. Empty string when
 * there are no links (caller should not show an empty block).
 *
 * @param {ReturnType<typeof normalizeEvidenceLink>[]} links
 * @param {{ esc?: (s: unknown) => string }} [opts]
 * @returns {string}
 */
export function evidenceLinksHtml(links, { esc = defaultEsc } = {}) {
  if (!Array.isArray(links) || links.length === 0) return '';
  const items = links
    .map((link) => {
      const label = link.title
        ? `${esc(link.ref)} — ${esc(link.title)}`
        : esc(link.ref);
      const fw = esc(link.frameworkName);
      return `<li class="f-cmp-item">
        <span class="f-cmp-fw">${fw}</span>
        <a class="f-cmp-link" href="${esc(link.href)}" title="${fw}: ${label}">${label}</a>
      </li>`;
    })
    .join('');
  return `<section class="f-compliance" aria-label="Compliance evidence">
    <h3 class="f-compliance-h">Compliance evidence</h3>
    <p class="f-compliance-hint">Framework controls this high-severity finding supports — open Compliance for the full map.</p>
    <ul class="f-cmp-list">${items}</ul>
  </section>`;
}

/* AIM-696 — auto-attach compliance control evidence to high-severity findings.
 *
 * Pure module (no db/auth). Maps a finding's ruleId through
 * policies/compliance/framework-map.yaml and returns the control refs an
 * auditor needs when triaging a high/critical finding. Medium/low findings
 * get null so list responses stay lean; the field is only present when
 * attachComplianceEvidence decides to set it.
 *
 * Does not store anything — attachment is a read-time enrichment from the
 * same map the compliance report uses, so control links never drift from
 * framework-map.yaml.
 */

/** Severities that receive control evidence (product definition of high-sev). */
export const HIGH_SEVERITIES = Object.freeze(['critical', 'high']);

const HIGH_SEV = new Set(HIGH_SEVERITIES);

/**
 * Resolve mapped controls for one rule from a loaded compliance map.
 * @param {ReturnType<import('./compliance-map.js').loadComplianceMap>} map
 * @param {string} ruleId
 * @returns {{ controls: object[], rationale: string|null, unmapped: boolean }}
 */
export function controlsForRule(map, ruleId) {
  const ruleMap = map?.rules?.[ruleId];
  if (!ruleMap) {
    return { controls: [], rationale: null, unmapped: true };
  }
  const controls = [];
  for (const fw of Object.values(map.frameworks ?? {})) {
    const m = ruleMap[fw.id];
    if (!m?.controls?.length) continue;
    for (const ctrlId of m.controls) {
      const ctrl = fw.controls?.[ctrlId];
      if (!ctrl) continue;
      controls.push({
        frameworkId: fw.id,
        frameworkName: fw.name,
        controlId: ctrl.id,
        ref: ctrl.ref,
        title: ctrl.title,
        summary: ctrl.summary || '',
      });
    }
  }
  return {
    controls,
    rationale: ruleMap.rationale || null,
    unmapped: controls.length === 0,
  };
}

/**
 * Build the complianceEvidence payload for a public finding object.
 * Returns null when severity is not high/critical (caller omits the field).
 *
 * @param {{ severity?: string, ruleId?: string }} finding  camelCase API shape
 * @param {ReturnType<import('./compliance-map.js').loadComplianceMap>} map
 * @returns {object|null}
 */
export function complianceEvidenceForFinding(finding, map) {
  if (!finding || !HIGH_SEV.has(finding.severity)) return null;
  const ruleId = finding.ruleId ?? null;
  const { controls, rationale, unmapped } = controlsForRule(map, ruleId);
  return {
    ruleId,
    mappingVersion: map?.version ?? null,
    mappingHash: map?.contentHash ?? null,
    rationale,
    unmapped,
    controls,
  };
}

/**
 * Attach complianceEvidence onto a finding when high-sev.
 * Non-high findings are returned unchanged (no null field noise).
 *
 * @param {object} finding  camelCase API finding
 * @param {object} map      loadComplianceMap() result
 * @returns {object}
 */
export function attachComplianceEvidence(finding, map) {
  const evidence = complianceEvidenceForFinding(finding, map);
  if (!evidence) return finding;
  return { ...finding, complianceEvidence: evidence };
}

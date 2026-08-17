/* — Active control → framework control ID map helpers.
 *
 * Pure functions over the /api/compliance/report payload so every live
 * guardrail rule (active control) answers:
 *   - which framework control IDs it maps to (AI Act / NIST / ISO / OWASP)
 *   - live pass/fail/unknown for the rule and for each mapped control
 *   - explicit gap list (missing mappings + unmonitored framework controls)
 *
 * No DOM here — compliance.js owns rendering; tests exercise this module.
 */

/** Live status for one active guardrail rule from its finding counts. */
export function ruleLiveStatus(rule) {
  const open = Number(rule?.findings?.open ?? 0);
  if (open > 0) {
    return { status: 'fail', reason: 'open_findings' };
  }
  return { status: 'pass', reason: 'no_open_findings' };
}

/**
 * Index framework controls by id for O(1) live-status lookup.
 * @returns {Map<string, Map<string, object>>} fwId → controlId → control
 */
export function indexFrameworkControls(frameworks = []) {
  const byFw = new Map();
  for (const fw of frameworks ?? []) {
    const byId = new Map();
    for (const c of fw.controls ?? []) {
      byId.set(c.id, c);
    }
    byFw.set(fw.id, byId);
  }
  return byFw;
}

/**
 * Resolve a rule's mapping for one framework into control refs + live status.
 * @returns {{ kind: 'missing'|'na'|'mapped', controls: Array, na?: string }}
 */
export function resolveFrameworkMapping(rule, framework, controlIndex) {
  const m = rule?.mappings?.[framework.id];
  if (!m) {
    return { kind: 'missing', controls: [] };
  }
  const ids = Array.isArray(m.controls) ? m.controls : [];
  if (!ids.length) {
    return { kind: 'na', controls: [], na: m.na ?? 'n/a' };
  }
  const byId = controlIndex?.get(framework.id) ?? new Map();
  const controls = ids.map((id) => {
    const live = byId.get(id);
    const status = live?.status
      ?? (live?.rules?.length
        ? ((live.findings?.open ?? 0) > 0 ? 'fail' : 'pass')
        : 'unknown');
    return {
      id,
      ref: live?.ref ?? id,
      title: live?.title ?? id,
      status,
      statusReason: live?.statusReason ?? null,
      open: live?.findings?.open ?? 0,
      total: live?.findings?.total ?? 0,
    };
  });
  return { kind: 'mapped', controls };
}

/**
 * Worst status among mapped framework controls (fail > unknown > pass).
 * Missing mapping → fail (gap). Justified n/a → pass (explicit exemption).
 */
export function worstMappingStatus(resolved) {
  if (!resolved || resolved.kind === 'missing') return 'fail';
  if (resolved.kind === 'na') return 'pass';
  let worst = 'pass';
  for (const c of resolved.controls) {
    if (c.status === 'fail') return 'fail';
    if (c.status === 'unknown') worst = 'unknown';
  }
  return worst;
}

/**
 * Build one row per active control for the map table.
 * @returns {Array<{ rule, live, frameworks: Record<string, object>, mapOk: boolean, gapReasons: string[] }>}
 */
export function buildControlMapRows(report) {
  const frameworks = report?.frameworks ?? [];
  const index = indexFrameworkControls(frameworks);
  const gapByRule = new Map();
  for (const g of report?.coverage?.gaps ?? []) {
    if (!gapByRule.has(g.ruleId)) gapByRule.set(g.ruleId, []);
    gapByRule.get(g.ruleId).push(g);
  }

  return (report?.rules ?? []).map((rule) => {
    const live = ruleLiveStatus(rule);
    const byFw = {};
    const gapReasons = [];
    for (const fw of frameworks) {
      const resolved = resolveFrameworkMapping(rule, fw, index);
      byFw[fw.id] = resolved;
      if (resolved.kind === 'missing') {
        gapReasons.push(`${fw.id}: no control mapping`);
      }
    }
    for (const g of gapByRule.get(rule.id) ?? []) {
      const line = `${g.framework}: ${g.reason}`;
      if (!gapReasons.includes(line)) gapReasons.push(line);
    }
    return {
      rule,
      live,
      frameworks: byFw,
      mapOk: gapReasons.length === 0,
      gapReasons,
    };
  });
}

/**
 * List gaps for the four frameworks (and any others present).
 * Categories:
 *   - rule_mapping: active control missing a framework mapping
 *   - unmonitored_control: framework control with no live mapped rules (unknown)
 *   - unmapped_findings: findings attributed to rules no longer in the map
 *
 * @returns {{ ok: boolean, items: Array, summary: { ruleGaps: number, unmonitored: number, unmappedFindings: number } }}
 */
export function listMappingGaps(report) {
  const items = [];

  for (const g of report?.coverage?.gaps ?? []) {
    items.push({
      kind: 'rule_mapping',
      framework: g.framework,
      controlId: null,
      ruleId: g.ruleId,
      reason: g.reason || 'no control mapping',
    });
  }

  for (const fw of report?.frameworks ?? []) {
    for (const c of fw.controls ?? []) {
      const status = c.status
        ?? (c.rules?.length
          ? ((c.findings?.open ?? 0) > 0 ? 'fail' : 'pass')
          : 'unknown');
      if (status === 'unknown' || !(c.rules?.length)) {
        items.push({
          kind: 'unmonitored_control',
          framework: fw.id,
          frameworkName: fw.name,
          controlId: c.id,
          controlRef: c.ref ?? c.id,
          controlTitle: c.title ?? c.id,
          ruleId: null,
          reason: c.statusReason === 'no_mapped_rules' || !(c.rules?.length)
            ? 'no live guardrail rule mapped (audit-event or catalog-only)'
            : (c.statusReason || 'unknown status'),
        });
      }
    }
  }

  for (const ruleId of report?.unmappedFindingRules ?? []) {
    items.push({
      kind: 'unmapped_findings',
      framework: null,
      controlId: null,
      ruleId,
      reason: 'findings in period for a rule not present in the live map',
    });
  }

  const summary = {
    ruleGaps: items.filter((i) => i.kind === 'rule_mapping').length,
    unmonitored: items.filter((i) => i.kind === 'unmonitored_control').length,
    unmappedFindings: items.filter((i) => i.kind === 'unmapped_findings').length,
  };

  return {
    ok: summary.ruleGaps === 0 && summary.unmappedFindings === 0,
    // Unmonitored catalog controls are listed but do not fail "maps complete"
    // for active controls — they are intentional gaps (audit-evidenced only).
    items,
    summary,
  };
}

/** Short framework column labels for the dense map table. */
export function frameworkColumnLabel(fw) {
  const id = fw?.id ?? '';
  if (id === 'eu_ai_act') return 'EU AI Act';
  if (id === 'owasp_llm') return 'OWASP LLM';
  if (id === 'nist_ai_rmf') return 'NIST AI RMF';
  if (id === 'iso_42001') return 'ISO 42001';
  return fw?.name ?? id;
}

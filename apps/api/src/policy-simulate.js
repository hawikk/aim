// Policy simulation / dry-run against historical findings (AIM-686).
//
// Replays the last N days of stored dispositions under a *candidate* policy
// without writing anything. Two rails:
//
//   alerts  — findings table (guardrail rule firings). Project which historical
//             findings would still fire under the candidate ruleset (drop rules
//             that disappear; remap severity overrides). New rules with no
//             history are listed as unprojectable.
//
//   blocks  — events.payload.enforcement (endpoint dispositions). Remap
//             blocked ↔ would_block based on whether the candidate bundle would
//             enforce each rule_id. confirmed (break-glass) demotes to
//             would_block when the rule leaves enforce mode.
//
// Honesty: this is a disposition-level projection, not a full re-scan of
// prompt text (content never leaves the endpoint). Match-rule evidence already
// fired once; we only answer "would this still alert / hard-block under the
// candidate policy hash and enforce flags?".

import yaml from 'js-yaml';
import { createHash } from 'node:crypto';

export const DEFAULT_SIM_DAYS = 7;
export const MAX_SIM_DAYS = 90;
export const BLOCK_ACTIONS = ['blocked', 'would_block', 'confirmed', 'redacted'];
export const ALERT_SEVERITIES = ['critical', 'high', 'medium', 'low'];

export function parseSimDays(raw, def = DEFAULT_SIM_DAYS, max = MAX_SIM_DAYS) {
  if (raw === undefined || raw === null || raw === '') return def;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 1) return def;
  return Math.min(Math.floor(n), max);
}

export function emptyBlockTotals() {
  return Object.fromEntries(BLOCK_ACTIONS.map((a) => [a, 0]).concat([['total', 0]]));
}

export function emptyAlertTotals() {
  return Object.fromEntries(ALERT_SEVERITIES.map((s) => [s, 0]).concat([['total', 0]]));
}

export function deltaMap(baseline, candidate) {
  const keys = new Set([...Object.keys(baseline ?? {}), ...Object.keys(candidate ?? {})]);
  const out = {};
  for (const k of keys) {
    out[k] = (Number(candidate?.[k]) || 0) - (Number(baseline?.[k]) || 0);
  }
  return out;
}

/**
 * Project one historical enforcement disposition under a candidate rule.
 * @param {string} action  blocked | would_block | confirmed | redacted
 * @param {boolean} ruleEnforced  candidate would hard-enforce this rule
 * @returns {string} projected action
 */
export function projectEnforcementAction(action, ruleEnforced) {
  if (!BLOCK_ACTIONS.includes(action)) return action;
  if (ruleEnforced) {
    if (action === 'would_block') return 'blocked';
    return action;
  }
  if (action === 'blocked' || action === 'confirmed' || action === 'redacted') {
    return 'would_block';
  }
  return action;
}

export function ruleEnforcedInBundle(bundle, ruleId) {
  if (!bundle || typeof bundle !== 'object') return false;
  if (bundle.mode !== 'enforce') return false;
  const entry = bundle.rules?.[ruleId];
  if (!entry || typeof entry !== 'object') return false;
  return entry.enforce === true;
}

export function buildEnforceMap(bundle, ruleIds = []) {
  const map = new Map();
  for (const id of ruleIds) {
    map.set(id, ruleEnforcedInBundle(bundle, id));
  }
  if (bundle?.rules && typeof bundle.rules === 'object') {
    for (const id of Object.keys(bundle.rules)) {
      if (!map.has(id)) map.set(id, ruleEnforcedInBundle(bundle, id));
    }
  }
  return map;
}

export function projectEnforcementCounts(rows, candidateBundle) {
  const ruleIds = [];
  for (const r of rows ?? []) {
    const id = r.rule_id ?? r.ruleId;
    if (id && !ruleIds.includes(id)) ruleIds.push(id);
  }
  const enforceMap = buildEnforceMap(candidateBundle, ruleIds);
  const byRuleMap = new Map();
  const totals = emptyBlockTotals();

  for (const r of rows ?? []) {
    const id = r.rule_id ?? r.ruleId;
    if (!id) continue;
    const action = r.action;
    if (!BLOCK_ACTIONS.includes(action)) continue;
    const n = Number(r.n ?? r.count ?? 0) || 0;
    if (n <= 0) continue;
    const enforced = enforceMap.get(id) === true;
    const projected = projectEnforcementAction(action, enforced);
    if (!byRuleMap.has(id)) {
      byRuleMap.set(id, {
        ruleId: id,
        enforced,
        baseline: emptyBlockTotals(),
        candidate: emptyBlockTotals(),
      });
    }
    const row = byRuleMap.get(id);
    row.baseline[action] = (row.baseline[action] || 0) + n;
    row.baseline.total += n;
    row.candidate[projected] = (row.candidate[projected] || 0) + n;
    row.candidate.total += n;
  }

  for (const row of byRuleMap.values()) {
    for (const a of BLOCK_ACTIONS) {
      totals[a] += row.candidate[a] || 0;
    }
    totals.total += row.candidate.total || 0;
  }

  const byRule = [...byRuleMap.values()].sort((a, b) => a.ruleId.localeCompare(b.ruleId));
  const enforceObj = Object.fromEntries([...enforceMap.entries()].sort((a, b) => a[0].localeCompare(b[0])));
  return { byRule, totals, enforceMap: enforceObj };
}

export function sumEnforcementBaseline(rows) {
  const totals = emptyBlockTotals();
  const byRuleMap = new Map();
  for (const r of rows ?? []) {
    const id = r.rule_id ?? r.ruleId;
    if (!id) continue;
    const action = r.action;
    if (!BLOCK_ACTIONS.includes(action)) continue;
    const n = Number(r.n ?? r.count ?? 0) || 0;
    if (n <= 0) continue;
    if (!byRuleMap.has(id)) byRuleMap.set(id, { ruleId: id, ...emptyBlockTotals() });
    const row = byRuleMap.get(id);
    row[action] = (row[action] || 0) + n;
    row.total += n;
    totals[action] += n;
    totals.total += n;
  }
  const byRule = [...byRuleMap.values()].sort((a, b) => a.ruleId.localeCompare(b.ruleId));
  return { byRule, totals };
}

export function rulesFromPackFiles(files) {
  const rules = new Map();
  const parseErrors = [];
  const hasher = createHash('sha256');
  const sorted = [...(files ?? [])].sort((a, b) => String(a.name).localeCompare(String(b.name)));

  for (const f of sorted) {
    let raw;
    try {
      if (f.content != null) {
        raw = Buffer.from(String(f.content), 'utf8');
      } else if (f.contentB64) {
        raw = Buffer.from(String(f.contentB64).trim(), 'base64');
      } else {
        parseErrors.push(`${f.name}: missing content`);
        continue;
      }
    } catch (err) {
      parseErrors.push(`${f.name}: ${err.message}`);
      continue;
    }
    hasher.update(raw);
    let data;
    try {
      data = yaml.load(raw.toString('utf8')) ?? {};
    } catch (err) {
      parseErrors.push(`${f.name}: YAML parse error: ${err.message}`);
      continue;
    }
    for (const [ruleId, override] of Object.entries(data.rule_overrides ?? {})) {
      if (override && typeof override === 'object' && override.severity && rules.has(ruleId)) {
        rules.get(ruleId).severity = override.severity;
      }
    }
    for (const rule of data.rules ?? []) {
      if (!rule || typeof rule !== 'object' || !rule.id) continue;
      rules.set(rule.id, {
        id: rule.id,
        severity: ALERT_SEVERITIES.includes(rule.severity) ? rule.severity : 'medium',
        type: rule.type ?? null,
        title: rule.title ?? rule.id,
      });
    }
  }

  return {
    rules,
    policyHash: sorted.length ? hasher.digest('hex') : null,
    parseErrors,
  };
}

export function candidateRulesFromLive(policy, deltas = {}) {
  const rules = new Map();
  for (const r of policy?.rules ?? []) {
    if (!r?.id) continue;
    rules.set(r.id, {
      id: r.id,
      severity: ALERT_SEVERITIES.includes(r.severity) ? r.severity : 'medium',
      type: r.type ?? null,
      title: r.title ?? r.id,
    });
  }
  return applyRuleDeltas(rules, deltas);
}

export function applyRuleDeltas(rules, deltas = {}) {
  const out = new Map(rules);
  const disable = new Set(deltas.disableRules ?? []);
  const enableOnly = deltas.enableOnlyRules;
  const sev = deltas.severityOverrides ?? {};

  if (Array.isArray(enableOnly)) {
    const keep = new Set(enableOnly);
    for (const id of [...out.keys()]) {
      if (!keep.has(id)) out.delete(id);
    }
  }
  for (const id of disable) out.delete(id);

  for (const [id, severity] of Object.entries(sev)) {
    if (!out.has(id)) continue;
    if (!ALERT_SEVERITIES.includes(severity)) continue;
    out.set(id, { ...out.get(id), severity });
  }
  return out;
}

export function projectFindingCounts(rows, candidateRules) {
  const ruleMap = candidateRules instanceof Map
    ? candidateRules
    : new Map(Object.entries(candidateRules ?? {}).map(([id, v]) => [
      id,
      typeof v === 'object' && v ? v : { id, severity: 'medium' },
    ]));

  const byRuleMap = new Map();
  const totals = emptyAlertTotals();
  const dropped = [];
  const severityChanged = [];

  for (const r of rows ?? []) {
    const id = r.rule_id ?? r.ruleId;
    if (!id) continue;
    const severity = ALERT_SEVERITIES.includes(r.severity) ? r.severity : 'medium';
    const n = Number(r.n ?? r.count ?? 0) || 0;
    if (n <= 0) continue;

    if (!byRuleMap.has(id)) {
      byRuleMap.set(id, {
        ruleId: id,
        baseline: emptyAlertTotals(),
        candidate: emptyAlertTotals(),
        inCandidate: ruleMap.has(id),
        candidateSeverity: ruleMap.get(id)?.severity ?? null,
      });
    }
    const row = byRuleMap.get(id);
    row.baseline[severity] = (row.baseline[severity] || 0) + n;
    row.baseline.total += n;

    if (!ruleMap.has(id)) {
      continue;
    }
    const candSev = ruleMap.get(id).severity || severity;
    row.candidate[candSev] = (row.candidate[candSev] || 0) + n;
    row.candidate.total += n;
    if (candSev !== severity) {
      severityChanged.push({ ruleId: id, from: severity, to: candSev, count: n });
    }
  }

  for (const row of byRuleMap.values()) {
    if (!row.inCandidate && row.baseline.total > 0) {
      dropped.push({ ruleId: row.ruleId, count: row.baseline.total, bySeverity: { ...row.baseline } });
    }
    for (const s of ALERT_SEVERITIES) {
      totals[s] += row.candidate[s] || 0;
    }
    totals.total += row.candidate.total || 0;
  }

  const historicalIds = new Set(byRuleMap.keys());
  const unprojectableNewRules = [...ruleMap.keys()]
    .filter((id) => !historicalIds.has(id))
    .sort();

  const byRule = [...byRuleMap.values()].sort((a, b) => a.ruleId.localeCompare(b.ruleId));
  return { byRule, totals, dropped, severityChanged, unprojectableNewRules };
}

export function sumFindingBaseline(rows) {
  const totals = emptyAlertTotals();
  const byRuleMap = new Map();
  for (const r of rows ?? []) {
    const id = r.rule_id ?? r.ruleId;
    if (!id) continue;
    const severity = ALERT_SEVERITIES.includes(r.severity) ? r.severity : 'medium';
    const n = Number(r.n ?? r.count ?? 0) || 0;
    if (n <= 0) continue;
    if (!byRuleMap.has(id)) {
      byRuleMap.set(id, { ruleId: id, ...emptyAlertTotals() });
    }
    const row = byRuleMap.get(id);
    row[severity] = (row[severity] || 0) + n;
    row.total += n;
    totals[severity] += n;
    totals.total += n;
  }
  return {
    byRule: [...byRuleMap.values()].sort((a, b) => a.ruleId.localeCompare(b.ruleId)),
    totals,
  };
}

export function buildSimulationReport({
  days,
  from,
  to,
  baselineBlocks,
  candidateBlocks,
  baselineAlerts,
  candidateAlerts,
  candidateMeta = {},
  notes = [],
} = {}) {
  const blocksBaseline = baselineBlocks?.totals ?? emptyBlockTotals();
  const blocksCandidate = candidateBlocks?.totals ?? emptyBlockTotals();
  const alertsBaseline = baselineAlerts?.totals ?? emptyAlertTotals();
  const alertsCandidate = candidateAlerts?.totals ?? emptyAlertTotals();

  return {
    kind: 'aim.policy-simulate/v1',
    dryRun: true,
    window: {
      days,
      from: from ?? null,
      to: to ?? null,
    },
    candidate: {
      source: candidateMeta.source ?? null,
      packId: candidateMeta.packId ?? null,
      policyHash: candidateMeta.policyHash ?? null,
      enforcementMode: candidateMeta.enforcementMode ?? null,
      enforcementPolicyHash: candidateMeta.enforcementPolicyHash ?? null,
      ruleCount: candidateMeta.ruleCount ?? null,
      notes: candidateMeta.notes ?? [],
    },
    baseline: {
      blocks: blocksBaseline,
      alerts: alertsBaseline,
    },
    projected: {
      blocks: blocksCandidate,
      alerts: alertsCandidate,
    },
    delta: {
      blocks: deltaMap(blocksBaseline, blocksCandidate),
      alerts: deltaMap(alertsBaseline, alertsCandidate),
      summary: {
        blocked: (blocksCandidate.blocked || 0) - (blocksBaseline.blocked || 0),
        would_block: (blocksCandidate.would_block || 0) - (blocksBaseline.would_block || 0),
        alerts: (alertsCandidate.total || 0) - (alertsBaseline.total || 0),
        criticalAlerts:
          (alertsCandidate.critical || 0) - (alertsBaseline.critical || 0),
      },
    },
    byRule: {
      blocks: candidateBlocks?.byRule ?? baselineBlocks?.byRule ?? [],
      alerts: candidateAlerts?.byRule ?? baselineAlerts?.byRule ?? [],
    },
    droppedRules: candidateAlerts?.dropped ?? [],
    severityChanged: candidateAlerts?.severityChanged ?? [],
    unprojectableNewRules: candidateAlerts?.unprojectableNewRules ?? [],
    notes: [
      'Dry-run only — no policy was promoted and no events were rewritten.',
      'Blocks are projected from historical enforcement dispositions (action remapped by candidate enforce flags).',
      'Alerts are projected from historical findings (rules absent from the candidate are dropped; severity overrides remapped).',
      'New candidate rules with zero historical firings cannot be projected without content re-scan (listed under unprojectableNewRules).',
      ...notes,
    ],
  };
}

export function formatSimulationSummary(report) {
  const d = report.delta?.summary ?? {};
  const w = report.window ?? {};
  const lines = [
    `aim policy simulate — last ${w.days ?? '?'} day(s) (dry-run)`,
    `  window: ${w.from ?? '?'} → ${w.to ?? '?'}`,
    `  candidate: source=${report.candidate?.source ?? 'n/a'}`
      + (report.candidate?.packId ? ` packId=${report.candidate.packId}` : '')
      + (report.candidate?.policyHash ? ` policyHash=${String(report.candidate.policyHash).slice(0, 12)}…` : ''),
    '  Δ blocks/alerts:',
    `    blocked:      ${fmtDelta(d.blocked)}  (baseline ${report.baseline?.blocks?.blocked ?? 0} → projected ${report.projected?.blocks?.blocked ?? 0})`,
    `    would_block:  ${fmtDelta(d.would_block)}  (baseline ${report.baseline?.blocks?.would_block ?? 0} → projected ${report.projected?.blocks?.would_block ?? 0})`,
    `    alerts:       ${fmtDelta(d.alerts)}  (baseline ${report.baseline?.alerts?.total ?? 0} → projected ${report.projected?.alerts?.total ?? 0})`,
    `    critical:     ${fmtDelta(d.criticalAlerts)}  (baseline ${report.baseline?.alerts?.critical ?? 0} → projected ${report.projected?.alerts?.critical ?? 0})`,
  ];
  if (report.droppedRules?.length) {
    lines.push(`  dropped rules (${report.droppedRules.length}): ${report.droppedRules.map((r) => r.ruleId).join(', ')}`);
  }
  if (report.unprojectableNewRules?.length) {
    lines.push(`  unprojectable new rules: ${report.unprojectableNewRules.join(', ')}`);
  }
  return lines.join('\n');
}

function fmtDelta(n) {
  const v = Number(n) || 0;
  if (v > 0) return `+${v}`;
  return String(v);
}

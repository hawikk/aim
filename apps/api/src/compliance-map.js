// Compliance framework map reader (AIM-87).
//
// Loads policies/compliance/framework-map.yaml straight from disk on every
// request (same no-drift principle as guardrail-policy.js) and validates
// referential integrity: every control key a rule references must exist in
// the frameworks section. The file's own sha256 content hash is reported
// next to findings.policy_hash so an auditor can pin both artifacts.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

const here = dirname(fileURLToPath(import.meta.url));
// Dev default: repo layout apps/api/src -> <repo>/policies/compliance.
// Override with COMPLIANCE_MAP_PATH (Docker image, tests).
export const DEFAULT_MAP_PATH = join(here, '..', '..', '..', 'policies', 'compliance', 'framework-map.yaml');

export function complianceMapPath() {
  return process.env.COMPLIANCE_MAP_PATH || DEFAULT_MAP_PATH;
}

// A mapping entry is either a list of control keys or { 'n/a': justification }.
function normalizeMapping(entry, label, validKeys) {
  if (entry === undefined || entry === null) {
    throw new Error(`${label}: missing mapping`);
  }
  if (Array.isArray(entry)) {
    if (entry.length === 0) throw new Error(`${label}: empty mapping — use n/a with a justification instead`);
    for (const key of entry) {
      if (!validKeys.has(key)) throw new Error(`${label}: unknown control '${key}'`);
    }
    return { controls: entry, na: null };
  }
  if (typeof entry === 'object' && typeof entry['n/a'] === 'string' && entry['n/a'].trim().length > 0) {
    return { controls: [], na: entry['n/a'] };
  }
  throw new Error(`${label}: mapping must be a list of control keys or { n/a: "<justification>" }`);
}

export function loadComplianceMap(path = complianceMapPath()) {
  const raw = readFileSync(path);
  const data = yaml.load(raw) ?? {};
  const contentHash = createHash('sha256').update(raw).digest('hex');

  const frameworks = {};
  for (const [fwId, fw] of Object.entries(data.frameworks ?? {})) {
    const controls = {};
    for (const [ctrlId, ctrl] of Object.entries(fw.controls ?? {})) {
      controls[ctrlId] = { id: ctrlId, ref: ctrl.ref ?? ctrlId, title: ctrl.title ?? '', summary: ctrl.summary ?? '' };
    }
    frameworks[fwId] = { id: fwId, name: fw.name ?? fwId, controls };
  }

  const rules = {};
  for (const [ruleId, m] of Object.entries(data.rules ?? {})) {
    const entry = { rationale: m.rationale ?? '' };
    for (const fwId of Object.keys(frameworks)) {
      entry[fwId] = normalizeMapping(m[fwId], `rules.${ruleId}.${fwId}`, new Set(Object.keys(frameworks[fwId].controls)));
    }
    rules[ruleId] = entry;
  }

  const auditEvents = {};
  for (const [action, m] of Object.entries(data.audit_events ?? {})) {
    const entry = { rationale: m.rationale ?? '' };
    for (const fwId of Object.keys(frameworks)) {
      // Audit event classes may legitimately not map to every framework.
      entry[fwId] = m[fwId] === undefined
        ? { controls: [], na: null }
        : normalizeMapping(m[fwId], `audit_events.${action}.${fwId}`, new Set(Object.keys(frameworks[fwId].controls)));
    }
    auditEvents[action] = entry;
  }

  // Evidence retention policy per report type (AIM-99). Day counts are
  // enforced by the snapshot store; the note is surfaced verbatim so the
  // policy statement travels with the report.
  const retention = {
    weeklySnapshotDays: Number(data.retention?.weekly_snapshot_days ?? 400),
    onDemandSnapshotDays: Number(data.retention?.on_demand_snapshot_days ?? 90),
    note: data.retention?.note ?? '',
  };
  for (const [k, v] of [['weekly_snapshot_days', retention.weeklySnapshotDays], ['on_demand_snapshot_days', retention.onDemandSnapshotDays]]) {
    if (!Number.isFinite(v) || v < 1) throw new Error(`retention.${k}: must be a positive number of days`);
  }

  return {
    version: data.version ?? null,
    frameworks,
    rules,
    auditEvents,
    retention,
    scopingNote: data.scoping_note ?? '',
    contentHash,
    source: path,
  };
}

// Coverage check (acceptance criterion): every live guardrail rule must map
// to >=1 control per framework, or carry an explicit justified n/a.
// Returns [{ ruleId, framework, ok, reason }] — one row per rule × framework.
export function coverageReport(map, liveRuleIds) {
  const rows = [];
  for (const ruleId of liveRuleIds) {
    for (const fwId of Object.keys(map.frameworks)) {
      const m = map.rules[ruleId]?.[fwId];
      if (!m) {
        rows.push({ ruleId, framework: fwId, ok: false, reason: 'rule missing from framework-map.yaml' });
      } else if (m.controls.length > 0) {
        rows.push({ ruleId, framework: fwId, ok: true, reason: null });
      } else if (m.na) {
        rows.push({ ruleId, framework: fwId, ok: true, reason: `n/a — ${m.na}` });
      } else {
        rows.push({ ruleId, framework: fwId, ok: false, reason: 'no controls mapped and no n/a justification' });
      }
    }
  }
  return rows;
}

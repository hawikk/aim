// Guardrail policy reader + humanizer (AIM-81).
//
// Reads the SAME YAML policy files the guardrail engine (services/guardrail)
// loads, straight from disk on every request — the rules viewer can never
// drift from the live policy. The content hash replicates the engine's
// hashing exactly (sha256 over the concatenated raw bytes of the sorted
// *.yaml/*.yml files), so it matches findings.policy_hash.
//
// The humanizer turns the engine's condition ops into plain English so a
// security user can see what a rule does without reading YAML. It mirrors
// services/guardrail/src/guardrail/conditions.py — when a new op is added
// there, add it here (unknown ops fail loud, not silent).
//
// Top-level rule_overrides maps (AIM-94, machine-owned ui-overrides.yaml) are
// collected from every file and applied to threshold rules after parsing —
// unknown rule ids or keys throw, matching the duplicate-id posture.
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

const here = dirname(fileURLToPath(import.meta.url));
// Dev default: repo layout apps/api/src -> <repo>/policies/guardrail/v1.
// The Docker image sets GUARDRAIL_POLICY_PATH to the copied-in policy dir.
export const DEFAULT_POLICY_PATH = join(here, '..', '..', '..', 'policies', 'guardrail', 'v1');

export function policyPath() {
  return process.env.GUARDRAIL_POLICY_PATH || DEFAULT_POLICY_PATH;
}

export function loadPolicy(path = policyPath()) {
  const stat = statSync(path);
  const files = stat.isDirectory()
    ? readdirSync(path)
        .filter((f) => /\.ya?ml$/.test(f))
        .sort()
        .map((f) => join(path, f))
    : [path];
  if (files.length === 0) throw new Error(`no YAML ruleset files found at ${path}`);

  const hasher = createHash('sha256');
  const settings = {};
  const rules = [];
  let version = null;
  const seen = new Set();
  // Top-level rule_overrides maps from every file (AIM-94 UI-tunable rules),
  // merged per-rule per-key — later file wins per key.
  const ruleOverrides = {};

  for (const file of files) {
    const raw = readFileSync(file);
    hasher.update(raw);
    const data = yaml.load(raw) ?? {};
    if (version === null) version = data.version ?? null;
    // Same shallow-merge semantics as the engine (rules.py): dicts merge,
    // everything else is replaced by the later file.
    for (const [k, v] of Object.entries(data.settings ?? {})) {
      if (v && typeof v === 'object' && !Array.isArray(v) && settings[k] && typeof settings[k] === 'object' && !Array.isArray(settings[k])) {
        Object.assign(settings[k], v);
      } else {
        settings[k] = v;
      }
    }
    for (const [ruleId, override] of Object.entries(data.rule_overrides ?? {})) {
      ruleOverrides[ruleId] = { ...(ruleOverrides[ruleId] ?? {}), ...(override ?? {}) };
    }
    for (const rule of data.rules ?? []) {
      if (seen.has(rule.id)) throw new Error(`${file}: duplicate rule id '${rule.id}'`);
      seen.add(rule.id);
      rules.push(rule);
    }
  }
  applyRuleOverrides(rules, ruleOverrides);
  return { version, settings, rules, ruleOverrides, contentHash: hasher.digest('hex'), sources: files };
}

// Keys a UI override may touch on a threshold rule (AIM-94). Everything else
// (metric, group_by, filters) stays PR-managed in the core policy files.
const OVERRIDE_KEYS = ['gt', 'gte', 'window_seconds', 'severity'];

// Applies collected rule_overrides to the parsed rules list. Fails loud —
// unknown rule id or unknown override key is a policy error, same posture as
// duplicate rule ids. Overridden rules are marked and keep their original
// values under overrideOriginals.
export function applyRuleOverrides(rules, ruleOverrides) {
  for (const [ruleId, override] of Object.entries(ruleOverrides)) {
    const rule = rules.find((r) => r.id === ruleId);
    if (!rule) throw new Error(`rule_overrides references unknown rule id '${ruleId}'`);
    for (const key of Object.keys(override)) {
      if (!OVERRIDE_KEYS.includes(key)) {
        throw new Error(`rule_overrides.${ruleId}: unknown key '${key}' (allowed: ${OVERRIDE_KEYS.join(', ')})`);
      }
    }
    if (Object.keys(override).length === 0) continue;
    const originals = {};
    for (const [key, value] of Object.entries(override)) {
      originals[key] = rule[key] ?? null;
      rule[key] = value;
    }
    rule.overridden = true;
    rule.overrideOriginals = originals;
  }
}

/* ---------- human-readable rendering ---------- */

const backtick = (v) => `\`${String(v)}\``;
const fmtList = (v) => (Array.isArray(v) ? v.map(backtick).join(', ') : backtick(v));

// A bare string operand names a list in settings (engine: _resolve_reference).
function resolveRef(value, settings) {
  if (typeof value === 'string' && Array.isArray(settings[value])) return settings[value];
  return value;
}

function fmtWindow(seconds) {
  if (seconds % 86400 === 0) return `${seconds / 86400} day${seconds === 86400 ? '' : 's'}`;
  if (seconds % 3600 === 0) return `${seconds / 3600} hour${seconds === 3600 ? '' : 's'}`;
  if (seconds % 60 === 0) return `${seconds / 60} minute${seconds === 60 ? '' : 's'}`;
  return `${seconds} seconds`;
}

function fmtMetric(metric) {
  if (metric === 'count') return 'the number of events';
  if (metric === 'sum_tokens') return 'total tokens (prompt + completion)';
  if (typeof metric === 'string' && metric.startsWith('sum:')) return `the sum of ${backtick(metric.slice(4))}`;
  return backtick(metric);
}

function offHoursText(settings) {
  const start = settings.off_hours_start ?? 20;
  const end = settings.off_hours_end ?? 7;
  return `off-hours (${String(start).padStart(2, '0')}:00–${String(end).padStart(2, '0')}:00, endpoint-local when available)`;
}

/** AIM-690: ABAC attribute leaves use ``attr:`` instead of ``field:``. */
function describeAttrLeaf(cond, settings = {}) {
  const attr = cond.attr;
  const ops = Object.keys(cond).filter((k) => k !== 'attr');
  const op = ops[0];
  const expected = cond[op];
  const dim = backtick(attr);
  switch (op) {
    case 'eq':
      return `attribute ${dim} is ${backtick(expected)}`;
    case 'neq':
      return `attribute ${dim} is not ${backtick(expected)}`;
    case 'in':
      return `attribute ${dim} is one of: ${fmtList(resolveRef(expected, settings))}`;
    case 'not_in':
      return `attribute ${dim} is not one of: ${fmtList(resolveRef(expected, settings))}`;
    default:
      return `attribute ${dim} ${op} ${JSON.stringify(expected)} (unrecognized attr op — update guardrail-policy.js)`;
  }
}

export function describeLeaf(cond, settings = {}) {
  // AIM-690: ABAC attribute conditions (user / group / repo_class / tool).
  if (cond && Object.prototype.hasOwnProperty.call(cond, 'attr')) {
    return describeAttrLeaf(cond, settings);
  }
  const field = cond.field;
  const ops = Object.keys(cond).filter((k) => k !== 'field');
  const op = ops[0];
  const expected = cond[op];
  switch (op) {
    case 'eq':
      return `${backtick(field)} is ${backtick(expected)}`;
    case 'neq':
      return `${backtick(field)} is not ${backtick(expected)}`;
    case 'in':
      return `${backtick(field)} is one of: ${fmtList(resolveRef(expected, settings))}`;
    case 'not_in':
      return `${backtick(field)} is not one of: ${fmtList(resolveRef(expected, settings))}`;
    case 'contains':
      return `${backtick(field)} contains ${backtick(expected)}`;
    case 'contains_detector': {
      const val = String(expected);
      return val.endsWith('*')
        ? `a detector starting with ${backtick(val.slice(0, -1))} fired at the collection point (match flag present)`
        : `detector ${backtick(val)} fired at the collection point (match flag present)`;
    }
    case 'gt':
      return `${backtick(field)} is greater than ${expected}`;
    case 'gte':
      return `${backtick(field)} is at least ${expected}`;
    case 'lt':
      return `${backtick(field)} is less than ${expected}`;
    case 'lte':
      return `${backtick(field)} is at most ${expected}`;
    case 'not_in_approved_providers_for':
      return `${backtick(field)} is not in the approved provider list for the event's ${backtick(expected)}`;
    case 'not_in_approved_models_for':
      return `${backtick(field)} is not in the approved model list for the event's ${backtick(expected)}`;
    case 'model_provider_not_permitted_for_scope':
      return expected
        ? `the event's model/provider is not permitted for its scope (team allowlist when set, else global approved_models, else approved_providers)`
        : `the event's model/provider is permitted for its scope`;
    case 'in_off_hours':
      return expected ? `the event occurs during ${offHoursText(settings)}` : `the event occurs outside ${offHoursText(settings)}`;
    case 'in_restricted_repos':
      return expected ? `the event's ${backtick(field)} matches the restricted-repository list` : `the event's ${backtick(field)} is outside the restricted-repository list`;
    case 'mcp_call_to_unapproved_server':
      return `a ${backtick(field)} entry is an MCP call to a server outside the approved-server list (unknown server counts as unapproved)`;
    case 'tool_call_action_class_in':
      return `a ${backtick(field)} entry has action class ${fmtList(expected)}`;
    case 'tool_call_name_matches':
      return `a ${backtick(field)} entry has a tool name matching ${fmtList(resolveRef(expected, settings))}`;
    case 'configured_mcp_server_unapproved':
      return `a ${backtick(field)} entry names an MCP server outside the approved-server list`;
    default:
      // New engine op not yet mirrored here — surface it verbatim, never hide it.
      return `${backtick(field)} ${op} ${JSON.stringify(expected)} (unrecognized op — update guardrail-policy.js)`;
  }
}

// Returns an array of lines; nested all/any (one level, like the engine) become indented bullets.
export function describeTree(tree, settings = {}) {
  const combiner = tree.all ? 'ALL' : tree.any ? 'ANY' : null;
  if (!combiner) return [describeLeaf(tree, settings)];
  const lines = [`${combiner} of these must hold:`];
  for (const sub of tree.all ?? tree.any) {
    for (const line of describeTree(sub, settings)) {
      lines.push(`  • ${line}`);
    }
  }
  return lines;
}

export function describeRule(rule, settings = {}) {
  if (rule.type === 'match') {
    return { conditionText: describeTree(rule.when, settings).join('\n'), thresholdText: null };
  }
  const op = 'gt' in rule ? 'exceeds' : 'reaches';
  const value = 'gt' in rule ? rule.gt : rule.gte;
  const lines = [
    `Fires once when ${fmtMetric(rule.metric)} per ${rule.group_by.map(backtick).join(' × ')} ` +
      `over a sliding ${fmtWindow(rule.window_seconds)} window ${op} ${Number(value).toLocaleString('en-US')}.`,
    'Refires only after the window value drops back below the threshold.',
  ];
  if (rule.filter) {
    lines.push('Only events matching this filter count toward the window:', ...describeTree(rule.filter, settings).map((l) => `  ${l}`));
  }
  return { conditionText: null, thresholdText: lines.join('\n') };
}

/* ---------- AIM-441 rule posture (active / inert / discovery) ----------
 * Never ship a permanently silent control without a dashboard label. Rules
 * may declare inert_until: [keys]; we also auto-detect restricted-repo
 * dependencies from the condition tree. */

const INERT_REASON = {
  restricted_repos_populated: 'settings.restricted_repos is empty — rule cannot match',
  aim_hash_salt_configured: 'AIM_HASH_SALT is unset on the guardrail service — HMAC match disabled',
  approved_models_or_providers_scope:
    'model allowlist empty and no provider-matrix scope applies for unscoped tools (degrade-open half)',
  approved_models_populated: 'settings.approved_models is empty — model half of the allowlist is degrade-open',
};

function treeUsesOp(tree, op) {
  if (!tree || typeof tree !== 'object') return false;
  if (tree.all) return tree.all.some((s) => treeUsesOp(s, op));
  if (tree.any) return tree.any.some((s) => treeUsesOp(s, op));
  return Object.prototype.hasOwnProperty.call(tree, op);
}

/**
 * Compute effective posture for a rule against current settings + process env.
 * Returns { status: 'active'|'inert'|'discovery', reasons: string[], label }.
 */
export function rulePosture(rule, settings = {}, env = process.env) {
  const reasons = [];
  const declared = Array.isArray(rule.inert_until) ? rule.inert_until : [];
  const keys = new Set(declared);

  // Auto-detect restricted-repo dependency even if YAML omitted inert_until.
  const cond = rule.when ?? rule.filter ?? null;
  if (treeUsesOp(cond, 'in_restricted_repos')) {
    keys.add('restricted_repos_populated');
    keys.add('aim_hash_salt_configured');
  }

  for (const key of keys) {
    if (key === 'restricted_repos_populated') {
      if (!Array.isArray(settings.restricted_repos) || settings.restricted_repos.length === 0) {
        reasons.push(INERT_REASON.restricted_repos_populated);
      }
    } else if (key === 'aim_hash_salt_configured') {
      if (!env.AIM_HASH_SALT) {
        reasons.push(INERT_REASON.aim_hash_salt_configured);
      }
    } else if (key === 'approved_models_populated') {
      const models = settings.approved_models ?? {};
      if (!models || typeof models !== 'object' || Object.keys(models).length === 0) {
        reasons.push(INERT_REASON.approved_models_populated);
      }
    } else if (key === 'approved_models_or_providers_scope') {
      // Partially active: provider matrix still fires for tools that have
      // approved_providers entries. Label as active with a note when models
      // empty but providers exist; inert only when both empty.
      const models = settings.approved_models ?? {};
      const providers = settings.approved_providers ?? {};
      const hasModels = models && typeof models === 'object' && Object.keys(models).length > 0;
      const hasProviders = providers && typeof providers === 'object' && Object.keys(providers).length > 0;
      if (!hasModels && !hasProviders) {
        reasons.push(INERT_REASON.approved_models_or_providers_scope);
      }
    } else {
      reasons.push(`unmet prerequisite: ${key}`);
    }
  }

  if (reasons.length > 0) {
    return {
      status: 'inert',
      reasons,
      label: 'Inert until configured',
    };
  }

  // MCP allowlist: discovery mode is a labelled active posture (every call
  // flags) — distinct from inert. AIM-441 closed discovery → deny_unlisted.
  const mcpMode = settings.mcp_allowlist_mode ?? 'deny_unlisted';
  const mcpEmpty = !Array.isArray(settings.approved_mcp_servers) || settings.approved_mcp_servers.length === 0;
  const mcpRule = rule.id === 'unapproved-mcp-server' || rule.id === 'unapproved-mcp-server-configured';
  if (mcpRule && mcpEmpty && mcpMode === 'discovery') {
    return {
      status: 'discovery',
      reasons: ['approved_mcp_servers empty — discovery mode flags every MCP server'],
      label: 'Discovery mode (allowlist empty)',
    };
  }

  return { status: 'active', reasons: [], label: 'Active' };
}

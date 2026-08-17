// Endpoint enforcement policy reader + per-rule mode matrix.
//
// Declared fleet intent lives in the same JSON bundle endpoints load
// (`enforcement.json` / default_enforcement.json). This module reads that
// bundle from disk on every request so the dashboard cannot drift from what
// collectors seed, and joins last-7d disposition counts from `events.payload
// -> enforcement` so an analyst can answer "what is enforced where, with what
// outcomes?" without SQL.
//
// Modes (per rule, not global):
//   observe  — shadow / flag-off: would_block only (or would_redact via would_block)
//   confirm  — challenge UX when enforced (pii-in-prompt)
//   enforce  — hard block or redact when global mode=enforce AND rule.enforce
//   not_configured — rail is catalogued but absent from the loaded bundle
// (e.g. secret-in-tool-input/redact lands)
//
// Actions: block | redact. Primary disposition when the rule is applied.

import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
// Repo layout: apps/api/src → <repo>/deploy/enforcement/enforcement.enforce.json
// Docker image copies the same tree to /app/enforcement (see apps/api/Dockerfile).
export const DEFAULT_ENFORCEMENT_CANDIDATES = [
  join(here, '..', '..', '..', 'deploy', 'enforcement', 'enforcement.enforce.json'),
  join(here, '..', '..', '..', 'collectors', 'claude-code', 'aim_collector', 'default_enforcement.json'),
  '/app/enforcement/enforcement.enforce.json',
];

/** Fixed catalog of endpoint-enforceable rails (residual B). */
export const ENDPOINT_RAILS = [
  {
    id: 'secret-pattern-in-prompt',
    title: 'Secret pattern in prompt',
    // When enforced: hard block + break-glass resubmit → confirmed.
    disposition: 'block',
    modeWhenEnforced: 'enforce',
    hook: 'UserPromptSubmit',
    optional: false,
    notes: 'Break-glass resubmit within secret_override_ttl_seconds is audited as confirmed.',
  },
  {
    id: 'unapproved-mcp-server',
    title: 'Unapproved MCP server',
    disposition: 'block',
    modeWhenEnforced: 'enforce',
    hook: 'PreToolUse',
    optional: false,
    notes: 'Deny PreToolUse for mcp__* servers outside approved_mcp_servers.',
  },
  {
    id: 'restricted-repo-access',
    title: 'Restricted repository access',
    disposition: 'block',
    modeWhenEnforced: 'enforce',
    hook: 'PreToolUse',
    optional: false,
    notes: 'Deny file-touching tools under restricted_repo_paths.',
  },
  {
    id: 'pii-in-prompt',
    title: 'PII in prompt (confirm)',
    disposition: 'block',
    modeWhenEnforced: 'confirm',
    hook: 'UserPromptSubmit',
    optional: false,
    notes: 'Confirm-prompt: first hit challenges, identical resubmit within TTL confirms.',
  },
  {
    id: 'secret-in-tool-input',
    title: 'Secret in tool input (redact)',
    disposition: 'redact',
    modeWhenEnforced: 'enforce',
    hook: 'PreToolUse',
    // Absent from the shipped bundle until redact land.
    optional: true,
    notes: 'PreToolUse updatedInput rewrite; action redacted. Row ships as not_configured until the rail lands in the bundle.',
  },
];

export const DISPOSITION_ACTIONS = ['blocked', 'would_block', 'confirmed', 'redacted'];

export function enforcementPath(candidates = DEFAULT_ENFORCEMENT_CANDIDATES) {
  if (process.env.AIM_ENFORCEMENT_FILE) {
    return process.env.AIM_ENFORCEMENT_FILE;
  }
  for (const c of candidates) {
    if (c && existsSync(c)) return c;
  }
  return candidates[0] ?? null;
}

/**
 * Load the declared endpoint enforcement bundle.
 * Returns { loaded, path, policy, error? }. Never throws on missing/malformed
 * files — the matrix still enumerates rails with mode not_configured / observe.
 */
export function loadEnforcementPolicy(path = enforcementPath()) {
  if (!path) {
    return { loaded: false, path: null, policy: null, error: 'no_path' };
  }
  if (!existsSync(path)) {
    return { loaded: false, path, policy: null, error: 'missing' };
  }
  try {
    const raw = readFileSync(path, 'utf8');
    const policy = JSON.parse(raw);
    if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
      return { loaded: false, path, policy: null, error: 'invalid_shape' };
    }
    return { loaded: true, path, policy, error: null };
  } catch (err) {
    return { loaded: false, path, policy: null, error: err.message };
  }
}

function ruleEntry(policy, ruleId) {
  const rules = policy?.rules;
  if (!rules || typeof rules !== 'object' || Array.isArray(rules)) return null;
  const entry = rules[ruleId];
  return entry && typeof entry === 'object' && !Array.isArray(entry) ? entry : null;
}

/**
 * Resolve per-rule mode + action from declared policy + catalog.
 *
 * @returns {{
 *   mode: 'observe'|'confirm'|'enforce'|'not_configured',
 *   action: 'block'|'redact',
 *   enforce: boolean,
 *   enforceFlag: boolean,
 *   configured: boolean,
 * }}
 */
export function resolveRuleMode(rail, policy) {
  const defaultAction = rail.disposition === 'redact' ? 'redact' : 'block';
  if (!policy) {
    return {
      mode: 'not_configured',
      action: defaultAction,
      enforce: false,
      enforceFlag: false,
      configured: false,
    };
  }
  const entry = ruleEntry(policy, rail.id);
  if (!entry) {
    return {
      mode: 'not_configured',
      action: defaultAction,
      enforce: false,
      enforceFlag: false,
      configured: false,
    };
  }
  const actionRaw = typeof entry.action === 'string' ? entry.action.toLowerCase() : null;
  const action = actionRaw === 'redact' || actionRaw === 'block'
    ? actionRaw
    : defaultAction;
  const enforceFlag = entry.enforce === true;
  const globalEnforce = policy.mode === 'enforce';
  const enforce = globalEnforce && enforceFlag;
  if (!enforce) {
    return {
      mode: 'observe',
      action,
      enforce: false,
      enforceFlag,
      configured: true,
    };
  }
  const mode = rail.modeWhenEnforced === 'confirm' ? 'confirm' : 'enforce';
  return { mode, action, enforce: true, enforceFlag, configured: true };
}

/**
 * Build the per-rule matrix rows (no DB). Pure, testable.
 */
export function buildModeMatrix(policy, rails = ENDPOINT_RAILS) {
  return rails.map((rail) => {
    const resolved = resolveRuleMode(rail, policy);
    return {
      id: rail.id,
      title: rail.title,
      hook: rail.hook,
      notes: rail.notes,
      optional: rail.optional === true,
      mode: resolved.mode,
      action: resolved.action,
      enforce: resolved.enforce,
      enforceFlag: resolved.enforceFlag,
      configured: resolved.configured,
      policyHash: typeof policy?.policy_hash === 'string' ? policy.policy_hash : null,
    };
  });
}

/** Empty disposition bucket for one rule. */
export function emptyCounts() {
  return Object.fromEntries(DISPOSITION_ACTIONS.map((a) => [a, 0]).concat([['total', 0]]));
}

/**
 * Merge SQL disposition rows into a Map(ruleId → counts).
 * rows: [{ rule_id, action, n }]
 */
export function mergeDispositionCounts(rows) {
  const map = new Map();
  for (const r of rows ?? []) {
    const id = r.rule_id ?? r.ruleId;
    if (!id || typeof id !== 'string') continue;
    const action = r.action;
    if (!DISPOSITION_ACTIONS.includes(action)) continue;
    if (!map.has(id)) map.set(id, emptyCounts());
    const c = map.get(id);
    const n = Number(r.n ?? r.count ?? 0) || 0;
    c[action] += n;
    c.total += n;
  }
  return map;
}

export function attachCounts(matrix, countMap) {
  return matrix.map((row) => ({
    ...row,
    last7d: countMap.get(row.id) ?? emptyCounts(),
  }));
}

export function modeCounts(rules) {
  const acc = { observe: 0, confirm: 0, enforce: 0, not_configured: 0 };
  for (const r of rules) {
    if (acc[r.mode] !== undefined) acc[r.mode] += 1;
  }
  return acc;
}

export function totalsLast7d(rules) {
  const t = emptyCounts();
  for (const r of rules) {
    const c = r.last7d ?? emptyCounts();
    for (const a of DISPOSITION_ACTIONS) t[a] += c[a] ?? 0;
    t.total += c.total ?? 0;
  }
  return t;
}

/**
 * Scorecard-pack evidence export (consumer).
 * Deterministic given the same matrix + policy snapshot.
 */
export function buildEvidencePack({ policyMeta, rules, window }) {
  const matrix = rules.map((r) => ({
    ruleId: r.id,
    title: r.title,
    mode: r.mode,
    action: r.action,
    enforce: r.enforce,
    enforceFlag: r.enforceFlag,
    configured: r.configured,
    policyHash: r.policyHash,
    hook: r.hook,
    last7d: r.last7d,
  }));
  return {
    kind: 'aim-enforcement-mode-matrix',
    version: 1,
    scorecardPack: true,
    generatedAt: window?.to ?? new Date().toISOString(),
    window: {
      days: window?.days ?? 7,
      from: window?.from ?? null,
      to: window?.to ?? null,
    },
    policy: {
      loaded: policyMeta?.loaded === true,
      path: policyMeta?.path ?? null,
      policyHash: policyMeta?.policy?.policy_hash ?? null,
      mode: policyMeta?.policy?.mode ?? null,
      version: policyMeta?.policy?.version ?? null,
      error: policyMeta?.error ?? null,
    },
    modeCounts: modeCounts(rules),
    totalsLast7d: totalsLast7d(rules),
    matrix,
    analystAnswer: {
      question: 'What is enforced where, with what outcomes?',
      enforcedRules: matrix.filter((r) => r.mode === 'enforce' || r.mode === 'confirm').map((r) => r.ruleId),
      observeRules: matrix.filter((r) => r.mode === 'observe').map((r) => r.ruleId),
      notConfigured: matrix.filter((r) => r.mode === 'not_configured').map((r) => r.ruleId),
      note: 'Modes come from the declared endpoint enforcement bundle; last-7d counts are measured dispositions from events.payload.enforcement. Per-host coverage is.',
    },
  };
}

// Deterministic per-event security score.
//
// A PURE, config-driven function of fields the schema already collects — no
// new data collection, no model, no randomness. Identical inputs always
// produce an identical score AND an identical factor breakdown, because the
// Auditability lens is non-negotiable: "we scored it 9 but can't say why" is
// unacceptable. Every point above the baseline is attributable to a named
// factor the UI can show.
//
// Scoring model: start at SCORE_CONFIG.base and ADD the weight of each factor
// that fires, then clamp to [1, 10]. Factors are additive and independent so
// the breakdown reads as a plain sum. Weights are calibrated so benign usage
// lands at 1–2 and a secret-flagged shell tool-call lands at 8–10 (see the
// unit fixtures in test/activity-score.test.js).
//
// Grounded in existing config so the score cannot drift from policy:
// * sanctioned tools come from sanctioned.js (the locked list),
//   * "known model" is a key in the pricing.js price table,
//   * approved MCP servers mirror the guardrail policy's discovery-mode
//     default (empty list ⇒ every MCP call is unapproved — intentional
//     observe-only inventory posture, see policies/guardrail/v1/core.yaml).
import { SANCTIONED_TOOLS } from './sanctioned.js';
import { PRICE_PER_MTOK } from './pricing.js';

// All weights and thresholds live here — the single config the score is
// tuned from. Changing a number here changes the score everywhere and is the
// only place a reviewer needs to look to understand the scale.
export const SCORE_CONFIG = {
  base: 1,
  // match_flags contribute the MAX of (category + severity) over all flags —
  // the single most-severe detector dominates rather than summing noise. All
  // flags are still listed in the breakdown.
  matchCategory: { secret: 6, pii: 4, injection: 4, policy: 2 },
  matchSeverityBump: { low: 0, medium: 1, high: 2 },
  matchSeverityDefault: 'medium', // schema makes severity optional
  // tool_calls contribute the MAX action-class weight present — capability
  // risk, not volume. shell/network (exfil + arbitrary exec) outrank writes,
  // which outrank reads.
  actionClass: { shell: 3, network: 3, fs_write: 2, mcp_call: 1, fs_read: 0, other: 0 },
  unapprovedTool: 3, // tool='other' (unknown/unapproved); genai_app is excluded
  unknownModel: 1, // model set but absent from the price table
  unapprovedMcpServer: 2, // an mcp_call to a server outside approvedMcpServers
  approvedMcpServers: [], // empty = discovery mode (mirrors guardrail policy)
  enforcement: { blocked: 3, would_block: 1, confirmed: 1 },
  finding: { critical: 4, high: 3, medium: 2, low: 1 }, // a finding raised on the event
  min: 1,
  max: 10,
  // Score → color band for the UI badge.
  bands: [
    { band: 'green', max: 3 },
    { band: 'amber', max: 6 },
    { band: 'red', max: 10 },
  ],
};

function bandFor(score, cfg) {
  for (const b of cfg.bands) if (score <= b.max) return b.band;
  return cfg.bands[cfg.bands.length - 1].band;
}

// Score one event. `event` carries schema fields (tool, model, event_type,
// match_flags, tool_calls, enforcement). `ctx.findingSeverity` is the
// highest severity of any finding the guardrail engine raised on this event
// (joined by the caller), or null. `ctx.config` overrides SCORE_CONFIG.
//
// Returns { score, band, factors }, factors sorted by weight desc then code
// (stable, deterministic ordering) — each { code, label, weight, detail? }.
export function scoreEvent(event = {}, ctx = {}) {
  const cfg = ctx.config ?? SCORE_CONFIG;
  const factors = [];
  const add = (code, label, weight, detail) => {
    if (weight > 0) factors.push({ code, label, weight, ...(detail ? { detail } : {}) });
  };

  // --- detector match flags: most-severe category dominates ---
  const flags = Array.isArray(event.match_flags) ? event.match_flags : [];
  let topFlag = null;
  let topFlagWeight = 0;
  for (const f of flags) {
    const catW = cfg.matchCategory[f?.category] ?? 0;
    const sevW = cfg.matchSeverityBump[f?.severity ?? cfg.matchSeverityDefault] ?? 0;
    const w = catW + sevW;
    if (catW > 0 && w > topFlagWeight) {
      topFlagWeight = w;
      topFlag = f;
    }
  }
  if (topFlag) {
    const sev = topFlag.severity ?? cfg.matchSeverityDefault;
    add(
      `match:${topFlag.category}`,
      `${topFlag.category} detector fired`,
      topFlagWeight,
      `${topFlag.detector ?? topFlag.category} (${sev}${flags.length > 1 ? `; +${flags.length - 1} more flag${flags.length > 2 ? 's' : ''}` : ''})`
    );
  }

  // --- agent tool-call capability: highest-risk action class present ---
  const calls = Array.isArray(event.tool_calls) ? event.tool_calls : [];
  let topAction = null;
  let topActionWeight = -1;
  const approved = new Set(cfg.approvedMcpServers ?? []);
  let unapprovedMcp = null;
  for (const c of calls) {
    const w = cfg.actionClass[c?.action_class] ?? 0;
    if (w > topActionWeight) {
      topActionWeight = w;
      topAction = c;
    }
    if (c?.action_class === 'mcp_call' && !approved.has(c?.mcp_server)) {
      unapprovedMcp = unapprovedMcp ?? (c?.mcp_server ?? null);
    }
  }
  if (topAction && topActionWeight > 0) {
    add(
      `action:${topAction.action_class}`,
      `${topAction.action_class} tool call`,
      topActionWeight,
      `${topAction.tool_name}${topAction.count > 1 ? ` ×${topAction.count}` : ''}`
    );
  }
  if (unapprovedMcp !== null || calls.some((c) => c?.action_class === 'mcp_call' && !approved.has(c?.mcp_server))) {
    add('mcp:unapproved', 'unapproved MCP server', cfg.unapprovedMcpServer, unapprovedMcp ?? '(unknown server)');
  }

  // --- unapproved tool / unknown model ---
  // genai_app is first-party app telemetry, excluded from tool-approval
  // reporting by schema contract — never scored as an unapproved tool.
  if (event.tool && event.tool !== 'genai_app' && !SANCTIONED_TOOLS.has(event.tool)) {
    add('tool:unapproved', 'unapproved tool', cfg.unapprovedTool, event.tool_raw || event.tool);
  }
  if (event.model && !(event.model in PRICE_PER_MTOK)) {
    add('model:unknown', 'unrecognized model', cfg.unknownModel, event.model);
  }

  // --- endpoint enforcement outcome ---
  const action = event.enforcement?.action;
  if (action && cfg.enforcement[action]) {
    // confirmed is shared by secret break-glass and PII confirm
    // label by rule so Activity trail does not mis-tag secret overrides as PII.
    const ruleId = event.enforcement?.rule_id;
    let label = 'would block (shadow)';
    if (action === 'blocked') label = 'endpoint blocked';
    else if (action === 'confirmed') {
      label = ruleId === 'secret-pattern-in-prompt'
        ? 'secret break-glass override'
        : ruleId === 'pii-in-prompt'
          ? 'PII send confirmed'
          : 'enforcement override confirmed';
    }
    add(`enforcement:${action}`, label, cfg.enforcement[action], ruleId);
  }

  // --- guardrail finding raised on this event ---
  const fsev = ctx.findingSeverity;
  if (fsev && cfg.finding[fsev]) {
    add(`finding:${fsev}`, `${fsev} finding raised`, cfg.finding[fsev]);
  }

  const raw = cfg.base + factors.reduce((s, f) => s + f.weight, 0);
  const score = Math.max(cfg.min, Math.min(cfg.max, raw));
  factors.sort((a, b) => b.weight - a.weight || a.code.localeCompare(b.code));
  return { score, band: bandFor(score, cfg), factors };
}

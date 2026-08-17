/**
 * Severity taxonomy v1.
 *
 * Maps guardrail finding types to Microsoft Sentinel alert severities.
 * Sentinel severities: Informational, Low, Medium, High.
 * (Sentinel has no "Critical" alert severity; High is the top of the scale.)
 *
 * CEF numeric severity (0-10) is derived for the CEF payload.
 *
 * NOTE: observe-only posture. Severity drives SOC triage
 * order and notification routing, not automated blocking.
 */

export const SENTINEL_SEVERITY = {
  INFORMATIONAL: 'Informational',
  LOW: 'Low',
  MEDIUM: 'Medium',
  HIGH: 'High',
} as const;

export type SentinelSeverity = (typeof SENTINEL_SEVERITY)[keyof typeof SENTINEL_SEVERITY];

/** Sentinel severity -> CEF numeric severity (0-10). */
export const CEF_SEVERITY: Record<SentinelSeverity, number> = {
  Informational: 2,
  Low: 4,
  Medium: 6,
  High: 9,
};

export interface TaxonomyEntry {
  severity: SentinelSeverity;
  /** Stable runbook slug; resolved to a full URL by alerting config (RUNBOOK_BASE_URL). */
  runbook: string;
  rationale: string;
}

export interface Classification extends TaxonomyEntry {
  /** false when the finding type was not in the taxonomy (fell back). */
  known: boolean;
}

/**
 * findingType -> taxonomy entry.
 * Runbook slugs resolve under the corporate wiki runbook space.
 */
export const TAXONOMY: Record<string, TaxonomyEntry> = {
  // Credential/secret pattern matched in prompt metadata (pattern id only —
  // the secret value itself is never collected, per metadata-only policy).
  secret_pattern_detected: {
    severity: SENTINEL_SEVERITY.HIGH,
    runbook: 'rb-secret-exposure',
    rationale: 'Potential credential exposure; rotate-then-investigate posture.',
  },
  // Engineer using a tool outside the sanctioned list (Claude Code, Cursor, Kilo Code).
  unapproved_tool_detected: {
    severity: SENTINEL_SEVERITY.MEDIUM,
    runbook: 'rb-unapproved-tool',
    rationale: 'Unsanctioned data egress path; needs review, may be benign new tool.',
  },
  // PII pattern flag in telemetry metadata.
  pii_pattern_detected: {
    severity: SENTINEL_SEVERITY.MEDIUM,
    runbook: 'rb-pii-exposure',
    rationale: 'Possible personal-data egress; EU/works-council sensitivity.',
  },
  // AI tool used against a restricted repository. Engine severity is
  // critical; Sentinel tops out at High.
  restricted_repo_access: {
    severity: SENTINEL_SEVERITY.HIGH,
    runbook: 'rb-restricted-repo',
    rationale: 'Secrets-heavy or regulated repo exposed to an AI tool.',
  },
  // Sanctioned tool talking to an unapproved provider/model. Same triage path
  // as an unapproved tool: unsanctioned egress, may be benign.
  unapproved_provider_or_model: {
    severity: SENTINEL_SEVERITY.MEDIUM,
    runbook: 'rb-unapproved-tool',
    rationale: 'Unsanctioned data egress path; needs review, may be benign config drift.',
  },
  // Usage anomaly (volume spike, off-hours burst, new model/host for user).
  usage_anomaly: {
    severity: SENTINEL_SEVERITY.LOW,
    runbook: 'rb-usage-anomaly',
    rationale: 'Weak signal; correlate before escalating.',
  },
  // Explicit policy violation once enforce-mode policies exist.
  policy_violation: {
    severity: SENTINEL_SEVERITY.HIGH,
    runbook: 'rb-policy-violation',
    rationale: 'Deliberate or negligent breach of an approved policy.',
  },
  // Per-tool-call rail: shell/command-execution tool used against a
  // restricted repository. Same triage path as restricted_repo_access.
  shell_tool_restricted_repo: {
    severity: SENTINEL_SEVERITY.HIGH,
    runbook: 'rb-restricted-repo',
    rationale: 'Autonomous command execution inside a secrets-heavy or regulated repo.',
  },
  // Per-tool-call rail: network-egress tool (web fetch/search)
  // against a restricted repository — possible data movement, lower confidence.
  network_tool_restricted_repo: {
    severity: SENTINEL_SEVERITY.MEDIUM,
    runbook: 'rb-restricted-repo',
    rationale: 'Possible data egress from a restricted repo; may be benign research.',
  },
  // Per-tool-call rail: an MCP server outside the approved list is
  // present in an AI tool's configuration (inventory event). Intent-to-use,
  // not observed traffic — same triage path as an unapproved tool.
  unapproved_mcp_server_configured: {
    severity: SENTINEL_SEVERITY.MEDIUM,
    runbook: 'rb-unapproved-tool',
    rationale: 'Unsanctioned MCP egress path configured; needs review, may be benign.',
  },
  // Collector/pipeline health events surfaced as findings (self-monitoring).
  telemetry_gap: {
    severity: SENTINEL_SEVERITY.INFORMATIONAL,
    runbook: 'rb-telemetry-gap',
    rationale: 'Visibility loss; not a user-security event.',
  },
  // team token/cost budget threshold (80% warn / 100% critical).
  // Cost figures are estimates — see docs/cost-attribution-accuracy.md.
  team_budget_threshold: {
    severity: SENTINEL_SEVERITY.MEDIUM,
    runbook: 'rb-usage-anomaly',
    rationale: 'Team AI spend or token volume crossed a configured budget threshold.',
  },
  // model/provider not on the scoped allowlist.
  model_provider_not_permitted: {
    severity: SENTINEL_SEVERITY.MEDIUM,
    runbook: 'rb-unapproved-tool',
    rationale: 'Model or provider outside the allowlist for the event scope.',
  },
  // tool_calls[] tool_name looks credential-shaped (metadata only).
  credential_shaped_tool_call: {
    severity: SENTINEL_SEVERITY.HIGH,
    runbook: 'rb-secret-exposure',
    rationale: 'Agent invoked a credential-shaped tool name; review before enforce.',
  },
  // high network tool volume against one repo.
  high_volume_repo_egress: {
    severity: SENTINEL_SEVERITY.HIGH,
    runbook: 'rb-usage-anomaly',
    rationale: 'Bulk network-class tool use against one repository (egress proxy).',
  },
  // bulk shell tool activity per user/hour.
  bulk_shell_hourly: {
    severity: SENTINEL_SEVERITY.MEDIUM,
    runbook: 'rb-usage-anomaly',
    rationale: 'Unattended agent loops or bulk shell automation.',
  },
  // high token volume against one repository.
  high_volume_repo_tokens: {
    severity: SENTINEL_SEVERITY.MEDIUM,
    runbook: 'rb-usage-anomaly',
    rationale: 'Bulk codebase ingest or large responses against one repo.',
  },
  // App-LLM phase-1 new-source signal: first-ever proxy provider-API
  // call from a host_ref. Shadow-AI-in-built-software triage path.
  app_llm_new_source: {
    severity: SENTINEL_SEVERITY.MEDIUM,
    runbook: 'rb-app-llm-new-source',
    rationale:
      'A source made its first-ever call to a direct LLM provider API; may be sanctioned app rollout or shadow AI.',
  },
  // provider catalogue completeness — provider string not in
  // endpoints.json (all rule providers). Catalogue-ops, not user security.
  app_llm_new_provider: {
    severity: SENTINEL_SEVERITY.LOW,
    runbook: 'rb-app-llm-catalogue-drift',
    rationale:
      'First-ever observation of a provider id outside the domain catalogue; add a rule or accept as residual.',
  },
  // model catalogue completeness — model id not in PRICE_PER_MTOK.
  app_llm_new_model: {
    severity: SENTINEL_SEVERITY.LOW,
    runbook: 'rb-app-llm-catalogue-drift',
    rationale:
      'First-ever observation of a model id outside the list-price table; cost falls back to DEFAULT until priced.',
  },
};

const FALLBACK: TaxonomyEntry = {
  severity: SENTINEL_SEVERITY.LOW,
  runbook: 'rb-unknown-finding',
  rationale: 'Unclassified finding type; default low until triaged.',
};

/**
 * Engine rule ids (kebab-case, policies/guardrail/v1/core.yaml) -> taxonomy
 * finding types (snake_case), so findings carrying the rule id classify onto
 * the same taxonomy. Port of RULE_ID_ALIASES in
 * services/guardrail/src/guardrail/notify.py — keep in sync.
 */
export const RULE_ID_ALIASES: Record<string, string> = {
  'secret-pattern-in-prompt': 'secret_pattern_detected',
  'unapproved-tool': 'unapproved_tool_detected',
  'unapproved-provider-or-model': 'unapproved_provider_or_model',
  'restricted-repo-access': 'restricted_repo_access',
  'pii-in-prompt': 'pii_pattern_detected',
  // MCP call to an unapproved server classifies as a generic policy
  // violation — a dedicated finding type would be a taxonomy change.
  'unapproved-mcp-server': 'policy_violation',
  // prompt-injection detector fired — generic policy violation, same
  // rationale as unapproved-mcp-server (a dedicated type is Security's call).
  'injection-attempt-in-prompt': 'policy_violation',
  // per-tool-call rail: dedicated finding types (see TAXONOMY).
  'shell-tool-restricted-repo': 'shell_tool_restricted_repo',
  'network-tool-restricted-repo': 'network_tool_restricted_repo',
  'unapproved-mcp-server-configured': 'unapproved_mcp_server_configured',
// MCP tool-name allowlist (was mapped in notify.py, missing here — breaks unit tests on main).
  'unapproved-mcp-tool': 'policy_violation',
  'anomalous-volume-hourly': 'usage_anomaly',
  'off-hours-bulk-usage': 'usage_anomaly',
  // model/cost governance.
  'model-provider-not-permitted': 'model_provider_not_permitted',
  'team-budget-tokens-warn': 'team_budget_threshold',
  'team-budget-tokens-critical': 'team_budget_threshold',
  'team-budget-cost-warn': 'team_budget_threshold',
  'team-budget-cost-critical': 'team_budget_threshold',
  // expanded detection depth.
  'credential-shaped-tool-call': 'credential_shaped_tool_call',
  'high-volume-repo-egress': 'high_volume_repo_egress',
  'bulk-shell-hourly': 'bulk_shell_hourly',
  'high-volume-repo-tokens': 'high_volume_repo_tokens',
  // App-LLM new-sources → SOC.
  'app-llm-new-source': 'app_llm_new_source',
  // catalogue completeness / drift.
  'app-llm-new-provider': 'app_llm_new_provider',
  'app-llm-new-model': 'app_llm_new_model',
};

/**
 * Resolve a finding to its taxonomy entry. Accepts either a taxonomy finding
 * type or an engine rule id (resolved via RULE_ID_ALIASES). Unknown types fall
 * back loudly (callers should log the unknown type so the taxonomy can be
 * extended).
 */
export function classifyFinding(findingType: string): Classification {
  const entry = TAXONOMY[RULE_ID_ALIASES[findingType] ?? findingType];
  if (entry) return { ...entry, known: true };
  return { ...FALLBACK, known: false };
}

/** CEF numeric severity for a Sentinel severity label. */
export function cefSeverity(sentinelSeverity: SentinelSeverity): number {
  return CEF_SEVERITY[sentinelSeverity] ?? CEF_SEVERITY.Low;
}

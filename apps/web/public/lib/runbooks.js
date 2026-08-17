/**
 * AIM-703 — SOC runbook catalog for every alert class.
 *
 * Source of truth for in-app deep links (`#/runbooks/<slug>`). Slugs match
 * packages/alerting/src/severity.ts so Sentinel/webhook `RunbookUrl` values
 * land on the same pages when RUNBOOK_BASE_URL points at this dashboard
 * (`https://<host>/#/runbooks/`).
 *
 * Every taxonomy finding type and every engine rule id (RULE_ID_ALIASES) must
 * resolve to a catalog entry with body content. Unmapped live rules from
 * GET /api/guardrail/rules surface as gaps — never silent 404s.
 */

/** @typedef {{ title: string, summary: string, severity: string, when: string, steps: string[], relatedRules: string[], relatedFindingTypes: string[] }} Runbook */

/**
 * Stable runbook pages. Keys are the taxonomy `runbook` slugs.
 * @type {Record<string, Runbook>}
 */
export const RUNBOOKS = {
  'rb-secret-exposure': {
    title: 'Secret / credential exposure',
    summary:
      'A detector saw a credential-shaped pattern (or a credential-shaped tool name) in AI tool traffic. Matched content is never collected — only pattern id / metadata.',
    severity: 'high',
    when: 'secret_pattern_detected, credential_shaped_tool_call (and engine rules secret-pattern-in-prompt, credential-shaped-tool-call).',
    steps: [
      'Confirm the finding is not a known fixture / synthetic fingerprint (cluster A). If it is, resolve as false_positive with a note.',
      'Identify the subject (user_ref / host_ref / repo_ref) and the AI tool + session window from the finding detail.',
      'Assume the secret may already be live: open the credential rotation path for the pattern family (AWS key, GitHub token, private key, etc.). Prefer rotate-then-investigate.',
      'After rotation, check hygiene / secret scanners for residual use of the old credential.',
      'Interview or async-notify the engineer: was this intentional (fixture, docs example) or accidental paste into a prompt?',
      'If intentional and sanctioned, document and resolve; if not, open a security case and watch for repeat hits on the same subject.',
      'Never request or render the raw secret value in this product — metadata-only policy holds.',
    ],
    relatedRules: ['secret-pattern-in-prompt', 'credential-shaped-tool-call'],
    relatedFindingTypes: ['secret_pattern_detected', 'credential_shaped_tool_call'],
  },
  'rb-unapproved-tool': {
    title: 'Unapproved tool, provider, model, or MCP path',
    summary:
      'Traffic or configuration left the sanctioned allowlist: an unsanctioned AI coding tool, provider/model, or MCP server. Often benign first use — still needs a decision.',
    severity: 'medium',
    when: 'unapproved_tool_detected, unapproved_provider_or_model, model_provider_not_permitted, unapproved_mcp_server_configured (and matching engine rules).',
    steps: [
      'Read the finding: tool / provider / model / MCP server name and the subject (user, host, team if attributed).',
      'Check whether the item is already under review (pending allowlist PR) or is a known pilot exception.',
      'If the tool/provider is new but acceptable: file or link the allowlist change (policy PR on policies/guardrail/v1) and acknowledge the finding.',
      'If the path is not acceptable: notify the engineer and their manager; set an expectation to stop use. Escalate if it continues after notice.',
      'For MCP servers: verify scope (user vs project vs global config) and whether any restricted repos are in play.',
      'Close only when the allowlist is updated or the subject has stopped using the path — do not leave open "ack forever" without a decision.',
    ],
    relatedRules: [
      'unapproved-tool',
      'unapproved-provider-or-model',
      'model-provider-not-permitted',
      'unapproved-mcp-server-configured',
    ],
    relatedFindingTypes: [
      'unapproved_tool_detected',
      'unapproved_provider_or_model',
      'model_provider_not_permitted',
      'unapproved_mcp_server_configured',
    ],
  },
  'rb-pii-exposure': {
    title: 'PII-like pattern in AI traffic',
    summary:
      'A detector flagged personal-data-shaped content in prompt/telemetry metadata. High EU / works-council sensitivity — minimize further collection.',
    severity: 'medium',
    when: 'pii_pattern_detected (engine rule pii-in-prompt).',
    steps: [
      'Do not attempt to recover or display the matched content — only the detector label and subject metadata are available by design.',
      'Note the detector category, tool, subject, and time window.',
      'Check whether the subject is in a regulated region or role (if HR/geo signals exist outside this product); escalate to Privacy when required by policy.',
      'Ask the engineer (async) what they were doing — common false positives: synthetic test data, public docs, ticket numbers that look like national IDs.',
      'If genuine PII egress risk: document, involve Privacy/Legal per company procedure, and watch for recurrence.',
      'Resolve with a clear note (benign vs referred-to-Privacy). Do not store free-text that reintroduces the PII into the audit trail.',
    ],
    relatedRules: ['pii-in-prompt'],
    relatedFindingTypes: ['pii_pattern_detected'],
  },
  'rb-restricted-repo': {
    title: 'AI tool activity on a restricted repository',
    summary:
      'An AI coding tool (or shell/network tool-call class) operated against a secrets-heavy or regulated repository on the restricted list.',
    severity: 'high',
    when: 'restricted_repo_access, shell_tool_restricted_repo, network_tool_restricted_repo (and matching engine rules).',
    steps: [
      'Confirm the repo_ref is still on the restricted list (policy settings) and identify the tool + action class (chat vs shell vs network).',
      'Treat shell-class tool use as higher urgency than chat-only — autonomous command execution inside a regulated tree.',
      'Identify the engineer and whether they have an approved exception for that repo (break-glass / time-bound grant).',
      'If no exception: stop-the-line with the engineer and their manager; confirm no secrets left the boundary via other channels if shell/network fired.',
      'If endpoint enforcement is on for this rule, check usage events for enforcement.action (blocked / would_block / confirmed) — do not treat 100% observe findings alone as "enforcement off".',
      'Document outcome; open a security case when shell/network + restricted repo coincide without an exception.',
    ],
    relatedRules: [
      'restricted-repo-access',
      'shell-tool-restricted-repo',
      'network-tool-restricted-repo',
    ],
    relatedFindingTypes: [
      'restricted_repo_access',
      'shell_tool_restricted_repo',
      'network_tool_restricted_repo',
    ],
  },
  'rb-usage-anomaly': {
    title: 'Usage anomaly / volume / budget signal',
    summary:
      'Weak-to-medium signal: volume spikes, off-hours bulk use, high egress/token volume, or team budget thresholds. Correlate before treating as an incident.',
    severity: 'low',
    when: 'usage_anomaly, team_budget_threshold, high_volume_repo_egress, bulk_shell_hourly, high_volume_repo_tokens (and matching threshold rules).',
    steps: [
      'Pull the subject’s recent activity (user timeline / team view) for the same window — is this a known deadline, migration, or CI job?',
      'For team budget thresholds: confirm the estimate accuracy note (cost figures are estimates) and notify the team owner; do not page on-call for budget alone unless policy says otherwise.',
      'For bulk shell / high network egress against one repo: check restricted-repo status and whether an unattended agent loop is running.',
      'Correlate with other open findings on the same subject (secrets, unapproved tools). Anomaly + secret is the real combo.',
      'If benign (load test, batch job): acknowledge with a note. If unexplained after correlation: escalate severity mentally and dig with the engineer.',
      'Do not auto-block based on this class under observe-only posture.',
    ],
    relatedRules: [
      'anomalous-volume-hourly',
      'off-hours-bulk-usage',
      'team-budget-tokens-warn',
      'team-budget-tokens-critical',
      'team-budget-cost-warn',
      'team-budget-cost-critical',
      'high-volume-repo-egress',
      'bulk-shell-hourly',
      'high-volume-repo-tokens',
    ],
    relatedFindingTypes: [
      'usage_anomaly',
      'team_budget_threshold',
      'high_volume_repo_egress',
      'bulk_shell_hourly',
      'high_volume_repo_tokens',
    ],
  },
  'rb-policy-violation': {
    title: 'Policy violation (generic)',
    summary:
      'Catch-all for deliberate or high-confidence policy breaches that do not yet have a dedicated finding type (e.g. unapproved MCP call, prompt-injection detector).',
    severity: 'high',
    when: 'policy_violation (engine rules unapproved-mcp-server, injection-attempt-in-prompt, and future enforce-mode violations).',
    steps: [
      'Read the rule id and condition text carefully — this class spans MCP allowlist hits and injection detectors.',
      'For unapproved MCP call traffic: confirm the server is still unlisted; check whether the call was exploratory or production-critical.',
      'For injection / jailbreak phrasing: treat as a signal that someone (or content) tried to subvert the tool — correlate with restricted repos and secrets findings.',
      'Notify the subject’s manager when the hit is high-confidence and not a false positive from public adversarial examples.',
      'If enforce-mode policies are active for this rule, verify endpoint decision telemetry; otherwise stay in observe-and-document mode.',
      'Prefer promoting repeated, well-understood hits into a dedicated taxonomy type (Security approval) rather than living forever under this catch-all.',
    ],
    relatedRules: ['unapproved-mcp-server', 'injection-attempt-in-prompt'],
    relatedFindingTypes: ['policy_violation'],
  },
  'rb-telemetry-gap': {
    title: 'Telemetry / coverage gap',
    summary:
      'Collector or pipeline visibility loss. Not a user-security event — fix coverage so real alerts can be trusted again.',
    severity: 'informational',
    when: 'telemetry_gap and coverage/fleet health alerts that map here.',
    steps: [
      'Open Coverage & Trust and Fleet: which hosts or tools went dark, and since when?',
      'Check pipeline liveness and ingest auth (token expiry, collector version skew).',
      'If a single host: re-enroll or restart the collector; if a whole site: escalate to platform on-call.',
      'Do not treat a quiet Findings inbox as clean while coverage is red — silent hosts hide real incidents.',
      'After recovery, note the gap window in the case/ticket so SOC knows detection was incomplete for that period.',
      'Resolve the finding when coverage returns; leave a note with duration and root cause class (auth, crash, network, unenrolled).',
    ],
    relatedRules: [],
    relatedFindingTypes: ['telemetry_gap'],
  },
  // AIM-575 / taxonomy: first-ever proxy provider-API call from a host_ref.
  'rb-app-llm-new-source': {
    title: 'New application-LLM source',
    summary:
      'A host or service made its first-ever call to a direct LLM provider API (OpenAI, Anthropic, OpenRouter, etc.) via the corporate proxy. May be a sanctioned app rollout or shadow AI in built software.',
    severity: 'medium',
    when: 'app_llm_new_source (App-LLM phase-1 new-source signal).',
    steps: [
      'Open App-LLM / new-sources and identify host_ref, provider class, and first-seen window.',
      'Check whether the source is a known sanctioned application rollout (inventory, deploy ticket, owner team).',
      'If sanctioned: document the owner and expected traffic shape; acknowledge the finding so the first-seen alert does not recur as noise.',
      'If unknown or personal tooling: treat as shadow AI — notify the host owner / manager and decide allowlist vs stop-use.',
      'Correlate with unapproved-tool / unapproved-provider findings on the same subject; first-seen + unsanctioned is higher urgency.',
      'Close only after a clear decision (allowlisted app vs stopped) is recorded — do not leave perpetual open first-seen alerts.',
    ],
    relatedRules: [],
    relatedFindingTypes: ['app_llm_new_source'],
  },
  // AIM-738: provider/model catalogue completeness (taxonomy app_llm_new_provider / app_llm_new_model).
  'rb-app-llm-catalogue-drift': {
    title: 'Application-LLM catalogue drift',
    summary:
      'A provider id or model id was observed that is not in the domain catalogue / list-price table. Catalogue-ops signal, not a user-security breach — still needs an owner decision (add rule, price model, or accept residual).',
    severity: 'low',
    when: 'app_llm_new_provider or app_llm_new_model (catalogue completeness).',
    steps: [
      'Open App-LLM catalogue drift and identify the unknown provider id and/or model id, host_ref, and first-seen window.',
      'Confirm the string is a real provider/model (not a typo, test harness, or spoofed User-Agent).',
      'If legitimate and in-scope: add an endpoints.json / PRICE_PER_MTOK entry (or accept residual with an explicit note) so cost and allowlisting stay honest.',
      'If out of policy: treat as shadow AI / unapproved provider — notify the owner and decide allowlist vs stop-use.',
      'Close only after catalogue update, residual acceptance, or stop-use is recorded.',
    ],
    relatedRules: [],
    relatedFindingTypes: ['app_llm_new_provider', 'app_llm_new_model'],
  },
  'rb-unknown-finding': {
    title: 'Unclassified finding type',
    summary:
      'Fallback when a finding type or rule id is not in the severity taxonomy. Default low severity until triaged — and the taxonomy must be extended.',
    severity: 'low',
    when: 'Any finding type or rule id missing from packages/alerting TAXONOMY / RULE_ID_ALIASES.',
    steps: [
      'Treat as unknown, not benign: open the raw finding (rule id, evidence keys) and classify manually for this instance.',
      'File an engineering follow-up to add the type to the taxonomy (severity.ts + this runbook map) so the next hit does not fall through.',
      'Until the taxonomy is updated, route severity by engineering judgment and document the interim decision in the triage note.',
      'If the payload looks secret- or restricted-repo-shaped, upgrade urgency even though the automated severity is Low.',
      'Do not silence the fallback — unknown volume is a product defect, not an analyst nuisance.',
    ],
    relatedRules: [],
    relatedFindingTypes: [],
  },
};

/**
 * Engine rule ids (kebab-case) → runbook slug.
 * Keep in sync with packages/alerting/src/severity.ts RULE_ID_ALIASES + TAXONOMY.
 * @type {Record<string, string>}
 */
export const RULE_RUNBOOKS = {
  'secret-pattern-in-prompt': 'rb-secret-exposure',
  'unapproved-tool': 'rb-unapproved-tool',
  'unapproved-provider-or-model': 'rb-unapproved-tool',
  'restricted-repo-access': 'rb-restricted-repo',
  'pii-in-prompt': 'rb-pii-exposure',
  'unapproved-mcp-server': 'rb-policy-violation',
  'injection-attempt-in-prompt': 'rb-policy-violation',
  'shell-tool-restricted-repo': 'rb-restricted-repo',
  'network-tool-restricted-repo': 'rb-restricted-repo',
  'unapproved-mcp-server-configured': 'rb-unapproved-tool',
  'anomalous-volume-hourly': 'rb-usage-anomaly',
  'off-hours-bulk-usage': 'rb-usage-anomaly',
  'model-provider-not-permitted': 'rb-unapproved-tool',
  'team-budget-tokens-warn': 'rb-usage-anomaly',
  'team-budget-tokens-critical': 'rb-usage-anomaly',
  'team-budget-cost-warn': 'rb-usage-anomaly',
  'team-budget-cost-critical': 'rb-usage-anomaly',
  'credential-shaped-tool-call': 'rb-secret-exposure',
  'high-volume-repo-egress': 'rb-usage-anomaly',
  'bulk-shell-hourly': 'rb-usage-anomaly',
  'high-volume-repo-tokens': 'rb-usage-anomaly',
};

/**
 * Taxonomy finding types (snake_case) → runbook slug.
 * @type {Record<string, string>}
 */
export const FINDING_TYPE_RUNBOOKS = {
  secret_pattern_detected: 'rb-secret-exposure',
  unapproved_tool_detected: 'rb-unapproved-tool',
  pii_pattern_detected: 'rb-pii-exposure',
  restricted_repo_access: 'rb-restricted-repo',
  unapproved_provider_or_model: 'rb-unapproved-tool',
  usage_anomaly: 'rb-usage-anomaly',
  policy_violation: 'rb-policy-violation',
  shell_tool_restricted_repo: 'rb-restricted-repo',
  network_tool_restricted_repo: 'rb-restricted-repo',
  unapproved_mcp_server_configured: 'rb-unapproved-tool',
  telemetry_gap: 'rb-telemetry-gap',
  team_budget_threshold: 'rb-usage-anomaly',
  model_provider_not_permitted: 'rb-unapproved-tool',
  app_llm_new_source: 'rb-app-llm-new-source',
  app_llm_new_provider: 'rb-app-llm-catalogue-drift',
  app_llm_new_model: 'rb-app-llm-catalogue-drift',
  credential_shaped_tool_call: 'rb-secret-exposure',
  high_volume_repo_egress: 'rb-usage-anomaly',
  bulk_shell_hourly: 'rb-usage-anomaly',
  high_volume_repo_tokens: 'rb-usage-anomaly',
};

export const FALLBACK_RUNBOOK = 'rb-unknown-finding';

/** Shareable hash for a runbook slug (or index when slug is empty). */
export function runbookHash(slug = null) {
  if (!slug) return '#/runbooks';
  return `#/runbooks/${encodeURIComponent(slug)}`;
}

/**
 * Resolve a rule id or finding type to a catalog entry.
 * @param {string | null | undefined} key
 * @returns {{ slug: string, runbook: Runbook, known: boolean, key: string | null }}
 */
export function resolveRunbook(key) {
  const raw = typeof key === 'string' ? key.trim() : '';
  if (!raw) {
    return { slug: FALLBACK_RUNBOOK, runbook: RUNBOOKS[FALLBACK_RUNBOOK], known: false, key: null };
  }
  // Direct slug.
  if (RUNBOOKS[raw]) {
    return { slug: raw, runbook: RUNBOOKS[raw], known: true, key: raw };
  }
  const slug =
    RULE_RUNBOOKS[raw] ||
    FINDING_TYPE_RUNBOOKS[raw] ||
    // Tolerate accidental snake/kebab swap on rule ids.
    RULE_RUNBOOKS[raw.replaceAll('_', '-')] ||
    FINDING_TYPE_RUNBOOKS[raw.replaceAll('-', '_')] ||
    null;
  if (slug && RUNBOOKS[slug]) {
    return { slug, runbook: RUNBOOKS[slug], known: true, key: raw };
  }
  return { slug: FALLBACK_RUNBOOK, runbook: RUNBOOKS[FALLBACK_RUNBOOK], known: false, key: raw };
}

/** True when the catalog has a real (non-fallback) page for this key. */
export function hasRunbook(key) {
  const r = resolveRunbook(key);
  return r.known && r.slug !== FALLBACK_RUNBOOK;
}

/**
 * Catalog integrity + optional live-rule gaps.
 * @param {string[] | null} [liveRuleIds] rule ids from GET /api/guardrail/rules
 * @returns {{ catalogGaps: Array<{kind:string,id:string,detail:string}>, liveGaps: Array<{kind:string,id:string,detail:string}>, ok: boolean }}
 */
export function listRunbookGaps(liveRuleIds = null) {
  const catalogGaps = [];
  for (const [slug, rb] of Object.entries(RUNBOOKS)) {
    if (!rb?.title || !Array.isArray(rb.steps) || rb.steps.length === 0) {
      catalogGaps.push({
        kind: 'empty_runbook',
        id: slug,
        detail: 'Runbook page exists but has no triage steps',
      });
    }
  }
  for (const [ruleId, slug] of Object.entries(RULE_RUNBOOKS)) {
    if (!RUNBOOKS[slug]) {
      catalogGaps.push({
        kind: 'missing_page',
        id: ruleId,
        detail: `Rule maps to missing slug ${slug}`,
      });
    }
  }
  for (const [ft, slug] of Object.entries(FINDING_TYPE_RUNBOOKS)) {
    if (!RUNBOOKS[slug]) {
      catalogGaps.push({
        kind: 'missing_page',
        id: ft,
        detail: `Finding type maps to missing slug ${slug}`,
      });
    }
  }
  // Every taxonomy finding type should appear in FINDING_TYPE_RUNBOOKS — checked
  // by unit tests against the exported map; liveGaps cover production rules.

  const liveGaps = [];
  if (Array.isArray(liveRuleIds)) {
    for (const id of liveRuleIds) {
      if (typeof id !== 'string' || !id) continue;
      if (!RULE_RUNBOOKS[id] && !RUNBOOKS[id]) {
        liveGaps.push({
          kind: 'unmapped_rule',
          id,
          detail: 'Live guardrail rule has no runbook mapping — falls back to rb-unknown-finding',
        });
      }
    }
  }
  return {
    catalogGaps,
    liveGaps,
    ok: catalogGaps.length === 0 && liveGaps.length === 0,
  };
}

/** All catalog entries as a stable sorted list for index rendering. */
export function listRunbooks() {
  return Object.entries(RUNBOOKS)
    .map(([slug, runbook]) => ({ slug, ...runbook }))
    .sort((a, b) => a.slug.localeCompare(b.slug));
}

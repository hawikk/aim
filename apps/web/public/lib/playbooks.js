/* — guided investigation playbooks for common detections.
 *
 * Pure content + HTML helpers (DOM-free except optional esc). findings.js and
 * rules.js import this; node:test covers catalog completeness without a browser.
 *
 * Design rules:
 *  - Metadata-only. Never instruct the analyst to read prompt content — the
 *    product never stores it, and playbooks must not invent a path to it.
 *  - One playbook can cover several rule ids that share a triage path.
 *  - Steps are numbered, checkable, and self-contained: title + what to do +
 *    where to look. Disposition hints sit after the steps, not instead of them.
 *  - External wiki runbook slugs (rb-*) align with packages/alerting taxonomy
 * so deep-links and in-product playbooks stay consistent.
 */

import { esc } from '../lib/dom.js';

import { severityBadge } from '../lib/severity.js';

/**
 * @typedef {{ id: string, title: string, body: string, where?: string }} PlaybookStep
 * @typedef {{
 *   id: string,
 *   ruleIds: string[],
 *   title: string,
 *   severity: 'critical'|'high'|'medium'|'low',
 *   summary: string,
 *   timeEstimate: string,
 *   steps: PlaybookStep[],
 *   disposition: { resolve: string, falsePositive: string, escalate?: string },
 *   relatedViews?: { href: string, label: string }[],
 *   runbookSlug: string,
 * }} Playbook
 */

/** @type {Playbook[]} */
export const PLAYBOOKS = [
  {
    id: 'secret-exposure',
    ruleIds: ['secret-pattern-in-prompt', 'credential-shaped-tool-call'],
    title: 'Secret / credential exposure',
    severity: 'critical',
    summary:
      'A secret-shaped pattern or credential-named tool call was observed in AI traffic. Treat as rotate-then-investigate: assume the material may have left the endpoint until proven otherwise.',
    timeEstimate: '15–40 min',
    runbookSlug: 'rb-secret-exposure',
    relatedViews: [
      { href: '#/findings', label: 'Findings' },
      { href: '#/security', label: 'Security flags' },
      { href: '#/users', label: 'Users' },
    ],
    steps: [
      {
        id: 'ack',
        title: 'Acknowledge and claim the finding',
        body: 'Acknowledge so the SLA clock is owned. Note the detector name and any redacted fingerprints shown in evidence — fingerprints are the proof handle; matched content is never stored.',
      },
      {
        id: 'classify-fixture',
        title: 'Check for fixture / synthetic cluster',
        body: 'If a “cluster A · fixture” hint appears, this fingerprint matches the dead-key registry and is almost certainly synthetic. Confirm, document “fixture”, and close as false positive.',
        where: 'Finding detail → Fingerprints',
      },
      {
        id: 'scope',
        title: 'Map blast radius (user, host, tool, time)',
        body: 'Open the subject user timeline. Note tool, host_ref, and time window. Ask: one prompt, or a burst? Same secret fingerprint on other findings?',
        where: 'Finding → user timeline · Findings filtered by rule',
      },
      {
        id: 'rotate',
        title: 'Initiate credential rotation (if live)',
        body: 'If not a fixture: open an incident with the secret owner (or Security on-call). Rotate/revoke the credential class implied by the detector (API key, cloud key, token). Do not wait for full investigation to finish rotation when confidence is high.',
      },
      {
        id: 'tool-path',
        title: 'Confirm egress path',
        body: 'Check whether the tool is sanctioned and which provider/model was used. Unapproved tools or providers raise exfil confidence; sanctioned Claude Code/Cursor against corporate providers may still be a paste accident.',
        where: 'Security → Unapproved · Tools / Providers',
      },
      {
        id: 'close',
        title: 'Close with a durable note',
        body: 'Resolve with: what was rotated (or why not), fixture vs live decision, and any follow-up (policy tune, coaching). False-positive only for fixture/dead-key or proven non-secret pattern.',
      },
    ],
    disposition: {
      resolve:
        'Live or plausible secret: rotation completed (or documented owner accepted residual risk) and blast radius reviewed.',
      falsePositive:
        'Fingerprint matches fixture registry, or detector misclass with evidence that no secret material was present.',
      escalate: 'Multiple users/hosts with the same fingerprint, or restricted-repo co-occurrence → Security IR.',
    },
  },
  {
    id: 'restricted-repo',
    ruleIds: [
      'restricted-repo-access',
      'shell-tool-restricted-repo',
      'network-tool-restricted-repo',
    ],
    title: 'Restricted repository access',
    severity: 'critical',
    summary:
      'An AI tool touched a Security-listed restricted repository (secrets-heavy, regulated, or customer data). Findings carry only the repo pseudonym — never the cleartext name.',
    timeEstimate: '20–45 min',
    runbookSlug: 'rb-restricted-repo',
    relatedViews: [
      { href: '#/repos', label: 'Repos' },
      { href: '#/security', label: 'Security' },
      { href: '#/findings', label: 'Findings' },
    ],
    steps: [
      {
        id: 'ack',
        title: 'Acknowledge and freeze assumptions',
        body: 'Acknowledge immediately. Do not attempt to “decode” the repo_ref — use Security’s restricted-list map offline if you need the cleartext name.',
      },
      {
        id: 'activity',
        title: 'Characterize the activity class',
        body: 'Match rule: restricted-repo-access = any AI use; shell-tool = autonomous command execution; network-tool = possible egress. Shell and network raise urgency.',
        where: 'Finding → Rule id / Why it fired',
      },
      {
        id: 'user-context',
        title: 'Check whether access is expected',
        body: 'Open the user timeline. Is this engineer on the repo’s ACL? First time this week? Same host? Coordinate with eng manager before confronting the user when works-council rules apply.',
        where: 'Users → timeline',
      },
      {
        id: 'tool-scope',
        title: 'Inspect tool and MCP surface',
        body: 'Confirm tool, model, and any MCP servers in the same window. Unapproved MCP plus restricted repo is a high-priority combo.',
        where: 'MCP · Security flags',
      },
      {
        id: 'contain',
        title: 'Contain if unexpected',
        body: 'If access is unauthorized: suspend tool enrollment for the host if policy allows, revoke repo access via SCM, and open IR. If authorized: document business justification and consider allowlisting via policy PR only with Security sign-off.',
      },
      {
        id: 'close',
        title: 'Disposition',
        body: 'Resolve with authorization outcome + any containment. Do not mark false positive solely because the engineer is senior — restricted list is policy, not reputation.',
      },
    ],
    disposition: {
      resolve: 'Authorized use documented, or unauthorized use contained and IR opened.',
      falsePositive:
        'Only if restricted_repos / salt misconfiguration is proven (rule should be inert until configured — file an eng issue).',
      escalate: 'Shell or network tool on restricted repo without ACL → IR page.',
    },
  },
  {
    id: 'unapproved-tool',
    ruleIds: ['unapproved-tool'],
    title: 'Unapproved AI coding tool',
    severity: 'high',
    summary:
      'Traffic from a tool outside settings.approved_tools. Often benign discovery (new IDE plugin); still an unsanctioned data path until Security says otherwise.',
    timeEstimate: '10–25 min',
    runbookSlug: 'rb-unapproved-tool',
    relatedViews: [
      { href: '#/tools', label: 'Tools' },
      { href: '#/security', label: 'Security → Unapproved' },
      { href: '#/shadow-ai', label: 'Shadow AI' },
    ],
    steps: [
      {
        id: 'identify',
        title: 'Identify the tool',
        body: 'Read tool and tool_raw from the finding/evidence. Map volume: one engineer experimenting vs fleet-wide rollout.',
        where: 'Finding evidence · Security → Unapproved table',
      },
      {
        id: 'data-path',
        title: 'Assess data sensitivity',
        body: 'Check co-occurring findings (secrets, PII, restricted repos) for the same user/window. High volume + sensitive co-fire → escalate faster.',
      },
      {
        id: 'policy',
        title: 'Decide: sanction, coach, or block path',
        body: 'If the tool is acceptable: Security admin can Sanction from the Unapproved table (reason required, audit trail). If not: coach the user/team and leave unsanctioned; enforcement stays observe-only until policy flips.',
        where: 'Security → Unapproved → Sanction',
      },
      {
        id: 'close',
        title: 'Close the finding',
        body: 'Resolve after sanction or documented coaching. False positive only if collector mis-tagged a sanctioned tool name.',
      },
    ],
    disposition: {
      resolve: 'Tool sanctioned with reason, or user coached and usage stopped / accepted risk recorded.',
      falsePositive: 'Misattribution of a sanctioned tool identity.',
    },
  },
  {
    id: 'unapproved-provider',
    ruleIds: ['unapproved-provider-or-model', 'model-provider-not-permitted'],
    title: 'Unapproved provider or model',
    severity: 'high',
    summary:
      'A (possibly sanctioned) tool is talking to a provider/model outside the approved matrix — personal API keys, third-party relays, or out-of-scope models.',
    timeEstimate: '15–30 min',
    runbookSlug: 'rb-unapproved-tool',
    relatedViews: [
      { href: '#/providers', label: 'Providers' },
      { href: '#/app-llm', label: 'App LLM' },
      { href: '#/security', label: 'Security' },
    ],
    steps: [
      {
        id: 'provider',
        title: 'Name the provider / model',
        body: 'From evidence and Providers/App-LLM views, identify the destination. Note whether this is endpoint tool traffic or application LLM (OTel / proxy).',
        where: 'Providers · App LLM',
      },
      {
        id: 'path',
        title: 'Determine if personal key or config drift',
        body: 'Personal API keys and consumer endpoints are higher risk than a team mis-set model allowlist. Check whether the same user hits approved providers too.',
      },
      {
        id: 'remediate',
        title: 'Remediate',
        body: 'Coach rotation off the personal key; or open a policy PR to expand approved_providers / approved_models if the business case is real. Do not silently widen allowlists from the UI.',
        where: 'Rules → settings (read-only) · policy PR',
      },
      {
        id: 'close',
        title: 'Disposition',
        body: 'Resolve when traffic stops or the allowlist change is merged and verified. False positive only for provider attribution bugs.',
      },
    ],
    disposition: {
      resolve: 'Egress moved to approved provider/model, or policy updated via PR with Security sign-off.',
      falsePositive: 'Provider field mis-attributed with corroborating evidence.',
    },
  },
  {
    id: 'unapproved-mcp',
    ruleIds: ['unapproved-mcp-server', 'unapproved-mcp-server-configured'],
    title: 'Unapproved MCP server',
    severity: 'high',
    summary:
      'An MCP server was called or configured outside approved_mcp_servers. Empty allowlist + deny-unlisted means discovery is closed — every server is unapproved until Security lists it.',
    timeEstimate: '15–35 min',
    runbookSlug: 'rb-unapproved-tool',
    relatedViews: [
      { href: '#/mcp', label: 'MCP inventory' },
      { href: '#/security', label: 'Security' },
      { href: '#/rules', label: 'Rules' },
    ],
    steps: [
      {
        id: 'inventory',
        title: 'Locate the server in MCP inventory',
        body: 'Open MCP view: configured vs discovered, call counts, tools exposed. Note whether this finding is “configured” (intent) or “called” (observed traffic).',
        where: 'MCP',
      },
      {
        id: 'risk',
        title: 'Assess capability risk',
        body: 'Servers that expose shell, network, or credential-adjacent tools are higher risk. Cross-check restricted-repo and secret findings for the same user.',
      },
      {
        id: 'decide',
        title: 'Allowlist or remove',
        body: 'If business-justified: Security adds the server via policy-as-code PR (approved_mcp_servers). If not: have the engineer remove the server from the tool config; leave deny-unlisted in place.',
        where: 'Rules · policy PR',
      },
      {
        id: 'close',
        title: 'Disposition',
        body: 'Resolve after removal or allowlist merge. Do not false-positive “because everyone uses it” without an allowlist entry.',
      },
    ],
    disposition: {
      resolve: 'Server removed from endpoints, or added to approved_mcp_servers via reviewed PR.',
      falsePositive: 'Inventory false positive with proof the server was never configured or called.',
    },
  },
  {
    id: 'pii-exposure',
    ruleIds: ['pii-in-prompt'],
    title: 'PII pattern in AI traffic',
    severity: 'low',
    summary:
      'A pii:* detector fired on metadata only. Historically noisy (bare emails); treat as coaching + precision check, not automatic IR — unless co-occurring with secrets or restricted repos.',
    timeEstimate: '10–20 min',
    runbookSlug: 'rb-pii-exposure',
    relatedViews: [
      { href: '#/findings', label: 'Findings' },
      { href: '#/compliance', label: 'Compliance' },
    ],
    steps: [
      {
        id: 'context',
        title: 'Read severity and co-findings',
        body: 'pii-in-prompt is warning-tier (low). Check the same subject for secret or restricted-repo findings in the window — those upgrade the response.',
      },
      {
        id: 'pattern',
        title: 'Note detector class only',
        body: 'Evidence may name the detector class (e.g. email vs national-id). Never seek raw content. High-sensitivity classes deserve faster privacy review.',
      },
      {
        id: 'privacy',
        title: 'Apply privacy / works-council posture',
        body: 'For EU/works-council contexts: minimize personal scrutiny; prefer aggregate coaching to teams. Escalate to Privacy when structured identifiers (national ID, etc.) are indicated.',
      },
      {
        id: 'close',
        title: 'Disposition',
        body: 'Resolve with coaching note or privacy ticket. False positive when the hit is a known low-sensitivity class in a pure engineering context and policy accepts it — document the policy reference.',
      },
    ],
    disposition: {
      resolve: 'Coaching or privacy review completed; no high-sensitivity co-fire.',
      falsePositive: 'Known accepted class under current detector tuning policy, documented in the note.',
    },
  },
  {
    id: 'injection-attempt',
    ruleIds: ['injection-attempt-in-prompt'],
    title: 'Prompt-injection class signal',
    severity: 'medium',
    summary:
      'An injection:* detector fired. Prose-class detectors produce defensive-discussion false positives (engineers talking about jailbreaks). Confirm intent before escalating.',
    timeEstimate: '10–25 min',
    runbookSlug: 'rb-policy-violation',
    relatedViews: [
      { href: '#/findings', label: 'Findings' },
      { href: '#/security', label: 'Security flags' },
    ],
    steps: [
      {
        id: 'fp-screen',
        title: 'Screen for defensive / research discussion',
        body: 'Security engineers and red-team work will trip this. Check role/team and recent volume. Single low-impact hits from known security staff are often false positives.',
      },
      {
        id: 'correlate',
        title: 'Correlate with tool actions',
        body: 'Look for shell/network tool_calls, unapproved MCP, or restricted-repo access in the same session window — those turn a prose signal into a real attack path.',
        where: 'Security flags · user timeline',
      },
      {
        id: 'act',
        title: 'Act on high-confidence cases only',
        body: 'If correlated with autonomous tool use against sensitive assets: acknowledge, open IR, and contain. Otherwise coach and consider detector feedback to Eng.',
      },
      {
        id: 'close',
        title: 'Disposition',
        body: 'False positive for isolated defensive discussion. Resolve for real attempts with IR reference.',
      },
    ],
    disposition: {
      resolve: 'Confirmed attempt handled (IR or containment) or user coached after correlation.',
      falsePositive: 'Defensive discussion / training content with no correlated risky tool actions.',
    },
  },
  {
    id: 'usage-anomaly',
    ruleIds: [
      'anomalous-volume-hourly',
      'off-hours-bulk-usage',
      'high-volume-repo-egress',
      'bulk-shell-hourly',
      'high-volume-repo-tokens',
    ],
    title: 'Usage / volume anomaly',
    severity: 'medium',
    summary:
      'Threshold rules caught unusual volume (tokens, events, shell, or repo egress). Weak signal alone — always correlate before escalating. Off-hours bulk has works-council sensitivity.',
    timeEstimate: '15–30 min',
    runbookSlug: 'rb-usage-anomaly',
    relatedViews: [
      { href: '#/users', label: 'Users' },
      { href: '#/activity', label: 'Activity' },
      { href: '#/repos', label: 'Repos' },
      { href: '#/rules', label: 'Rules (thresholds)' },
    ],
    steps: [
      {
        id: 'baseline',
        title: 'Compare to the user’s baseline',
        body: 'Open the user timeline and team usage. Is this a build/agent loop day, a hackathon, or a true outlier vs the last 7 days?',
        where: 'Users · Activity · Teams',
      },
      {
        id: 'rule-class',
        title: 'Read which threshold fired',
        body: 'Token volume, event count, shell bulk, and repo egress imply different risks. Repo egress + restricted-repo co-fire is the dangerous pair.',
        where: 'Finding → Why it fired · Rules thresholds',
      },
      {
        id: 'off-hours',
        title: 'Handle off-hours carefully',
        body: 'For off-hours-bulk-usage: confirm local-hour semantics and avoid punitive framing. Prefer “unusual automation” language. Works-council guidance applies before broad alerting.',
      },
      {
        id: 'tune-or-act',
        title: 'Tune threshold or investigate further',
        body: 'Chronic false alarms: Security can tune threshold rules inline (Rules tab) with audit trail, or reset to policy default. Real exfil suspicion: escalate with correlated secret/repo findings.',
        where: 'Rules → Edit thresholds',
      },
      {
        id: 'close',
        title: 'Disposition',
        body: 'Resolve with “benign bulk / agent loop” + optional threshold tune, or escalate. False positive when the threshold itself is wrong for this environment.',
      },
    ],
    disposition: {
      resolve: 'Explained by known workload, or investigation found no sensitive co-fire.',
      falsePositive: 'Threshold mis-tuned for fleet norms; tune documented.',
      escalate: 'Volume + secret/restricted-repo/MCP co-fire → IR.',
    },
  },
];

/** ruleId → playbook (first match wins; catalog is unique per rule). */
const BY_RULE = new Map();
for (const pb of PLAYBOOKS) {
  for (const rid of pb.ruleIds) {
    if (BY_RULE.has(rid)) {
      throw new Error(`playbooks: rule id "${rid}" claimed by both ${BY_RULE.get(rid).id} and ${pb.id}`);
    }
    BY_RULE.set(rid, pb);
  }
}

/* Fixture / legacy aliases — same playbook as the canonical engine rule id. */
const RULE_ALIASES = {
  'secret-in-prompt': 'secret-pattern-in-prompt',
};
for (const [alias, canon] of Object.entries(RULE_ALIASES)) {
  const pb = BY_RULE.get(canon);
  if (pb) BY_RULE.set(alias, pb);
}

/** @returns {Playbook | null} */
export function playbookForRule(ruleId) {
  if (!ruleId) return null;
  return BY_RULE.get(String(ruleId)) ?? null;
}

/** Sorted unique rule ids with a guided playbook. */
export function coveredRuleIds() {
  return [...BY_RULE.keys()].sort();
}

/** Count of distinct playbooks (the “top N”). */
export function playbookCount() {
  return PLAYBOOKS.length;
}

/**
 * Session-local step completion key. Scoped by finding when available so two
 * open investigations do not share ticks.
 * @param {string} playbookId
 * @param {string} [scopeId]
 */
export function storageKey(playbookId, scopeId) {
  return `aim-playbook:${playbookId}:${scopeId || 'global'}`;
}

/**
 * @param {string} playbookId
 * @param {string} [scopeId]
 * @returns {Set<string>}
 */
export function loadCompletedSteps(playbookId, scopeId) {
  try {
    if (typeof sessionStorage === 'undefined') return new Set();
    const raw = sessionStorage.getItem(storageKey(playbookId, scopeId));
    if (!raw) return new Set();
    const arr = JSON.parse(raw);
    return new Set(Array.isArray(arr) ? arr.map(String) : []);
  } catch {
    return new Set();
  }
}

/**
 * @param {string} playbookId
 * @param {string} [scopeId]
 * @param {Iterable<string>} completed
 */
export function saveCompletedSteps(playbookId, scopeId, completed) {
  try {
    if (typeof sessionStorage === 'undefined') return;
    sessionStorage.setItem(storageKey(playbookId, scopeId), JSON.stringify([...completed]));
  } catch {
    /* private mode / quota — progress is best-effort */
  }
}

/**
 * Toggle one step; returns the new completed set.
 * @param {string} playbookId
 * @param {string} stepId
 * @param {boolean} done
 * @param {string} [scopeId]
 */
export function setStepCompleted(playbookId, stepId, done, scopeId) {
  const set = loadCompletedSteps(playbookId, scopeId);
  if (done) set.add(stepId);
  else set.delete(stepId);
  saveCompletedSteps(playbookId, scopeId, set);
  return set;
}

/**
 * Render a guided playbook panel (HTML string).
 * @param {Playbook} pb
 * @param {{ scopeId?: string, compact?: boolean, headingLevel?: 2|3 }} [opts]
 */
export function playbookHtml(pb, opts = {}) {
  if (!pb) return '';
  const scopeId = opts.scopeId || '';
  const compact = Boolean(opts.compact);
  const h = opts.headingLevel === 2 ? '2' : '3';
  const completed = loadCompletedSteps(pb.id, scopeId);
  const total = pb.steps.length;
  const doneN = pb.steps.filter((s) => completed.has(s.id)).length;
  const pct = total ? Math.round((doneN / total) * 100) : 0;

  const steps = pb.steps
    .map((s, i) => {
      const checked = completed.has(s.id);
      const inputId = `pb-${esc(pb.id)}-${esc(s.id)}-${esc(scopeId || 'g')}`;
      return `<li class="pb-step${checked ? ' is-done' : ''}" data-step-id="${esc(s.id)}">
        <div class="pb-step-head">
          <input type="checkbox" class="pb-check" id="${inputId}" data-pb-check
            data-playbook="${esc(pb.id)}" data-step="${esc(s.id)}" data-scope="${esc(scopeId)}"
            ${checked ? 'checked' : ''} />
          <label for="${inputId}" class="pb-step-label">
            <span class="pb-num" aria-hidden="true">${i + 1}</span>
            <span class="pb-step-title">${esc(s.title)}</span>
          </label>
        </div>
        <div class="pb-step-body">
          <p>${esc(s.body)}</p>
          ${s.where ? `<p class="pb-where"><span class="pb-where-label">Where</span> ${esc(s.where)}</p>` : ''}
        </div>
      </li>`;
    })
    .join('');

  const views = (pb.relatedViews ?? [])
    .map((v) => `<a class="pb-link" href="${esc(v.href)}">${esc(v.label)}</a>`)
    .join('');

  const disposition = `<div class="pb-disposition">
    <h${h === '2' ? '3' : '4'} class="pb-subh">Disposition guidance</h${h === '2' ? '3' : '4'}>
    <dl class="pb-dl">
      <div><dt>Resolve when</dt><dd>${esc(pb.disposition.resolve)}</dd></div>
      <div><dt>False positive when</dt><dd>${esc(pb.disposition.falsePositive)}</dd></div>
      ${pb.disposition.escalate ? `<div><dt>Escalate when</dt><dd>${esc(pb.disposition.escalate)}</dd></div>` : ''}
    </dl>
  </div>`;

  return `<section class="pb-panel${compact ? ' pb-compact' : ''}" data-playbook-panel="${esc(pb.id)}" data-scope="${esc(scopeId)}" aria-labelledby="pb-h-${esc(pb.id)}-${esc(scopeId || 'g')}">
    <header class="pb-head">
      <div class="pb-head-main">
        <span class="sr-only">Playbook severity: </span>${severityBadge(pb.severity, 'reported')}
        <h${h} class="pb-title" id="pb-h-${esc(pb.id)}-${esc(scopeId || 'g')}">Playbook: ${esc(pb.title)}</h${h}>
        <span class="pb-time" title="Typical investigation time">${esc(pb.timeEstimate)}</span>
      </div>
      <div class="pb-progress" role="status" aria-live="polite" data-pb-progress>
        <span class="pb-progress-text">${doneN} of ${total} steps</span>
        <span class="pb-progress-bar" aria-hidden="true"><span class="pb-progress-fill" style="width:${pct}%"></span></span>
      </div>
    </header>
    <p class="pb-summary">${esc(pb.summary)}</p>
    ${views ? `<nav class="pb-related" aria-label="Related views">${views}</nav>` : ''}
    <ol class="pb-steps">${steps}</ol>
    ${disposition}
    <p class="pb-meta">In-product playbook · taxonomy runbook <code>${esc(pb.runbookSlug)}</code> · covers <code>${pb.ruleIds.map((r) => esc(r)).join('</code>, <code>')}</code></p>
  </section>`;
}

/**
 * Compact one-liner for rule cards when a full panel is too heavy.
 * @param {Playbook} pb
 */
export function playbookChipHtml(pb) {
  if (!pb) return '';
  return `<div class="pb-chip" data-playbook-chip="${esc(pb.id)}">
    <span class="pb-chip-label">Guided playbook</span>
    <span class="pb-chip-title">${esc(pb.title)}</span>
    <span class="pb-chip-meta">${pb.steps.length} steps · ${esc(pb.timeEstimate)}</span>
  </div>`;
}

/**
 * Bind checkbox progress inside a root element (findings list or rules list).
 * Safe to call after every re-render; uses event delegation once per root.
 * @param {ParentNode} root
 */
export function bindPlaybookProgress(root) {
  if (!root || root.__aimPlaybookBound) return;
  root.__aimPlaybookBound = true;
  root.addEventListener('change', (e) => {
    const t = e.target;
    if (!(t instanceof HTMLInputElement) || !t.matches('[data-pb-check]')) return;
    const playbookId = t.dataset.playbook;
    const stepId = t.dataset.step;
    const scopeId = t.dataset.scope || '';
    if (!playbookId || !stepId) return;
    setStepCompleted(playbookId, stepId, t.checked, scopeId);
    const li = t.closest('.pb-step');
    if (li) li.classList.toggle('is-done', t.checked);
    const panel = t.closest('[data-playbook-panel]');
    if (!panel) return;
    const checks = panel.querySelectorAll('[data-pb-check]');
    const total = checks.length;
    let doneN = 0;
    checks.forEach((c) => {
      if (c.checked) doneN += 1;
    });
    const pct = total ? Math.round((doneN / total) * 100) : 0;
    const prog = panel.querySelector('[data-pb-progress]');
    if (prog) {
      const text = prog.querySelector('.pb-progress-text');
      if (text) text.textContent = `${doneN} of ${total} steps`;
      const fill = prog.querySelector('.pb-progress-fill');
      if (fill) fill.style.width = `${pct}%`;
    }
  });
}

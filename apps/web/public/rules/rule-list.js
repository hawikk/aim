/* Rules list rendering (AIM-1147) — pure-moved from rules.js.
 *
 * Everything that paints the "Policy settings" dl and the "Active rules"
 * list: settings rows, posture chips, per-rule route chips, rule cards, and
 * the inline threshold edit form markup. Pure HTML builders plus the one
 * render pass over rulesState (renderRules); no event handlers, no fetches.
 */
import { fmtInt, relTime } from '../lib/format.js';
import { esc } from '../lib/dom.js';
import { severityBadge, severityRowClass } from '../lib/severity.js';
import { SEVERITIES, routingSummary, routesForSeverity, routeLabel } from '../lib/alert-routing.js';
import { emptyState } from '../lib/components.js';
import { rulesState } from './state.js';

function fmtWindow(seconds) {
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

const WINDOW_PRESETS = [
  [3600, '1 hour'],
  [86400, '24 hours'],
  [604800, '7 days'],
];

export function settingsHtml(settings) {
  const rows = [];
  if (Array.isArray(settings.approved_tools)) {
    rows.push(`<div><dt>Approved tools</dt><dd>${settings.approved_tools.map((t) => `<code>${esc(t)}</code>`).join(' ')}</dd></div>`);
  }
  if (settings.approved_providers && typeof settings.approved_providers === 'object') {
    const cells = Object.entries(settings.approved_providers)
      .map(([tool, provs]) => `<tr><th scope="row"><code>${esc(tool)}</code></th><td>${(provs ?? []).map((p) => esc(p)).join(', ')}</td></tr>`)
      .join('');
    // AIM-515: a headerless grid of tool → providers announces as bare cells.
    // The caption names the table; row headers bind each provider list to its tool.
    rows.push(`<div><dt>Approved providers</dt><dd><table class="mini-table">
      <caption class="sr-only">Approved providers per tool</caption>
      <thead><tr><th scope="col">Tool</th><th scope="col">Approved providers</th></tr></thead>
      <tbody>${cells}</tbody></table></dd></div>`);
  }
  if (settings.off_hours_start !== undefined) {
    rows.push(
      `<div><dt>Off-hours</dt><dd>${esc(String(settings.off_hours_start).padStart(2, '0'))}:00–${esc(String(settings.off_hours_end).padStart(2, '0'))}:00 (endpoint-local when available)</dd></div>`
    );
  }
  if (Array.isArray(settings.restricted_repos)) {
    // Cleartext repo identifiers stay in the PR-reviewed policy file; the
    // viewer shows only the count.
    const n = settings.restricted_repos.length;
    rows.push(
      `<div><dt>Restricted repos</dt><dd>${fmtInt(n)} configured${n === 0 ? ' <span class="chip posture-inert" title="Rules that depend on this list are labelled inert">empty — dependent rules inert</span>' : ''} (list lives in the policy file)</dd></div>`
    );
  }
  if (Array.isArray(settings.approved_mcp_servers)) {
    const mode = settings.mcp_allowlist_mode ?? 'deny_unlisted';
    const n = settings.approved_mcp_servers.length;
    rows.push(
      `<div><dt>Approved MCP servers</dt><dd>${fmtInt(n)} approved · mode <code>${esc(mode)}</code>${n === 0 && mode === 'deny_unlisted' ? ' <span class="chip" title="Empty allowlist denies every MCP server">deny-unlisted</span>' : ''}</dd></div>`
    );
  }
  return rows.join('');
}

function postureChip(rule) {
  const status = rule.posture ?? 'active';
  const label = rule.postureLabel ?? status;
  const title = (rule.postureReasons ?? []).join('; ') || label;
  if (status === 'inert') {
    return `<span class="chip posture-inert" title="${esc(title)}">${esc(label)}</span>`;
  }
  if (status === 'discovery') {
    return `<span class="chip posture-discovery" title="${esc(title)}">${esc(label)}</span>`;
  }
  return `<span class="chip posture-active" title="${esc(title)}">Active</span>`;
}

/* AIM-584: derived fan-out for one rule. Destinations are global; a rule of
 * severity S routes to every enabled destination whose floor is ≤ S. */
function ruleRoutesHtml(rule) {
  const lastAlerts = rulesState.lastAlerts;
  if (!lastAlerts) {
    return `<div class="rule-routes" data-rule-routes="${esc(rule.id)}" role="status">
      <span class="rule-routes-label">Routes to</span>
      <span class="rule-routes-empty">loading destinations…</span>
    </div>`;
  }
  const summary = routingSummary(lastAlerts);
  if (summary.noneEnabled) {
    return `<div class="rule-routes" data-rule-routes="${esc(rule.id)}" role="status">
      <span class="rule-routes-label">Routes to</span>
      <span class="rule-routes-empty">no destinations enabled — findings stay in the inbox only</span>
    </div>`;
  }
  const hits = routesForSeverity(lastAlerts, rule.severity);
  if (hits.length === 0) {
    return `<div class="rule-routes" data-rule-routes="${esc(rule.id)}" role="status">
      <span class="rule-routes-label">Routes to</span>
      <span class="rule-routes-empty">none — every enabled destination’s min severity is above ${esc(rule.severity)}</span>
    </div>`;
  }
  const chips = hits.map((r) => {
    const warn = r.secretConfigured ? '' : ' route-chip-warn';
    const title = r.secretConfigured
      ? routeLabel(r)
      : `${routeLabel(r)} — secret not configured (engine will fail closed)`;
    return `<span class="route-chip${warn}" title="${esc(title)}">${esc(routeLabel(r))}</span>`;
  }).join('');
  return `<div class="rule-routes" data-rule-routes="${esc(rule.id)}" role="status">
    <span class="rule-routes-label">Routes to</span>
    <span class="rule-routes-list">${chips}</span>
  </div>`;
}

function ruleHtml(rule) {
  const why = rule.conditionText ?? rule.thresholdText ?? '';
  const whyLabel = rule.type === 'threshold' ? 'When it fires (threshold)' : 'What fires it (condition)';
  const thresh = rule.threshold
    ? `<div class="rule-thresh">
        ${rule.threshold.windowSeconds ? `<span>window ${esc(fmtWindow(rule.threshold.windowSeconds))}</span>` : ''}
        <span>metric <code>${esc(rule.threshold.metric)}</code></span>
        <span>grouped by ${rule.threshold.groupBy.map((g) => `<code>${esc(g)}</code>`).join(' × ')}</span>
        <span>${rule.threshold.gt !== null ? `&gt; ${esc(fmtInt(rule.threshold.gt))}` : `≥ ${esc(fmtInt(rule.threshold.gte))}`}</span>
      </div>`
    : '';
  // AIM-94: threshold rules are tunable inline; match rules stay policy-as-code.
  // AIM-515: the edit button is a disclosure — aria-expanded/aria-controls are
  // the only signal that the editor is open. A label that flips between "Edit
  // thresholds" and "Close editor" otherwise reads as two unrelated buttons.
  const formId = `rule-edit-${esc(rule.id)}`;
  const actions = rule.threshold
    ? `<div class="rule-actions">
        <button type="button" class="rbtn" data-edit="${esc(rule.id)}"
                aria-expanded="false" aria-controls="${formId}">Edit thresholds<span class="sr-only"> for ${esc(rule.title)}</span></button>
        ${rule.overridden ? `<button type="button" class="rbtn" data-reset="${esc(rule.id)}">Reset to policy default<span class="sr-only"> for ${esc(rule.title)}</span></button>` : ''}
      </div>
      <div class="rule-edit" id="${formId}" data-form="${esc(rule.id)}" role="group" aria-label="Threshold settings for ${esc(rule.title)}" hidden></div>`
    : '<div class="rule-hint">Match rule — managed via policy PR (policy-as-code), not tunable here.</div>';
  const inertNote =
    rule.posture === 'inert' && (rule.postureReasons ?? []).length
      ? `<div class="rule-inert" role="status"><b>Inert by design until configured:</b> ${esc((rule.postureReasons ?? []).join(' · '))}</div>`
      : '';
  const statsText = rule.firedCount > 0
    ? `fired <b>${esc(fmtInt(rule.firedCount))}</b>× · last ${esc(relTime(rule.lastFiredAt))}`
    : rule.posture === 'inert'
      ? 'inert — will not fire until prerequisites are met'
      : 'never fired (no recorded findings)';
  return `<article class="rule ${severityRowClass(rule.severity)} posture-${esc(rule.posture ?? 'active')}" data-rule="${esc(rule.id)}" role="listitem" aria-labelledby="rule-t-${esc(rule.id)}">
    <div class="rule-head">
      ${severityBadge(rule.severity)}
      <span class="rule-type"><span class="sr-only">Rule type: </span>${esc(rule.type)}</span>
      <span class="rule-title" id="rule-t-${esc(rule.id)}">${esc(rule.title)}</span>
      ${postureChip(rule)}
      ${rule.overridden ? '<span class="chip">tuned via UI<span class="sr-only"> — this rule has UI overrides on top of the policy file</span></span>' : ''}
      <code class="rule-id"><span class="sr-only">Rule ID: </span>${esc(rule.id)}</code>
    </div>
    ${rule.description ? `<p class="rule-desc">${esc(rule.description)}</p>` : ''}
    ${inertNote}
    <div class="rule-why"><span class="rule-why-label">${esc(whyLabel)}</span><pre>${esc(why)}</pre></div>
    ${thresh}
    ${ruleRoutesHtml(rule)}
    <div class="rule-stats" title="Firing history from recorded findings">
      <span class="sr-only">Firing history from recorded findings: </span>${statsText}
    </div>
    ${actions}
  </article>`;
}

/* Retitle a per-rule button without losing the screen-reader suffix that makes
 * it unique. There is one "Edit thresholds" button per rule, so the bare label
 * is ambiguous in a list of buttons; the suffix is what disambiguates them. */
export function setLabel(button, text, ruleTitle) {
  button.innerHTML = `${esc(text)}<span class="sr-only"> for ${esc(ruleTitle)}</span>`;
}

// Inline tuning form for a threshold rule (AIM-94). gt vs gte is fixed by the
// rule — the operator is not editable, only its value, window and severity.
export function editFormHtml(rule) {
  const th = rule.threshold;
  const op = th.gt !== null && th.gt !== undefined ? 'gt' : 'gte';
  const val = op === 'gt' ? th.gt : th.gte;
  const w = th.windowSeconds;
  const isPreset = WINDOW_PRESETS.some(([s]) => s === w);
  return `<div class="re-grid">
    <label>Fire when metric ${op === 'gt' ? '&gt;' : '≥'}
      <input type="number" class="re-value" min="0" step="any" value="${esc(val)}" /></label>
    <label>Window
      <select class="re-window">
        ${WINDOW_PRESETS.map(([s, l]) => `<option value="${s}"${isPreset && s === w ? ' selected' : ''}>${l}</option>`).join('')}
        <option value="custom"${isPreset ? '' : ' selected'}>custom…</option>
      </select></label>
    <label class="re-custom"${isPreset ? ' hidden' : ''}>Custom window (seconds)
      <input type="number" class="re-window-custom" min="1" step="1" value="${isPreset ? '' : esc(w)}" /></label>
    <label>Severity
      <select class="re-severity">
        ${SEVERITIES.map((s) => `<option value="${s}"${s === rule.severity ? ' selected' : ''}>${s}</option>`).join('')}
      </select></label>
  </div>
  <div class="re-actions">
    <button type="button" class="rbtn primary" data-save>Save</button>
    <button type="button" class="rbtn" data-cancel>Cancel</button>
    <span class="re-err" role="alert"></span>
  </div>`;
}

export function renderRules() {
  const list = rulesState.list;
  list.setAttribute('aria-busy', 'false');
  list.innerHTML = rulesState.lastRules.map(ruleHtml).join('') || emptyState({
    reason: 'no-collector',
    title: 'No rules in the loaded policy',
    body: 'No guardrail rules are loaded, so no prompt or tool use is being evaluated against policy at all.',
  });
}

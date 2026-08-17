/* Escalation policy editor markup (AIM-1147) — pure-moved from rules.js.
 *
 * The AIM-990 multi-stage escalation ladder editor: stage rows, policy cards,
 * and the panel-level empty state. HTML builders only — the add/remove/save
 * interaction handlers live in ./alerts-panel.js, the policy model in
 * ../lib/escalation-policies.js.
 */
import { esc } from '../lib/dom.js';
import { SEVERITIES } from '../lib/alert-routing.js';
import {
  escalationSummary,
  formatStageDelay,
  stageDestLabel,
  cumulativeDelaySeconds,
  blankPolicy,
  PRIMARY_STAGE_DESTINATIONS,
  STAGE_DESTINATIONS,
  secondsToMinutesField,
} from '../lib/escalation-policies.js';
import { emptyState } from '../lib/components.js';

function destOptionsHtml(selected) {
  const sel = new Set(selected || []);
  const order = [
    ...PRIMARY_STAGE_DESTINATIONS,
    ...STAGE_DESTINATIONS.map((d) => d.id).filter((id) => !PRIMARY_STAGE_DESTINATIONS.includes(id)),
  ];
  const seen = new Set();
  return order.filter((id) => {
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  }).map((id) => `<option value="${esc(id)}"${sel.has(id) ? ' selected' : ''}>${esc(stageDestLabel(id))}</option>`).join('');
}

function stageEditorHtml(stage, index, stages, policyKey) {
  const isFirst = index === 0;
  const delayMin = isFirst ? '' : secondsToMinutesField(stage.afterSeconds);
  const delayLabel = isFirst ? 'Delay (stage 0 fires immediately)' : 'Delay after previous stage (minutes)';
  const cum = formatStageDelay(cumulativeDelaySeconds(stages, index));
  const stageId = `esc-stage-${policyKey}-${index}`;
  return `<li class="esc-stage esc-stage-edit" data-stage-index="${index}">
    <div class="esc-stage-meta">
      <span class="esc-stage-n" id="${stageId}-label">Stage ${index}</span>
      ${isFirst
        ? `<span class="esc-stage-delay" title="Fires with the finding">immediate</span>`
        : `<span class="esc-stage-cum" title="From finding insert">t+${esc(cum)}</span>`}
    </div>
    <label class="esc-field">
      <span class="esc-field-label">${esc(delayLabel)}</span>
      <input type="number" class="esc-after" min="${isFirst ? 0 : 1}" step="1"
        value="${isFirst ? '0' : esc(delayMin)}"
        ${isFirst ? 'readonly aria-readonly="true"' : ''}
        data-esc-unit="minutes"
        aria-labelledby="${stageId}-label"
        aria-describedby="${stageId}-hint" />
      <span class="sr-only" id="${stageId}-hint">${isFirst ? 'Stage zero always fires immediately.' : 'Minutes after previous stage.'}</span>
    </label>
    <label class="esc-field esc-field-dests">
      <span class="esc-field-label">Destinations</span>
      <select class="esc-dests" multiple size="4" aria-label="Destinations for stage ${index}">
        ${destOptionsHtml(stage.destinations)}
      </select>
      <span class="esc-field-hint">Hold Ctrl/Cmd to multi-select.</span>
    </label>
    ${index > 0 ? `<button type="button" class="rbtn danger esc-remove-stage" data-remove-stage="${index}" aria-label="Remove stage ${index}">Remove stage</button>` : ''}
  </li>`;
}

function policyEditorHtml(policy, policyIndex) {
  const key = (policy.id || `new-${policyIndex}`).replace(/[^a-zA-Z0-9_-]/g, '_');
  const headingId = `esc-h-${key}-${policyIndex}`;
  const stages = (policy.stages?.length ? policy.stages : blankPolicy().stages);
  const stageRows = stages.map((s, i) => stageEditorHtml(s, i, stages, `${key}-${policyIndex}`)).join('');
  return `<article class="esc-policy esc-policy-edit" data-policy-id="${esc(policy.id)}" data-editing="1" data-policy-index="${policyIndex}" role="group" aria-labelledby="${headingId}">
    <header class="esc-policy-head">
      <h4 id="${headingId}">Escalation policy</h4>
      <button type="button" class="rbtn danger esc-remove-policy" data-remove-policy="${policyIndex}" aria-label="Remove policy ${esc(policy.id || String(policyIndex))}">Remove</button>
    </header>
    <div class="esc-fields">
      <label class="esc-field">
        <span class="esc-field-label">Policy id</span>
        <input type="text" class="esc-id" value="${esc(policy.id)}"
          pattern="[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}" maxlength="64" required
          autocomplete="off" aria-required="true" placeholder="soc-oncall" />
      </label>
      <label class="esc-field">
        <span class="esc-field-label">Min severity</span>
        <select class="esc-minsev" aria-label="Minimum severity for policy ${esc(policy.id || 'new')}">
          ${SEVERITIES.map((s) => `<option value="${s}"${s === policy.minSeverity ? ' selected' : ''}>${s}</option>`).join('')}
        </select>
      </label>
      <label class="esc-field esc-field-wide">
        <span class="esc-field-label">Rule ids (optional, comma-separated; empty = all rules)</span>
        <input type="text" class="esc-rule-ids" value="${esc((policy.ruleIds || []).join(', '))}"
          placeholder="leave empty for all rules" autocomplete="off" />
      </label>
    </div>
    <ol class="esc-stages" aria-label="Stages for ${esc(policy.id || 'new policy')}">${stageRows}</ol>
    <div class="esc-stage-actions">
      <button type="button" class="rbtn" data-add-stage="${policyIndex}">Add stage</button>
    </div>
  </article>`;
}

export function escalationHtml(d) {
  const summary = escalationSummary(d);
  const policies = summary.policies.length ? summary.policies : [];
  const cards = policies.map((p, i) => policyEditorHtml(p, i)).join('');
  const empty = summary.noneConfigured
    ? emptyState({
        reason: 'no-data',
        title: 'No escalation ladders configured',
        body: 'Findings still fan out to every enabled destination immediately. Create a 2-stage ladder (e.g. Slack → PagerDuty after 15 minutes) so on-call is only paged when a finding stays open.',
        doc: 'docs/security/escalation-policies.md',
      })
    : '';
  return `<div id="escalation-policies" class="escalation-panel" data-esc-state="${summary.noneConfigured ? 'empty' : 'configured'}" data-esc-count="${summary.count}" aria-labelledby="esc-panel-h">
    <h3 id="esc-panel-h">Escalation policies <span class="hint">multi-stage routing · editable</span></h3>
    <p class="ac-hint">Stage 0 fires with the finding; later stages wait N minutes only while the finding stays <code>status=new</code>. Secrets stay env-managed — never entered here.</p>
    <div class="esc-toolbar">
      <button type="button" class="rbtn primary" data-add-policy>Add policy</button>
      <button type="button" class="rbtn primary" data-save-escalation>Save escalation policies</button>
      <span class="esc-all-err" role="alert"></span>
      <span class="esc-all-ok" role="status"></span>
    </div>
    <div class="esc-policy-list" id="esc-policy-list">${cards || empty}</div>
  </div>`;
}

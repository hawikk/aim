/* Alerts inbox rendering (split): alert cards, state badges,
 * evidence links, the dropped-entries warning, and the list render itself.
 * Pure presentation over inboxCtx — data loading lives in ./data.js. */

import {
  SNOOZE_PRESETS, resolveEvidenceUrl, matchesText, inboxStateOf,
  alertDomainFields,
} from '../lib/inbox.js';
import { severityBadge, severityRowClass } from '../lib/severity.js';
import { relTime } from '../lib/format.js';
import { esc } from '../lib/dom.js';
import { emptyState } from '../lib/components.js';
import { resolveRunbook, runbookHash } from '../lib/runbooks.js';
import { suggestDisposition, hintPillHtml } from '../lib/auto-triage.js';
import { inboxCtx } from './state.js';

export function stateBadge(alertId) {
  const { state } = inboxCtx;
  const st = inboxStateOf(state.states, alertId);
  if (st === 'acknowledged') {
    const by = state.states[alertId]?.actor;
    return `<span class="pill st-acknowledged" title="Acknowledged${by ? ` by ${esc(by)}` : ''}">acknowledged</span>`;
  }
  if (st === 'snoozed') {
    const until = state.states[alertId]?.snooze_until;
    return `<span class="pill st-snoozed" title="Snoozed until ${esc(until ?? '')}">snoozed</span>`;
  }
  return '<span class="pill st-open">open</span>';
}

export function evidenceLink(alert) {
  const ref = alert.evidence?.source_uri;
  if (!ref) return '';
  const url = inboxCtx.gatewayHost ? resolveEvidenceUrl(ref, inboxCtx.gatewayHost) : null;
  if (!url) {
    // Unknown scheme or no gateway host yet: the raw ref as TEXT. Never an
    // href — a scheme we do not know must not become a clickable URL.
    return `<span class="a-evidence-raw mono" title="Evidence reference (no resolvable link)">${esc(ref)}</span>`;
  }
  return `<a class="a-evidence" href="${esc(url)}" target="_blank" rel="noopener noreferrer" title="Open evidence in the owning pillar">evidence</a>`;
}

function fieldChip(label, value, title, href) {
  if (value == null || value === '') return '';
  const v = href
    ? `<a class="a-field-v a-field-link" href="${esc(href)}">${esc(value)}</a>`
    : `<span class="a-field-v">${esc(value)}</span>`;
  return `<span class="a-field" title="${esc(title || `${label}: ${value}`)}"><span class="a-field-k">${esc(label)}</span>${v}</span>`;
}

/**: rule / finding_type → runbook deep-link chip. */
function runbookChip(d) {
  const key = d.rule || d.findingType;
  if (!key) return '';
  const rb = resolveRunbook(key);
  return `<a class="a-field a-runbook${rb.known ? '' : ' gap'}" href="${esc(runbookHash(rb.slug))}" title="${esc(rb.runbook.title)}"><span class="a-field-k">runbook</span><span class="a-field-v">${esc(rb.slug)}${rb.known ? '' : ' · gap'}</span></a>`;
}

export function alertRow(a) {
  const { state } = inboxCtx;
  /*: AI-tool-governance card — tool/session/rule/exposure/user/repo.
     Do not render CNAPP pillar enums or cloud resource ARNs as the primary
     meta line; those read as cloud-security cards, not AI monitoring. */
  const d = alertDomainFields(a);
  // session chip deep-links to MCP session chain (analyst+).
  const sessionHref = d.sessionFull
    ? `#/mcp?session=${encodeURIComponent(d.sessionFull)}`
    : null;
  const fields = [
    fieldChip('tool', d.tool),
    fieldChip('session', d.session, d.sessionFull ? `session: ${d.sessionFull}` : null, sessionHref),
    fieldChip('rule', d.rule),
    runbookChip(d),
    fieldChip('exposure', d.exposureClass),
    fieldChip('user', d.user, d.userFull ? `user: ${d.userFull}` : null),
    fieldChip('repo', d.repo, d.repoFull ? `repo: ${d.repoFull}` : null),
  ].filter(Boolean).join('');
  const summary = a.evidence?.summary
    ? `<span class="a-summary">${esc(a.evidence.summary)}</span>`
    : '';
  // historical disposition hint (policy_hash + rule when available).
  const hint = state.outcomeIndex instanceof Map
    ? suggestDisposition(a, state.outcomeIndex)
    : null;
  const hintHtml = hintPillHtml(hint, esc);
  return `<div class="inbox-alert ${severityRowClass(a.severity, { id: a.severity_id })}" data-id="${esc(a.alert_id)}">
    <div class="a-head">
      ${severityBadge(a.severity, { id: a.severity_id, label: a.severity })}
      <span class="a-main">
        <span class="a-title">${esc(a.title)}</span>
        <span class="a-fields">${fields || '<span class="a-meta faint">No tool/session/rule context on this alert</span>'}</span>
        ${summary}
        ${hintHtml ? `<span class="a-triage-hint">${hintHtml}</span>` : ''}
      </span>
      <span class="a-side">
        ${stateBadge(a.alert_id)}
        <span class="a-time" title="${esc(a.last_seen_at)}">${esc(relTime(a.last_seen_at))}</span>
      </span>
    </div>
    <div class="a-actions">
      ${evidenceLink(a)}
      <span class="spacer"></span>
      <button type="button" class="btn btn-sm" data-act="ack">Ack</button>
      <select class="a-snooze" aria-label="Snooze this alert">
        <option value="" selected>Snooze…</option>
        ${SNOOZE_PRESETS.map(([label, minutes]) => `<option value="${minutes}">${label}</option>`).join('')}
      </select>
      <button type="button" class="btn btn-sm" data-act="unack">Unack</button>
    </div>
  </div>`;
}

export function render() {
  const { state, list, moreBtn, pageHint } = inboxCtx;
  if (state.busProblem) {
    // 503 (bus not configured) and 502 (bus down) both land here, stated
    // plainly — never rendered as an empty, all-clear inbox (§7.3).
    list.innerHTML = `<div class="err">${esc(state.busProblem)}</div>`;
    moreBtn.hidden = true;
    pageHint.textContent = '';
    return;
  }
  // Display by recency (§7.1: stream order says nothing about event time);
  // the cursor that paging depends on is untouched by this sort.
  const visible = state.alerts
    .filter((a) => matchesText(a, state.text))
    .sort((a, b) => new Date(b.last_seen_at) - new Date(a.last_seen_at));
  list.innerHTML = visible.length
    ? visible.map(alertRow).join('')
    : (state.alerts.length
      ? emptyState({ reason: 'filtered', title: 'No loaded alert matches the text filter', body: 'Alerts exist outside the current text filter.' })
      : emptyState({ reason: 'no-data', title: 'No alerts in the retention window', body: 'Nothing has fired into the alerts feed in the retention window.' }));
  moreBtn.hidden = state.exhausted;
  pageHint.textContent = state.exhausted
    ? `${state.alerts.length} alert${state.alerts.length === 1 ? '' : 's'} — the whole retention window is loaded`
    : `${state.alerts.length} loaded`;
}

export function renderDropped(dropped) {
  const { droppedEl } = inboxCtx;
  // A quiet drop is a security failure (D3.1): the counters stay visible
  // whenever non-zero, never folded away.
  const total = (dropped?.malformed ?? 0) + (dropped?.invalid ?? 0);
  if (!total) {
    droppedEl.hidden = true;
    return;
  }
  droppedEl.hidden = false;
  droppedEl.textContent =
    `${total} entr${total === 1 ? 'y was' : 'ies were'} rejected as non-conforming on the last page ` +
    `(malformed: ${dropped.malformed}, invalid: ${dropped.invalid}) — check the publishers before trusting this view.`;
}

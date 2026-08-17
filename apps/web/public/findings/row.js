/* Findings inbox row rendering (split of findings.js).
 * findingRow paints one finding (head + disclosure detail); renderHistory
 * fills the disposition-trail slot on expand. Pure rendering — mutations and
 * disclosure state live in ./triage.js, shared state in ./state.js. */
import { STATUS_LABEL, fctx } from './state.js';
import { STATUS_FLOW } from '../lib/triage.js';
import { findingLinkHtml } from '../lib/deeplinks.js';
import { extractSessionId, sessionHash } from '../lib/mcp-session-chain.js';
import { extractFingerprints, annotateWithFixtureHints } from '../lib/fingerprints.js';
import { suggestDisposition, hintPillHtml } from '../lib/auto-triage.js';
import { resolveComplianceEvidence, evidenceLinksHtml } from '../lib/compliance-evidence.js';
import { resolveRunbook, runbookHash } from '../lib/runbooks.js';
import { playbookForRule, playbookHtml } from '../lib/playbooks.js';
import { fmtSubject, fmtTs, relTime } from '../lib/format.js';
import { esc } from '../lib/dom.js';
import { sevPill, severityBadge, severityRowClass } from '../lib/severity.js';
import { api } from '../lib/api.js';

// Escapes like app.js's card(): callers pass raw strings, never markup.
export function findingRow(f, rules) {
  const { state, outcomeIndex, fixtureIndex, evidenceIndex } = fctx;
  const actions = STATUS_FLOW[f.status] ?? [];
  // the rule condition that fired, in plain language (from the
  // live policy via /api/guardrail-rules) — no YAML reading required.
  const rule = rules?.get(f.ruleId);
  const whyText = rule ? (rule.conditionText ?? rule.thresholdText) : null;
  // finding → user / tool / repo / fleet with range preserved.
  // subject.user_ref is the raw HMAC ref; /api/users/:pseudonym resolves
  // COALESCE(user_pseudonym, user_ref). Tool/repo come from evidence.context
  // when present. Never hand-build `#/users/…` — it drops ?days=.
  const entityLinks = findingLinkHtml(f, { days: state.days, esc });
  // deep-link into MCP session chain when evidence carries session_id
  // (engine context — metadata only; never matched content).
  const sessionId = extractSessionId(f.evidence);
  const sessionLink = sessionId
    ? ` · <a href="${sessionHash(sessionId)}" title="Open MCP session chain for ${esc(sessionId)}">MCP session chain →</a>`
    : '';
  // redacted per-occurrence fingerprints (schema v1.8) — the proof/
  // dedupe handle for secret findings. There is no matched content to show;
  // the fingerprint IS the finding's substance.
  // if fingerprint ∈ fixture registry → suggest cluster A (synthetic).
  const fps = annotateWithFixtureHints(extractFingerprints(f.evidence), fixtureIndex);
  const fixtureHits = fps.filter((p) => p.fixtureHint);
  const clusterAHint = fixtureHits.length
    ? `<span class="pill cluster-a" title="Fingerprint matches known dead-key fixture registry. Suggest cluster A — synthetic / fixture, not a live secret. Labels: ${esc(
        fixtureHits.map((p) => p.fixtureHint.label).join(', ')
      )}">cluster A · fixture</span>`
    : '';
  // only hint on open findings — closed rows already have a disposition.
  const autoHint = (f.status === 'new' || f.status === 'acknowledged')
    ? hintPillHtml(suggestDisposition(f, outcomeIndex), esc)
    : '';
  const fpBlock = fps.length
    ? `<div><dt>Fingerprints</dt><dd class="mono">${fps
        .map((p) => {
          const base =
            `${esc(p.detector)} fp=${esc(p.fingerprint)}` +
            (p.surface ? ` (${esc(p.surface)} offset ${p.offset ?? '—'})` : '');
          if (!p.fixtureHint) return base;
          const src = p.fixtureHint.source ? ` · ${esc(p.fixtureHint.source)}` : '';
          return (
            `${base}<br><span class="fp-fixture-hint">→ suggest cluster ${esc(
              p.fixtureHint.cluster
            )}: ${esc(p.fixtureHint.label)}${src}</span>`
          );
        })
        .join('<br>')}</dd></div>`
    : '';
  // high-sev → compliance control evidence links.
  const cmpLinks = resolveComplianceEvidence(f, evidenceIndex);
  const cmpBlock = evidenceLinksHtml(cmpLinks, { esc });
  // Stable id for the disclosure panel so aria-controls / focus return
  // survive re-renders. findingId is metadata (never free text from a prompt).
  const detailId = `f-detail-${f.findingId}`;
  const statusLabel = STATUS_LABEL[f.status] ?? f.status;
  // Accessible name for the expand control: severity is already inside the
  // pill with an sr-only prefix; title + status disambiguate a long list.
  const rowLabel = `Investigate ${f.severity} finding: ${f.title} (${statusLabel})`;
  return `<div class="finding ${severityRowClass(f.severity)}" data-id="${esc(f.findingId)}" role="listitem">
    <div class="f-head">
      <input type="checkbox" class="f-check" aria-label="Select finding for bulk triage: ${esc(f.title)}" />
      <button type="button" class="f-row" aria-expanded="false" aria-controls="${esc(detailId)}" aria-label="${esc(rowLabel)}">
      ${sevPill(f.severity)}
      <span class="f-main">
        <span class="f-title">${esc(f.title)}</span>
        <span class="f-meta" title="${esc(f.subject ? fmtSubject(f.subject, { full: true }) : '')}">${esc(f.ruleId)}${f.subject ? ` · ${esc(fmtSubject(f.subject))}` : ''}</span>
      </span>
      <span class="f-side">
        ${f.triagedBy ? `<span class="f-assignee" title="Last triaged by">${esc(f.triagedBy)}</span>` : ''}
        ${clusterAHint}
        ${autoHint}
        ${f.slaBreached ? severityBadge('critical', { title: 'Critical ack SLA breached', label: 'SLA' }) : ''}
        <span class="pill st-${esc(f.status)}">${esc(statusLabel)}</span>
        <span class="f-time" title="${esc(f.detectedAt)}${f.ageHours != null ? ` · age ${f.ageHours}h (${f.ageBucket || ''})` : ''}">${relTime(f.detectedAt)}${f.ageBucket ? ` · ${esc(f.ageBucket)}` : ''}</span>
      </span>
      </button>
    </div>
    <div class="f-detail" id="${esc(detailId)}" hidden>
      <dl class="f-fields">
        <div><dt>Rule</dt><dd>${esc(f.ruleId)}</dd></div>
        ${(() => {
          const rb = resolveRunbook(f.ruleId);
          return `<div><dt>Runbook</dt><dd><a class="f-runbook${rb.known ? '' : ' gap'}" href="${esc(runbookHash(rb.slug))}" title="${esc(rb.runbook.title)}">${esc(rb.runbook.title)}${rb.known ? '' : ' (unmapped fallback)'} →</a></dd></div>`;
        })()}
        ${whyText ? `<div><dt>Why it fired</dt><dd class="f-why">${esc(whyText)}</dd></div>` : ''}
        ${rule?.description ? `<div><dt>Rule intent</dt><dd>${esc(rule.description)}</dd></div>` : ''}
        <div><dt>Subject</dt><dd title="${esc(f.subject ? fmtSubject(f.subject, { full: true }) : '')}">${esc(f.subject ? fmtSubject(f.subject, { full: true }) : '—')}${entityLinks}${sessionLink}</dd></div>
        <div><dt>Decision</dt><dd>${esc(f.decision || '—')}</dd></div>
        <div><dt>Detected</dt><dd class="mono" title="${esc(f.detectedAt)}">${esc(fmtTs(f.detectedAt))}</dd></div>
        <div><dt>Event</dt><dd class="mono">${esc(f.eventId || '—')}</dd></div>
        <div><dt>Policy</dt><dd class="mono">${esc(f.policyHash ? String(f.policyHash).slice(0, 16) : '—')}</dd></div>
        ${sessionId ? `<div><dt>Session</dt><dd class="mono"><a href="${sessionHash(sessionId)}">${esc(sessionId)}</a></dd></div>` : ''}
        ${fpBlock}
        ${f.triagedBy ? `<div><dt>Triaged</dt><dd>${esc(f.triagedBy)} · <span class="mono" title="${esc(f.triagedAt)}">${esc(fmtTs(f.triagedAt))}</span></dd></div>` : ''}
        ${f.triageNote ? `<div><dt>Note</dt><dd>${esc(f.triageNote)}</dd></div>` : ''}
      </dl>
      ${cmpBlock}
      ${(() => {
        // step-by-step investigation playbook for top detections.
        const pb = playbookForRule(f.ruleId);
        return pb ? playbookHtml(pb, { scopeId: f.findingId, headingLevel: 3 }) : '';
      })()}
      ${f.evidence ? `<pre class="f-evidence">${esc(JSON.stringify(f.evidence, null, 2))}</pre>` : ''}
      <div class="f-history" aria-live="polite"></div>
      <div class="f-triage">
        <label class="sr-only" for="f-note-${esc(f.findingId)}">Triage note for ${esc(f.title)}</label>
        <textarea class="f-note" id="f-note-${esc(f.findingId)}" rows="2" placeholder="Triage note — required to resolve; recorded in the audit trail"></textarea>
        <div class="f-actions" role="group" aria-label="Triage actions for ${esc(f.title)}">${actions
          .map(([st, label, cls]) => `<button type="button" class="btn ${cls}" data-action="${st}">${label}</button>`)
          .join('')}</div>
      </div>
    </div>
  </div>`;
}

/*: disposition history for one finding, rendered into the detail
 * view's .f-history slot. Fetched on expand (never cached — the whole
 * point is that the trail is current). A fetch failure renders as a note,
 * not a toast storm: the triage controls below still work. */
export async function renderHistory(el) {
  const slot = el.querySelector('.f-history');
  if (!slot) return;
  slot.innerHTML = '<h3>Disposition history</h3><div class="f-h-empty">Loading…</div>';
  try {
    const d = await api(`/api/findings/${encodeURIComponent(el.dataset.id)}/transitions`);
    const items = (d.transitions ?? [])
      .map(
        (t) =>
          `<li><span class="f-h-change">${esc(STATUS_LABEL[t.from] ?? t.from)} → ${esc(
            STATUS_LABEL[t.to] ?? t.to
          )}</span> · ${esc(t.actor)} · <span title="${esc(t.at)}">${relTime(t.at)}</span>${
            t.reason ? ` — <span class="f-h-reason">${esc(t.reason)}</span>` : ''
          }</li>`
      )
      .join('');
    slot.innerHTML =
      '<h3>Disposition history</h3>' +
      (items ? `<ul>${items}</ul>` : '<div class="f-h-empty">No transitions recorded yet — history starts at the first triage after deploy.</div>');
  } catch {
    slot.innerHTML = '<h3>Disposition history</h3><div class="f-h-empty">History unavailable right now.</div>';
  }
}

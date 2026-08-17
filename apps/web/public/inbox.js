/* AIM-160 — unified cross-pillar alert inbox (the shell's "Alerts" tab).
 *
 * Self-contained module in the findings.js pattern: injects its own nav tab,
 * view section, stylesheet and health-strip polling at runtime, and activates
 * only for the analyst+ tier (capabilities.findingsConsole — the exact gate
 * the API applies to /api/alerts and the inbox state endpoints).
 *
 * What it deliberately does NOT do:
 *  - fetch the whole bus. It pages with nextCursor (limit=100) behind a
 *    "Load more" button; the severity/pillar filters re-QUERY the API, they
 *    never filter a full local copy.
 *  - mutate pillar data. Ack/snooze is shell state (POST /api/alerts/:id/*),
 *    stored by the API in alert_inbox_state, never written back to a pillar.
 *  - rewrite or embed pillar UIs (D1). Cross-pillar nav is deep links only.
 *
 * Trust: alert titles and resource labels are UNTRUSTED publisher input —
 * the conformance corpus includes XSS and prompt-injection payloads — so
 * everything rendered from an alert goes through esc(), and evidence
 * source_uri refs resolve only through lib/inbox.js's allowlisted
 * resolveEvidenceUrl() (unknown scheme = inert text, never an href).
 *
 * AIM-702: each alert card can show an auto-triage hint (likely disposition
 * + confidence) from historical closed findings keyed by policy_hash + rule.
 * Metadata only — the outcome index never loads content-bearing fields.
 *
 * Split (AIM-1181, mirroring the AIM-1177 policy / AIM-1172 compliance /
 * AIM-1163 activity splits) — the view's concerns live in sibling modules:
 *   ./inbox/state.js    shared view-private inboxCtx + reset
 *   ./inbox/render.js   alert cards, state badges, evidence links, list render
 *   ./inbox/data.js     alert paging, inbox-state fetch, outcome history
 *   ./inbox/actions.js  ack/snooze/unack mutations + filter/pager bindings
 *   ./inbox/health.js   stack-health strip + pillar deep links
 *
 * This file wires the gate, stylesheet, nav tab, view section, and module
 * view registration. Keep it thin — new inbox code goes in a sibling module.
 */

import {
  SEVERITIES, PILLARS, PILLAR_LABELS,
} from './lib/inbox.js';
import { registerModuleView } from './lib/router.js';
import { esc } from './lib/dom.js';
import { moduleTab, moduleSection } from './lib/a11y.js';
import { requireCapability } from './lib/form.js';
import { inboxCtx, resetInboxCtx } from './inbox/state.js';
import { reload, showProblem } from './inbox/data.js';
import { bindInboxActions, bindInboxFilters } from './inbox/actions.js';
import { startStackHealth } from './inbox/health.js';

/* ---------- Gate: server-computed capability, identical to /api/alerts ----
 * The inbox sits at the same privacy tier as the findings console (analyst+),
 * so it reuses the findingsConsole capability rather than inventing a
 * parallel one that could drift from the API's gate.
 * Gate helper: lib/form.js (AIM-1113). */
await requireCapability('findingsConsole', init, 'alert inbox');

async function init(me) {
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/inbox.css';
  document.head.appendChild(link);

  /* Toasts: findings.js owns the stack and shares this module's gate, so it
   * is already there; create it only if the console module is absent. */
  let toastStack = document.querySelector('#toasts');
  if (!toastStack) {
    toastStack = document.createElement('div');
    toastStack.id = 'toasts';
    toastStack.setAttribute('aria-live', 'polite');
    document.body.appendChild(toastStack);
  }
  function toast(msg, kind = 'info') {
    const t = document.createElement('div');
    t.className = `toast ${kind}`;
    const m = document.createElement('span');
    m.className = 't-msg';
    m.textContent = msg;
    t.appendChild(m);
    toastStack.appendChild(t);
    setTimeout(() => t.remove(), 8_000);
  }

  /* ---------- Nav tab, next to Findings ---------- */
  moduleTab({
    view: 'inbox',
    label: 'Alerts',
    icon: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg>',
  });

  /* ---------- View section ---------- */
  const section = moduleSection({ view: 'inbox', html: `
    <div class="banner info">AI tool-governance alerts — detector matches, unapproved tools, data-exposure classes and related signals on the shared bus. Ack and snooze are shell-side state recorded in the audit trail; source stores are never modified. Each card shows tool / session / rule / user / repo when the publisher supplied them.</div>
    <div class="controls-row inbox-controls">
      <div class="segmented" id="inbox-sev" role="group" aria-label="Severity filter (multi-select)">
        ${SEVERITIES.map((s) => `<button type="button" data-sev="${s}" aria-pressed="false">${s}</button>`).join('')}
      </div>
      <div class="segmented" id="inbox-pil" role="group" aria-label="Source filter (multi-select)">
        ${PILLARS.map((p) => `<button type="button" data-pil="${p}" aria-pressed="false">${esc(PILLAR_LABELS[p] ?? p.replace(/_/g, ' '))}</button>`).join('')}
      </div>
      <label class="picker">Filter loaded alerts:
        <input type="text" id="inbox-text" placeholder="tool / rule / user / title (loaded page only)" autocomplete="off" style="width:18em" />
      </label>
      <button type="button" class="btn-control" id="inbox-refresh">Refresh</button>
    </div>
    <div class="inbox-dropped" id="inbox-dropped" role="status" hidden></div>
    <div class="panel">
      <h2>Alerts <span class="hint">AI-native cards — tool, session, rule, exposure, user, repo</span></h2>
      <div class="inbox-pillars" id="inbox-pillars"></div>
      <div id="inbox-list"></div>
      <div class="inbox-pager">
        <button type="button" class="btn-control" id="inbox-more" hidden>Load more</button>
        <span class="hint" id="inbox-page-hint"></span>
      </div>
    </div>` });
  document.querySelector('main').appendChild(section);

  resetInboxCtx({ section, me, toast });

  registerModuleView('inbox', {
    onActivate: () => {
      const { state } = inboxCtx;
      if (state.alerts.length === 0 && !state.busProblem) {
        reload().catch((err) => showProblem(err));
      }
    },
  });

  bindInboxActions();
  bindInboxFilters();

  /* ---------- stack health strip + pillar deep links ---------- */

  const healthEl = document.createElement('span');
  healthEl.id = 'stack-health';
  healthEl.className = 'stack-health';
  healthEl.hidden = true;
  const pipelineChip = document.querySelector('#pipeline-health');
  if (pipelineChip) pipelineChip.after(healthEl);
  else document.querySelector('.controls')?.appendChild(healthEl);

  startStackHealth(healthEl);
}

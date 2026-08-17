/* — Case / investigation workflow.
 *
 * Self-contained module (same pattern as findings.js): injects nav tab, view
 * section, and stylesheet at runtime. Gated on findingsConsole — cases attach
 * findings and user pseudonyms, so the privacy bar matches /api/findings.
 *
 * Route: `#/cases` list · `#/cases/<id>` detail (module drill via router).
 * Matched content and cleartext identity are never stored or rendered.
 *
 * Split (mirroring the inbox policy /
 * compliance splits) — the view's concerns live in sibling modules:
 *   ./cases/state.js   shared view-private casesCtx + status pill
 *   ./cases/nav.js     hash-driven list ↔ detail pane navigation
 *   ./cases/list.js    list pane: filters, summary cards, rows, nav badge
 *   ./cases/detail.js  detail pane: transitions, evidence, notes, timeline
 *   ./cases/create.js  "Open case" create form
 *
 * This file wires the gate, stylesheet, nav tab, view section, and module
 * view registration. Keep it thin — new cases code goes in a sibling module.
 */

import { CASE_SEVERITIES } from './lib/cases.js';
import { registerModuleView } from './lib/router.js';
import { moduleTab, moduleSection } from './lib/a11y.js';
import { esc } from './lib/dom.js';
import { requireCapability } from './lib/form.js';
import { casesCtx, resetCasesCtx } from './cases/state.js';
import { activate } from './cases/nav.js';
import { bindListFilters, initBadge } from './cases/list.js';
import { bindCreateForm } from './cases/create.js';

/* Gate: server-computed capability, identical to /api/cases — the shared
 * lib/form.js helper owns the /api/me fetch and the 401 login redirect. */
await requireCapability('findingsConsole', init, 'cases workflow');

async function init() {
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/cases.css';
  document.head.appendChild(link);

  moduleTab({
    view: 'cases',
    label: 'Cases ',
    icon: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 20V4a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/><rect width="20" height="14" x="2" y="6" rx="2"/></svg>',
    extra: '<span id="cases-badge" class="badge" hidden></span>',
  });

  const section = moduleSection({
    view: 'cases',
    className: 'cases-view',
    html: `
    <div class="banner info">Investigation cases — open a case, attach findings / users / tools (refs only), track status, export. Restricted to the security group. Matched content is never stored.</div>
    <div class="cards" id="case-cards"></div>
    <div id="case-list-pane">
      <div class="controls-row case-controls">
        <label class="picker">Status: <select id="case-status-filter">
          <option value="active" selected>Active (not closed)</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="contained">Contained</option>
          <option value="closed">Closed</option>
          <option value="all">All</option>
        </select></label>
        <label class="picker">Severity: <select id="case-sev-filter">
          <option value="all" selected>all</option>
          ${CASE_SEVERITIES.map((s) => `<option value="${s}">${s}</option>`).join('')}
        </select></label>
        <button type="button" class="btn primary" id="case-new-btn">Open case</button>
        <a class="btn-export" id="case-export-list" href="/api/cases?format=csv&limit=200" download>CSV</a>
      </div>
      <div class="case-create panel" id="case-create" hidden>
        <h2>Open investigation case</h2>
        <form id="case-create-form" class="case-form">
          <label>Title <input type="text" id="case-title" name="title" maxlength="200" required autocomplete="off" placeholder="e.g. Unsanctioned tool cluster on eng laptops" /></label>
          <label>Severity <select id="case-severity" name="severity" required>
            ${CASE_SEVERITIES.map((s) => `<option value="${s}" ${s === 'high' ? 'selected' : ''}>${s}</option>`).join('')}
          </select></label>
          <label class="case-form-full">Description <textarea id="case-desc" name="description" maxlength="4000" rows="3" placeholder="What is under investigation? (no secrets / no prompt content)"></textarea></label>
          <label class="case-form-full">Seed finding IDs <span class="hint">optional, comma-separated</span>
            <input type="text" id="case-seed-findings" autocomplete="off" placeholder="uuid, uuid, …" />
          </label>
          <label class="case-form-full">Seed user refs <span class="hint">optional HMAC pseudonyms, comma-separated</span>
            <input type="text" id="case-seed-users" autocomplete="off" />
          </label>
          <label class="case-form-full">Seed tools <span class="hint">optional tool names, comma-separated</span>
            <input type="text" id="case-seed-tools" autocomplete="off" placeholder="kilo-code, …" />
          </label>
          <div class="case-form-actions">
            <button type="submit" class="btn primary">Create case</button>
            <button type="button" class="btn" id="case-create-cancel">Cancel</button>
            <span class="case-form-err" id="case-create-err" role="alert"></span>
          </div>
        </form>
      </div>
      <div class="panel">
        <h2>Cases <span class="hint">active first · severity · newest update</span></h2>
        <div id="cases-list"></div>
      </div>
    </div>
    <div id="case-detail-pane" hidden></div>`,
  });
  document.querySelector('main').appendChild(section);

  resetCasesCtx({ section });

  registerModuleView('cases', {
    drill: true,
    onActivate: () =>
      activate().catch((err) => {
        casesCtx.listEl.innerHTML = `<div class="err" role="alert">${esc(err.message)}</div>`;
      }),
  });

  bindCreateForm();
  bindListFilters();
  initBadge();
}

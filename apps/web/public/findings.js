/* AIM-70 — Security findings triage console. Orchestrator only.
 *
 * Self-contained module: injects its own nav tab, view section, stylesheet,
 * toast stack and polling loop at runtime. Kept separate from app.js so the
 * findings console (a distinct, security-gated bounded context with its own
 * state and polling) can evolve without touching the dashboard core — and so
 * parallel frontend work on app.js/index.html cannot clobber it.
 *
 * Split (AIM-1140, mirroring the AIM-1135 security split) — the panels live
 * in sibling modules with clear ownership:
 *   ./findings/state.js        shared view-private fctx + constants + rule/evidence caches
 *   ./findings/row.js          inbox row markup + disposition history (AIM-223)
 *   ./findings/triage.js       disclosure keyboard path (AIM-711), triage + bulk mutations (AIM-94)
 *   ./findings/saved-views.js  saved filter views (AIM-94/587) + hash round-trip
 *   ./findings/export.js       CSV/JSON metadata-only export (AIM-590)
 *
 * This file wires bootstrap, fetches, paints the KPI cards, and calls the
 * panels in order. Keep it thin — new panel code goes in a sibling module.
 *
 * Privacy gate mirrors the API: /api/findings is restricted to the security
 * group, so this module only activates for those users. Triage transitions go
 * through PATCH /api/findings/:id and are recorded in the immutable audit
 * trail (AIM-27). Findings carry detector metadata and pseudonyms only —
 * matched content is never stored or displayed.
 *
 * AIM-481: Overview was the universal post-login front page. AIM-707 lets the
 * SOC home persona land bare arrivals on Findings via app.js + home-role.js —
 * this module itself must still never steal an explicit destination.
 */

import { BULK_TARGETS } from './lib/triage.js';
import { buildOutcomeIndex } from './lib/auto-triage.js';
import { navigateToView, registerModuleView } from './lib/router.js';
import { moduleTab, moduleSection } from './lib/a11y.js';
import { indexFixtureRegistry } from './lib/fingerprints.js';
import { fmtInt } from './lib/format.js';
import { esc } from './lib/dom.js';
import { card, emptyState, EMPTY } from './lib/components.js';
import { bindPlaybookProgress } from './lib/playbooks.js';
import { isHighSeverityForEvidence } from './lib/compliance-evidence.js';
import { api } from './lib/api.js';
import { requireCapability } from './lib/form.js';
import {
  SEV_RANK,
  BULK_LABEL,
  POLL_MS,
  fctx,
  resetFindingsCtx,
  ruleMap,
  ensureEvidenceIndex,
} from './findings/state.js';
import { findingRow } from './findings/row.js';
import { syncBulkUI, bindFindingsList, bindBulkBar } from './findings/triage.js';
import { setupSavedViews } from './findings/saved-views.js';
import { syncExportLinks, bindExport } from './findings/export.js';

/* ---------- Gate: server-computed capability (same gate as /api/findings) ----------
 * /api/me.capabilities.findingsConsole is the API's exact SECURITY_GROUP
 * match surfaced to the UI. Do not reintroduce client-side group-name
 * sniffing (g.includes('security')) — it misfires on any unrelated group
 * whose name merely contains "security". Gate helper: lib/form.js (AIM-1113). */
await requireCapability('findingsConsole', init, 'findings console');

async function init() {
  resetFindingsCtx();

  // Stylesheet
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/findings.css';
  document.head.appendChild(link);

  // AIM-541: optional fixture fingerprint allowlist for cluster-A triage hints.
  // Registry is static JSON (HMAC fingerprints only). Dogfood/prod must deploy
  // a fleet-salt-generated copy — the committed CI salt_id will not match live
  // events. Failure to load is non-fatal; hints simply stay off.
  try {
    const regRes = await fetch('/fixture-fingerprint-registry.json', { cache: 'no-cache' });
    if (regRes.ok) {
      fctx.fixtureIndex = indexFixtureRegistry(await regRes.json());
    }
  } catch {
    /* optional */
  }

  // Toast stack
  const toastStack = document.createElement('div');
  toastStack.id = 'toasts';
  toastStack.setAttribute('aria-live', 'polite');
  document.body.appendChild(toastStack);

  function toast(msg, kind = 'info', onClick) {
    const t = document.createElement('div');
    t.className = `toast ${kind}${onClick ? ' clickable' : ''}`;
    const dot = document.createElement('span');
    dot.className = 't-dot';
    const m = document.createElement('span');
    m.className = 't-msg';
    m.textContent = msg;
    const x = document.createElement('button');
    x.className = 't-close';
    x.textContent = '×';
    x.setAttribute('aria-label', 'Dismiss');
    const dismiss = () => {
      t.classList.add('out');
      setTimeout(() => t.remove(), 260);
    };
    x.addEventListener('click', (e) => {
      e.stopPropagation();
      dismiss();
    });
    if (onClick) {
      t.addEventListener('click', () => {
        onClick();
        dismiss();
      });
    }
    t.append(dot, m, x);
    toastStack.appendChild(t);
    setTimeout(dismiss, 12_000);
  }
  fctx.toast = toast;

  // AIM-1070: moduleTab places into the primary rail via nav-ia.
  const btn = moduleTab({
    view: 'findings',
    label: 'Findings ',
    icon: '<svg class="ico" viewBox="0 0 16 16"><path d="M8 1.5L2 4v3.5c0 3.8 2.6 6.3 6 7.5 3.4-1.2 6-3.7 6-7.5V4L8 1.5z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M8 5v3.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="8" cy="11" r="0.9" fill="currentColor"/></svg>',
    extra: '<span id="findings-badge" class="badge" hidden></span>',
  });
  fctx.btn = btn;

  // View section
  const section = moduleSection({ view: 'findings', html: `
    <div class="banner info">Security findings from the guardrail engine — restricted to the security group. Every triage transition is written to the immutable audit trail. Findings carry detector evidence and pseudonyms only; matched content is never stored.</div>
    <div class="cards" id="find-cards"></div>
    <div class="controls-row find-controls">
      <label class="picker">Status: <select id="find-status">
        <option value="open" selected>Open (new + acknowledged)</option>
        <option value="new">New</option>
        <option value="acknowledged">Acknowledged</option>
        <option value="resolved">Resolved</option>
        <option value="false_positive">False positive</option>
        <option value="all">All</option>
      </select></label>
      <label class="picker">Severity: <select id="find-severity">
        <option value="all" selected>all</option>
        <option value="critical">critical</option>
        <option value="high">high</option>
        <option value="medium">medium</option>
        <option value="low">low</option>
      </select></label>
      <span class="find-views" role="group" aria-label="Saved views">
        <label class="picker">View: <select id="find-view-select"><option value="">Custom filters</option></select></label>
        <button type="button" class="btn" id="find-view-save">Save current…</button>
        <button type="button" class="btn" id="find-view-rename" hidden>Rename</button>
        <button type="button" class="btn" id="find-view-update" hidden>Update filters</button>
        <button type="button" class="btn" id="find-view-delete" hidden>Delete</button>
        <span class="hint" id="find-view-hint" hidden>Save this filter set to come back to it</span>
      </span>
      <span class="find-export" role="group" aria-label="Export filtered findings for SOC handoff">
        <a class="btn-export" id="find-export-csv" href="/api/findings?format=csv&amp;limit=200&amp;status=new,acknowledged" download="aim-findings.csv" title="Download current filtered findings as CSV (metadata only — no prompt content)">CSV</a>
        <button type="button" class="btn-export" id="find-export-json" title="Download current filtered findings as JSON (metadata only — no prompt content)">JSON</button>
      </span>
    </div>
    <div class="find-view-form" id="find-view-form" hidden>
      <input type="text" id="find-view-name" maxlength="80" placeholder="View name (1–80 chars)" autocomplete="off" />
      <button type="button" class="btn primary" id="find-view-confirm">Save view</button>
      <button type="button" class="btn" id="find-view-cancel">Cancel</button>
      <span class="find-form-err" id="find-view-err" role="alert"></span>
    </div>
    <div class="panel">
      <h2 id="findings-inbox-heading">Findings inbox <span class="hint">severity-ranked — critical first, then newest · activate a finding to triage (Enter/Space; Escape closes)</span></h2>
      <div class="find-bulkbar" id="find-bulkbar" hidden role="region" aria-label="Bulk triage">
        <b id="find-bulk-count"></b>
        <input type="text" class="find-bulk-note" id="find-bulk-note" placeholder="Shared note — required to resolve; recorded in the audit trail" autocomplete="off" aria-label="Shared triage note for selected findings" />
        ${BULK_TARGETS.map((t) => `<button type="button" class="btn" data-bulk="${t}">${BULK_LABEL[t]}</button>`).join('')}
        <button type="button" class="btn" id="find-bulk-clear">Clear</button>
      </div>
      <div class="find-list-head"><label><input type="checkbox" id="find-select-all" /> select all shown</label></div>
      <div id="findings-list" role="list" aria-labelledby="findings-inbox-heading"></div>
    </div>` });
  document.querySelector('main').appendChild(section);
  fctx.section = section;
  fctx.list = section.querySelector('#findings-list');
  const { state, list } = fctx;

  /* AIM-153: `#/findings` is a real route. The tab above is an ordinary
   * data-view button — app.js's delegated #tabs handler navigates it like any
   * static tab — and route() calls this to render. Nothing here touches
   * `.active` classes: showing the section is the router's job, and the two
   * disagreeing about what was on screen is what produced AIM-152. */

  async function loadFindings() {
    const rules = await ruleMap();
    // Export links track status + severity + rule_id (AIM-590).
    syncExportLinks();
    // Cards always reflect the full open inbox, independent of the filters,
    // so posture stays glanceable while you slice the list below.
    // AIM-442: summary endpoint is the source of truth for unhandled criticals,
    // age buckets, and SLA breaches — limit=200 list samples can under-count.
    const [newRes, ackRes, closedRes, summary] = await Promise.all([
      api('/api/findings?status=new&limit=200'),
      api('/api/findings?status=acknowledged&limit=200'),
      // AIM-702: closed outcomes for auto-triage hints (metadata only).
      api('/api/findings?status=resolved,false_positive&limit=200').catch(() => ({ findings: [] })),
      api('/api/findings/summary').catch(() => null),
    ]);
    fctx.outcomeIndex = buildOutcomeIndex(closedRes.findings ?? []);
    const open = [...newRes.findings, ...ackRes.findings];
    const bySev = (s) => open.filter((f) => f.severity === s).length;
    const unhandledCrit = summary?.unhandledCritical ?? open.filter((f) => f.severity === 'critical' && f.status === 'new').length;
    const slaBreaches = summary?.slaBreaches?.count ?? open.filter((f) => f.slaBreached).length;
    const oldestH = summary?.oldestCritical?.ageHours;
    const ageHint = summary?.ageBuckets
      ? Object.entries(summary.ageBuckets).filter(([, n]) => n > 0).map(([k, n]) => `${k}:${n}`).join(' · ')
      : '';
    const slaH = summary?.sla?.criticalAckHours ?? 4;
    section.querySelector('#find-cards').innerHTML = [
      card('Unhandled criticals', fmtInt(unhandledCrit), unhandledCrit > 0 ? 'bad' : 'good'),
      card(`SLA breaches (>${slaH}h)`, fmtInt(slaBreaches), slaBreaches > 0 ? 'bad' : 'good'),
      card('Open critical', fmtInt(summary?.openCritical ?? bySev('critical')), (summary?.openCritical ?? bySev('critical')) > 0 ? 'bad' : 'good'),
      card('Open high', fmtInt(summary?.bySeverity?.high ?? bySev('high')), (summary?.bySeverity?.high ?? bySev('high')) > 0 ? 'bad' : ''),
      card('Oldest critical age', oldestH != null ? `${oldestH}h` : '—', oldestH != null && oldestH > slaH ? 'bad' : ''),
      card('Open age mix', ageHint || '—'),
    ].join('');

    let findings;
    if (state.fstatus === 'open') {
      findings = open;
    } else {
      const status = state.fstatus === 'all' ? '' : `&status=${state.fstatus}`;
      findings = (await api(`/api/findings?limit=200${status}`)).findings;
    }
    if (state.fsev !== 'all') findings = findings.filter((f) => f.severity === state.fsev);
    findings.sort(
      (a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9) || new Date(b.detectedAt) - new Date(a.detectedAt)
    );
    // AIM-925: hydrate rule→control index when any high/critical row needs it
    // and the API has not already attached complianceEvidence on the finding.
    const needsIndex = findings.some(
      (f) =>
        isHighSeverityForEvidence(f.severity) &&
        !(f.complianceEvidence || f.compliance_evidence)
    );
    if (needsIndex) await ensureEvidenceIndex();
    // The loaded list changed — drop any stale selection before re-rendering.
    fctx.selected.clear();
    fctx.currentIds = findings.map((f) => f.findingId);
    syncBulkUI();
    list.innerHTML = findings.length
      ? findings.map((f) => findingRow(f, rules)).join('')
      : state.fstatus === 'open' && state.fsev === 'all'
        ? emptyState(EMPTY.findingsOpen)
        : emptyState(EMPTY.findingsFiltered);
    // AIM-710: checkbox progress for guided playbooks (delegation, once per list).
    bindPlaybookProgress(list);
  }
  fctx.loadFindings = loadFindings;

  // Wire the extracted panels.
  bindExport();
  bindFindingsList();
  bindBulkBar();
  const views = setupSavedViews();

  section.querySelector('#find-status').addEventListener('change', (e) => {
    state.fstatus = e.target.value;
    views.markCustom();
    loadFindings().catch((err) => (list.innerHTML = `<div class="err">${esc(err.message)}</div>`));
  });
  section.querySelector('#find-severity').addEventListener('change', (e) => {
    state.fsev = e.target.value;
    views.markCustom();
    loadFindings().catch((err) => (list.innerHTML = `<div class="err">${esc(err.message)}</div>`));
  });

  registerModuleView('findings', {
    onActivate: () =>
      views.activateFindings().catch((err) => {
        list.innerHTML = `<div class="err">${esc(err.message)}</div>`;
      }),
  });
  /** Send the operator here through the URL (used by the critical-finding toast). */
  const show = () => {
    if (!navigateToView('findings')) views.activateFindings().catch(() => {});
  };

  /* ---------- New-critical polling: nav badge + toast notifications ---------- */
  const seenCritical = new Set();
  let criticalSeeded = false;

  async function pollCritical(silent = false) {
    try {
      const d = await api('/api/findings?status=new&severity=critical&limit=50');
      // First poll only seeds the seen-set — existing criticals don't toast.
      const fresh = criticalSeeded ? d.findings.filter((f) => !seenCritical.has(f.findingId)) : [];
      d.findings.forEach((f) => seenCritical.add(f.findingId));
      criticalSeeded = true;
      const badge = btn.querySelector('#findings-badge');
      badge.hidden = d.total === 0;
      badge.textContent = d.total > 99 ? '99+' : String(d.total);
      if (!silent) {
        fresh.slice(0, 3).forEach((f) => toast(`Critical finding: ${f.title}`, 'crit', show));
      }
    } catch {
      /* findings API briefly unavailable — badge stays as-is until next poll */
    }
  }
  fctx.pollCritical = pollCritical;

  await loadFindings().catch(() => {}); // pre-warm so first tab open is instant
  views.loadViews(); // pre-warm saved views (silent on failure)
  pollCritical();
  setInterval(pollCritical, POLL_MS);
  // AIM-481: do not land security-group users on Findings. Overview is the
  // guaranteed post-login front page; Findings is reached via the nav or KPI.
}

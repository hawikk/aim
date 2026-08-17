/* AIM-87 / AIM-99 / AIM-693 / AIM-694 / AIM-695 — Compliance evidence + control map.
 *
 * Self-contained module, same pattern as rules.js / findings.js: injects its
 * own nav tab, view section and stylesheet at runtime, activates on
 * capabilities.compliance (same gate as /api/compliance/report).
 *
 * Renders findings grouped by compliance framework control (EU AI Act
 * articles, OWASP LLM Top 10, NIST AI RMF, ISO/IEC 42001) with live
 * pass/fail/unknown status (AIM-694), counts, and drill-through to the
 * underlying findings, plus the regulator-ready exports (CSV/JSON/signed
 * evidence bundle) carrying the audit-chain verification result and policy_hash.
 *
 * AIM-99: posture history — weekly + on-demand snapshots stored server-side
 * (GET/POST /api/compliance/snapshots); any snapshot renders the exact
 * report captured at that time (including control statuses).
 *
 * AIM-693: self-serve offline pack for non-engineer auditors — one ZIP with
 * SUMMARY, report JSON/CSV, signed evidence bundle, SHA256SUMS, README.
 * Built client-side from the existing report APIs (no new backend formats).
 *
 * AIM-695: every active guardrail control → framework control IDs with live
 * status, plus an explicit gaps list (missing mappings + unmonitored controls).
 * AIM-696: `#/compliance?framework=&control=` deep-links from high-sev
 * finding control chips scroll/highlight the matching control row.
 *
 * Split (AIM-1172, mirroring the AIM-1140 findings / AIM-1147 rules /
 * AIM-1157 mcp / AIM-1163 activity splits) — the panels live in sibling
 * modules with clear ownership:
 *   ./compliance/state.js         shared view-private cmpCtx + period/error helpers
 *   ./compliance/badges.js        audit-chain + live control status badges (pure)
 *   ./compliance/offline-pack.js  AIM-693 auditor offline pack (ZIP) export
 *   ./compliance/control-map.js   AIM-695 control → framework map + gaps panel
 *   ./compliance/frameworks.js    per-framework panels + rule coverage detail
 *   ./compliance/report.js        report load + render (live or snapshot)
 *   ./compliance/snapshots.js     AIM-99 posture history panel
 *   ./compliance/drillthrough.js  control/rule drill-through + AIM-696 deep-links
 *
 * This file wires the tab, the view section, the controls, and the panels in
 * order. Keep it thin — new panel code goes in a sibling module.
 */

import { registerModuleView } from './lib/router.js';
import { moduleTab, moduleSection } from './lib/a11y.js';
import { api } from './lib/api.js';
import { cmpCtx, resetComplianceCtx, showErr, periodQuery } from './compliance/state.js';
import { exportOfflinePack } from './compliance/offline-pack.js';
import { load } from './compliance/report.js';
import { loadSnapshots } from './compliance/snapshots.js';
import { bindRuleLinkClicks } from './compliance/drillthrough.js';

/* ---------- Gate: server-computed capability (same gate as the API) ----------
 * capabilities.compliance is true for analyst, auditor, viewer and admin —
 * this is the auditor's primary surface alongside the audit trail. */
const me = await api('/api/me').catch(() => null);
if (me?.capabilities?.compliance) {
  try {
    init();
  } catch (err) {
    console.error('compliance view failed to start:', err);
  }
}

function init() {
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/compliance.css';
  document.head.appendChild(link);

  // Nav tab after Rules (or Findings/Security as fallback anchors).
  moduleTab({
    view: 'compliance',
    label: 'Compliance',
    icon: '<svg class="ico" viewBox="0 0 16 16"><path d="M8 1.5l5.5 2.5v4c0 3.5-2.3 5.7-5.5 6.5-3.2-.8-5.5-3-5.5-6.5V4L8 1.5z" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/><path d="M5.5 8l1.8 1.8L10.8 6" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  });

  const section = moduleSection({ view: 'compliance', html: `
    <div class="banner info" id="cmp-scope"></div>

    <section class="panel cmp-portal" aria-labelledby="cmp-portal-title">
      <h2 id="cmp-portal-title">Auditor offline pack <span class="hint">self-serve · complete period export · checksums included</span></h2>
      <p class="cmp-portal-lead" id="cmp-portal-lead">
        Download one ZIP an external auditor can open without product access or engineering help.
        Contains SUMMARY, full report (JSON + CSV), signed evidence bundle, <code>SHA256SUMS</code>, and a README with
        <code>sha256sum -c</code> steps.
      </p>
      <div class="controls-row cmp-portal-controls">
        <label class="picker">From: <input type="date" id="cmp-from"></label>
        <label class="picker">To: <input type="date" id="cmp-to"></label>
        <button type="button" class="btn-export" id="cmp-apply">Apply period</button>
        <button type="button" class="btn-export cmp-pack-btn" id="cmp-pack" title="Build and download the offline evidence pack (ZIP with SHA-256 checksums)">
          Download offline pack (.zip)
        </button>
      </div>
      <div class="cmp-pack-status" id="cmp-pack-status" role="status" aria-live="polite"></div>
      <details class="cmp-pack-details">
        <summary>What is in the pack</summary>
        <ul class="cmp-pack-contents">
          <li><code>README.txt</code> — how to verify checksums offline (no Node required)</li>
          <li><code>SUMMARY.txt</code> — one-page executive summary for the period</li>
          <li><code>report.json</code> / <code>report.csv</code> — full compliance report</li>
          <li><code>evidence-bundle.json</code> — signed, audit-chain-anchored bundle</li>
          <li><code>SHA256SUMS</code> — GNU <code>sha256sum -c</code> listing</li>
          <li><code>MANIFEST.json</code> — machine-readable inventory + pack metadata</li>
        </ul>
      </details>
      <div class="controls-row cmp-single-exports" role="group" aria-label="Individual evidence exports">
        <span class="hint">Single-file exports:</span>
        <a class="btn-export" id="cmp-csv" href="/api/compliance/report?format=csv" download>CSV report</a>
        <a class="btn-export" id="cmp-json" href="/api/compliance/report" target="_blank" rel="noopener">JSON</a>
        <a class="btn-export" id="cmp-bundle" href="/api/compliance/report?format=bundle" download title="Signed, immutable JSON bundle hash-linked to the audit chain">Evidence bundle</a>
      </div>
    </section>

    <div class="cards" id="cmp-cards"></div>

    <section class="panel cmp-map-panel" aria-labelledby="cmp-map-title">
      <h2 id="cmp-map-title">Active control → framework map <span class="hint">every live guardrail · AI Act / NIST / ISO / OWASP · live status</span></h2>
      <p class="cmp-map-lead" id="cmp-map-lead">
        Each row is an active product control (live guardrail rule). Cells list the framework
        control IDs it maps to, with the live pass/fail/unknown status of those controls for the selected period.
      </p>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Active control to framework map, scrollable">
        <table class="cmp-table cmp-map-table" id="cmp-control-map"></table>
      </div>
    </section>

    <section class="panel cmp-gaps-panel" aria-labelledby="cmp-gaps-title">
      <h2 id="cmp-gaps-title">Mapping gaps <span class="hint" id="cmp-gaps-hint">rule coverage + unmonitored framework controls</span></h2>
      <div id="cmp-gaps" role="region" aria-label="Compliance mapping gaps"></div>
    </section>

    <div id="cmp-frameworks"></div>
    <div class="panel"><h2>Rule coverage detail <span class="hint">raw control IDs per framework — gaps fail the report</span></h2>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Rule coverage table, scrollable"><table id="cmp-coverage"></table></div>
    </div>
    <div class="panel"><h2>Posture history <span class="hint" id="cmp-retention"></span></h2>
      <div class="controls-row"><button class="btn-export" id="cmp-snap-now">Snapshot now</button>
        <span class="hint">weekly snapshots are taken automatically; on-demand ones use the period above</span></div>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Snapshot history table, scrollable"><table id="cmp-snapshots"></table></div>
    </div>` });
  document.querySelector('main').appendChild(section);
  resetComplianceCtx(section);

  const { fromEl, toEl } = cmpCtx;
  const now = new Date();
  toEl.value = now.toISOString().slice(0, 10);
  fromEl.value = new Date(now.getTime() - 30 * 86400_000).toISOString().slice(0, 10);

  // AIM-153: `#/compliance` is a real route — the tab is an ordinary data-view
  // button handled by app.js, and route() calls this to render.
  registerModuleView('compliance', { onActivate: () => load().catch(showErr) });
  section.querySelector('#cmp-apply').addEventListener('click', () => load().catch(showErr));
  section.querySelector('#cmp-snap-now').addEventListener('click', async (e) => {
    const b = e.currentTarget;
    b.disabled = true;
    try {
      await api(`/api/compliance/snapshots?${periodQuery()}`, { method: 'POST' });
      await loadSnapshots();
    } catch (err) {
      showErr(err);
    } finally {
      b.disabled = false;
    }
  });
  section.querySelector('#cmp-pack').addEventListener('click', () => {
    exportOfflinePack().catch(() => {});
  });

  // Delegated rule drill-through, bound once (see compliance/drillthrough.js).
  bindRuleLinkClicks();
}

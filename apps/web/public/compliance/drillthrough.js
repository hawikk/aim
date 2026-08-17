/* Drill-through + deep-links for the Compliance evidence view (AIM-1172
 * split). Expanding a control lists its mapped rules with per-rule counts;
 * clicking a rule fetches the underlying findings. AIM-696: a
 * `#/compliance?framework=&control=` hash scrolls/highlights the row. */

import { esc } from '../lib/dom.js';
import { fmtInt, fmtTs } from '../lib/format.js';
import { tableHtml } from '../lib/components.js';
import { severityBadge } from '../lib/severity.js';
import { api } from '../lib/api.js';
import { parseComplianceControlFromHash } from '../lib/compliance-evidence.js';
import { cmpCtx } from './state.js';

const DRILL_FINDING_COLS = [
  { key: 'findingId', label: 'Finding', render: (f) => `<code>${esc(String(f.findingId).slice(0, 8))}…</code>` },
  { key: 'detectedAt', label: 'Detected', render: (f) => `<span class="mono" title="${esc(f.detectedAt)}">${esc(fmtTs(f.detectedAt))}</span>` },
  { key: 'severity', label: 'Severity', render: (f) => severityBadge(f.severity) },
  { key: 'status', label: 'Status', render: (f) => esc(f.status) },
  { key: 'title', label: 'Title', render: (f) => esc(f.title) },
];

/** Scroll + highlight a control row when the hash carries framework/control. */
export function focusControlFromHash() {
  const { framework, control } = parseComplianceControlFromHash(location.hash);
  if (!framework || !control) return;
  const section = cmpCtx.section;
  const row = section.querySelector(
    `tr.cmp-ctrl[data-fw="${CSS.escape(framework)}"][data-ctrl="${CSS.escape(control)}"]`,
  );
  if (!row) return;
  section.querySelectorAll('tr.cmp-ctrl.cmp-focus').forEach((el) => el.classList.remove('cmp-focus'));
  row.classList.add('cmp-focus');
  row.scrollIntoView({ behavior: 'smooth', block: 'center' });
  // Expand drill-through when the control has findings (same path as click).
  if (row.classList.contains('has-findings')) {
    row.click();
  }
}

/* Row-expansion handlers are bound per render (the rows themselves are
 * re-created each render). The delegated rule-click handler is bound once by
 * the orchestrator — it used to be re-bound on every render, stacking
 * duplicate listeners that toggled the findings box multiple times per click. */
export function wireDrillthrough(d) {
  cmpCtx.section.querySelectorAll('tr.cmp-ctrl.has-findings').forEach((tr) => {
    tr.style.cursor = 'pointer';
    tr.addEventListener('click', (e) => {
      if (e.target.classList.contains('cmp-rule-chip')) return;
      const drillRow = tr.nextElementSibling;
      const body = drillRow.querySelector('.cmp-drill-body');
      drillRow.hidden = !drillRow.hidden;
      if (drillRow.hidden || body.dataset.loaded) return;
      body.dataset.loaded = '1';
      const rules = d.frameworks.find((f) => f.id === body.dataset.fw)
        .controls.find((c) => c.id === body.dataset.ctrl).rules;
      body.innerHTML = rules.map((rid) => {
        const rule = d.rules.find((r) => r.id === rid);
        return `<div class="cmp-drill-rule">
          <button class="cmp-link" data-rule="${esc(rid)}">${esc(rid)}</button>
          <span class="hint">${esc(rule?.title ?? '')} — ${esc(fmtInt(rule?.findings.total ?? 0))} finding(s), ${esc(fmtInt(rule?.findings.open ?? 0))} open</span>
          <div class="cmp-findings" data-rule="${esc(rid)}"></div>
        </div>`;
      }).join('');
    });
  });
}

/** Bound once by the orchestrator: delegated click on a rule link fetches
 * the latest findings for that rule into its drill box. */
export function bindRuleLinkClicks() {
  cmpCtx.section.addEventListener('click', async (e) => {
    const b = e.target.closest('.cmp-link[data-rule]');
    if (!b) return;
    const box = cmpCtx.section.querySelector(`.cmp-findings[data-rule="${CSS.escape(b.dataset.rule)}"]`);
    if (box.dataset.loaded) { box.hidden = !box.hidden; return; }
    box.dataset.loaded = '1';
    box.hidden = false;
    box.textContent = 'loading…';
    try {
      const res = await api(`/api/findings?rule_id=${encodeURIComponent(b.dataset.rule)}&limit=10`);
      box.innerHTML = findingsTable(res.findings);
    } catch (err) {
      box.innerHTML = `<div class="err">${esc(err.message)}</div>`;
    }
  });
}

function findingsTable(findings) {
  // Shared tableHtml path (AIM-526 contract). Dual-merge had left a hand-rolled
  // early return in front of this block, which made the rest unreachable.
  const note = findings.length
    ? `<div class="hint">latest ${findings.length} — full list in the Findings tab</div>`
    : '';
  return `<table class="cmp-table">${tableHtml(DRILL_FINDING_COLS, findings, {
    caption: 'Findings raised by this rule, with detection time, severity and triage status',
    empty: { reason: 'no-data', title: 'No findings for this rule', body: 'This rule has not matched anything in the reporting period.' },
  })}</table>${note}`;
}

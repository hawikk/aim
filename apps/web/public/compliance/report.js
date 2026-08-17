/* Report load + render for the Compliance evidence view (AIM-1172 split).
 * load() fetches the live report for the selected period and refreshes the
 * export links; render() paints any report object — live or a stored snapshot
 * (snap banners the view as history). */

import { esc } from '../lib/dom.js';
import { fmtInt, fmtTs } from '../lib/format.js';
import { card } from '../lib/components.js';
import { api } from '../lib/api.js';
import { cmpCtx, periodQuery } from './state.js';
import { chainBadge } from './badges.js';
import { controlMapHtml, gapsHtml } from './control-map.js';
import { fwHtml, coverageHtml, deriveLegacyStatus } from './frameworks.js';
import { wireDrillthrough, focusControlFromHash } from './drillthrough.js';
import { loadSnapshots } from './snapshots.js';

export async function load() {
  const qs = periodQuery();
  const section = cmpCtx.section;
  section.querySelector('#cmp-csv').href = `/api/compliance/report?format=csv&${qs}`;
  section.querySelector('#cmp-json').href = `/api/compliance/report?${qs}`;
  section.querySelector('#cmp-bundle').href = `/api/compliance/report?format=bundle&${qs}`;
  const d = await api(`/api/compliance/report?${qs}`);
  render(d, null);
  await loadSnapshots();
}

// Render any report object — live or a stored snapshot. `snap` (when set)
// is { id, createdAt, kind, bundleHash } and banners the view as history.
export function render(d, snap) {
  const section = cmpCtx.section;
  section.querySelector('#cmp-scope').innerHTML =
    (snap
      ? `<b>Snapshot #${esc(snap.id)}</b> (${esc(snap.kind)}, taken ${esc(fmtTs(snap.createdAt))}, bundle hash <code>${esc(String(snap.bundleHash).slice(0, 12))}…</code>) — stored report below. `
      : '') +
    `<b>Scoping:</b> ${esc(d.scopingNote)} ` +
    `<span class="hint">policy v${esc(d.policy.version)} · hash <code>${esc(String(d.policy.contentHash).slice(0, 12))}…</code> · mapping v${esc(d.mapping.version)} · hash <code>${esc(String(d.mapping.contentHash).slice(0, 12))}…</code></span>`;

  const totalFindings = d.rules.reduce((n, r) => n + r.findings.total, 0);
  const openFindings = d.rules.reduce((n, r) => n + r.findings.open, 0);
  // Prefer server rollup (AIM-694); fall back for older stored snapshots.
  const cs = d.controlStatus ?? rollupControlStatus(d.frameworks);
  section.querySelector('#cmp-cards').innerHTML = [
    card({ label: 'Audit chain', valueHtml: chainBadge(d.auditChain) }),
    card({ label: 'Findings in period', valueHtml: esc(fmtInt(totalFindings)) }),
    card({ label: 'Open findings', valueHtml: esc(fmtInt(openFindings)) }),
    card({ label: 'Rule coverage', valueHtml: d.coverage.ok
      ? `<span class="cmp-badge tone-good">complete — ${esc(d.coverage.rules)} rules</span>`
      : `<span class="cmp-badge tone-bad">${esc(d.coverage.gaps.length)} gap(s)</span>` }),
    card({ label: 'Controls pass', valueHtml: `<span class="cmp-badge tone-good">${esc(fmtInt(cs.pass))} / ${esc(fmtInt(cs.total))}</span>` }),
    card({ label: 'Controls fail', valueHtml: cs.fail > 0
      ? `<span class="cmp-badge tone-bad">${esc(fmtInt(cs.fail))}</span>`
      : `<span class="cmp-badge tone-good">0</span>` }),
    card({ label: 'Controls unknown', valueHtml: cs.unknown > 0
      ? `<span class="cmp-badge tone-warn">${esc(fmtInt(cs.unknown))}</span>`
      : `<span class="cmp-badge tone-good">0</span>` }),
  ].join('');

  section.querySelector('#cmp-control-map').innerHTML = controlMapHtml(d);
  section.querySelector('#cmp-gaps').innerHTML = gapsHtml(d);
  section.querySelector('#cmp-frameworks').innerHTML = d.frameworks.map(fwHtml).join('');
  section.querySelector('#cmp-coverage').innerHTML = coverageHtml(d);
  wireDrillthrough(d);
  // AIM-696: honour control deep-link from a high-sev finding chip.
  focusControlFromHash();
}

/** Client-side rollup for pre-AIM-694 snapshots that lack controlStatus. */
function rollupControlStatus(frameworks) {
  const out = { pass: 0, fail: 0, unknown: 0, total: 0 };
  for (const fw of frameworks ?? []) {
    for (const c of fw.controls ?? []) {
      out.total += 1;
      const s = c.status ?? deriveLegacyStatus(c);
      if (s === 'pass' || s === 'fail' || s === 'unknown') out[s] += 1;
      else out.unknown += 1;
    }
  }
  return out;
}

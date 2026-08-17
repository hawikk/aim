/* Framework panels + rule coverage detail (AIM-1172 split).
 * fwHtml renders one panel per framework with live pass/fail/unknown rows and
 * the hidden drill-through row under each control; coverageHtml renders the
 * raw rule × framework mapping table (gaps fail the report). */

import { esc } from '../lib/dom.js';
import { fmtInt } from '../lib/format.js';
import { controlStatusBadge } from './badges.js';

/** Legacy fallback for pre-AIM-694 snapshots that lack control.status. */
export function deriveLegacyStatus(c) {
  if (!c.rules?.length) return 'unknown';
  if ((c.findings?.open ?? 0) > 0) return 'fail';
  return 'pass';
}

export function fwHtml(fw) {
  const rows = fw.controls.map((c) => {
    const f = c.findings;
    const status = c.status ?? deriveLegacyStatus(c);
    const reason = c.statusReason ?? '';
    const rowClass = [
      'cmp-ctrl',
      f.total > 0 ? 'has-findings' : '',
      status === 'fail' ? 'is-fail' : '',
      status === 'unknown' ? 'is-unknown' : '',
      status === 'pass' ? 'is-pass' : '',
    ].filter(Boolean).join(' ');
    return `<tr data-fw="${esc(fw.id)}" data-ctrl="${esc(c.id)}" class="${rowClass}">
      <td><b>${esc(c.ref)}</b></td>
      <td>${esc(c.title)}<div class="hint">${esc(c.summary)}</div></td>
      <td>${controlStatusBadge(status, reason)}</td>
      <td>${c.rules.map((r) => `<code class="cmp-rule-chip" data-rule="${esc(r)}">${esc(r)}</code>`).join(' ') || '<span class="hint">—</span>'}</td>
      <td class="num">${esc(fmtInt(f.total))}</td>
      <td class="num">${esc(fmtInt(f.open))}</td>
      <td class="num">${f.bySeverity.critical || ''}</td>
      <td class="num">${f.bySeverity.high || ''}</td>
      <td class="num">${f.bySeverity.medium || ''}</td>
      <td class="num">${f.bySeverity.low || ''}</td>
    </tr>
    <tr class="cmp-drill" hidden><td colspan="10"><div class="cmp-drill-body" data-fw="${esc(fw.id)}" data-ctrl="${esc(c.id)}"></div></td></tr>`;
  }).join('');
  return `<div class="panel"><h2>${esc(fw.name)} <span class="hint">live pass/fail/unknown · click a control with findings to drill through</span></h2>
    <div class="table-wrap" tabindex="0" role="region" aria-label="${esc(fw.name)} controls table, scrollable">
    <table class="cmp-table"><caption class="sr-only">Framework control live status and coverage for ${esc(fw.name)}</caption><thead><tr>
      <th scope="col">Control</th><th scope="col">Title</th><th scope="col">Status</th><th scope="col">Mapped rules</th><th scope="col" class="num">Findings</th><th scope="col" class="num">Open</th>
      <th scope="col" class="num">crit</th><th scope="col" class="num">high</th><th scope="col" class="num">med</th><th scope="col" class="num">low</th>
    </tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

export function coverageHtml(d) {
  const byRule = new Map();
  for (const g of d.coverage.gaps) {
    if (!byRule.has(g.ruleId)) byRule.set(g.ruleId, []);
    byRule.get(g.ruleId).push(`${g.framework}: ${g.reason}`);
  }
  const rows = d.rules.map((r) => {
    const maps = d.frameworks.map((fw) => {
      const m = r.mappings?.[fw.id];
      if (!m) return `<td><span class="cmp-badge tone-bad">missing</span></td>`;
      if (m.controls.length) {
        const ctrlById = new Map((fw.controls ?? []).map((c) => [c.id, c]));
        return `<td>${m.controls.map((id) => {
          const live = ctrlById.get(id);
          const st = live?.status
            ?? (live?.rules?.length
              ? ((live.findings?.open ?? 0) > 0 ? 'fail' : 'pass')
              : null);
          const badge = st ? ` ${controlStatusBadge(st, live?.statusReason)}` : '';
          return `<code>${esc(id)}</code>${badge}`;
        }).join(' ')}</td>`;
      }
      return `<td><span class="hint" title="${esc(m.na)}">n/a (justified)</span></td>`;
    }).join('');
    const gaps = byRule.get(r.id);
    return `<tr><td><code>${esc(r.id)}</code></td><td>${esc(r.title)}</td>${maps}<td>${gaps ? `<span class="cmp-badge tone-bad">${esc(gaps.join('; '))}</span>` : '<span class="cmp-badge tone-good">ok</span>'}</td></tr>`;
  }).join('');
  const fwHeads = d.frameworks.map((fw) => `<th scope="col">${esc(fw.name)}</th>`).join('');
  return `<caption class="sr-only">Rule coverage across frameworks with mapping status</caption>`
    + `<thead><tr><th scope="col">Rule</th><th scope="col">Title</th>${fwHeads}<th scope="col">Status</th></tr></thead><tbody>${rows}</tbody>`;
}

/* AIM-695: active control → framework map + mapping gaps panel (AIM-1172
 * split). Pure renderers over a report object; the only DOM touch is the
 * gaps-hint line, reached through cmpCtx. */

import { esc } from '../lib/dom.js';
import { fmtInt } from '../lib/format.js';
import { emptyState as _emptyState } from '../lib/components.js';
import {
  buildControlMapRows,
  listMappingGaps,
  frameworkColumnLabel,
  worstMappingStatus,
} from '../lib/control-framework-map.js';
import { controlStatusBadge } from './badges.js';
import { cmpCtx } from './state.js';

/** AIM-695: active control → framework control IDs with live status. */
export function controlMapHtml(d) {
  const frameworks = d.frameworks ?? [];
  const rows = buildControlMapRows(d);
  if (!rows.length) {
    return `<caption class="sr-only">Active control to framework map</caption>`
      + `<tbody><tr><td>${_emptyState({
        reason: 'no-data',
        title: 'No active controls',
        body: 'The live guardrail ruleset is empty — nothing to map.',
      })}</td></tr></tbody>`;
  }
  const heads = frameworks.map((fw) =>
    `<th scope="col">${esc(frameworkColumnLabel(fw))}</th>`).join('');
  const body = rows.map((row) => {
    const r = row.rule;
    const cells = frameworks.map((fw) => {
      const resolved = row.frameworks[fw.id];
      if (!resolved || resolved.kind === 'missing') {
        return `<td><span class="cmp-badge tone-bad">missing</span></td>`;
      }
      if (resolved.kind === 'na') {
        return `<td><span class="hint" title="${esc(resolved.na)}">n/a</span></td>`;
      }
      const chips = resolved.controls.map((c) =>
        `<span class="cmp-map-chip" title="${esc(c.title)} · ${esc(c.status)}">`
        + `<code>${esc(c.ref)}</code>${controlStatusBadge(c.status, c.statusReason)}`
        + `</span>`).join(' ');
      const worst = worstMappingStatus(resolved);
      return `<td data-map-status="${esc(worst)}">${chips}</td>`;
    }).join('');
    const mapCell = row.mapOk
      ? '<span class="cmp-badge tone-good">ok</span>'
      : `<span class="cmp-badge tone-bad" title="${esc(row.gapReasons.join('; '))}">gap</span>`;
    return `<tr class="cmp-map-row is-${esc(row.live.status)}">`
      + `<td><code>${esc(r.id)}</code><div class="hint">${esc(r.title ?? '')}</div></td>`
      + `<td>${controlStatusBadge(row.live.status, row.live.reason)}</td>`
      + `<td class="num">${esc(fmtInt(r.findings?.open ?? 0))}</td>`
      + `${cells}<td>${mapCell}</td></tr>`;
  }).join('');
  return `<caption class="sr-only">Active control to framework map with live status</caption>`
    + `<thead><tr>`
    + `<th scope="col">Active control</th><th scope="col">Live</th><th scope="col" class="num">Open</th>`
    + `${heads}<th scope="col">Map</th>`
    + `</tr></thead><tbody>${body}</tbody>`;
}

/** AIM-695: explicit gaps list for rule mappings + unmonitored framework controls. */
export function gapsHtml(d) {
  const gaps = listMappingGaps(d);
  const hint = cmpCtx.section.querySelector('#cmp-gaps-hint');
  if (hint) {
    hint.textContent = gaps.ok
      ? `maps complete for active controls · ${gaps.summary.unmonitored} unmonitored catalog control(s)`
      : `${gaps.summary.ruleGaps} rule gap(s) · ${gaps.summary.unmonitored} unmonitored · ${gaps.summary.unmappedFindings} stale finding rule(s)`;
  }
  if (!gaps.items.length) {
    return `<div class="cmp-gaps-empty">`
      + `<span class="cmp-badge tone-good">maps complete</span> `
      + `Every active control maps to AI Act / NIST / ISO / OWASP (or justified n/a). `
      + `No unmonitored framework controls.</div>`;
  }
  const ruleGaps = gaps.items.filter((i) => i.kind === 'rule_mapping');
  const unmonitored = gaps.items.filter((i) => i.kind === 'unmonitored_control');
  const stale = gaps.items.filter((i) => i.kind === 'unmapped_findings');

  const block = (title, tone, rows, emptyMsg) => {
    if (!rows.length) {
      return `<div class="cmp-gaps-block"><h3 class="cmp-gaps-sub">${esc(title)} `
        + `<span class="cmp-badge tone-good">0</span></h3>`
        + `<p class="hint">${esc(emptyMsg)}</p></div>`;
    }
    const lis = rows.map((g) => {
      if (g.kind === 'rule_mapping') {
        return `<li><code>${esc(g.ruleId)}</code> → <b>${esc(g.framework)}</b>: ${esc(g.reason)}</li>`;
      }
      if (g.kind === 'unmonitored_control') {
        return `<li><b>${esc(g.frameworkName || g.framework)}</b> `
          + `<code>${esc(g.controlRef)}</code> ${esc(g.controlTitle)} — ${esc(g.reason)}</li>`;
      }
      return `<li><code>${esc(g.ruleId)}</code> — ${esc(g.reason)}</li>`;
    }).join('');
    return `<div class="cmp-gaps-block"><h3 class="cmp-gaps-sub">${esc(title)} `
      + `<span class="cmp-badge ${tone}">${esc(fmtInt(rows.length))}</span></h3>`
      + `<ul class="cmp-gaps-list">${lis}</ul></div>`;
  };

  const banner = gaps.ok
    ? `<div class="cmp-gaps-banner tone-good"><span class="cmp-badge tone-good">active-control maps complete</span> `
      + `AI Act / NIST / ISO / OWASP rule mappings have no gaps. Unmonitored catalog controls (audit-event-only) are listed below for completeness.</div>`
    : `<div class="cmp-gaps-banner tone-bad"><span class="cmp-badge tone-bad">mapping gaps</span> `
      + `Fix rule coverage gaps before treating the multi-framework map as complete.</div>`;

  return banner
    + block('Rule → framework gaps', 'tone-bad', ruleGaps, 'Every active control maps to each framework (or justified n/a).')
    + block('Unmonitored framework controls', 'tone-warn', unmonitored, 'Every catalog control has at least one live mapped rule.')
    + block('Findings for unmapped rules', 'tone-warn', stale, 'No findings attributed to removed rules in this period.');
}

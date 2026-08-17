/* Row + state rendering for the Live Activity trail (AIM-1163 split, extracted
 * from activity.js). Pure renderers: everything here turns an event (or a
 * loading/empty/error spec) into HTML/rows and owns no fetch, timer, or
 * listener. */

import { fmtCost, fmtTs } from '../lib/format.js';
import { esc } from '../lib/dom.js';
import { entityHref } from '../lib/deeplinks.js';
import { state as dashState } from '../lib/runtime.js';
import { emptyState } from '../lib/components.js';

const BAND_CLASS = { green: 'score-green', amber: 'score-amber', red: 'score-red' };
const BAND_LABEL = { green: 'Low', amber: 'Med', red: 'High' };

/* Tokens are data: grouped thousands, mono, tabular. Rendered as a total with
 * the in/out split in the title — the split matters when reading cost, but two
 * more numeric columns would cost more scan-width than it buys. */
function fmtTokens(inTok, outTok) {
  const a = Number(inTok) || 0;
  const b = Number(outTok) || 0;
  if (a + b === 0) return '<span class="faint">—</span>';
  return `<span title="${a.toLocaleString('en-US')} in / ${b.toLocaleString('en-US')} out">${(a + b).toLocaleString('en-US')}</span>`;
}

function scoreBadge(score, band) {
  const cls = BAND_CLASS[band] ?? 'score-green';
  const tip = `Score ${score}/10 — ${BAND_LABEL[band] ?? band} risk`;
  return `<span class="score-badge ${cls}" title="${esc(tip)}">${score}</span>`;
}

/* Score factors expand inline in the cell rather than into an alert() dialog.
 * A modal to read six words is hostile in a stream you are scanning, and a
 * title-attribute tooltip is unreachable by keyboard and untruncatable. */
function flagsSummary(flags, factors) {
  const parts = [];
  if (flags?.length) {
    parts.push(flags.map((f) => `<span class="flag-chip ${f.category ?? ''}" title="${esc(f.detector ?? f.category)}">${esc(f.category ?? '?')}</span>`).join(' '));
  }
  if (factors?.length) {
    const items = factors.map((f) => '<li>'
      + `<span class="fx-label">${esc(f.label)}</span>`
      + `<span class="fx-weight">+${esc(String(f.weight))}</span>`
      + (f.detail ? `<span class="fx-detail">${esc(f.detail)}</span>` : '')
      + '</li>').join('');
    parts.push(
      '<button type="button" class="factors-link" aria-expanded="false">Why</button>'
      + `<ul class="factors-detail" hidden>${items}</ul>`,
    );
  }
  return parts.join(' ') || '<span class="faint">—</span>';
}

function toolCallsSummary(calls) {
  if (!calls?.length) return '';
  const classes = [...new Set(calls.map((c) => c.action_class).filter(Boolean))];
  return classes.map((ac) => `<span class="action-chip ${esc(ac)}">${esc(ac)}</span>`).join(' ');
}

/* An event whose identity could not be resolved is unattributed, not anonymous
 * and not broken. Label it so a reviewer reads it as a known coverage gap
 * (AIM-149) rather than as a UI failure. */
function userCell(pseudonym) {
  if (!pseudonym) {
    return '<span class="faint" title="Identity could not be resolved for this event — the collector reported no user reference.">unattributed</span>';
  }
  const shown = pseudonym.length > 11 ? `${pseudonym.slice(0, 10)}…` : pseudonym;
  // AIM-483 / AIM-589: drill-down via entityHref so ?days= survives the hop.
  // data-user stays for the legacy filter handoff.
  const href = entityHref('users', pseudonym, { days: dashState.days });
  return `<a class="pseudo-link" href="${esc(href)}" data-user="${esc(pseudonym)}" title="${esc(pseudonym)}">${esc(shown)}</a>`;
}

function toolCell(tool) {
  if (!tool) return '—';
  const href = entityHref('tools', tool, { days: dashState.days });
  return `<a href="${esc(href)}">${esc(tool)}</a>`;
}

export function buildRow(ev) {
  const tr = document.createElement('tr');
  tr.className = `act-row band-${ev.score_band ?? 'green'}`;
  tr.dataset.eventId = ev.event_id;
  tr.innerHTML = `
    <td class="act-ts mono" title="${esc(ev.ts)}">${esc(fmtTs(ev.ts))}</td>
    <td class="act-score">${scoreBadge(ev.security_score, ev.score_band)}</td>
    <td class="act-user">${userCell(ev.pseudonym)}</td>
    <td class="act-tool">${toolCell(ev.tool)}${toolCallsSummary(ev.tool_calls)}</td>
    <td class="act-model" title="${esc(ev.model)}">${esc(ev.model ? ev.model.replace(/^claude-/, 'cl-') : '—')}</td>
    <td class="act-event">${esc(ev.event_type ?? '—')}</td>
    <td class="act-tokens num">${fmtTokens(ev.tokens_in, ev.tokens_out)}</td>
    <td class="act-cost num">${fmtCost(ev.est_cost_usd)}</td>
    <td class="act-flags">${flagsSummary(ev.match_flags, ev.score_factors)}</td>
  `;
  return tr;
}

/* Column count — the loading/empty/error rows must span the whole table. */
export const COLS = 9;

/* Loading is a skeleton of the real table shape, not the word "Loading". The
 * row rhythm stays put when data lands, so the panel does not jump. */
export function skeletonRows(n = 12) {
  const cells = Array.from({ length: COLS }, () => '<td><span class="skel-line"></span></td>').join('');
  return Array.from({ length: n }, () => `<tr class="act-skel" aria-hidden="true">${cells}</tr>`).join('');
}

/* Empty and error states say what nothing means here and what to do next.
 * Both are one row spanning the table so the header stays readable. */
/* AIM-526: activity already drew no-data / filtered / error by hand — that is
 * where the shared emptyState() signature came from. Optional control HTML
 * (Retry / Clear filters) is appended inside the empty-state container. */
export function stateRow(spec, control = '') {
  const inner = emptyState(spec);
  if (!control) return `<tr class="empty-row"><td colspan="${COLS}">${inner}</td></tr>`;
  const withControl = inner.replace(/<\/div>\s*$/, `<div class="empty-action">${control}</div></div>`);
  return `<tr class="empty-row"><td colspan="${COLS}">${withControl}</td></tr>`;
}

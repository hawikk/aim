/* Badges for the Compliance evidence view (AIM-1172 split) — pure renderers.
 * The audit-chain badge (report cards) and the AIM-694 live pass/fail/unknown
 * control badge (control map, framework panels, coverage detail). */

import { esc } from '../lib/dom.js';
import { fmtInt } from '../lib/format.js';

export function chainBadge(chain) {
  if (!chain.enabled) return '<span class="cmp-badge tone-warn">audit chain not configured</span>';
  return chain.ok
    ? `<span class="cmp-badge tone-good">audit chain verified — ${esc(fmtInt(chain.records))} records</span>`
    : `<span class="cmp-badge tone-bad">AUDIT CHAIN FAILED — ${esc(chain.reason)}</span>`;
}

/** AIM-694: live continuous-monitoring badge for a single control. */
export function controlStatusBadge(status, reason) {
  const s = status || 'unknown';
  const tone = s === 'pass' ? 'tone-good' : s === 'fail' ? 'tone-bad' : 'tone-warn';
  const label = s === 'pass' ? 'pass' : s === 'fail' ? 'fail' : 'unknown';
  const title = reason ? ` title="${esc(reason)}"` : '';
  return `<span class="cmp-badge ${tone}"${title}>${esc(label)}</span>`;
}

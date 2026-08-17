/* Advanced (admins) panel for the Policy editor view (split).
 * Read-only summary of the per-rule enforcement flags from the loaded
 * guardrail policy settings — YAML-managed, edited via policy PR or the
 * Rules view thresholds, never here. */

import { esc } from '../lib/dom.js';
import { api } from '../lib/api.js';
import { enforcementRuleModes } from '../lib/policy-editor.js';
import { polCtx, modePill } from './state.js';

export async function loadAdvanced() {
  const { advanced, ruleModes } = polCtx;
  if (!advanced || !ruleModes) return;
  try {
    const d = await api('/api/guardrail/rules');
    const modes = enforcementRuleModes(d.settings);
    if (!modes.length) {
      ruleModes.innerHTML = '<span class="hint">No per-rule enforcement flags in the loaded policy settings.</span>';
      return;
    }
    ruleModes.innerHTML = modes.map((m) =>
      `<span class="chip" title="YAML-managed — edit via policy PR or Rules thresholds only for tunable fields">
        <code>${esc(m.id)}</code> · ${modePill(m.modeLabel)}
      </span>`).join('');
  } catch (err) {
    ruleModes.innerHTML = `<span class="pol-err" role="alert">${esc(err.message)}</span>`;
  }
}

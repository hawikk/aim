/* AIM-1007 — mount helper for the live Attribution health panel.
 *
 * Shared by Overview (SOC/Admin home) and Fleet so neither view imports the
 * other. Fetches GET /api/pipeline/attribution-health and paints the shell.
 */

import { $ } from '../lib/dom.js';
import { fmtInt, relTime } from '../lib/format.js';
import { api } from '../lib/runtime.js';
import { setVerifiedStamp } from '../lib/ui.js';
import { renderAttributionHealthHtml } from '../lib/attribution-health-ui.js';

let _attrHealthCss = false;

export function ensureAttrHealthCss() {
  if (_attrHealthCss || typeof document === 'undefined') return;
  if (document.querySelector('link[data-attr-health-css]')) {
    _attrHealthCss = true;
    return;
  }
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/attribution-health.css';
  link.dataset.attrHealthCss = '1';
  document.head.appendChild(link);
  _attrHealthCss = true;
}

/**
 * Load and render the Epic A attribution health panel into a host element.
 * @param {string|Element} hostSelector
 * @param {string|null} [verifiedSelector]
 * @returns {Promise<object|null>}
 */
export async function loadAttributionHealthPanel(hostSelector, verifiedSelector) {
  ensureAttrHealthCss();
  const host = typeof hostSelector === 'string' ? $(hostSelector) : hostSelector;
  if (!host) return null;
  host.innerHTML = '<div class="muted">Loading attribution health…</div>';
  try {
    const data = await api('/api/pipeline/attribution-health');
    if (verifiedSelector) setVerifiedStamp(verifiedSelector, data?.lastVerifiedAt);
    host.innerHTML = renderAttributionHealthHtml(data, { fmtInt, relTime });
    return data;
  } catch (err) {
    if (verifiedSelector) setVerifiedStamp(verifiedSelector, null);
    host.innerHTML = renderAttributionHealthHtml(null, {
      error: err?.message || String(err),
      fmtInt,
      relTime,
    });
    return null;
  }
}

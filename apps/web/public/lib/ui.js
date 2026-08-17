/* Cross-view UI helpers pure-moved from app.js (AIM-527). */
/* Import path must contain `lib/dom.js` so the AIM-523 import guard matches. */
import { esc, $ } from '../lib/dom.js';
import { state, setStatus } from './runtime.js';
import {
  SEVERITY_RANK, SEVERITY_BANDS, SEVERITY_FILTER_BANDS,
  severityBadge, severityBand, severityRowClass, severityColors,
  compareSeverity, worstSeverity, exposureBadge, sevPill,
} from './severity.js';

export {
  SEVERITY_RANK, SEVERITY_BANDS, SEVERITY_FILTER_BANDS,
  severityBadge, severityBand, severityRowClass, severityColors,
  compareSeverity, worstSeverity, exposureBadge, sevPill,
};

/* AIM-782 union repair: views/* still import the pre-split underscore aliases
 * that app.js used as module-private names. Re-export so DOM mounts do not
 * die on missing `_SEVERITY_RANK` / `_delta` (blocks every MODULE_SCRIPTS test). */
export {
  SEVERITY_RANK as _SEVERITY_RANK,
  severityBadge as _severityBadge,
  exposureBadge as _exposureBadge,
  sevPill as _sevPill,
};

export function verifiedStampHtml(iso) {
  if (!iso) {
    return '<span class="verified-stamp faint" title="Server did not return a verification timestamp">last verified: unknown</span>';
  }
  const d = new Date(iso);
  const abs = Number.isFinite(d.getTime())
    ? d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, 'Z')
    : String(iso);
  return `<span class="verified-stamp" title="End-to-end verification timestamp for this coverage claim">last verified end-to-end: ${esc(abs)}</span>`;
}

export function setVerifiedStamp(sel, iso) {
  const el = $(sel);
  if (!el) return;
  el.innerHTML = verifiedStampHtml(iso);
  el.hidden = false;
}

const ARROW_UP = '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m18 15-6-6-6 6"/></svg>';
const ARROW_DOWN = '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>';

export function delta(current, previous, { badWhen } = {}) {
  const cur = Number(current) || 0;
  const prev = Number(previous) || 0;
  if (prev === 0) {
    return '<div class="delta"><span class="base">no prior period data</span></div>';
  }
  const pct = ((cur - prev) / prev) * 100;
  if (Math.abs(pct) < 0.05) {
    return '<div class="delta"><span class="base">unchanged vs. previous period</span></div>';
  }
  const dir = pct > 0 ? 'up' : 'down';
  const tone = badWhen === dir ? 'bad' : badWhen ? 'good' : '';
  const magnitude = `${Math.abs(pct) >= 10 ? Math.abs(pct).toFixed(0) : Math.abs(pct).toFixed(1)}%`;
  return `<div class="delta" data-dir="${dir}"${tone ? ` data-tone="${tone}"` : ''}>`
    + (dir === 'up' ? ARROW_UP : ARROW_DOWN)
    + `<span>${magnitude}</span><span class="base">vs. previous ${state.days}d</span></div>`;
}

const REF_TITLE = 'Salted-HMAC pseudonym — the platform never stores the raw identity. Click to copy the full value.';

export function refCell(value, { href } = {}) {
  if (value == null || value === '') return '<span class="faint">—</span>';
  const full = String(value);
  const shown = full.length > 11 ? `${full.slice(0, 10)}…` : full;
  const inner = `<button type="button" class="ref" data-ref="${esc(full)}" title="${esc(REF_TITLE)}" aria-label="Pseudonym ${esc(full)}, click to copy">${esc(shown)}</button>`;
  return href ? `${inner} <a class="ref-open" href="${href}" aria-label="Open ${esc(full)}" title="Open detail">&rsaquo;</a>` : inner;
}

/** One delegated listener for every ref on the page — call once from app.js bootstrap. */
export function bindRefClipboard() {
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.ref');
    if (!btn) return;
    e.preventDefault();
    try {
      await navigator.clipboard.writeText(btn.dataset.ref);
      btn.dataset.copied = '1';
      setStatus(`Copied pseudonym ${btn.dataset.ref}`);
      setTimeout(() => { delete btn.dataset.copied; }, 1200);
    } catch {
      const r = document.createRange();
      r.selectNodeContents(btn);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(r);
      setStatus('Clipboard unavailable — the full pseudonym is selected, copy it manually.');
    }
  });
}

/* Underscore aliases for local helpers (severity aliases are above). */
export {
  delta as _delta,
  verifiedStampHtml as _verifiedStampHtml,
  setVerifiedStamp as _setVerifiedStamp,
  refCell as _refCell,
};


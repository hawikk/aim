/*: auditor offline pack panel (split).
 * Assembles the offline pack from the existing report endpoints and downloads
 * a ZIP. Fails closed — any missing artifact aborts the download with a clear
 * status (never a partial silent pack). */

import { esc } from '../lib/dom.js';
import { fmtInt } from '../lib/format.js';
import { api, apiText } from '../lib/api.js';
import { buildOfflinePack, triggerDownload } from '../lib/offline-pack.js';
import { cmpCtx, periodQuery, setPackStatus } from './state.js';

export async function exportOfflinePack() {
  const btn = cmpCtx.section.querySelector('#cmp-pack');
  const qs = periodQuery();
  if (btn) btn.disabled = true;
  setPackStatus('Building offline pack — fetching report, CSV, and signed bundle…', 'loading');
  try {
    const [report, csvText, bundle] = await Promise.all([
      api(`/api/compliance/report?${qs}`),
      apiText(`/api/compliance/report?format=csv&${qs}`),
      api(`/api/compliance/report?format=bundle&${qs}`),
    ]);
    if (!report || typeof report !== 'object') {
      throw new Error('Compliance report was empty — cannot build pack');
    }
    if (!csvText || !String(csvText).trim()) {
      throw new Error('CSV report was empty — cannot build pack');
    }
    if (!bundle || typeof bundle !== 'object') {
      throw new Error('Evidence bundle was empty — cannot build pack');
    }
    const exportedAt = new Date().toISOString();
    const pack = await buildOfflinePack({
      report,
      csvText,
      bundle,
      period: report.period ?? {
        from: cmpCtx.fromEl.value ? `${cmpCtx.fromEl.value}T00:00:00Z` : undefined,
        to: cmpCtx.toEl.value ? `${cmpCtx.toEl.value}T23:59:59Z` : undefined,
      },
      exportedAt,
    });
    triggerDownload(pack.filename, pack.zip, 'application/zip');
    const fileCount = pack.files.length;
    const hashShort = String(pack.packSha256).slice(0, 12);
    setPackStatus(
      `<span class="cmp-badge tone-good">Pack ready</span> `
      + `Downloaded <code>${esc(pack.filename)}</code> `
      + `(${esc(fmtInt(fileCount))} files · content inventory SHA-256 <code>${esc(hashShort)}…</code>). `
      + `Auditor next step: unzip, then <code>sha256sum -c SHA256SUMS</code>.`,
      'good',
    );
  } catch (err) {
    setPackStatus(
      `<span class="cmp-badge tone-bad">Pack failed</span> ${esc(err.message || String(err))}`,
      'bad',
    );
  } finally {
    if (btn) btn.disabled = false;
  }
}

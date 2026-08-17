/* Findings export (AIM-590, AIM-1140 split of findings.js). CSV/JSON export
 * mirrors the visible filters and is metadata-only — no prompt/response/
 * matched content. JSON is stripped to the metadata column set client-side
 * and scanned for privacy leaks before the download triggers. */
import { fctx } from './state.js';
import {
  buildFindingsExportQuery,
  buildFindingsExportUrl,
  buildMetadataExportPayload,
  exportFilename,
  privacyViolations,
  triggerDownload,
} from '../lib/findings-export.js';
import { api } from '../lib/api.js';
import { withBusy } from '../lib/form.js';

/* AIM-590: keep export targets in lockstep with visible filters (status,
 * severity, rule_id from saved views). CSV goes through the API attachment
 * path; JSON is fetched and stripped to the metadata column set client-side
 * so evidence blobs never leave with the handoff file. */
export function syncExportLinks() {
  const csv = fctx.section.querySelector('#find-export-csv');
  if (csv) {
    csv.href = buildFindingsExportUrl(fctx.state, 'csv');
    csv.setAttribute('download', exportFilename('csv'));
  }
}

async function exportJson() {
  const { section, state, toast } = fctx;
  const btn = section.querySelector('#find-export-json');
  await withBusy(btn, async () => {
    // Same filters as the CSV link; omit format so the list endpoint returns JSON.
    const data = await api(`/api/findings?${buildFindingsExportQuery(state)}`);
    const payload = buildMetadataExportPayload(data.findings ?? [], {
      exportedAt: new Date().toISOString(),
      status: state.fstatus,
      severity: state.fsev,
      ruleId: state.ruleId,
    });
    const leaks = privacyViolations(payload);
    if (leaks.length) {
      toast(`Export blocked — privacy scan failed (${leaks[0]})`, 'bad');
      return;
    }
    triggerDownload(
      exportFilename('json'),
      JSON.stringify(payload, null, 2),
      'application/json;charset=utf-8'
    );
    toast(`Exported ${payload.total} finding${payload.total === 1 ? '' : 's'} (metadata only)`, 'ok');
  }, { reenable: 'always' }).catch((err) => {
    toast(`JSON export failed: ${err.message}`, 'bad');
  });
}

export function bindExport() {
  fctx.section.querySelector('#find-export-json').addEventListener('click', () => {
    exportJson().catch(() => {});
  });
}

/* AIM-99: posture history panel (AIM-1172 split) — weekly + on-demand
 * snapshots stored server-side; any snapshot re-renders the exact report
 * captured at that time (including control statuses). */

import { esc } from '../lib/dom.js';
import { fmtInt, fmtTs } from '../lib/format.js';
import { table as dataTable } from '../lib/components.js';
import { api } from '../lib/api.js';
import { cmpCtx, showErr } from './state.js';
import { render } from './report.js';

const SNAPSHOT_COLS = [
  { key: 'takenAt', label: 'Taken', render: (s) => esc(fmtTs(s.takenAt ?? s.createdAt)) },
  { key: 'kind', label: 'Kind', render: (s) => esc(s.kind ?? s.type ?? '—') },
  { key: 'period', label: 'Period', render: (s) => esc(s.period ?? s.periodLabel ?? '—') },
  { key: 'findings', label: 'Findings', num: true, render: (s) => fmtInt(s.findings ?? s.findingCount ?? 0) },
  { key: 'open', label: 'Open', num: true, render: (s) => fmtInt(s.open ?? s.openCount ?? 0) },
  { key: 'chain', label: 'Audit chain', render: (s) => s.chainHtml ?? esc(s.chainStatus ?? '—') },
  { key: 'hash', label: 'Hash', render: (s) => `<code>${esc(String(s.hash ?? s.contentHash ?? '').slice(0, 12))}</code>` },
  { key: '_dl', label: 'Download', render: (s) => s.downloadHtml ?? '' },
];

export async function loadSnapshots() {
  const section = cmpCtx.section;
  const d = await api('/api/compliance/snapshots');
  section.querySelector('#cmp-retention').textContent =
    `retention: weekly ${d.retention.weeklySnapshotDays}d · on-demand ${d.retention.onDemandSnapshotDays}d`;
  const tbl = section.querySelector('#cmp-snapshots');
  if (!d.snapshots.length) {
    dataTable(tbl, SNAPSHOT_COLS, [], {
      caption: 'Compliance snapshot history with audit chain status',
      empty: {
        reason: 'no-data',
        title: 'No snapshots yet',
        body: 'The weekly job takes the first one automatically.',
      },
    });
    return;
  }
  const rows = d.snapshots.map((s) => `<tr>
    <td>${esc(fmtTs(s.createdAt))}</td>
    <td>${esc(s.kind)}</td>
    <td>${esc(fmtTs(s.period.from).slice(0, 10))} → ${esc(fmtTs(s.period.to).slice(0, 10))}</td>
    <td class="num">${esc(fmtInt(s.findings.total))}</td>
    <td class="num">${esc(fmtInt(s.findings.open))}</td>
    <td>${s.auditChainOk === null ? '<span class="hint">n/a</span>' : s.auditChainOk
      ? '<span class="cmp-badge tone-good">chain ok</span>'
      : '<span class="cmp-badge tone-bad">chain FAILED</span>'}</td>
    <td><code>${esc(String(s.bundleHash).slice(0, 12))}…</code></td>
    <td><button class="cmp-link" data-snap="${esc(s.id)}">view</button></td>
  </tr>`).join('');
  tbl.innerHTML = `<caption class="sr-only">Compliance snapshot history with audit chain status</caption><thead><tr><th scope="col">Taken</th><th scope="col">Kind</th><th scope="col">Period</th><th scope="col" class="num">Findings</th><th scope="col" class="num">Open</th><th scope="col">Audit chain</th><th scope="col">Hash</th><th scope="col"><span class="sr-only">Download</span></th></tr></thead><tbody>${rows}</tbody>`;
  tbl.querySelectorAll('button.cmp-link[data-snap]').forEach((b) => {
    b.addEventListener('click', async () => {
      try {
        const snap = await api(`/api/compliance/snapshots/${encodeURIComponent(b.dataset.snap)}`);
        render(snap.report, snap);
        section.scrollIntoView({ behavior: 'smooth' });
      } catch (err) {
        showErr(err);
      }
    });
  });
}

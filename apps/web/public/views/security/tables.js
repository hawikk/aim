/* Security view tables (AIM-1135 split): guardrail flags by detector with the
 * AIM-482 criticality filter, and discovered-but-unsanctioned tools with the
 * AIM-484 admin Sanction action. Rows stay clickable (AIM-482 drill-down lives
 * in ./detail.js). */
import { $, esc } from '../../lib/dom.js';
import { fmtInt, fmtTok, fmtDay, fmtUsd } from '../../lib/format.js';
import { hashFor, setStatus, canMutateSanctioned, promptReason, sanctionTool } from '../../lib/runtime.js';
import { EMPTY, table } from '../../lib/components.js';
import { severityBadge, exposureBadge, SEVERITY_RANK, severityBand, compareSeverity } from '../../lib/ui.js';
import { secState } from './state.js';
import { canOpenFindings, findingsTriageHref, wireFindingsCtas } from './findings-hops.js';

function secSeverityFilter() {
  const el = $('#sec-severity');
  const v = el?.value || secState.severity || 'all';
  return v in SEVERITY_RANK ? v : 'all';
}

export function renderSecFlagsTable() {
  const flags = secState.flags;
  if (!flags) return;
  const sev = secSeverityFilter();
  secState.severity = sev;
  const all = [...flags.detectors].sort(
    (a, b) => compareSeverity(a.severity, b.severity) || b.hits - a.hits,
  );
  const detectorRows = sev === 'all' ? all : all.filter((r) => severityBand(r.severity) === sev);
  const hint = $('#sec-filter-hint');
  if (hint) {
    hint.textContent = sev === 'all'
      ? `${all.length} detector${all.length === 1 ? '' : 's'}`
      : `${detectorRows.length} of ${all.length} at ${sev}`;
  }
  // AIM-1023: CTAs track the criticality filter so "high" opens high findings.
  wireFindingsCtas(sev);
  const canFindings = canOpenFindings();
  const cols = [
    { key: 'detector', label: 'Detector', render: (r) => `<span class="pill detector">${esc(r.detector)}</span>` },
    {
      key: 'severity',
      label: 'Severity',
      // Explicit severity hop — row click still opens detector evidence.
      render: (r) => {
        const badge = severityBadge(r.severity, { source: r.severitySource });
        if (!canFindings) return badge;
        const band = severityBand(r.severity) || r.severity || 'all';
        const href = findingsTriageHref(band);
        return `<a class="sec-sev-link" href="${esc(href)}" title="Open open ${esc(band)} findings">${badge}</a>`;
      },
    },
    { key: 'category', label: 'Category', render: (r) => `<span class="pill muted">${esc(r.category)}</span>` },
    { key: 'hits', label: 'Matches', num: true, render: (r) => fmtInt(r.hits) },
    { key: 'users', label: 'Users', num: true },
    { key: 'tools', label: 'Tools', num: true },
    { key: 'firstSeen', label: 'First seen', render: (r) => fmtDay(r.firstSeen) },
    { key: 'lastSeen', label: 'Last seen', render: (r) => fmtDay(r.lastSeen) },
  ];
  if (canFindings) {
    cols.push({
      key: '_triage',
      label: 'Triage',
      render: (r) => {
        const band = severityBand(r.severity) || r.severity || 'all';
        return `<a class="panel-link" href="${esc(findingsTriageHref(band))}">Open findings →</a>`;
      },
    });
  }
  table($('#flags-table'), cols, detectorRows, {
    caption: 'Guardrail match flags by detector — click a row for evidence; Open findings for the full alert list',
    empty: sev === 'all' ? EMPTY.flags : {
      needsEvents: true,
      title: `No ${sev} detectors in this range`,
      body: 'Widen the criticality filter or the day window to see more match flags.',
    },
    rowClass: () => 'is-clickable',
    rowAttrs: (r) => ({
      'data-sec-kind': 'detector',
      'data-sec-key': r.detector,
      tabindex: '0',
      role: 'button',
      'aria-label': `Open detail for detector ${r.detector}`,
    }),
  });
}

export function renderSecUnapprovedTable({ reload }) {
  const unapproved = secState.unapproved;
  if (!unapproved) return;
  const canSanction = canMutateSanctioned();
  const cols = [
    { key: 'tool', label: 'Tool', render: (r) => `<a href="${hashFor('tools', r.tool)}">${esc(r.tool)}</a>` },
    { key: 'exposure', label: 'Exposure', render: (r) => exposureBadge(r) },
    { key: 'provider', label: 'Provider', render: (r) => (r.provider ? `<a href="${hashFor('providers', r.provider)}">${esc(r.provider)}</a>` : '<span class="faint" title="No provider could be attributed — this tool was seen by endpoint telemetry only.">unattributed</span>') },
    { key: 'firstSeen', label: 'First seen', render: (r) => fmtDay(r.firstSeen) },
    { key: 'lastSeen', label: 'Last seen', render: (r) => fmtDay(r.lastSeen) },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'users', label: 'Users', num: true },
    { key: 'teams', label: 'Teams', num: true },
    { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
    { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => fmtUsd(r.costUsd) },
  ];
  // AIM-484: admin-only Sanction action (keep AIM-482 row drill-down intact).
  if (canSanction) {
    cols.push({
      key: '_action',
      label: 'Action',
      render: (r) => `<button type="button" class="btn btn-sm btn-primary" data-sanction="${esc(r.tool)}">Sanction</button>`,
    });
  }
  table($('#unapproved-table'), cols, unapproved.unapproved, {
    caption: 'Discovered tools not on the sanctioned list — click a row for detail',
    empty: EMPTY.unapproved,
    rowClass: () => 'is-clickable',
    rowAttrs: (r) => ({
      'data-sec-kind': 'unapproved',
      'data-sec-key': r.tool,
      tabindex: '0',
      role: 'button',
      'aria-label': `Open detail for unapproved tool ${r.tool}`,
    }),
  });
  if (canSanction) {
    const tbl = $('#unapproved-table');
    tbl?.querySelectorAll('[data-sanction]').forEach((btn) => {
      btn.addEventListener('click', async (ev) => {
        ev.preventDefault();
        ev.stopPropagation(); // do not open row detail
        const tool = btn.dataset.sanction;
        // AIM-151: no modal dialogs — reason prompt is the confirm step.
        const reason = promptReason('Sanction', tool);
        if (!reason) return;
        btn.disabled = true;
        try {
          await sanctionTool(tool, reason);
          setStatus(`Sanctioned ${tool} — audit trail updated.`);
          await reload();
        } catch (err) {
          setStatus(`Sanction failed: ${err.message}`);
          btn.disabled = false;
        }
      });
    });
  }
}

/* Security view (AIM-482/484) — orchestrator only.
 *
 * Pure-moved from app.js (AIM-527), then split (AIM-1135) — the panels live in
 * sibling modules with clear ownership:
 *   ./state.js             view-private secState (zero cross-view surface)
 *   ./findings-hops.js     Findings capability gate + severity-aware hops (AIM-1023)
 *   ./enforce-coverage.js  fleet enforce coverage panel (AIM-796)
 *   ./tables.js            flags + unapproved tables, criticality filter, Sanction (AIM-482/484)
 *   ./detail.js            row drill-down panel (AIM-482)
 *   ./charts.js            severity mix / flags trend / detection volume / enforce blocks (AIM-524/588)
 *   ./break-glass.js       break-glass trail (AIM-567) + grants mutations (AIM-784)
 *
 * This file wires interactions, fetches, paints the KPI cards, and calls the
 * panels in order. Keep it thin — new panel code goes in a sibling module.
 */
import { $, esc } from '../lib/dom.js';
import { fmtInt, fmtDay } from '../lib/format.js';
import { state, api, refreshSanctionedHint } from '../lib/runtime.js';
import { EMPTY, table, card, skeletonCards } from '../lib/components.js';
import { SEVERITY_RANK, worstSeverity } from '../lib/ui.js';
import { secState } from './security/state.js';
import { canOpenFindings, findingsTriageHref } from './security/findings-hops.js';
import { loadEnforceCoverage } from './security/enforce-coverage.js';
import { renderSecFlagsTable, renderSecUnapprovedTable } from './security/tables.js';
import { closeSecDetail, openDetectorDetail, openUnapprovedDetail } from './security/detail.js';
import { renderSecSeverityMix, renderFlagsTrendChart, renderDetectionVolumeChart, renderEnforceBlocksChart } from './security/charts.js';
import { loadBreakGlass, loadBreakGlassGrants } from './security/break-glass.js';

function bindSecInteractions() {
  if (secState.bound) return;
  secState.bound = true;
  const sev = $('#sec-severity');
  if (sev) sev.addEventListener('change', () => {
    renderSecFlagsTable();
    renderSecSeverityMix(secState.flags?.detectors);
  });
  const close = $('#sec-detail-close');
  if (close) close.addEventListener('click', closeSecDetail);
  const onRowActivate = (tr) => {
    if (!tr) return;
    const kind = tr.dataset.secKind;
    const key = tr.dataset.secKey;
    if (!kind || !key) return;
    if (kind === 'detector') openDetectorDetail(key);
    else if (kind === 'unapproved') openUnapprovedDetail(key);
  };
  for (const tableId of ['#flags-table', '#unapproved-table']) {
    const el = $(tableId);
    if (!el) continue;
    el.addEventListener('click', (e) => {
      if (e.target.closest('a')) return;
      onRowActivate(e.target.closest('tr[data-sec-kind]'));
    });
    el.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const tr = e.target.closest('tr[data-sec-kind]');
      if (!tr) return;
      e.preventDefault();
      onRowActivate(tr);
    });
  }
}

export async function loadSecurity() {
  bindSecInteractions();
  closeSecDetail();
  $('#sec-cards').innerHTML = skeletonCards(5);
  // AIM-796: fire enforce-coverage in parallel with the existing security
  // fetches. It self-gates on capabilities and never blocks flags/unapproved.
  const coverageP = loadEnforceCoverage();
  const [flags, unapproved, toolCalls, enforcement] = await Promise.all([
    api(`/api/flags?days=${state.days}`),
    api(`/api/unapproved?days=${state.days}`),
    api(`/api/tool-calls?days=${state.days}`),
    // Optional until the API lands the daily rollup (AIM-588).
    api(`/api/enforcement?days=${state.days}`).catch(() => null),
  ]);
  secState.flags = flags;
  secState.unapproved = unapproved;
  secState.toolCalls = toolCalls;
  const worst = typeof worstSeverity === 'function'
    ? worstSeverity(flags.detectors.map((d) => d.severity))
    : flags.detectors.reduce(
      (acc, d) => ((SEVERITY_RANK[d.severity] ?? 0) > (SEVERITY_RANK[acc] ?? 0) ? d.severity : acc),
      null,
    );
  const blockTotals = enforcement?.totals ?? {};
  const blockedN = Number(blockTotals.blocked) || 0;
  const wouldBlockN = Number(blockTotals.would_block) || 0;
  // AIM-1023: KPI cards that show alert volume / severity hop into Findings
  // so operators never stare at "high" with nowhere to click.
  const canFindings = canOpenFindings();
  const allFindingsHref = canFindings ? findingsTriageHref('all') : null;
  const worstHref = canFindings && worst ? findingsTriageHref(worst) : null;
  $('#sec-cards').innerHTML = [
    card('Detector matches', fmtInt(flags.totalHits), flags.totalHits > 0 ? 'bad' : 'good', null, allFindingsHref),
    card('Detectors triggered', fmtInt(flags.detectors.length)),
    card(
      'Highest severity',
      worst ?? 'none',
      worst === 'critical' || worst === 'high' ? 'bad' : worst ? 'warn' : 'good',
      canFindings && worst
        ? `<div class="delta"><span class="base">open ${esc(worst)} findings</span></div>`
        : null,
      worstHref,
    ),
    card('Blocked (range)', enforcement ? fmtInt(blockedN) : '—', blockedN > 0 ? 'bad' : enforcement ? 'good' : undefined),
    card('Would-block (shadow)', enforcement ? fmtInt(wouldBlockN) : '—', wouldBlockN > 0 ? 'warn' : undefined),
    card('Unapproved tools', fmtInt(unapproved.unapproved.length), unapproved.unapproved.length > 0 ? 'bad' : 'good'),
    card('MCP servers seen', fmtInt(toolCalls.mcpServers.length)),
  ].join('');
  renderSecFlagsTable();
  renderSecSeverityMix(flags.detectors);
  renderFlagsTrendChart(flags);
  renderDetectionVolumeChart(flags);
  renderEnforceBlocksChart(enforcement);
  await refreshSanctionedHint();
  renderSecUnapprovedTable({ reload: loadSecurity });
  /* MCP server usage (AIM-86): mcp_call tool_calls entries grouped by server.
     This is where unapproved-MCP findings correlate — server names come from
     collector MCP config ids and are matched against the approved allowlist. */
  table($('#mcp-table'), [
    { key: 'mcpServer', label: 'MCP server' },
    { key: 'calls', label: 'Calls', num: true, render: (r) => fmtInt(r.calls) },
    { key: 'tools', label: 'Tools', num: true },
    { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
    { key: 'users', label: 'Users', num: true },
    { key: 'firstSeen', label: 'First seen', render: (r) => fmtDay(r.firstSeen) },
    { key: 'lastSeen', label: 'Last seen', render: (r) => fmtDay(r.lastSeen) },
  ], toolCalls.mcpServers, { caption: 'MCP server usage from tool_use events', empty: EMPTY.mcpServers });
  await coverageP;

  // AIM-567/784: break-glass trail + grants. Failures must not blank the rest
  // of Security — each panel degrades to an error empty state.
  await loadBreakGlass();
  await loadBreakGlassGrants();
}

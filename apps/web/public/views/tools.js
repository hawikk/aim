/* Tools view — pure-moved from app.js.
 * Cross-view: writes state.tools for the tool-picker; Overview also writes it.
 * See docs/frontend-app-js-split-map.md Group D. */
import { $, esc } from '../lib/dom.js';
import { fmtInt, fmtTok, fmtDay, fmtDaySafe, fmtUsd } from '../lib/format.js';
import { state, hashFor, api, setStatus, canMutateSanctioned, promptReason, sanctionTool, unsanctionTool } from '../lib/runtime.js';
import { EMPTY, table, card, skeletonCards } from '../lib/components.js';
import { mergeVendorTools, renderVendorFeedBanner, vendorFeedEmpty } from '../lib/vendor-feeds.js';
import { lineChart, setChartState, chartSummary, ACCENT, GOOD } from '../lib/charts.js';

export async function loadTools() {
  // inventory table first so every tool is a clickable row, then the
  // selected tool's drill-down (picker + cards + models + versions + trend).
  const [list, vendorFeeds] = await Promise.all([
    api(`/api/tools?days=${state.days}`),
    api(`/api/vendor-admin/feeds?days=${state.days}`).catch(() => null),
  ]);
  const feeds = vendorFeeds?.feeds ?? list.vendorFeeds ?? [];
  renderVendorFeedBanner($('#tools-vendor-feeds'), feeds);
  list.tools = mergeVendorTools(list.tools, feeds);
  state.tools = list.tools.map((t) => t.tool);
  const expList = $('#exp-tools-list');
  if (expList) expList.href = `/api/tools?days=${state.days}&format=csv`;
  table($('#tools-table'), [
    {
      key: 'tool', label: 'Tool',
      render: (r) => `<a href="${hashFor('tools', r.tool)}">${esc(r.tool)}</a>`,
    },
    {
      key: 'sanctioned', label: 'Status',
      render: (r) => (r.sanctioned
        ? '<span class="pill ok">sanctioned</span>'
        : '<span class="pill bad">unapproved</span>'),
    },
    { key: 'users', label: 'Users', num: true, render: (r) => fmtInt(r.users) },
    { key: 'hosts', label: 'Hosts', num: true, render: (r) => fmtInt(r.hosts) },
    { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
    { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
    { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => fmtUsd(r.costUsd) },
    { key: 'latestVersion', label: 'Version', render: (r) => (r.latestVersion ? esc(r.latestVersion) : '—') },
    { key: 'firstSeen', label: 'First seen', render: (r) => fmtDaySafe(r.firstSeen) },
    { key: 'lastSeen', label: 'Last seen', render: (r) => fmtDaySafe(r.lastSeen) },
  ], list.tools, { caption: 'AI tools observed in range — click a row for the drill-down', empty: vendorFeedEmpty(EMPTY.noTools, feeds) });

  const picker = $('#tool-picker');
  picker.innerHTML = state.tools.map((t) => `<option value="${esc(t)}">${esc(t)}</option>`).join('');
  picker.dataset.filled = state.tools.length ? '1' : '';
  if (state.tools.length === 0) {
    $('#tool-cards').innerHTML = '';
    table($('#tool-models'), [{ key: 'model', label: 'Model' }], [], { caption: 'Models used by the selected tool', empty: EMPTY.noTools });
    table($('#tool-versions'), [{ key: 'version', label: 'Version' }], [], { caption: 'Versions observed for the selected tool', empty: EMPTY.noTools });
    setChartState('#tool-trend', true, EMPTY.toolTrend);
    return;
  }
  const tool = state.entity || picker.value || state.tools[0];
  $('#exp-tool').href = `/api/tools/${encodeURIComponent(tool)}?days=${state.days}&format=csv`;
  if ([...picker.options].some((o) => o.value === tool)) picker.value = tool;
  $('#tool-cards').innerHTML = skeletonCards(10);
  const d = await api(`/api/tools/${encodeURIComponent(tool)}?days=${state.days}`);
  $('#tool-cards').innerHTML = [
    card('Status', d.sanctioned ? 'sanctioned' : 'unapproved', d.sanctioned ? 'good' : 'bad'),
    card('Users', fmtInt(d.users)),
    card('Hosts', fmtInt(d.hosts)),
    card('Sessions', fmtInt(d.sessions)),
    card('Events', fmtInt(d.events)),
    card('Tokens', fmtTok(d.tokensInput + d.tokensOutput)),
    card('Est. cost', fmtUsd(d.costUsd)),
    card('Version', d.latestVersion ?? '—'),
    card('First seen', fmtDaySafe(d.firstSeen)),
    card('Last seen', fmtDaySafe(d.lastSeen)),
  ].join('');
  // admin Sanction / Unsanction on the Tools drill-down.
  const actions = $('#tool-sanction-actions');
  if (actions) {
    if (canMutateSanctioned() && d.sanctioned) {
      actions.hidden = false;
      actions.innerHTML = `<button type="button" class="btn btn-sm btn-danger" id="tool-unsanction-btn" data-tool="${esc(tool)}">Unsanction</button>`;
      const btn = actions.querySelector('#tool-unsanction-btn');
      btn?.addEventListener('click', async () => {
        // no modal dialogs — reason prompt is the confirm step.
        const reason = promptReason('Unsanction', tool);
        if (!reason) return;
        btn.disabled = true;
        try {
          await unsanctionTool(tool, reason);
          setStatus(`Unsanctioned ${tool} — audit trail updated.`);
          state.tools = [];
          delete $('#tool-picker').dataset.filled;
          await loadTools();
        } catch (err) {
          setStatus(`Unsanction failed: ${err.message}`);
          btn.disabled = false;
        }
      });
    } else if (canMutateSanctioned() && !d.sanctioned) {
      actions.hidden = false;
      actions.innerHTML = `<button type="button" class="btn btn-sm btn-primary" id="tool-sanction-btn" data-tool="${esc(tool)}">Sanction</button>`;
      const btn = actions.querySelector('#tool-sanction-btn');
      btn?.addEventListener('click', async () => {
        // no modal dialogs — reason prompt is the confirm step.
        const reason = promptReason('Sanction', tool);
        if (!reason) return;
        btn.disabled = true;
        try {
          await sanctionTool(tool, reason);
          setStatus(`Sanctioned ${tool} — audit trail updated.`);
          state.tools = [];
          delete $('#tool-picker').dataset.filled;
          await loadTools();
        } catch (err) {
          setStatus(`Sanction failed: ${err.message}`);
          btn.disabled = false;
        }
      });
    } else {
      actions.hidden = true;
      actions.innerHTML = '';
    }
  }
  table($('#tool-models'), [
    { key: 'model', label: 'Model' },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'tokensInput', label: 'Tokens in', num: true, render: (r) => fmtTok(r.tokensInput) },
    { key: 'tokensOutput', label: 'Tokens out', num: true, render: (r) => fmtTok(r.tokensOutput) },
    { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => fmtUsd(r.costUsd) },
  ], d.models, { caption: `Models used by ${tool}`, empty: EMPTY.models });
  table($('#tool-versions'), [
    { key: 'version', label: 'Version' },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'hosts', label: 'Hosts', num: true, render: (r) => fmtInt(r.hosts) },
    { key: 'lastSeen', label: 'Last seen', render: (r) => fmtDaySafe(r.lastSeen) },
  ], d.versions ?? [], {
    caption: `Collector/tool versions observed for ${tool}`,
    empty: { title: 'No version metadata', body: 'Collectors did not report tool_version for this tool in the selected range.' },
  });
  if (d.trend.length === 0) {
    setChartState('#tool-trend', true, EMPTY.toolTrend);
  } else {
    const toolSeries = [
      { label: 'Active users', data: d.trend.map((t) => t.activeUsers), token: ACCENT },
      { label: 'Sessions', data: d.trend.map((t) => t.sessions), token: GOOD },
    ];
    lineChart('#tool-trend', d.trend.map((t) => fmtDay(t.day)), toolSeries, chartSummary('Line', d.trend, toolSeries));
  }
}

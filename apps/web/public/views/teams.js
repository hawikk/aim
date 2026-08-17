/* Teams view (AIM-94/483) — pure-moved from app.js (AIM-527). */
import { $, esc } from '../lib/dom.js';
import { fmtInt, fmtTok, fmtDaySafe, fmtUsd, fmtTs } from '../lib/format.js';
import { state, hashFor, api, apiJson, setStatus, refresh, canManageTeams } from '../lib/runtime.js';
import { EMPTY, table, card } from '../lib/components.js';
import { barChart, setChartState } from '../lib/charts.js';
import { hideEntityDetail, entityDetailError, entityDetailShell } from '../lib/entity-detail.js';
import { refCell } from '../lib/ui.js';

export async function loadTeams() {
  // AIM-94 / AIM-737: matrix + model rollup load independently so a single
  // aggregate failure can't blank the teams table/chart above.
  loadTeamsMatrix().catch((err) => {
    $('#teams-matrix').innerHTML = `<tbody><tr><td><div class="err">Team × tool matrix failed to load: ${esc(err.message)}</div></td></tr></tbody>`;
  });
  loadTeamsModels().catch((err) => {
    const tbl = $('#teams-models-table');
    if (tbl) {
      table(tbl, [{ key: 'team', label: 'Team' }], [], {
        caption: 'Model usage by team — failed to load',
        empty: { reason: 'error', body: `Model usage by team failed to load: ${err.message}` },
      });
    }
    setChartState('#teams-models-chart', true, {
      reason: 'error',
      body: `Model cost chart failed to load: ${err.message}`,
    });
  });
  const d = await api(`/api/teams?days=${state.days}`);
  const banner = $('#teams-attr-banner');
  if (banner) {
    if (d.attribution?.warning) {
      banner.hidden = false;
      banner.textContent = d.attribution.warning
        + (d.attribution.unattributedPct != null
          ? ` Unattributed share: ${d.attribution.unattributedPct}% of ${fmtInt(d.attribution.events)} events.`
          : '');
    } else {
      banner.hidden = true;
      banner.textContent = '';
    }
  }
  await renderTeamDetail(d);
  table($('#teams-table'), [
    {
      key: 'team', label: 'Team',
      render: (r) => {
        const label = r.displayName && r.displayName !== r.team
          ? `${esc(r.displayName)} <span class="faint mono" title="Attribution key">${esc(r.team)}</span>`
          : esc(r.displayName || r.team);
        return `<a href="${hashFor('teams', r.team)}">${label}</a>`;
      },
    },
    { key: 'activeUsers', label: 'AI users', num: true },
    { key: 'activeHosts', label: 'Hosts', num: true },
    { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
    { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
    { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => fmtUsd(r.costUsd) },
    { key: 'sanctionedToolCount', label: 'Sanctioned', num: true },
    { key: 'unsanctionedToolCount', label: 'Unapproved', num: true, render: (r) => (r.unsanctionedToolCount > 0 ? `<span class="pill bad">${esc(r.unsanctionedToolCount)}</span>` : '0') },
  ], d.teams, { caption: 'Per-team AI usage and estimated cost', empty: EMPTY.teams });
  if (d.teams.length === 0) {
    setChartState('#teams-chart', true, EMPTY.teams);
    return;
  }
  barChart(
    '#teams-chart',
    d.teams.map((t) => t.displayName || t.team),
    d.teams.map((t) => t.costUsd),
    'Est. cost USD',
    `Bar chart of estimated cost by team. ${d.teams.map((t) => `${t.displayName || t.team}: ${fmtUsd(t.costUsd)}`).join('; ')}.`,
  );
}

// Drill-down panel for a single team (AIM-483): usage cards, rename + membership
// management for security-admin, member list, and local identity audit trail.
export async function renderTeamDetail(listPayload) {
  const box = $('#team-detail');
  if (!state.entity) {
    hideEntityDetail(box);
    return;
  }
  let d;
  try {
    d = await api(`/api/teams/${encodeURIComponent(state.entity)}?days=${state.days}`);
  } catch (err) {
    // Fall back to list-row cards when the detail endpoint is missing/404.
    const t = listPayload?.teams?.find((x) => x.team === state.entity);
    if (!t) {
      entityDetailError(box, { view: 'teams', backLabel: 'Teams', message: err.message });
      return;
    }
    d = {
      team: t.team,
      displayName: t.displayName || t.team,
      canManage: canManageTeams(),
      summary: t,
      members: [],
      audit: [],
    };
  }
  const s = d.summary;
  const title = d.displayName && d.displayName !== d.team
    ? `${esc(d.displayName)} <span class="faint mono" title="Stable attribution key">${esc(d.team)}</span>`
    : esc(d.displayName || d.team);
  const manage = d.canManage || canManageTeams();
  entityDetailShell(box, {
    view: 'teams',
    backLabel: 'Teams',
    titleHtml: title,
    cards: [
      card('AI users', fmtInt(s.activeUsers ?? s.active_users ?? 0)),
      card('Hosts', fmtInt(s.activeHosts ?? 0)),
      card('Sessions', fmtInt(s.sessions)),
      card('Tokens', fmtTok(s.tokens)),
      card('Est. cost', fmtUsd(s.costUsd)),
      card('Sanctioned tools', fmtInt(s.sanctionedToolCount ?? 0)),
      card('Unapproved tools', fmtInt(s.unsanctionedToolCount ?? 0), (s.unsanctionedToolCount ?? 0) > 0 ? 'bad' : 'good'),
      card('Unapproved events', fmtInt(s.unsanctionedEvents ?? 0)),
    ],
    body: `
    ${manage ? `
      <div class="team-manage">
        <h3>Team identity <span class="hint">rename is a display alias — the attribution key stays stable; changes are audit-logged</span></h3>
        <form id="team-rename-form" class="inline-form">
          <label class="field">
            <span class="field-label">Display name</span>
            <input class="input" id="team-rename-input" maxlength="200" value="${esc(d.displayName || d.team)}" required>
          </label>
          <button type="submit" class="btn btn-primary btn-sm">Save name</button>
          ${d.renamed ? '<button type="button" class="btn btn-ghost btn-sm" id="team-rename-clear">Clear alias</button>' : ''}
          <span class="field-hint" id="team-rename-status" role="status"></span>
        </form>
      </div>` : '<p class="hint">Team rename and membership edits require the security-admin role.</p>'}
    <h3>Models <span class="hint">tokens and estimated cost by model for this team (employee tooling; OTel apps have no team)</span> <a class="btn-export" id="exp-team-models" href="/api/aggregate?group_by=team,model&amp;format=csv" download>CSV</a></h3>
    <div class="table-wrap" tabindex="0" role="region" aria-label="Team models, scrollable"><table id="team-models"></table></div>
    <h3>Members <span class="hint">pseudonyms observed in range${manage ? '; assign moves the override only — event history is not rewritten' : ''}</span></h3>
    <div class="table-wrap" tabindex="0" role="region" aria-label="Team members, scrollable"><table id="team-members"></table></div>
    <h3>Identity audit <span class="hint">local trail of rename / membership changes for this team</span></h3>
    <div class="table-wrap" tabindex="0" role="region" aria-label="Team identity audit, scrollable"><table id="team-audit"></table></div>`,
  });

  // AIM-737: model/token/cost for this team via aggregate (filter client-side).
  loadTeamDetailModels(d.team).catch((err) => {
    table($('#team-models'), [{ key: 'model', label: 'Model' }], [], {
      caption: 'Models for this team — failed to load',
      empty: { reason: 'error', body: `Could not load models: ${err.message}` },
    });
  });
  const expTeamModels = box.querySelector('#exp-team-models');
  if (expTeamModels) {
    expTeamModels.href = `/api/aggregate?group_by=team,model&days=${state.days}&format=csv`;
  }

  table($('#team-members'), [
    {
      key: 'pseudonym', label: 'Pseudonym',
      render: (r) => refCell(r.pseudonym, { href: hashFor('users', r.pseudonym) }),
    },
    { key: 'sessions', label: 'Sessions', num: true, render: (r) => fmtInt(r.sessions) },
    { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
    { key: 'lastActive', label: 'Last active', render: (r) => fmtDaySafe(r.lastActive) },
    { key: 'source', label: 'Source', render: (r) => `<span class="pill muted">${esc(r.source ?? 'events')}</span>` },
    ...(manage ? [{
      key: 'move', label: 'Move',
      render: (r) => `<button type="button" class="btn btn-ghost btn-sm team-move" data-pseudo="${esc(r.pseudonym)}">Move…</button>`,
    }] : []),
  ], d.members ?? [], { caption: 'Members attributed to this team', empty: { title: 'No members in range', body: 'No pseudonyms were observed on this team in the selected range.' } });

  table($('#team-audit'), [
    { key: 'ts', label: 'Time', render: (r) => fmtTs(r.ts) },
    { key: 'actor', label: 'Actor' },
    { key: 'action', label: 'Action', render: (r) => `<span class="mono">${esc(r.action)}</span>` },
    { key: 'detail', label: 'Detail', render: (r) => `<span class="mono">${esc(JSON.stringify(r.detail ?? {}))}</span>` },
  ], d.audit ?? [], { caption: 'Recent identity changes for this team', empty: { title: 'No identity changes yet', body: 'Renames and membership edits will appear here.' } });

  if (manage) {
    const form = box.querySelector('#team-rename-form');
    const status = box.querySelector('#team-rename-status');
    form?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = box.querySelector('#team-rename-input').value.trim();
      status.textContent = 'Saving…';
      try {
        await apiJson(`/api/teams/${encodeURIComponent(d.team)}/name`, 'PUT', { displayName: name });
        status.textContent = 'Saved.';
        setStatus(`Renamed team ${d.team} → ${name}`);
        await refresh();
      } catch (err) {
        status.textContent = err.message;
      }
    });
    box.querySelector('#team-rename-clear')?.addEventListener('click', async () => {
      status.textContent = 'Clearing…';
      try {
        await apiJson(`/api/teams/${encodeURIComponent(d.team)}/name`, 'PUT', { displayName: null });
        status.textContent = 'Cleared.';
        await refresh();
      } catch (err) {
        status.textContent = err.message;
      }
    });
    box.querySelectorAll('.team-move').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const pseudo = btn.dataset.pseudo;
        const dest = window.prompt(`Move ${pseudo} to which team key? (stable attribution key, e.g. Engineering)`, d.team);
        if (!dest) return;
        try {
          await apiJson(`/api/teams/members/${encodeURIComponent(pseudo)}`, 'PUT', { team: dest.trim() });
          setStatus(`Moved ${pseudo} → ${dest.trim()}`);
          await refresh();
        } catch (err) {
          setStatus(`Move failed: ${err.message}`);
        }
      });
    });
  }
}

/* AIM-737: team × model — tokens and estimated cost from the aggregate
 * endpoint. OTel app spans have no team; this table covers employee tooling
 * attribution (same event population as the teams rollup). Export via #exp-teams-models. */
export async function loadTeamsModels() {
  const tableEl = $('#teams-models-table');
  if (!tableEl) return;
  const d = await api(`/api/aggregate?group_by=team,model&days=${state.days}`);
  const rows = (d.rows ?? [])
    .map((r) => ({
      team: r.team || '(unattributed)',
      model: r.model || '(unspecified)',
      events: r.events ?? 0,
      tokens: r.tokens ?? ((r.tokensInput ?? 0) + (r.tokensOutput ?? 0)),
      tokensInput: r.tokensInput ?? 0,
      tokensOutput: r.tokensOutput ?? 0,
      costUsd: r.costUsd ?? 0,
    }))
    .sort((a, b) => (b.costUsd - a.costUsd) || (b.tokens - a.tokens));
  table(tableEl, [
    {
      key: 'team',
      label: 'Team',
      render: (r) => `<a href="${hashFor('teams', r.team)}">${esc(r.team)}</a>`,
    },
    { key: 'model', label: 'Model' },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'tokensInput', label: 'Tokens in', num: true, render: (r) => fmtTok(r.tokensInput) },
    { key: 'tokensOutput', label: 'Tokens out', num: true, render: (r) => fmtTok(r.tokensOutput) },
    { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
    { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => fmtUsd(r.costUsd) },
  ], rows, {
    caption: 'Tokens and estimated cost by team and model',
    empty: EMPTY.teamsModels,
  });
  // Fleet cost by model (sum across teams) for the chart — top 12.
  const byModel = new Map();
  for (const r of rows) {
    byModel.set(r.model, (byModel.get(r.model) ?? 0) + r.costUsd);
  }
  const ranked = [...byModel.entries()].sort((a, b) => b[1] - a[1]);
  if (ranked.length === 0) {
    setChartState('#teams-models-chart', true, EMPTY.teamsModels);
    return;
  }
  const top = ranked.slice(0, 12);
  barChart(
    '#teams-models-chart',
    top.map(([m]) => m),
    top.map(([, c]) => c),
    'Est. cost USD',
    `Bar chart of estimated cost by model across teams. Top ${top.length} of ${ranked.length} model(s).`,
  );
}

/** AIM-737: models for one team (filter team×model aggregate client-side). */
export async function loadTeamDetailModels(teamKey) {
  const el = $('#team-models');
  if (!el) return;
  const d = await api(`/api/aggregate?group_by=team,model&days=${state.days}`);
  const rows = (d.rows ?? [])
    .filter((r) => (r.team || '(unattributed)') === teamKey)
    .map((r) => ({
      model: r.model || '(unspecified)',
      events: r.events ?? 0,
      tokensInput: r.tokensInput ?? 0,
      tokensOutput: r.tokensOutput ?? 0,
      tokens: r.tokens ?? ((r.tokensInput ?? 0) + (r.tokensOutput ?? 0)),
      costUsd: r.costUsd ?? 0,
    }))
    .sort((a, b) => (b.costUsd - a.costUsd) || (b.tokens - a.tokens));
  table(el, [
    { key: 'model', label: 'Model' },
    { key: 'events', label: 'Events', num: true, render: (r) => fmtInt(r.events) },
    { key: 'tokensInput', label: 'Tokens in', num: true, render: (r) => fmtTok(r.tokensInput) },
    { key: 'tokensOutput', label: 'Tokens out', num: true, render: (r) => fmtTok(r.tokensOutput) },
    { key: 'tokens', label: 'Tokens', num: true, render: (r) => fmtTok(r.tokens) },
    { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => fmtUsd(r.costUsd) },
  ], rows, {
    caption: `Models used by team ${teamKey}`,
    empty: EMPTY.teamsModels,
  });
}

/* AIM-94: team × tool matrix — tokens per team per tool from the generic
 * aggregate endpoint. Top teams by total tokens get their own row; the rest
 * fold into "(other)". Follows state.days via the normal refresh cycle. */
export const MATRIX_TOP_TEAMS = 12;

export async function loadTeamsMatrix() {
  const d = await api(`/api/aggregate?group_by=team,tool&days=${state.days}`);
  const rows = d.rows ?? [];
  if (rows.length === 0) {
    table($('#teams-matrix'), [{ key: 'team', label: 'Team' }], [], {
      caption: 'Tokens by team and tool',
      empty: EMPTY.teamsMatrix,
    });
    return;
  }
  // Per team: total tokens (for ranking) + per-tool cells.
  const byTeam = new Map(); // team → { total, cells: Map(tool → {tokens, events, costUsd}) }
  for (const r of rows) {
    const team = r.team || '(unattributed)';
    if (!byTeam.has(team)) byTeam.set(team, { total: 0, cells: new Map() });
    const t = byTeam.get(team);
    t.cells.set(r.tool, { tokens: r.tokens ?? 0, events: r.events ?? 0, costUsd: r.costUsd ?? 0 });
    t.total += r.tokens ?? 0;
  }
  const ranked = [...byTeam.entries()].sort((a, b) => b[1].total - a[1].total);
  const rowNames = ranked.slice(0, MATRIX_TOP_TEAMS).map(([name]) => name);
  if (ranked.length > MATRIX_TOP_TEAMS) rowNames.push('(other)');
  const cellsOf = new Map(rowNames.map((n) => [n, new Map()]));
  ranked.forEach(([name, entry], i) => {
    const cells = cellsOf.get(i < MATRIX_TOP_TEAMS ? name : '(other)');
    for (const [tool, c] of entry.cells) {
      const cur = cells.get(tool) ?? { tokens: 0, events: 0, costUsd: 0 };
      cur.tokens += c.tokens;
      cur.events += c.events;
      cur.costUsd += c.costUsd;
      cells.set(tool, cur);
    }
  });
  // Columns: tools by total tokens desc.
  const toolTotals = new Map();
  for (const r of rows) toolTotals.set(r.tool, (toolTotals.get(r.tool) ?? 0) + (r.tokens ?? 0));
  const tools = [...toolTotals.entries()].sort((a, b) => b[1] - a[1]).map(([t]) => t);
  const cols = [
    {
      key: 'team', label: 'Team',
      render: (r) => (r.team === '(other)' ? '(other)' : `<a href="${hashFor('teams', r.team)}">${esc(r.team)}</a>`),
    },
    ...tools.map((tool) => ({
      key: tool,
      // Column headers stay plain text (table() escapes labels); cells link via title.
      label: tool,
      num: true,
      render: (r) => {
        const c = r.cells.get(tool);
        if (!c || c.tokens === 0) return '<span class="mtx-empty">—</span>';
        return `<a href="${hashFor('tools', tool)}" title="${esc(`${tool}: ${fmtInt(c.events)} events · ${fmtUsd(c.costUsd)} est. cost`)}">${fmtInt(c.tokens)}</a>`;
      },
    })),
  ];
  table($('#teams-matrix'), cols, rowNames.map((name) => ({ team: name, cells: cellsOf.get(name) })), {
    caption: 'Tokens by team and tool',
  });
}

/* Security view row drill-down panel (AIM-482), split out of
 * views/security.js (AIM-1135). Detector evidence fetches /api/flags detail;
 * unapproved-tool detail renders from the cached list payload. */
import { $, esc } from '../../lib/dom.js';
import { fmtInt, fmtTok, fmtDay, fmtUsd } from '../../lib/format.js';
import { state, hashFor, api } from '../../lib/runtime.js';
import { refCell, severityBadge, exposureBadge } from '../../lib/ui.js';
import { entityHref } from '../../lib/deeplinks.js';
import { findingsHash } from '../../lib/view-filters.js';
import { secState } from './state.js';

export function closeSecDetail() {
  const panel = $('#sec-detail');
  if (!panel) return;
  panel.hidden = true;
  const body = $('#sec-detail-body');
  if (body) body.innerHTML = '';
}

function openSecDetailShell(titleHtml) {
  const panel = $('#sec-detail');
  const title = $('#sec-detail-title');
  const body = $('#sec-detail-body');
  if (!panel || !title || !body) return null;
  title.innerHTML = titleHtml;
  body.innerHTML = '<div class="faint">Loading…</div>';
  panel.hidden = false;
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  return body;
}

function secDl(items) {
  return `<dl class="sec-dl">${items.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${v}</dd></div>`).join('')}</dl>`;
}

function secMiniTable(headers, rowsHtml, emptyMsg) {
  if (!rowsHtml) return `<p class="faint">${esc(emptyMsg)}</p>`;
  return `<div class="table-wrap" tabindex="0" role="region"><table>
    <thead><tr>${headers.map((h) => `<th scope="col">${esc(h)}</th>`).join('')}</tr></thead>
    <tbody>${rowsHtml}</tbody></table></div>`;
}

export async function openDetectorDetail(detector) {
  const body = openSecDetailShell(`Detector <code>${esc(detector)}</code>`);
  if (!body) return;
  try {
    const d = await api(`/api/flags?days=${state.days}&detector=${encodeURIComponent(detector)}`);
    const summary = d.detail?.summary
      ?? d.detectors?.find((x) => x.detector === detector)
      ?? null;
    const det = d.detail || {};
    const sev = summary?.severity || 'medium';
    // AIM-587 severity filter + AIM-589 range: findingsHash carries both.
    const findingsHref = findingsHash({ fstatus: 'open', fsev: sev, days: state.days });
    const findingsNote = summary
      ? `Open Findings triage (filter severity=${sev}) for the backing findings.`
      : 'Open Findings triage for the backing findings.';
    const userBlock = det.usersWithheld
      ? '<p class="faint">Pseudonymous users withheld by policy for this session (analyst+ required).</p>'
      : secMiniTable(
        ['User', 'Matches', 'Last seen'],
        (det.users || []).map((u) => `<tr>
          <th scope="row" class="rowhead">${refCell(u.user, { href: hashFor('users', u.user) })}</th>
          <td class="num">${fmtInt(u.hits)}</td>
          <td>${esc(fmtDay(u.lastSeen))}</td></tr>`).join(''),
        'No attributed users in this window.',
      );
    body.innerHTML = [
      secDl([
        ['Detector', `<span class="pill detector">${esc(detector)}</span>`],
        ['Severity', summary ? severityBadge(summary.severity, { source: summary.severitySource }) : '—'],
        ['Data-exposure class', summary ? `<span class="pill muted">${esc(summary.category)}</span>` : '—'],
        ['Matches', summary ? fmtInt(summary.hits) : '—'],
        ['Users (count)', summary ? String(summary.users) : '—'],
        ['Tools (count)', summary ? String(summary.tools) : '—'],
        ['First seen', summary ? fmtDay(summary.firstSeen) : '—'],
        ['Last seen', summary ? fmtDay(summary.lastSeen) : '—'],
      ]),
      `<p class="sec-triage-link"><a class="btn-control" href="${esc(findingsHref)}">Open Findings triage →</a>
        <span class="hint">${esc(findingsNote)}</span></p>`,
      '<h3>Affected tools</h3>',
      secMiniTable(
        ['Tool', 'Matches'],
        (det.tools || []).map((t) => `<tr>
          <th scope="row" class="rowhead"><a href="${hashFor('tools', t.tool)}">${esc(t.tool)}</a></th>
          <td class="num">${fmtInt(t.hits)}</td></tr>`).join(''),
        'No tool breakdown for this detector.',
      ),
      '<h3>Affected sessions</h3>',
      secMiniTable(
        ['Session', 'Tool', 'Matches', 'Last seen'],
        (det.sessions || []).map((s) => `<tr>
          <th scope="row" class="rowhead">${refCell(s.sessionId)}</th>
          <td>${s.tool ? `<a href="${hashFor('tools', s.tool)}">${esc(s.tool)}</a>` : '—'}</td>
          <td class="num">${fmtInt(s.hits)}</td>
          <td>${esc(fmtDay(s.lastSeen))}</td></tr>`).join(''),
        'No sessions recorded for this detector in the window.',
      ),
      '<h3>Affected repos</h3>',
      secMiniTable(
        ['Repo', 'Matches', 'Last seen'],
        (det.repos || []).map((r) => `<tr>
          <th scope="row" class="rowhead">${refCell(r.repo, { href: hashFor('repos', r.repo) })}</th>
          <td class="num">${fmtInt(r.hits)}</td>
          <td>${esc(fmtDay(r.lastSeen))}</td></tr>`).join(''),
        'No repos attributed for this detector in the window.',
      ),
      '<h3>Affected users</h3>',
      userBlock,
    ].join('');
  } catch (err) {
    body.innerHTML = `<div class="err">${esc(err.message)}</div>`;
  }
}

export function openUnapprovedDetail(tool) {
  const body = openSecDetailShell(`Unapproved tool <code>${esc(tool)}</code>`);
  if (!body) return;
  const row = secState.unapproved?.unapproved?.find((t) => t.tool === tool);
  if (!row) {
    body.innerHTML = '<div class="err">Tool no longer present in the unapproved list for this range.</div>';
    return;
  }
  body.innerHTML = [
    secDl([
      ['Tool', `<a href="${hashFor('tools', row.tool)}">${esc(row.tool)}</a>`],
      ['Exposure (reach)', exposureBadge(row)],
      ['Provider', row.provider
        ? `<a href="${hashFor('providers', row.provider)}">${esc(row.provider)}</a>`
        : '<span class="faint">unattributed</span>'],
      ['Events', fmtInt(row.events)],
      ['Users', String(row.users)],
      ['Teams', String(row.teams)],
      ['Tokens', fmtTok(row.tokens)],
      ['Est. cost', fmtUsd(row.costUsd)],
      ['First seen', fmtDay(row.firstSeen)],
      ['Last seen', fmtDay(row.lastSeen)],
    ]),
    `<p class="sec-triage-link"><a class="btn-control" href="${hashFor('tools', row.tool)}">Open tool drill-down →</a>
      <a class="btn-control" href="${esc(entityHref('findings', null, { days: state.days }))}">Open Findings triage →</a>
      <span class="hint">Unapproved-tool findings correlate here; triage lives on the Findings inbox.</span></p>`,
  ].join('');
}

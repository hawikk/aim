/* MCP override path (AIM-1157 split): runtime-denials panel, the inline
 * override-deny form (AIM-667 — permanent allowlist approve with required
 * reason, optional dual control, full audit), and the recent-overrides
 * audit panel.
 * The orchestrator (public/mcp.js) populates fctx before bind*() runs. */

import { fmtInt, fmtDay } from '../lib/format.js';
import { esc } from '../lib/dom.js';
import { announce } from '../lib/a11y.js';
import { table as dataTable, emptyState } from '../lib/components.js';
import { severityBadge } from '../lib/severity.js';
import {
  buildApproveOverridePayload,
  isOverrideCandidate,
  overrideUrgency,
  validateOverrideForm,
} from '../lib/mcp-override.js';
import { api, apiJson } from '../lib/api.js';
import { fctx } from './state.js';
import { statusPill, loadInventory } from './inventory.js';
import { renderAllowlist, setAllowlistErr } from './allowlist.js';

const DENY_FINDING_COLS = [
  {
    key: 'subject',
    label: 'Subject',
    render: (f) => `<code>${esc(f.subject ?? '—')}</code>`,
  },
  {
    key: 'severity',
    label: 'Sev',
    render: (f) => severityBadge(f.severity),
  },
  {
    key: 'status',
    label: 'Status',
    render: (f) => esc(f.status ?? '—'),
  },
  {
    key: 'title',
    label: 'Title',
    render: (f) => esc(f.title ?? f.ruleId ?? '—'),
  },
  {
    key: 'detectedAt',
    label: 'Detected',
    render: (f) => esc(fmtDay(f.detectedAt ?? f.ts)),
  },
  {
    key: 'override',
    label: 'Override',
    render: (f) => {
      const server = serverFromFinding(f);
      if (!server) return '—';
      return `<button type="button" class="btn btn-sm btn-primary mcp-override-btn" data-server="${esc(server)}" aria-label="Override deny for ${esc(server)}">Override deny</button>`;
    },
  },
];

/** Best-effort MCP server id from a finding subject / title. */
function serverFromFinding(f) {
  const subject = String(f?.subject ?? '');
  // Common shapes: "mcp_server=foo", "server:foo", bare server id, or title text.
  const m =
    subject.match(/(?:mcp[_-]?server|server)\s*[=:]\s*([A-Za-z0-9][A-Za-z0-9._@+/-]*)/i) ||
    subject.match(/^([A-Za-z0-9][A-Za-z0-9._@+/-]{0,127})$/);
  if (m) return m[1];
  const title = String(f?.title ?? '');
  const tm = title.match(/\b([A-Za-z0-9][A-Za-z0-9._@+/-]{1,80})\b/);
  return tm ? tm[1] : null;
}

function setOverrideErr(msg) {
  const el = fctx.section.querySelector('#mcp-override-err');
  if (!msg) {
    el.hidden = true;
    el.textContent = '';
    return;
  }
  el.hidden = false;
  el.textContent = msg;
}

export async function loadDenials() {
  const { denyMeta, denyUrgency, denyBody, mcpState, endpointEnforce } = fctx;
  denyMeta.textContent = 'open unapproved-mcp findings + unapproved inventory';
  denyUrgency.textContent = overrideUrgency(endpointEnforce);

  const unapproved = (mcpState.servers ?? []).filter((s) => isOverrideCandidate(s));
  let findings = [];
  try {
    const d = await api(
      '/api/findings?rule_id=unapproved-mcp-server&status=new,acknowledged&limit=50',
    );
    findings = d.findings ?? [];
  } catch (err) {
    // Findings may be empty/error; still show inventory unapproved.
    if (err.status !== 403) {
      denyBody.innerHTML = `<p class="hint">Findings load failed: ${esc(err.message)}. Showing inventory unapproved only.</p>`;
    }
  }

  // Also surface configured-unapproved inventory findings if any.
  try {
    const d2 = await api(
      '/api/findings?rule_id=unapproved-mcp-server-configured&status=new,acknowledged&limit=25',
    );
    findings = findings.concat(d2.findings ?? []);
  } catch {
    /* optional second rule */
  }

  const parts = [];
  if (unapproved.length) {
    parts.push(`
      <h3 class="mcp-subh">Unapproved servers in inventory <span class="hint">${fmtInt(unapproved.length)}</span></h3>
      <ul class="mcp-deny-list">
        ${unapproved
          .slice(0, 40)
          .map(
            (s) =>
              `<li><code>${esc(s.name)}</code> ${statusPill(s.status)} ` +
              `<span class="hint">${esc(fmtInt(s.callCount ?? 0))} calls · ${esc(fmtInt(s.hosts ?? 0))} hosts</span> ` +
              `<button type="button" class="btn btn-sm btn-primary mcp-override-btn" data-server="${esc(s.name)}">Override deny</button></li>`,
          )
          .join('')}
      </ul>`);
  }

  if (findings.length) {
    parts.push(`
      <h3 class="mcp-subh">Open unapproved-MCP findings <span class="hint">${fmtInt(findings.length)}</span></h3>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Open unapproved MCP findings, scrollable"><table id="mcp-deny-findings-table"></table></div>`);
  }

  if (!parts.length) {
    denyBody.innerHTML = emptyState({
      reason: 'no-data',
      title: 'No open MCP denials to override',
      body: endpointEnforce
        ? 'No unapproved servers in inventory and no open unapproved-mcp findings. When PreToolUse denies an unapproved server, it will appear here for analyst override.'
        : 'No unapproved inventory rows or open findings. Endpoint enforce is off/shadow — flip enforce only after the allowlist is intentional.',
    });
    return;
  }

  denyBody.innerHTML = parts.join('');
  const ft = denyBody.querySelector('#mcp-deny-findings-table');
  if (ft) {
    dataTable(ft, DENY_FINDING_COLS, findings, {
      caption: 'Open unapproved-MCP findings — override path',
      empty: { reason: 'no-data', title: 'No findings', body: '' },
    });
  }
}

export async function loadOverrideAudit() {
  const { me, auditBody } = fctx;
  if (!me?.capabilities?.auditTrail) {
    auditBody.innerHTML =
      '<p class="hint">Audit trail is restricted to auditor + admin. Allowlist writes still record <code>mcp.allowlist_update</code> server-side; ask an auditor to filter that action on the Audit tab.</p>';
    return;
  }
  try {
    const d = await api('/api/audit/events?action=mcp.allowlist_update&limit=25');
    const events = d.events ?? [];
    if (!events.length) {
      auditBody.innerHTML = emptyState({
        reason: 'no-data',
        title: 'No allowlist overrides yet',
        body: 'When an analyst approves a denied MCP server, the audited mcp.allowlist_update row appears here with reason and dual-control when used.',
      });
      return;
    }
    dataTable(
      (() => {
        auditBody.innerHTML =
          '<div class="table-wrap" tabindex="0" role="region" aria-label="Recent MCP allowlist overrides, scrollable"><table id="mcp-audit-table"></table></div>';
        return auditBody.querySelector('#mcp-audit-table');
      })(),
      [
        { key: 'ts', label: 'When', render: (e) => esc(fmtDay(e.ts)) },
        { key: 'actor', label: 'Actor', render: (e) => esc(e.actor ?? '—') },
        {
          key: 'detail',
          label: 'Change',
          render: (e) => {
            const det = e.detail && typeof e.detail === 'object' ? e.detail : {};
            const added = (det.added ?? []).join(', ') || '—';
            const removed = (det.removed ?? []).join(', ') || '—';
            const reason = det.reason ? esc(det.reason) : '<span class="faint">(no reason)</span>';
            const dc = det.dualControl?.approver
              ? ` · dual-control: ${esc(det.dualControl.approver)}`
              : '';
            return `+${esc(added)} / −${esc(removed)} · ${reason}${dc}`;
          },
        },
      ],
      events.slice().reverse(),
      { caption: 'Recent mcp.allowlist_update audit events' },
    );
  } catch (err) {
    auditBody.innerHTML = `<p class="err">${esc(err.message)}</p>`;
  }
}

export function openOverridePanel(serverName) {
  const { section, overridePanel } = fctx;
  const name = String(serverName || '').trim();
  if (!name) return;
  if (fctx.allowlist.includes(name)) {
    setAllowlistErr(`'${name}' is already on the allowlist — no override needed.`);
    return;
  }
  overridePanel.hidden = false;
  section.querySelector('#mcp-override-title').innerHTML =
    `Override deny: <code>${esc(name)}</code>`;
  section.querySelector('#mcp-override-server').value = name;
  section.querySelector('#mcp-override-reason').value = '';
  section.querySelector('#mcp-override-dual').checked = false;
  section.querySelector('#mcp-override-approver').value = '';
  section.querySelector('#mcp-override-approver-wrap').hidden = true;
  section.querySelector('#mcp-override-confirm').checked = false;
  section.querySelector('#mcp-override-status').textContent = '';
  setOverrideErr('');
  overridePanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  section.querySelector('#mcp-override-reason').focus();
  announce(`Override form opened for ${name}`);
}

function closeOverridePanel() {
  const { overridePanel, section } = fctx;
  overridePanel.hidden = true;
  setOverrideErr('');
  section.querySelector('#mcp-override-status').textContent = '';
}

export function bindOverride() {
  const { section } = fctx;

  section.querySelector('#mcp-override-dual').addEventListener('change', (e) => {
    section.querySelector('#mcp-override-approver-wrap').hidden = !e.target.checked;
  });
  section.querySelector('#mcp-override-cancel').addEventListener('click', () => closeOverridePanel());
  section.querySelector('#mcp-override-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const server = section.querySelector('#mcp-override-server').value;
    const reason = section.querySelector('#mcp-override-reason').value;
    const dualControl = section.querySelector('#mcp-override-dual').checked;
    const dualControlApprover = section.querySelector('#mcp-override-approver').value;
    const confirm = section.querySelector('#mcp-override-confirm').checked;
    const blocker = validateOverrideForm({
      server,
      reason,
      dualControl,
      dualControlApprover,
      confirm,
    });
    if (blocker) {
      setOverrideErr(blocker);
      return;
    }
    setOverrideErr('');
    const submitBtn = section.querySelector('#mcp-override-submit');
    submitBtn.disabled = true;
    section.querySelector('#mcp-override-status').textContent = 'Saving override…';
    try {
      const body = buildApproveOverridePayload(fctx.allowlist, server, {
        reason,
        dualControl,
        dualControlApprover,
        confirm: true,
      });
      const d = await apiJson('/api/mcp-allowlist', 'PUT', body);
      renderAllowlist(d);
      section.querySelector('#mcp-override-status').textContent =
        `Override saved · +${(d.added ?? [server]).join(', ')} · policy_hash ${String(d.contentHash ?? '').slice(0, 12)}…` +
        (d.dualControl?.approver ? ` · dual-control ${d.dualControl.approver}` : '');
      announce(`Override approved for ${server}`);
      await fctx.refreshDerived();
      // Keep panel open briefly so the analyst sees success, then close.
      setTimeout(() => closeOverridePanel(), 1200);
    } catch (err) {
      setOverrideErr(err.message);
      section.querySelector('#mcp-override-status').textContent = '';
    } finally {
      submitBtn.disabled = false;
    }
  });

  // Delegate Override deny buttons from inventory, denials, findings tables.
  section.addEventListener('click', (e) => {
    const obtn = e.target.closest('.mcp-override-btn');
    if (obtn) {
      e.preventDefault();
      e.stopPropagation(); // do not open row drill-down
      openOverridePanel(obtn.dataset.server);
      return;
    }
    const retry = e.target.closest('[data-empty-retry="mcp"]');
    if (retry) {
      e.preventDefault();
      loadInventory().catch(() => {});
    }
  });
}

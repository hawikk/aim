/* MCP server inventory + allowlist + runtime-deny override UX. Orchestrator only.
 *.
 *
 * Self-contained module, same pattern as rules.js / findings.js: injects its
 * own nav tab, view section and stylesheet at runtime, activates on the
 * server-computed findingsConsole capability (analyst + admin —
 * MCP inventory is security-relevant: it answers "who has what MCP server
 * configured" and is where unapproved-MCP findings correlate).
 *
 * Split (mirroring the findings split) — the panels live
 * in sibling modules with clear ownership:
 *   ./mcp/state.js      shared view-private fctx + reset
 *   ./mcp/inventory.js  fleet catalogue table, KPI cards, filters, install drill-down
 * ./mcp/allowlist.js approved-server manage panel
 * ./mcp/override.js runtime-denials panel, override-deny form, override audit
 * ./mcp/session.js session chain panel + #/mcp?session=<id> deep link
 *
 * This file wires the capability gate, tab/section injection, element refs,
 * the router activation, and the panels in order. Keep it thin — new panel
 * code goes in a sibling module.
 *
 * Data comes from GET /api/mcp-servers: the CURRENT fleet inventory derived
 * from the latest event_type='inventory' snapshot per host+tool (schema
 * v1.2). A server removed from a config disappears once a newer snapshot for
 * that host+tool arrives without it. Metadata only — server names and config
 * scope as users wrote them; commands, URLs and env values are never
 * collected.
 *
 * analyst+admin manage settings.approved_mcp_servers via
 * GET/PUT /api/mcp-allowlist (audited machine-owned mcp-allowlist.yaml).
 *
 * when MCP enforce denies (or would deny) an unapproved server,
 * the analyst override path is permanent allowlist approve with required
 * reason, optional dual-control second approver, and full audit
 * (mcp.allowlist_update). No browser modal — inline panel.
 *
 * session chain panel loads GET /api/mcp-sessions/:sessionId
 *. Deep link: #/mcp?session=<id>. Never displays args/results.
 *
 * Row click drills into per-installation rows (user pseudonyms, hosts) via
 * the gated ?server= endpoint; a role without user-level access sees the
 * API's explanatory 403 detail instead of data.
 */

import { registerModuleView } from './lib/router.js';
import { moduleTab, moduleSection } from './lib/a11y.js';
import { skeletonCards } from './lib/components.js';
import { parseSessionFromHash } from './lib/mcp-session-chain.js';
import { api } from './lib/api.js';
import { fctx, resetMcpCtx } from './mcp/state.js';
import { loadInventory, setError, bindInventory } from './mcp/inventory.js';
import { loadAllowlist, bindAllowlist } from './mcp/allowlist.js';
import { loadDenials, loadOverrideAudit, bindOverride } from './mcp/override.js';
import { loadSession, bindSession } from './mcp/session.js';

/* Pure helpers stay importable from the orchestrator so existing unit tests
 * (and any external consumer) keep their contract across the split. */
export { statusPill, filterServers, activeFilterLabels } from './mcp/inventory.js';

/* ---------- Gate: server-computed capability (analyst + admin) ----------
 * /api/me.capabilities.findingsConsole is the API's role-computed gate for
 * security surfaces. Do not reintroduce client-side group-name
 * sniffing — it misfires on any group whose name merely contains "security". */
const me = await api('/api/me').catch((err) => {
  // SSO mode with no session → full-page redirect to the login flow. Personal
  // mode never 401s; network errors just leave this module inert.
  if (err.status === 401) window.location.assign('/auth/login');
  return null;
});
if (me?.capabilities?.findingsConsole) {
  init().catch((err) => console.error('mcp inventory viewer failed to start:', err));
}

async function init() {
  resetMcpCtx();
  fctx.me = me;

  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/mcp.css';
  document.head.appendChild(link);

  // Nav tab (after Rules when present, else after Findings/Security)
  moduleTab({
    view: 'mcp',
    label: 'MCP servers',
    icon: '<svg class="ico" viewBox="0 0 16 16"><rect x="2" y="2.5" width="12" height="4.5" rx="1" fill="none" stroke="currentColor" stroke-width="1.3"/><rect x="2" y="9" width="12" height="4.5" rx="1" fill="none" stroke="currentColor" stroke-width="1.3"/><circle cx="4.5" cy="4.75" r="0.9" fill="currentColor"/><circle cx="4.5" cy="11.25" r="0.9" fill="currentColor"/></svg>',
  });

  const section = moduleSection({ view: 'mcp', html: `
    <div class="banner info">Fleet MCP catalogue: <b>configured</b> ∪ <b>discovered</b> MCP servers. Approval is <code>settings.approved_mcp_servers</code> under <code>deny_unlisted</code>. When endpoint enforce denies an unapproved server, use <b>Override deny</b> — permanent allowlist approve with required reason, optional dual-control, full audit. Metadata only — never commands, URLs, env, args, or results.</div>
    <div class="cards" id="mcp-cards" aria-busy="true">${skeletonCards(7)}</div>

    <div class="panel" id="mcp-allowlist-panel">
      <h2>Approved MCP servers <span class="hint" id="mcp-allowlist-meta"></span></h2>
      <p class="hint">Exact server ids only (no wildcards). Changes write <code>mcp-allowlist.yaml</code> and are audited as <code>mcp.allowlist_update</code>. Endpoint PreToolUse deny uses the same names when <code>unapproved-mcp-server.enforce</code> is on.</p>
      <div id="mcp-allowlist-chips" class="chip-row"></div>
      <form id="mcp-allowlist-form" class="mcp-allowlist-form">
        <label class="mcp-field">
          <span class="hint">Add server id</span>
          <input type="text" id="mcp-allowlist-input" class="input" placeholder="e.g. github" autocomplete="off" maxlength="128" />
        </label>
        <button type="submit" class="btn btn-primary btn-sm" id="mcp-allowlist-add">Add</button>
        <button type="button" class="btn btn-ghost btn-sm" id="mcp-allowlist-reload">Reload</button>
      </form>
      <p id="mcp-allowlist-status" class="hint" role="status"></p>
      <p id="mcp-allowlist-err" class="err" hidden role="alert"></p>
    </div>

    <div class="panel" id="mcp-deny-panel">
      <h2>Runtime MCP denials <span class="hint" id="mcp-deny-meta"></span></h2>
      <p class="hint" id="mcp-deny-urgency"></p>
      <div id="mcp-deny-body"></div>
    </div>

    <div class="panel" id="mcp-override-panel" hidden>
      <h2 id="mcp-override-title">Override deny</h2>
      <p class="hint">Permanent analyst override: add this server to the approved allowlist. Endpoint collectors refresh the bundle on the next delivery cycle. Engineer-side resubmit break-glass (when deployed) is separate and audited as <code>enforcement.action=confirmed</code>.</p>
      <form id="mcp-override-form" class="mcp-override-form">
        <input type="hidden" id="mcp-override-server" value="" />
        <label class="mcp-field mcp-field-block">
          <span class="hint">Reason <span class="req" aria-hidden="true">*</span> <span class="sr-only">(required for audit)</span></span>
          <textarea id="mcp-override-reason" class="input" rows="3" maxlength="2000" required placeholder="Why is this server permitted? Incident id, business justification, TTL expectation…"></textarea>
        </label>
        <label class="mcp-check">
          <input type="checkbox" id="mcp-override-dual" />
          <span>Require dual control <span class="hint">(optional — second analyst identity recorded in audit)</span></span>
        </label>
        <label class="mcp-field mcp-field-block" id="mcp-override-approver-wrap" hidden>
          <span class="hint">Second approver identity</span>
          <input type="text" id="mcp-override-approver" class="input" maxlength="320" placeholder="name or email of second analyst" autocomplete="off" />
        </label>
        <label class="mcp-check">
          <input type="checkbox" id="mcp-override-confirm" />
          <span>I confirm this permanently adds the server to the fleet allowlist and is fully audited</span>
        </label>
        <div class="mcp-override-actions">
          <button type="submit" class="btn btn-primary btn-sm" id="mcp-override-submit">Approve server (override)</button>
          <button type="button" class="btn btn-ghost btn-sm" id="mcp-override-cancel">Cancel</button>
        </div>
        <p id="mcp-override-err" class="err" hidden role="alert"></p>
        <p id="mcp-override-status" class="hint" role="status"></p>
      </form>
    </div>

    <div class="panel" id="mcp-audit-panel">
      <h2>Recent allowlist overrides <span class="hint">audit <code>mcp.allowlist_update</code></span></h2>
      <div id="mcp-audit-body"></div>
    </div>

    <div class="controls-row" id="mcp-filters">
      <label class="picker">Status: <select id="mcp-status" aria-label="Filter MCP servers by approval status">
        <option value="all" selected>all</option>
        <option value="unapproved">unapproved</option>
        <option value="approved">approved</option>
      </select></label>
      <label class="picker">Source: <select id="mcp-source" aria-label="Filter MCP servers by discovery source">
        <option value="all" selected>all</option>
        <option value="configured">configured</option>
        <option value="discovered">discovered</option>
        <option value="discovered_only">discovered only</option>
      </select></label>
      <span class="hint" id="mcp-filter-hint"></span>
    </div>
    <div class="panel"><h2>MCP servers <span class="hint" id="mcp-range"></span></h2>
      <div class="table-wrap" tabindex="0" role="region" aria-label="MCP server inventory table, scrollable"><table id="mcp-inv-table" aria-busy="true"></table></div></div>
    <div class="panel" id="mcp-detail-panel" hidden>
      <div class="sec-detail-head">
        <h2 id="mcp-detail-title">Detail</h2>
        <button type="button" class="btn-control" id="mcp-detail-close">Close</button>
      </div>
      <div id="mcp-detail-body"></div>
    </div>
    <div class="panel" id="mcp-session-panel">
      <h2>Session chain <span class="hint">tool_calls + agent_handoffs (metadata only)</span></h2>
      <form id="mcp-session-form" class="mcp-session-form" autocomplete="off">
        <label class="mcp-session-label" for="mcp-session-input">Session id
          <input type="text" id="mcp-session-input" name="session" maxlength="128"
            placeholder="paste session_id from a finding or user timeline"
            spellcheck="false" />
        </label>
        <button type="submit" class="btn btn-sm" id="mcp-session-load">Load chain</button>
        <button type="button" class="btn btn-ghost btn-sm" id="mcp-session-clear" hidden>Clear</button>
      </form>
      <div id="mcp-session-body" class="mcp-session-body" aria-live="polite">
        <p class="hint">Enter a session id to reconstruct the request→tool→result timeline. Chain edges require schema v1.10 <code>call_id</code>/<code>parent_call_id</code> when collectors emit them. Args and results are never returned by the API and never rendered here.</p>
      </div>
    </div>` });
  document.querySelector('main').appendChild(section);

  // Element refs the panels share.
  Object.assign(fctx, {
    section,
    cards: section.querySelector('#mcp-cards'),
    table: section.querySelector('#mcp-inv-table'),
    detailPanel: section.querySelector('#mcp-detail-panel'),
    detailTitle: section.querySelector('#mcp-detail-title'),
    detailBody: section.querySelector('#mcp-detail-body'),
    sessionInput: section.querySelector('#mcp-session-input'),
    sessionBody: section.querySelector('#mcp-session-body'),
    sessionClear: section.querySelector('#mcp-session-clear'),
    statusSel: section.querySelector('#mcp-status'),
    sourceSel: section.querySelector('#mcp-source'),
    filterHint: section.querySelector('#mcp-filter-hint'),
    chipsEl: section.querySelector('#mcp-allowlist-chips'),
    metaEl: section.querySelector('#mcp-allowlist-meta'),
    statusEl: section.querySelector('#mcp-allowlist-status'),
    errEl: section.querySelector('#mcp-allowlist-err'),
    inputEl: section.querySelector('#mcp-allowlist-input'),
    overridePanel: section.querySelector('#mcp-override-panel'),
    denyBody: section.querySelector('#mcp-deny-body'),
    denyMeta: section.querySelector('#mcp-deny-meta'),
    denyUrgency: section.querySelector('#mcp-deny-urgency'),
    auditBody: section.querySelector('#mcp-audit-body'),
  });

  // Panels derived from the allowlist reload together after a write.
  fctx.refreshDerived = () => Promise.all([loadInventory(), loadDenials(), loadOverrideAudit()]);

  // `#/mcp` is a real route — the tab is an ordinary data-view button
  // handled by app.js, and route() calls this to render.
  registerModuleView('mcp', {
    // Return the promise so app.js showError can attach the view-level Retry banner.
    onActivate: () => {
      const fromHash = parseSessionFromHash(location.hash);
      if (fromHash && fromHash !== fctx.activeSessionId) {
        fctx.sessionInput.value = fromHash;
        loadSession(fromHash).catch(() => {});
      }
      return Promise.all([loadInventory(), loadAllowlist(), loadDenials(), loadOverrideAudit()]).catch((err) => {
        setError(err);
        throw err;
      });
    },
  });

  // Wire the extracted panels.
  bindInventory();
  bindAllowlist();
  bindOverride();
  bindSession();

  Promise.all([loadInventory(), loadAllowlist(), loadDenials(), loadOverrideAudit()]).catch(() => {}); // pre-warm
}

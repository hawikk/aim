/* MCP allowlist manage panel (split): approved-server chips,
 * add/remove/reload wiring. Writes go through PUT /api/mcp-allowlist and
 * are audited as mcp.allowlist_update.
 * The orchestrator (public/mcp.js) populates fctx before bind*() runs. */

import { fmtInt } from '../lib/format.js';
import { esc } from '../lib/dom.js';
import { overrideUrgency } from '../lib/mcp-override.js';
import { api, apiJson } from '../lib/api.js';
import { fctx } from './state.js';

export function setAllowlistErr(msg) {
  const { errEl } = fctx;
  if (!msg) {
    errEl.hidden = true;
    errEl.textContent = '';
    return;
  }
  errEl.hidden = false;
  errEl.textContent = msg;
}

export function renderAllowlist(d) {
  const { metaEl, chipsEl, statusEl, denyUrgency } = fctx;
  fctx.allowlist = [...(d.approvedMcpServers ?? [])];
  fctx.endpointEnforce = !!d.endpointEnforce;
  const enforce = fctx.endpointEnforce ? 'endpoint enforce ON' : 'endpoint enforce off/shadow';
  metaEl.textContent =
    `mode ${d.mcpAllowlistMode ?? 'deny_unlisted'} · ${fmtInt(fctx.allowlist.length)} approved · ${enforce}` +
    (d.contentHash ? ` · policy_hash ${String(d.contentHash).slice(0, 12)}…` : '');
  denyUrgency.textContent = overrideUrgency(fctx.endpointEnforce);
  if (fctx.allowlist.length === 0) {
    chipsEl.innerHTML = '<span class="hint">Empty allowlist — every MCP server is unapproved (deny-unlisted).</span>';
  } else {
    chipsEl.innerHTML = fctx.allowlist
      .map(
        (name) =>
          `<span class="chip" data-name="${esc(name)}"><code>${esc(name)}</code> ` +
          `<button type="button" class="btn btn-ghost btn-sm mcp-allowlist-remove" data-name="${esc(name)}" ` +
          `aria-label="Remove ${esc(name)} from allowlist">×</button></span>`,
      )
      .join('');
  }
  statusEl.textContent = d.note ?? '';
}

export async function loadAllowlist() {
  const { metaEl } = fctx;
  setAllowlistErr('');
  try {
    const d = await api('/api/mcp-allowlist');
    renderAllowlist(d);
  } catch (err) {
    // Wave-1 API may not be deployed yet on some stacks — surface clearly.
    if (err.status === 404) {
      setAllowlistErr('Allowlist manage API not available on this deployment (needs wave-1 /api/mcp-allowlist). Override path disabled.');
      metaEl.textContent = 'API missing';
      return;
    }
    setAllowlistErr(err.message);
  }
}

export async function saveAllowlist(next, extra = {}) {
  const { statusEl } = fctx;
  setAllowlistErr('');
  statusEl.textContent = 'Saving…';
  try {
    const d = await apiJson('/api/mcp-allowlist', 'PUT', { approvedMcpServers: next, ...extra });
    renderAllowlist(d);
    statusEl.textContent = `Saved · policy_hash ${String(d.contentHash ?? '').slice(0, 12)}…`;
    await fctx.refreshDerived();
    return d;
  } catch (err) {
    setAllowlistErr(err.message);
    statusEl.textContent = '';
    throw err;
  }
}

export function bindAllowlist() {
  const { section, inputEl, chipsEl } = fctx;

  section.querySelector('#mcp-allowlist-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const name = (inputEl.value || '').trim();
    if (!name) {
      setAllowlistErr('Enter a server id');
      return;
    }
    if (fctx.allowlist.includes(name)) {
      setAllowlistErr(`'${name}' is already on the allowlist`);
      return;
    }
    // Bulk add without dual-control still gets a short default reason so the
    // audit trail is never empty for allowlist growth.
    inputEl.value = '';
    saveAllowlist([...fctx.allowlist, name], {
      reason: `Manual allowlist add of ${name} from MCP tab`,
    }).catch(() => {});
  });
  chipsEl.addEventListener('click', (e) => {
    const rbtn = e.target.closest('.mcp-allowlist-remove');
    if (!rbtn) return;
    const name = rbtn.dataset.name;
    saveAllowlist(fctx.allowlist.filter((n) => n !== name), {
      reason: `Manual allowlist remove of ${name} from MCP tab`,
    }).catch(() => {});
  });
  section.querySelector('#mcp-allowlist-reload').addEventListener('click', () => {
    loadAllowlist().catch((err) => setAllowlistErr(err.message));
  });
}

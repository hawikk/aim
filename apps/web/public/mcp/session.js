/* MCP session chain panel (AIM-1157 split): GET /api/mcp-sessions/:sessionId
 * reconstruction (AIM-800 / AIM-627), deep link #/mcp?session=<id>.
 * Metadata only — args and results are never returned by the API and the
 * client privacy check refuses to paint if a regression leaks them.
 * The orchestrator (public/mcp.js) populates fctx before bind*() runs. */

import { emptyState } from '../lib/components.js';
import { api } from '../lib/api.js';
import {
  parseSessionFromHash,
  sessionPanelHtml,
  htmlLooksSafe,
} from '../lib/mcp-session-chain.js';
import { fctx } from './state.js';

export async function loadSession(sessionId) {
  const { sessionBody, sessionClear } = fctx;
  const sid = String(sessionId || '').trim();
  if (!sid || sid.length > 128) {
    sessionBody.innerHTML = emptyState({
      reason: 'error',
      title: 'Invalid session id',
      body: 'Session ids are non-empty strings up to 128 characters.',
    });
    return;
  }
  fctx.activeSessionId = sid;
  sessionClear.hidden = false;
  sessionBody.innerHTML = emptyState({ reason: 'loading', title: 'Loading session chain…' });
  sessionBody.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  try {
    const d = await api(`/api/mcp-sessions/${encodeURIComponent(sid)}`);
    const html = sessionPanelHtml(d);
    // Defense in depth: refuse to paint if a future API regression leaks content.
    if (!htmlLooksSafe(html)) {
      sessionBody.innerHTML = emptyState({
        reason: 'error',
        title: 'Session response blocked',
        body: 'Response failed the client privacy check (args/results must never render).',
      });
      return;
    }
    sessionBody.innerHTML = html;
  } catch (err) {
    sessionBody.innerHTML = emptyState({
      reason: 'error',
      title: err.status === 404 ? 'Session not found' : 'Could not load session chain',
      body: err.message,
    });
  }
}

function clearSession() {
  const { sessionInput, sessionBody, sessionClear } = fctx;
  fctx.activeSessionId = null;
  sessionInput.value = '';
  sessionClear.hidden = true;
  sessionBody.innerHTML = `<p class="hint">Enter a session id to reconstruct the request→tool→result timeline. Chain edges require schema v1.10 <code>call_id</code>/<code>parent_call_id</code> when collectors emit them. Args and results are never returned by the API and never rendered here.</p>`;
  // Drop ?session= from the hash without leaving the MCP tab.
  if (parseSessionFromHash(location.hash)) {
    const next = '#/mcp';
    if (location.hash !== next) location.hash = next;
  }
}

export function bindSession() {
  const { section, sessionInput, sessionClear } = fctx;

  section.querySelector('#mcp-session-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const sid = sessionInput.value.trim();
    if (!sid) return;
    // Keep the URL shareable when the operator loads a chain by hand.
    const next = `#/mcp?session=${encodeURIComponent(sid)}`;
    if (location.hash !== next) location.hash = next;
    else loadSession(sid).catch(() => {});
  });
  sessionClear.addEventListener('click', () => clearSession());

  // Deep-link warm path when the module boots already on #/mcp?session=…
  const bootSession = parseSessionFromHash(location.hash);
  if (bootSession) {
    sessionInput.value = bootSession;
    loadSession(bootSession).catch(() => {});
  }
}

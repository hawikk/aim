/* — Analyst-facing policy editor (safe subset, no raw YAML).
 *
 * Self-contained module, same pattern as rules.js / mcp.js: injects its own
 * nav tab, view section and stylesheet at runtime.
 *
 * Safe subset (existing policy APIs):
 *   - Sanctioned-tool allowlist — GET/POST /api/sanctioned, unsanction
 *   - Model/provider allowlist with observe|enforce modes —
 *     GET/POST/DELETE /api/governance/model-allowlist
 *
 * Advanced YAML (policies/guardrail/v1/*.yaml + Rules tab) stays admin-only
 * via capabilities.guardrail. This editor never writes core policy files.
 *
 * Gate: findingsConsole (analyst+) so security analysts can inspect the
 * live allowlists. Mutations still require capabilities.admin (same as the
 * APIs) — non-admins see a validated read-only surface.
 *
 * Split (mirroring the compliance activity /
 * rules mcp splits) — the panels live in sibling modules
 * with clear ownership:
 *   ./policy/state.js     shared view-private polCtx + mode pill + summary cards
 *   ./policy/tools.js     sanctioned-tools panel (form, table, mutations)
 *   ./policy/models.js    model/provider allowlist panel (form, table, mutations)
 *   ./policy/advanced.js  read-only per-rule enforcement flags (admins)
 *
 * This file wires the tab, the view section, the panel loaders, and the
 * mutation handlers. Keep it thin — new panel code goes in a sibling module.
 */

import { registerModuleView } from './lib/router.js';
import { esc } from './lib/dom.js';
import { moduleTab, moduleSection, announce } from './lib/a11y.js';
import { api } from './lib/api.js';
import { polCtx, resetPolicyCtx, renderCards } from './policy/state.js';
import { mountToolsForm, loadSanctioned, bindToolHandlers } from './policy/tools.js';
import { mountModelsForm, loadAllowlist, bindModelHandlers } from './policy/models.js';
import { loadAdvanced } from './policy/advanced.js';

/* ---------- Gate: server-computed capability ---------- */
const me = await api('/api/me').catch((err) => {
  if (err.status === 401) window.location.assign('/auth/login');
  return null;
});
if (me?.capabilities?.findingsConsole) {
  init(me).catch((err) => console.error('policy editor failed to start:', err));
}

function canMutate(session) {
  return Boolean(session?.capabilities?.admin);
}

function canSeeAdvanced(session) {
  return Boolean(session?.capabilities?.guardrail);
}

async function init(session) {
  const mutate = canMutate(session);
  const advanced = canSeeAdvanced(session);

  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/policy.css';
  document.head.appendChild(link);

  moduleTab({
    view: 'policy',
    label: 'Policy',
    icon: '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><path d="M3 2.5h7l3 3V13.5H3z" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M10 2.5V5.5h3" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M5 8.5h6M5 11h4" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>',
  });

  const writeNote = mutate
    ? 'You can edit the safe subset below. Every change is validated and audit-logged.'
    : 'This session can inspect the safe subset. Editing requires an admin role (same gate as the APIs).';

  const section = moduleSection({
    view: 'policy',
    html: `
    <div class="banner info">
      Analyst-facing policy editor — <b>safe subset only</b> (sanctioned tools and model/provider allowlists with observe→enforce modes).
      No raw YAML here. ${esc(writeNote)}
      ${advanced
        ? 'Advanced guardrail YAML and threshold tuning remain on the <a href="#/rules">Rules</a> tab.'
        : 'Advanced guardrail YAML stays on the Rules tab for admins with the guardrail capability.'}
    </div>
    <div class="cards" id="pol-cards" role="list" aria-label="Policy editor summary"></div>
    <div class="pol-grid">
      <div class="panel">
        <h2 id="pol-tools-h">Sanctioned tools <span class="hint">fleet tool allowlist</span></h2>
        <p class="pol-readonly-note">Tools on this list are treated as approved fleet tooling. Removing a tool immediately reclassifies it as unapproved in coverage and discovery.</p>
        <div id="pol-tools-form" ${mutate ? '' : 'hidden'}></div>
        <div class="pol-table-wrap" tabindex="0" role="region" aria-labelledby="pol-tools-h">
          <div id="pol-tools-list" aria-busy="true"></div>
        </div>
      </div>
      <div class="panel">
        <h2 id="pol-models-h">Model / provider allowlist <span class="hint">observe → enforce rollout</span></h2>
        <p class="pol-readonly-note">Empty allowlist for a scope = unrestricted (fail-open). Mode <code>observe</code> records violations; <code>enforce</code> is the hard gate once Security signs off.</p>
        <div id="pol-models-form" ${mutate ? '' : 'hidden'}></div>
        <div class="pol-table-wrap" tabindex="0" role="region" aria-labelledby="pol-models-h">
          <div id="pol-models-list" aria-busy="true"></div>
        </div>
      </div>
      <div class="panel" id="pol-adv-panel" ${advanced ? '' : 'hidden'}>
        <div class="pol-adv">
          <div>
            <h2 id="pol-adv-h">Advanced (admins) <span class="hint">YAML policy-as-code</span></h2>
            <p class="pol-readonly-note">Match rules, MCP allowlist contents, restricted repos, and endpoint enforcement flags live in <code>policies/guardrail/v1/*.yaml</code>. Toggle thresholds and alert destinations on the Rules view — not here.</p>
            <div class="pol-rule-modes" id="pol-rule-modes" aria-labelledby="pol-adv-h"></div>
          </div>
          <a class="pol-link" href="#/rules">Open Rules →</a>
        </div>
      </div>
    </div>`,
  });
  document.querySelector('main').appendChild(section);
  resetPolicyCtx(section, { mutate, advanced });

  if (mutate) {
    mountToolsForm();
    mountModelsForm();
  }

  async function loadAll() {
    const { toolsList, modelsList } = polCtx;
    const results = await Promise.allSettled([
      loadSanctioned().catch((err) => {
        toolsList.setAttribute('aria-busy', 'false');
        toolsList.innerHTML = `<div class="err" role="alert">${esc(err.message)}</div>`;
        throw err;
      }),
      loadAllowlist().catch((err) => {
        modelsList.setAttribute('aria-busy', 'false');
        modelsList.innerHTML = `<div class="err" role="alert">${esc(err.message)}</div>`;
        throw err;
      }),
      loadAdvanced(),
    ]);
    // Cards only when at least one panel loaded.
    if (results[0].status === 'fulfilled' || results[1].status === 'fulfilled') {
      renderCards();
    }
    const fails = results.filter((r) => r.status === 'rejected');
    if (fails.length) {
      const msg = fails[0].reason?.message ?? 'Failed to load policy';
      if (fails.length === results.length) {
        announce(`Policy editor failed to load: ${msg}`);
      } else {
        announce(`Policy panel failed: ${msg}`);
      }
    }
  }

  registerModuleView('policy', {
    onActivate: () => {
      loadAll().catch((err) => {
        const { toolsList, modelsList } = polCtx;
        toolsList.setAttribute('aria-busy', 'false');
        modelsList.setAttribute('aria-busy', 'false');
        toolsList.innerHTML = `<div class="err" role="alert">${esc(err.message)}</div>`;
        announce(`Policy editor failed to load: ${err.message}`);
      });
    },
  });

  /* ---------- Mutations (admin only) ---------- */
  if (mutate) {
    bindToolHandlers();
    bindModelHandlers();
  }

  // Pre-warm so first tab open is instant.
  loadAll().catch(() => {});
}

/* AIM-81 — Guardrail rules transparency viewer. Orchestrator only.
 *
 * Self-contained module, same pattern as findings.js: injects its own nav
 * tab, view section and stylesheet at runtime, gated on the server-computed
 * capabilities.guardrail flag (same gate as the API).
 *
 * History: AIM-94 made the viewer a working tool (threshold rules tunable
 * inline via PATCH /api/guardrail/rules/:id; alert destinations panel on
 * GET/PUT /api/guardrail/alerts). AIM-584 multi-destination routing is
 * form-only. AIM-987/990/699 added PagerDuty + Slack cards and the
 * multi-stage escalation editor. AIM-998 deep-links the destinations toolbar
 * to Audit filtered on `guardrail.alerts_update`. AIM-988 added the email
 * Test send. Match rules stay read-only: they are policy-as-code and change
 * via PR on policies/guardrail/v1/*.yaml. Alert secrets are env-managed and
 * never entered in this UI.
 *
 * Split (AIM-1147) — the panels live in sibling modules with clear ownership:
 *   ./state.js             view-private rulesState (last rules, last alerts, DOM roots)
 *   ./rule-list.js         policy settings dl + Active rules list + threshold edit form markup
 *   ./alert-cards.js       alert destination cards + routing summary markup
 *   ./escalation.js        multi-stage escalation ladder editor markup
 *   ./threshold-editor.js  threshold editor interactions + PATCH handlers
 *   ./alerts-panel.js      alert destinations load/save, Test send, escalation mutations
 *
 * This file wires the module: capability gate, nav tab, view section, the
 * rules fetch + KPI cards, and the two interaction binders. Keep it thin —
 * new panel code goes in a sibling module.
 *
 * Rule data comes from GET /api/guardrail/rules, which reads the same YAML
 * files the engine loads, on every request — this view cannot drift from the
 * live policy. Findings link back here via findings.policy_hash.
 */

import { registerModuleView } from './lib/router.js';
import { fmtInt } from './lib/format.js';
import { esc } from './lib/dom.js';
import { moduleTab, moduleSection, announce } from './lib/a11y.js';
import { card } from './lib/components.js';
import { api } from './lib/api.js';
import { requireCapability } from './lib/form.js';
import { rulesState } from './rules/state.js';
import { settingsHtml, renderRules } from './rules/rule-list.js';
import { loadAlerts, bindAlertsPanel } from './rules/alerts-panel.js';
import { bindThresholdEditor } from './rules/threshold-editor.js';

/* ---------- Gate: server-computed capability (same gate as /api/guardrail/rules) ----------
 * /api/me.capabilities.guardrail is the API's role-computed gate for the
 * guardrail surface (AIM-95). Do not reintroduce client-side group-name
 * sniffing — it misfires on any group whose name merely contains "security".
 * Gate helper: lib/form.js (AIM-1113). */
await requireCapability('guardrail', init, 'rules viewer');

async function init() {
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/rules.css';
  document.head.appendChild(link);

  // Nav tab (after Findings when present, else after Security)
  moduleTab({
    view: 'rules',
    label: 'Rules',
    icon: '<svg class="ico" viewBox="0 0 16 16"><path d="M3 3.5h10M3 8h10M3 12.5h6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="12.5" cy="12.5" r="2" fill="none" stroke="currentColor" stroke-width="1.3"/></svg>',
  });

  const section = moduleSection({ view: 'rules', html: `
    <div class="banner info">Live guardrail policy as the engine has it loaded — read from the policy files on every request, so this view cannot drift. <b>Threshold rules can be tuned here</b> (overrides on top of the policy, resettable); match rules stay policy-as-code and change via PR on <code>policies/guardrail/v1/*.yaml</code> (Security approval required). Detector outcomes only — matched content is never collected.</div>
    <div class="panel"><h2 id="rules-alerts-h">Alert destinations <span class="hint">multi-destination routing — each rule fans out to every enabled destination</span></h2>
      <div id="alert-cards" aria-labelledby="rules-alerts-h" aria-busy="true"></div>
      <p class="alert-note">Secrets (webhook secret, Sentinel shared key, Google Chat / Slack incoming-webhook URLs, email SMTP host/from/password, PagerDuty routing key) are managed via the deployment environment — never entered here. Enabling a destination whose env secret is not configured will fail engine-side; the badge on each card shows the current state. Escalation ladders are edited below and saved via the alerts API — no raw YAML. Secrets stay env-managed.</p>
    </div>
    <div class="cards" id="rules-cards" role="list" aria-label="Guardrail policy summary"></div>
    <div class="panel"><h2 id="rules-settings-h">Policy settings <span class="hint">shared rule inputs from the same policy files</span></h2><dl class="f-fields" id="rules-settings"></dl></div>
    <div class="panel"><h2 id="rules-list-h">Active rules <span class="hint" id="rules-hash"></span></h2><div id="rules-list" role="list" aria-labelledby="rules-list-h" aria-busy="true"></div></div>` });
  document.querySelector('main').appendChild(section);

  rulesState.section = section;
  rulesState.list = section.querySelector('#rules-list');
  rulesState.alertCards = section.querySelector('#alert-cards');
  const list = rulesState.list;

  // AIM-153: `#/rules` is a real route — the tab is an ordinary data-view
  // button handled by app.js, and route() calls this to render.
  registerModuleView('rules', {
    onActivate: () => {
      load().catch((err) => {
        list.setAttribute('aria-busy', 'false');
        list.innerHTML = `<div class="err" role="alert">${esc(err.message)}</div>`;
        announce(`Guardrail rules failed to load: ${err.message}`);
      });
      loadAlerts();
    },
  });

  /* AIM-515: cards sit in a list; attach role=listitem without reimplementing card(). */
  const statCard = (label, value, tone) => card({ label, value, tone, role: 'listitem' });

  async function load() {
    const d = await api('/api/guardrail/rules');
    rulesState.lastRules = d.rules;
    const totalFired = d.rules.reduce((n, r) => n + r.firedCount, 0);
    const fired = d.rules.filter((r) => r.firedCount > 0).length;
    // AIM-441: "active" means evaluable (not inert), not "has fired".
    const pc = d.postureCounts ?? {};
    const activeN = pc.active ?? d.rules.filter((r) => (r.posture ?? 'active') === 'active').length;
    const inertN = pc.inert ?? d.rules.filter((r) => r.posture === 'inert').length;
    section.querySelector('#rules-cards').innerHTML = [
      statCard('Active rules', fmtInt(activeN), activeN >= 12 ? 'good' : ''),
      statCard('Inert (labelled)', fmtInt(inertN), inertN > 0 ? '' : 'good'),
      statCard('Recorded firings', fmtInt(totalFired)),
      statCard('Rules that have fired', fmtInt(fired), fired > 0 ? '' : 'good'),
      statCard('Policy version', `v${d.version ?? '?'}`),
    ].join('');
    section.querySelector('#rules-hash').textContent =
      `content hash ${String(d.contentHash).slice(0, 12)}… — matches findings.policy_hash · MCP mode ${d.mcpAllowlistMode ?? d.settings?.mcp_allowlist_mode ?? 'deny_unlisted'} · source: ${d.sources.map((s) => s.split('/').slice(-2).join('/')).join(', ')}`;
    section.querySelector('#rules-settings').innerHTML = settingsHtml(d.settings) || '<div><dt>—</dt><dd>no settings</dd></div>';
    renderRules();
  }

  bindThresholdEditor();
  bindAlertsPanel();

  load().catch(() => {}); // pre-warm so first tab open is instant
  loadAlerts();
}

/* dashboard, premium redesign. Plain ES modules against the read API; Chart.js vendored.
 * hash-based routing — every view/entity selection is a shareable URL
 * (`#/view[/entity]?days=N&source=...`), with browser back/forward support.
 * designed empty states, retryable error banners, keyboard tabs, SR tables/charts.
 * view loaders live under views/*.js; this file is bootstrap + router wiring. */
import { parseHash, setHash, moduleView, onModuleViewRegistered, isKnownView } from './lib/router.js';
import { attributionLabel, verifiedStamp, verifiedTitle } from './lib/attribution-label.js';
import { fmtTs } from './lib/format.js';
import { $ } from './lib/dom.js';
import { state, setRefresh, hashFor, setStatus, clearError, showError, api, refresh } from './lib/runtime.js';
import { isUnauthorized, redirectToLogin } from './lib/api.js';
import { setInstallState, installBanner } from './lib/components.js';
import { bindRefClipboard } from './lib/ui.js';
import { initHomeRolePicker, resolveLandingView, HOME_EVENT } from './lib/home-role.js';
import { initNavIa, revealViewInNav, refreshAllGroupVisibility } from './lib/nav-ia.js';
import { initCharts } from './lib/charts.js'; // theme toggle + chart retheme side-effects
import { loadOverview } from './views/overview.js';
import { loadProviders } from './views/providers.js';
import { loadAppLlm } from './views/app-llm.js';
import { loadApps } from './views/apps.js';
import { loadTeams } from './views/teams.js';
import { loadTools } from './views/tools.js';
import { loadSecurity } from './views/security.js';
import { loadFleet } from './views/fleet.js';
import { loadRepos } from './views/repos.js';
import { loadUsers } from './views/users.js';
import { loadAudit } from './views/audit.js';
import { loadActivity } from './views/activity.js';
import { initI18n } from './lib/i18n.js';
import { en } from './locales/en.js';
import { de } from './locales/de.js';
import { fr } from './locales/fr.js';
import { nl } from './locales/nl.js';
import { initLocalePicker } from './lib/locale-picker.js';

// register Security-named catalogs, resolve locale, stamp
// <html lang> before module views paint. English remains fail-closed fallback.
initI18n({ catalogs: { en, de, fr, nl } });
// Locale picker lists registered tags only (never LOCALES_AWAITING_SECURITY).
initLocalePicker({
  onChange: () => {
    // Re-run the active route so t()-backed chrome (severity, empty states, …)
    // repaints without a full reload.
    try {
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    } catch {
      try {
        window.dispatchEvent(new Event('hashchange'));
      } catch {
        /* re-paint is best-effort */
      }
    }
  },
});

bindRefClipboard();
// Per-boot (not module-load): harness cache-busts app.js but shares lib/*.
initCharts();

/*: set at bootstrap when /api/me returns role null — routing stays inert
 * because every view is capability-gated and there is nothing to render. */
let noAccess = false;

/* Returns true when the hash changed — the hashchange listener will call
 * route(). False means the URL already named this state, so nothing will fire
 * and the caller must re-render itself if it needs one. */
function navigate() {
  return setHash(location, hashFor(state.view, state.entity));
}

function route() {
  if (noAccess) return;
  const r = parseHash(location.hash);
  state.view = r.view;
  state.entity = r.entity;
  state.days = r.days;
  state.source = r.source;
  syncControls();
  refresh();
}

/*: feature modules become routable only once their capability fetch
 * settles, so a shared `#/findings` link resolves to Overview on the first
 * route and has to be picked up when the module arrives. Subscribed here,
 * synchronously and before this script's first await, because module scripts
 * run while app.js is parked on its /api/me bootstrap and would otherwise
 * register into a void. `bootstrapped` keeps this from double-rendering: a
 * module that registers before the initial route is picked up by that route. */
let bootstrapped = false;
onModuleViewRegistered((name) => {
  if (bootstrapped && parseHash(location.hash).view === name) route();
});

function syncControls() {
  document.querySelectorAll('#range button').forEach((b) => {
    const active = Number(b.dataset.days) === state.days;
    b.classList.toggle('active', active);
    b.setAttribute('aria-pressed', String(active));
  });
  document.querySelectorAll('#source-filter button').forEach((b) => {
    const active = b.dataset.source === state.source;
    b.classList.toggle('active', active);
    b.setAttribute('aria-pressed', String(active));
  });
}

/* ---------- CSV export links ---------- */
function updateExports() {
  const src = state.source === 'all' ? '' : `&source=${state.source}`;
  const set = (id, href) => { const el = $(id); if (el) el.href = href; };
  set('#exp-overview', `/api/overview?days=${state.days}&format=csv`);
  set('#exp-repos', `/api/repos?days=${state.days}&format=csv`);
  set('#exp-repos-tab', `/api/repos?days=${state.days}&format=csv`);
  set('#exp-providers', `/api/providers?days=${state.days}${src}&format=csv`);
  set('#exp-app-llm', `/api/app-llm?days=${state.days}&format=csv`);
  set('#exp-apps', `/api/apps/llm?days=${state.days}&format=csv`);
  set('#exp-apps-models', `/api/apps/llm?days=${state.days}&format=csv&breakdown=models`);
  set('#exp-teams', `/api/teams?days=${state.days}&format=csv`);
  set('#exp-teams-models', `/api/aggregate?group_by=team,model&days=${state.days}&format=csv`);
  set('#exp-flags', `/api/flags?days=${state.days}&format=csv`);
  set('#exp-unapproved', `/api/unapproved?days=${state.days}&format=csv`);
  set('#exp-users', `/api/users?days=${state.days}&format=csv`);
}

const loaders = {
  overview: loadOverview,
  providers: loadProviders,
  'app-llm': loadAppLlm,
  apps: loadApps,
  teams: loadTeams,
  tools: loadTools,
  repos: loadRepos,
  security: loadSecurity,
  activity: loadActivity,
  fleet: loadFleet,
  users: loadUsers,
  audit: loadAudit,
};

const rendererFor = (view) => moduleView(view)?.onActivate ?? loaders[view];

function markUpdated() {
  const el = $('#updated');
  const now = new Date();
  el.textContent = 'updated ' + fmtTs(now);
  el.title = now.toISOString();
}

let _pipelineStatus = null;
const PIPELINE_LABELS = {
  ok: 'pipeline live',
  idle: 'pipeline IDLE',
  no_collectors: 'no collectors',
  pending_collectors: 'collectors pending',
};

function renderAttributionHealth(att) {
  const el = $('#attribution-health');
  if (!el) return;
  const label = attributionLabel(att);
  if (label == null) { el.hidden = true; return; }
  el.dataset.status = att.status;
  const verified = verifiedStamp(att.lastVerifiedAt);
  const full = verified ? `${label} · ${verified}` : label;
  el.title = [att.message, verifiedTitle(att.lastVerifiedAt)].filter(Boolean).join(' — ');
  if (el.textContent !== full) el.textContent = full;
  el.hidden = false;
}

async function loadPipelineHealth() {
  const el = $('#pipeline-health');
  if (!el) return;
  let data;
  const clear = () => { el.hidden = true; _pipelineStatus = null; renderAttributionHealth(null); };
  try {
    const res = await fetch('/api/pipeline/liveness');
    if (!res.ok) { clear(); return; }
    data = await res.json();
  } catch { clear(); return; }
  el.dataset.status = data.status;
  el.title = data.message || '';
  const changed = _pipelineStatus !== data.status;
  _pipelineStatus = data.status;
  if (changed || !el.textContent) el.textContent = '● ' + (PIPELINE_LABELS[data.status] || 'pipeline');
  el.hidden = false;
  renderAttributionHealth(data.attribution);
}

async function doRefresh() {
  // only role=tab buttons carry data-view; group toggles must not
  // receive aria-selected. Reveal the active utility group so the selected
  // tab is not trapped inside a collapsed section.
  revealViewInNav(state.view);
  document.querySelectorAll('nav button[data-view]').forEach((b) => {
    const active = b.dataset.view === state.view;
    b.classList.toggle('active', active);
    b.setAttribute('aria-selected', String(active));
  });
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${state.view}`));
  clearError(state.view);
  updateExports();
  setStatus(`Loading ${state.view} view…`);
  try {
    await rendererFor(state.view)();
    markUpdated();
    setStatus(`${state.view} view updated.`);
  } catch (err) {
    showError(state.view, err);
    setStatus(`Error loading ${state.view} view: ${err.message}`);
  }
}
setRefresh(doRefresh);

/* ---------- Controls: every control change routes through the URL ---------- */
$('#tabs').addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-view]');
  if (btn) {
    state.view = btn.dataset.view;
    state.entity = null;
    if (!navigate()) route();
  }
});
$('#range').addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-days]');
  if (!btn) return;
  state.days = Number(btn.dataset.days);
  navigate();
});
$('#source-filter').addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-source]');
  if (!btn) return;
  state.source = btn.dataset.source;
  navigate();
});
$('#tool-picker').addEventListener('change', (e) => {
  state.entity = e.target.value;
  navigate();
});
$('#audit-refresh').addEventListener('click', () => refresh());
$('#sign-out').addEventListener('click', (e) => {
  e.preventDefault();
  window.location.assign('/auth/logout');
});
$('#tabs').addEventListener('keydown', (e) => {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
  // rove only visible data-view tabs (skip group toggles + collapsed).
  const tabs = [...$('#tabs').querySelectorAll('button[data-view]:not([hidden])')]
    .filter((b) => b.offsetParent !== null || b.getClientRects().length > 0);
  const i = tabs.indexOf(document.activeElement);
  if (i === -1) return;
  e.preventDefault();
  const next = e.key === 'Home' ? tabs[0]
    : e.key === 'End' ? tabs[tabs.length - 1]
    : e.key === 'ArrowRight' ? tabs[(i + 1) % tabs.length]
    : tabs[(i - 1 + tabs.length) % tabs.length];
  next.focus();
  next.click();
});

window.addEventListener('hashchange', route);

/* ---------- Bootstrap: /api/me capabilities decide which tabs are visible. ---------- */
try {
  state.me = await api('/api/me');
  if (!state.me.role) {
    noAccess = true;
    $('#tabs').hidden = true;
    const main = $('#main');
    main.replaceChildren();
    const msg = document.createElement('div');
    msg.className = 'banner warn no-access';
    msg.setAttribute('role', 'alert');
    msg.textContent = 'No access — your account has no AI Monitoring role. Contact your security team.';
    main.appendChild(msg);
  } else {
    if (state.me.capabilities?.userLevel) $('#tab-users').hidden = false;
    if (state.me.capabilities?.userLevel) $('#tab-activity').hidden = false;
    if (state.me.capabilities?.fleet) $('#tab-fleet').hidden = false;
    if (state.me.capabilities?.auditTrail) $('#tab-audit').hidden = false;

    // collapse utilities into groups; Home is the permanent main page.
    initNavIa({ getActiveView: () => state.view });
    refreshAllGroupVisibility();

    const install = await api('/api/onboarding/status').catch(() => null);
    setInstallState(install);
    installBanner(install);

    // persona picker + bare-arrival landing. Onboarding first-run
    // still wins later via landedWithoutView() (INITIAL_HASH), not live hash.
    // Preference only — do not yank the operator off an explicit view.
    initHomeRolePicker(state.me);
    window.addEventListener(HOME_EVENT, () => {
      if (state.view === 'overview') refresh();
    });
  }
  $('#me').textContent = state.me.email;
  const badge = $('#role-badge');
  if (badge && state.me.role) {
    badge.dataset.role = state.me.role;
    badge.textContent = state.me.role;
    badge.title = state.me.capabilities?.userLevel
      ? 'This session can see user-level rows. Every access is written to the audit trail.'
      : 'This session sees org and team aggregates only. User-level rows are withheld by policy.';
  }
  if (state.me.mode === 'sso') $('#sign-out').hidden = false;
  loadPipelineHealth();
  setInterval(loadPipelineHealth, 60000);
} catch (err) {
  if (isUnauthorized(err)) {
    redirectToLogin();
  } else {
    const banner = document.createElement('div');
    banner.className = 'error-banner';
    banner.setAttribute('role', 'alert');
    const msg = document.createElement('div');
    const strong = document.createElement('strong');
    strong.textContent = 'Couldn’t load your session. ';
    const detail = document.createElement('span');
    detail.className = 'err-detail';
    detail.textContent = err.message;
    msg.append(strong, detail);
    const retry = document.createElement('button');
    retry.className = 'btn btn-danger btn-sm';
    retry.textContent = 'Retry';
    retry.addEventListener('click', () => location.reload());
    banner.append(msg, retry);
    $('#main').prepend(banner);
    setStatus(`Error loading session: ${err.message}`);
  }
}
bootstrapped = true;
if (location.hash) {
  route();
} else if (!noAccess && state.me?.role) {
  // bare arrival lands on the persona home (findings / security /
  // overview). Explicit destinations and first-run onboarding are untouched.
  const landing = resolveLandingView(state.me, { isKnownView });
  location.replace(hashFor(landing));
} else {
  location.replace(hashFor('overview'));
}

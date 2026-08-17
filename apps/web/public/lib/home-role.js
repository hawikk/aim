/* AIM-707 — Role-based home (SOC vs Security Eng vs Admin).
 *
 * Personas are operator-facing home layouts, not API roles. API roles
 * (admin / analyst / auditor / viewer) still gate data and capabilities;
 * personas only choose default landing + which Overview widgets surface.
 *
 * Default mapping (overridable via localStorage when the session may use
 * more than one persona):
 *   admin   → admin
 *   analyst → soc
 *   auditor / viewer → no ops persona; overview-only home
 *
 * Configurable: aim.homeRole stores soc | seceng | admin. Preference is
 * best-effort (same storage posture as aim.theme) and is ignored when the
 * session lacks the capabilities that persona needs.
 */

export const HOME_KEY = 'aim.homeRole';
export const HOME_EVENT = 'aim:homechange';

/** @typedef {'soc' | 'seceng' | 'admin'} HomePersona */

export const HOME_PERSONAS = Object.freeze(['soc', 'seceng', 'admin']);

export const HOME_LABELS = Object.freeze({
  soc: 'SOC',
  seceng: 'Sec Eng',
  admin: 'Admin',
});

export const HOME_TITLES = Object.freeze({
  soc: 'SOC home — open criticals and triage first',
  seceng: 'Security engineering home — unapproved tools, coverage, repos',
  admin: 'Admin home — fleet posture, identity coverage, enrollment',
});

/* Widget ids match data-home-widget on Overview panels. Order = visual order.
 * AIM-1070 follow-up: Home is signals only (KPIs / alerts / tools / coverage) —
 * not a second tile-rail of every utility. Utilities stay in collapsible nav. */
export const HOME_WIDGETS = Object.freeze({
  soc: Object.freeze(['kpis', 'alerts', 'spark', 'tools', 'attribution']),
  seceng: Object.freeze(['kpis', 'tools', 'attribution', 'repos', 'alerts', 'spark']),
  admin: Object.freeze(['kpis', 'spark', 'attribution', 'tools', 'repos', 'alerts']),
});

/** Landing view per persona. Module views (findings) resolve after registration. */
export const HOME_LANDING = Object.freeze({
  soc: 'findings',
  seceng: 'security',
  admin: 'overview',
});

const PERSONA_SET = new Set(HOME_PERSONAS);

function storage() {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

/** Stored preference, or null if unset/unreadable/garbage. */
export function storedHomeRole() {
  try {
    const value = storage()?.getItem(HOME_KEY);
    return PERSONA_SET.has(value) ? value : null;
  } catch {
    return null;
  }
}

/**
 * Default persona from the server role. Analysts land on SOC; admins on Admin.
 * Auditor/viewer have no ops persona — null means "overview aggregate only".
 * @param {{ role?: string|null, capabilities?: object }|null} me
 * @returns {HomePersona|null}
 */
export function defaultHomeRole(me) {
  const role = me?.role;
  if (role === 'admin') return 'admin';
  if (role === 'analyst') return 'soc';
  return null;
}

/**
 * Which personas this session is allowed to pick.
 * - soc needs findings console (landing is Findings)
 * - seceng needs an ops security surface (findings, fleet, or coverage) —
 *   not bare dashboard, so viewer/auditor stay on aggregate Overview
 * - admin persona needs admin capability (enrollment / policy posture)
 * @param {{ role?: string|null, capabilities?: object }|null} me
 * @returns {HomePersona[]}
 */
export function availableHomeRoles(me) {
  const caps = me?.capabilities ?? {};
  const out = [];
  if (caps.findingsConsole) out.push('soc');
  if (caps.findingsConsole || caps.fleet || caps.coverage) out.push('seceng');
  if (caps.admin) out.push('admin');
  return out;
}

/**
 * Effective persona: stored preference if allowed, else role default if allowed,
 * else first available, else null.
 * @param {{ role?: string|null, capabilities?: object }|null} me
 * @param {string|null} [stored]
 * @returns {HomePersona|null}
 */
export function resolveHomeRole(me, stored = storedHomeRole()) {
  const allowed = availableHomeRoles(me);
  if (allowed.length === 0) return null;
  if (PERSONA_SET.has(stored) && allowed.includes(/** @type {HomePersona} */ (stored))) {
    return /** @type {HomePersona} */ (stored);
  }
  const fromRole = defaultHomeRole(me);
  if (fromRole && allowed.includes(fromRole)) return fromRole;
  return allowed[0];
}

/**
 * Default landing view for bare arrivals. Falls back when the preferred view
 * is not yet routable (module not registered) or the session cannot use it.
 * @param {{ role?: string|null, capabilities?: object }|null} me
 * @param {{ isKnownView?: (name: string) => boolean, persona?: HomePersona|null }} [opts]
 * @returns {string}
 */
export function resolveLandingView(me, opts = {}) {
  const persona = opts.persona !== undefined ? opts.persona : resolveHomeRole(me);
  const isKnown = opts.isKnownView ?? (() => true);
  if (!persona) return 'overview';
  let view = HOME_LANDING[persona] ?? 'overview';
  // SOC landing is findings only when the module is registered this session.
  if (view === 'findings' && !me?.capabilities?.findingsConsole) view = 'overview';
  if (view === 'findings' && !isKnown('findings')) {
    // Hash can still name findings; callers that need a guaranteed static
    // first paint use overview until registration re-routes.
    return 'findings';
  }
  if (view === 'security' && !isKnown('security')) view = 'overview';
  return view;
}

/**
 * Widget list for a persona. Unknown/null → full admin-style layout so a
 * missing preference never blanks the page.
 * @param {HomePersona|null|undefined} persona
 * @returns {readonly string[]}
 */
export function widgetsFor(persona) {
  if (persona && HOME_WIDGETS[persona]) return HOME_WIDGETS[persona];
  return HOME_WIDGETS.admin;
}

/**
 * Persist + announce a persona change. Returns the persona actually applied
 * (may clamp to an allowed value).
 * @param {string} persona
 * @param {{ role?: string|null, capabilities?: object }|null} me
 * @param {{ persist?: boolean }} [opts]
 * @returns {HomePersona|null}
 */
export function applyHomeRole(persona, me, { persist = true } = {}) {
  const allowed = availableHomeRoles(me);
  const next = allowed.includes(/** @type {HomePersona} */ (persona))
    ? /** @type {HomePersona} */ (persona)
    : resolveHomeRole(me, null);
  if (persist && next) {
    try {
      storage()?.setItem(HOME_KEY, next);
    } catch {
      /* preference is best-effort */
    }
  } else if (persist && !next) {
    try {
      storage()?.removeItem(HOME_KEY);
    } catch { /* ignore */ }
  }
  if (typeof document !== 'undefined' && document.documentElement) {
    if (next) document.documentElement.dataset.homeRole = next;
    else delete document.documentElement.dataset.homeRole;
  }
  if (typeof window !== 'undefined') {
    // Prefer the window's CustomEvent so jsdom realm checks pass in tests.
    const Ev = window.CustomEvent || globalThis.CustomEvent;
    if (Ev) window.dispatchEvent(new Ev(HOME_EVENT, { detail: { homeRole: next } }));
  }
  return next;
}

/**
 * Reorder / show-hide Overview panels by data-home-widget.
 * Panels not in the persona list are hidden; listed panels are shown in order.
 * @param {ParentNode|null} root
 * @param {HomePersona|null} persona
 */
export function applyHomeWidgets(root, persona) {
  if (!root) return;
  const order = widgetsFor(persona);
  const wanted = new Set(order);
  /** @type {HTMLElement[]} */
  const panels = [...root.querySelectorAll(':scope > [data-home-widget], [data-home-widget]')].filter(
    (el, i, arr) => arr.indexOf(el) === i,
  );
  const byId = new Map(panels.map((el) => [el.dataset.homeWidget, el]));
  for (const el of panels) {
    const id = el.dataset.homeWidget;
    el.hidden = !wanted.has(id);
  }
  // Keep non-widget chrome (e.g. home banner) ahead of reordered panels.
  let anchor = null;
  for (const child of root.children) {
    if (child.hasAttribute('data-home-widget')) break;
    anchor = child;
  }
  for (const id of order) {
    const el = byId.get(id);
    if (!el) continue;
    if (anchor) anchor.after(el);
    else root.prepend(el);
    anchor = el;
  }
}

/**
 * Wire the top-bar home persona picker. Safe to call with no picker in DOM.
 * @param {{ role?: string|null, capabilities?: object }|null} me
 * @param {{ onChange?: (persona: HomePersona|null) => void, doc?: Document }} [opts]
 * @returns {HomePersona|null}
 */
export function initHomeRolePicker(me, opts = {}) {
  const doc = opts.doc ?? (typeof document !== 'undefined' ? document : null);
  const group = doc?.getElementById('home-role');
  const persona = resolveHomeRole(me);
  applyHomeRole(persona, me, { persist: false });

  if (!group) return persona;

  const allowed = availableHomeRoles(me);
  // Hide the control entirely when there is nothing to choose (viewer) or
  // only one persona (no configuration surface).
  if (allowed.length < 2) {
    group.hidden = true;
    return persona;
  }
  group.hidden = false;

  for (const btn of group.querySelectorAll('button[data-home-role]')) {
    const id = btn.dataset.homeRole;
    const ok = allowed.includes(/** @type {HomePersona} */ (id));
    btn.hidden = !ok;
    btn.disabled = !ok;
    const active = id === persona;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-pressed', String(active));
  }

  if (group.dataset.bound === '1') return persona;
  group.dataset.bound = '1';
  group.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-home-role]');
    if (!btn || btn.hidden || btn.disabled) return;
    const next = applyHomeRole(btn.dataset.homeRole, me, { persist: true });
    for (const b of group.querySelectorAll('button[data-home-role]')) {
      const active = b.dataset.homeRole === next;
      b.classList.toggle('active', active);
      b.setAttribute('aria-pressed', String(active));
    }
    const status = doc.getElementById('sr-status');
    if (status && next) {
      status.textContent = `${HOME_LABELS[next]} home applied`;
    }
    opts.onChange?.(next);
  });

  return persona;
}

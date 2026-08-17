/* Hash-router core (AIM-71, extracted in AIM-152, module views in AIM-153).
 *
 * Pure URL logic, no DOM: app.js owns the rendering, this module owns the
 * "what does this URL mean / what URL means this state" mapping so it can be
 * unit-tested (see apps/web/test/router.test.js). The AIM-152 dead end lived
 * exactly here — a navigation that changed nothing silently rendered nothing —
 * so the no-change case is now an explicit, tested return value rather than a
 * bare `return`.
 *
 * AIM-153: feature modules (findings/rules/compliance/mcp/onboarding) used to
 * claim the main area imperatively — their tab click stopPropagation()'d past
 * app.js and toggled `.active` classes directly, never touching the URL. That
 * made their views unaddressable, invisible to history, and free to disagree
 * with the router about what was on screen; the AIM-152 dead end was one
 * symptom. They now `registerModuleView()` instead: the name becomes routable,
 * their tab is an ordinary `data-view` button, and route() dispatches to them.
 */

/* Views that exist in index.html and always route. Feature modules add theirs
 * at runtime via registerModuleView() — deliberately NOT by mutating this
 * array, so "static tab" and "capability-gated module view" stay separable and
 * an unregistered name has exactly one meaning: not routable in this session. */
export const VALID_VIEWS = ['overview', 'providers', 'app-llm', 'apps', 'teams', 'tools', 'repos', 'security', 'activity', 'fleet', 'users', 'audit'];
export const VALID_DAYS = [7, 30, 90];
export const VALID_SOURCES = ['all', 'proxy', 'endpoint'];
// Entity drill-down exists only for these views; anything else drops the segment.
// `runbooks` is a module view (AIM-703): `#/runbooks/<slug>` deep-links a SOC
// runbook page. Entity is only kept once the module has registered (isKnownView).
export const DRILL_VIEWS = ['providers', 'apps', 'teams', 'tools', 'repos', 'users', 'runbooks'];

/* The hash the operator actually arrived with.
 *
 * Captured at module evaluation, which happens before app.js's bootstrap can
 * rewrite it (`location.replace(hashFor('overview'))`) and before any feature
 * module's async status fetch settles. Modules that claim the main area on
 * first run (onboarding, findings) consult this instead of live
 * `location.hash`, so "land me on your inbox" stays a first-run nicety and
 * never overrides an explicit destination the operator typed or shared.
 */
export const INITIAL_HASH = typeof location === 'undefined' ? '' : location.hash;

/** True when the operator landed on a bare URL, i.e. no view was requested. */
export function landedWithoutView(hash = INITIAL_HASH) {
  return !hash || hash === '#' || hash === '#/';
}

/* ---------- Feature-module views (AIM-153) ----------
 *
 * A module view is routable only once its module has registered it, which
 * happens after the module's capability fetch settles. Two consequences the
 * callers depend on:
 *
 *  - Capability gating is the *absence* of a registration. `#/findings` in a
 *    session without the findings capability never becomes a known view, so
 *    parseHash falls it back to Overview — the session can't be shown a flash
 *    of a view it may not see, because nothing ever built that view.
 *  - Registration is late by construction. A shared `#/findings` link resolves
 *    to Overview on the first route and only becomes Findings once the module
 *    arrives, so registration has to be able to re-route: subscribers of
 *    onModuleViewRegistered re-run route() when the current hash names the
 *    module that just registered.
 */
const moduleViews = new Map();
const registrationListeners = new Set();

/** Make `name` routable and hand route() the callback that renders it.
 *
 * `drill: true` (AIM-706) keeps the second path segment as `entity` so module
 * views like Cases can deep-link a detail (`#/cases/<id>`). Default false —
 * a stray segment on Findings must not become a bogus entity. */
export function registerModuleView(name, { onActivate, drill = false }) {
  if (VALID_VIEWS.includes(name)) throw new Error(`"${name}" is a static view, not a module view`);
  if (typeof onActivate !== 'function') throw new Error(`module view "${name}" needs an onActivate function`);
  moduleViews.set(name, { name, onActivate, drill: Boolean(drill) });
  for (const fn of registrationListeners) fn(name);
  return name;
}

/** The registered module view for `name`, or null if it isn't one (or isn't yet). */
export function moduleView(name) {
  return moduleViews.get(name) ?? null;
}

/** True when `name` routes in this session — static tab or registered module. */
export function isKnownView(name) {
  return VALID_VIEWS.includes(name) || moduleViews.has(name);
}

/** Subscribe to registrations. Fires synchronously, after the view is routable. */
export function onModuleViewRegistered(fn) {
  registrationListeners.add(fn);
  return () => registrationListeners.delete(fn);
}

/** Test seam: drop all module registrations and listeners. */
export function resetModuleViews() {
  moduleViews.clear();
  registrationListeners.clear();
}

/** True when `view` keeps a second path segment as the entity id. */
export function viewAllowsDrill(view) {
  if (DRILL_VIEWS.includes(view)) return true;
  return Boolean(moduleViews.get(view)?.drill);
}

/** Parse a location hash into router state. Unknown values fall back, never throw. */
export function parseHash(hash = '') {
  const raw = String(hash).replace(/^#\/?/, '');
  const [pathPart, queryPart] = raw.split('?');
  const segs = pathPart.split('/').filter(Boolean).map(decodeURIComponent);
  const view = isKnownView(segs[0]) ? segs[0] : 'overview';
  const entity = viewAllowsDrill(view) ? segs[1] || null : null;
  const q = new URLSearchParams(queryPart || '');
  let days = Number(q.get('days'));
  if (!VALID_DAYS.includes(days)) days = 30;
  const source = VALID_SOURCES.includes(q.get('source')) ? q.get('source') : 'all';
  return { view, entity, days, source };
}

/** Build a shareable URL for a view/entity under the given range/source filters. */
export function hashFor(view, entity = null, { days = 30, source = 'all' } = {}) {
  const path = `#/${view}${entity ? `/${encodeURIComponent(entity)}` : ''}`;
  const q = new URLSearchParams();
  if (days !== 30) q.set('days', String(days));
  if (view === 'providers' && source !== 'all') q.set('source', source);
  const qs = q.toString();
  return qs ? `${path}?${qs}` : path;
}

/* Point `loc` at `hash`.
 *
 * Returns true when the hash actually changed — a hashchange event will fire
 * and the router re-renders itself. Returns FALSE when the hash was already
 * current: no event will fire, so the caller owns the re-render. AIM-152: the
 * old code returned void here, so a tab click whose hash already matched
 * rendered nothing at all — which left the operator stranded whenever a
 * feature module had claimed the main area out-of-band.
 */
export function setHash(loc, hash) {
  if (loc.hash === hash) return false;
  loc.hash = hash;
  return true;
}

/* Go to `view` the way a tab click does: push it onto the URL and let
 * hashchange re-render. Same contract as setHash — false means the URL already
 * named it, so no event will fire and the caller owns the re-render. For
 * deliberate operator actions (clicking a critical-finding toast). */
export function navigateToView(view, loc = location) {
  return setHash(loc, `#/${view}`);
}

/* Land on `view` without leaving a back entry.
 *
 * For the two module landings AIM-152 made explicit: first-run onboarding and
 * the security group's findings inbox. The operator never asked for whatever
 * was on screen first, so `replace` — a Back that returns to a view you were
 * only passing through is noise. Callers must still gate on
 * landedWithoutView(): a landing may never overwrite an explicit destination. */
export function landOnView(view, loc = location) {
  if (loc.hash === `#/${view}`) return false;
  loc.replace(`#/${view}`);
  return true;
}

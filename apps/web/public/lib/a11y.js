/* Shared accessibility primitives for feature-module views (AIM-515).
 *
 * index.html builds its twelve static views by hand and gets the ARIA tabs
 * pattern right: every tab is `role="tab"` with `aria-selected`/`aria-controls`,
 * every panel is `role="tabpanel"` with `aria-labelledby` back to its tab, and
 * every decorative icon is `aria-hidden`. Feature modules (findings, rules,
 * compliance, mcp, coverage, shadow-ai, onboarding, …) inject their tab and
 * panel at runtime instead, and seven of the ten re-derived that markup by
 * copy-paste and dropped the ARIA on the way. The result was not cosmetic:
 *
 *  - `#tabs` is `role="tablist"`. A child without `role="tab"` is not exposed
 *    as a tab at all, so those views were missing from the tab list a screen
 *    reader user navigates.
 *  - app.js `refresh()` sets `aria-selected` on every `nav button[data-view]`.
 *    On an element with no tab role that attribute is invalid ARIA, so the
 *    selected view was both unannounced and malformed.
 *  - With no `aria-labelledby`, the panel that opened had no accessible name
 *    and no relationship to the control that opened it.
 *
 * Fixing that per-module is how it drifted in the first place. These builders
 * are the one place the markup contract lives, so view #21 inherits it instead
 * of re-deriving it. They deliberately mirror index.html exactly — if the
 * static markup and these helpers ever disagree, that is the bug.
 *
 * AIM-1070: moduleTab() also places the button via lib/nav-ia.js so modules no
 * longer need bespoke insertBefore chains (and so utilities land under the
 * collapsible groups instead of growing a 30-tab primary rail).
 */

import { placeNavTab } from './nav-ia.js';

/** Views that must never be built through here — index.html already owns them. */
const STATIC_VIEW_IDS = new Set(['overview', 'security', 'activity', 'fleet', 'users', 'audit',
  'providers', 'app-llm', 'apps', 'teams', 'tools', 'repos']);

/**
 * Build a nav tab that satisfies the ARIA tabs pattern `#tabs` declares, then
 * place it into its AIM-1070 group (primary rail or collapsible utility).
 *
 * Callers may still call placeNavTab themselves; a second place is a no-op
 * reorder. Prefer leaving placement to this helper.
 *
 * @param {object} opts
 * @param {string} opts.view   router view name; also derives the id pair
 * @param {string} opts.label  visible text, and the accessible name
 * @param {string} [opts.icon] decorative SVG markup; forced `aria-hidden`
 * @param {string} [opts.extra] trailing markup (e.g. onboarding's warning badge)
 * @param {boolean} [opts.place=true] set false only in unit tests that assert markup alone
 * @returns {HTMLButtonElement}
 */
export function moduleTab({ view, label, icon = '', extra = '', place = true } = {}) {
  if (STATIC_VIEW_IDS.has(view)) {
    throw new Error(`"${view}" is a static view declared in index.html; do not rebuild its tab`);
  }
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.dataset.view = view;
  btn.id = `tab-${view}`;
  btn.setAttribute('role', 'tab');
  // app.js refresh() keeps this in sync from here on; 'false' is the pre-route
  // truth for a tab whose view is not the one currently showing.
  btn.setAttribute('aria-selected', 'false');
  btn.setAttribute('aria-controls', `view-${view}`);
  btn.innerHTML = `${withHiddenIcon(icon)}${label}${extra}`;
  if (place && typeof document !== 'undefined' && document.querySelector?.('#tabs')) {
    placeNavTab(btn);
  }
  return btn;
}

/**
 * Build the `<section>` panel a module view renders into.
 *
 * `tabIndex = 0` matches index.html: the panel itself is focusable so the
 * skip link and a tab-activation land somewhere meaningful, and so a panel
 * whose content is a scroll region is reachable without a mouse.
 *
 * @param {object} opts
 * @param {string} opts.view   router view name, matching its moduleTab()
 * @param {string} [opts.html] initial innerHTML
 * @param {string} [opts.className] extra classes alongside `view`
 * @returns {HTMLElement}
 */
export function moduleSection({ view, html = '', className = '' }) {
  const section = document.createElement('section');
  section.id = `view-${view}`;
  section.className = className ? `view ${className}` : 'view';
  section.setAttribute('role', 'tabpanel');
  section.setAttribute('aria-labelledby', `tab-${view}`);
  section.tabIndex = 0;
  section.innerHTML = html;
  return section;
}

/** Force `aria-hidden` onto a decorative inline SVG that may or may not carry it. */
function withHiddenIcon(icon) {
  if (!icon) return '';
  return icon.includes('aria-hidden') ? icon : icon.replace(/<svg\b/, '<svg aria-hidden="true"');
}

/* ---------- Announcements ----------
 *
 * index.html ships a single polite live region (`#sr-status`) and app.js
 * narrates view loads through it. Module views do their own async work —
 * saving a guardrail threshold, minting an enrollment token, revoking one —
 * and none of it was announced, so a screen reader user got silence where a
 * sighted user got a "Saved" chip.
 *
 * One shared region, not one per module: multiple simultaneous live regions
 * interleave unpredictably, and this app never has two announcements racing.
 */
export function announce(message) {
  const el = document.querySelector('#sr-status');
  if (!el) return;
  /* Re-announce identical consecutive messages. Assistive tech only speaks a
   * live region when its text *changes*, so saving twice in a row would say
   * nothing the second time — exactly when the operator most wants confirmation
   * that the second save also landed. */
  if (el.textContent === message) el.textContent = '';
  el.textContent = message;
}

/* ---------- Focus management ----------
 *
 * The app's async pattern is `container.innerHTML = render(freshData)`. That is
 * fine visually and hostile to the keyboard: the element the operator was on is
 * destroyed mid-interaction and focus silently resets to `<body>`, dropping them
 * back at the top of the document with no announcement. Every save path in
 * rules.js and onboarding.js did this.
 */

/**
 * Run `mutate()` (which may replace `container`'s subtree) and put focus back on
 * the equivalent element afterwards, located by CSS selector.
 *
 * Selector rather than node reference on purpose: the whole point is that the
 * original node no longer exists after a re-render.
 *
 * @param {Element} container   the subtree being replaced
 * @param {string}  selector    locates the post-render element to focus
 * @param {Function} mutate     may be async
 */
export async function preservingFocus(container, selector, mutate) {
  const hadFocus = container.contains(document.activeElement);
  await mutate();
  if (!hadFocus) return;
  const target = container.querySelector(selector);
  if (target) target.focus();
}

/**
 * Move focus to a container that has just appeared, without stealing it from an
 * operator who has already moved on.
 *
 * Used for the two "you must read this now" surfaces: the one-time enrollment
 * token (shown once, never retrievable) and an inline editor the operator just
 * opened. Both are useless if the keyboard is still parked on the trigger.
 *
 * @param {Element} el
 * @param {Element|null} [onlyIfFocusWithin] skip unless focus is still in here
 */
export function focusInto(el, onlyIfFocusWithin = null) {
  if (!el) return;
  if (onlyIfFocusWithin && !onlyIfFocusWithin.contains(document.activeElement)) return;
  const target = el.matches?.('input, select, textarea, button, a[href]')
    ? el
    : el.querySelector('input:not([type=hidden]), select, textarea, button, a[href], [tabindex]:not([tabindex="-1"])');
  if (target) {
    target.focus();
    return;
  }
  // Nothing focusable inside — make the container itself a one-shot focus stop
  // so the announcement has somewhere to land, then release it.
  if (!el.hasAttribute('tabindex')) {
    el.tabIndex = -1;
    el.addEventListener('blur', () => el.removeAttribute('tabindex'), { once: true });
  }
  el.focus();
}

/**
 * Wire a disclosure button to the region it expands.
 *
 * `aria-expanded` is the only signal that tells a screen reader user whether
 * the editor they just toggled is open; a button whose label flips between
 * "Edit thresholds" and "Close editor" reads as two unrelated buttons.
 */
export function setExpanded(button, region, expanded) {
  button.setAttribute('aria-expanded', String(expanded));
  if (region?.id) button.setAttribute('aria-controls', region.id);
  if (region) region.hidden = !expanded;
}

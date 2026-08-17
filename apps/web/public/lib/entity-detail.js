/* Entity detail-panel shell (AIM-1131; AIM-453 assessment Phase 3).
 *
 * The five drill-down panels (providers, apps, teams, repos, users) were
 * near-isomorphic copies: an entity guard that hides the box, a back-linked
 * heading, a `.err` failure state, a cards strip, then per-view charts/tables.
 * Copied markup is how a fix lands on four panels and not the fifth — this
 * module is the one copy of the shared skeleton, in the spirit of
 * lib/components.js: a view says *what* its detail panel shows, never *how*
 * the chrome around it is built.
 *
 * Three functions, matching the three moments every panel shares:
 *
 *   hideEntityDetail(el, onClear?)   no entity selected — hide + clear;
 *                                    onClear releases per-view resources
 *                                    (a live Chart.js instance survives
 *                                    innerHTML = '').
 *   entityDetailError(el, spec)      fetch failed / entity not in range —
 *                                    back link + .err, box stays visible.
 *   entityDetailShell(el, spec)      the panel itself: back-linked heading,
 *                                    cards strip, then the view's own body
 *                                    markup (charts, tables, forms).
 *
 * Escaping contract, same as card(): `title` and `backLabel` are escaped by
 * the shell; `titleHtml`, `cards` entries, and `body` are trusted markup the
 * caller built (via esc()/card()/table-wrap scaffolding) and are opt-in by
 * name or position. The back-link href comes from hashFor(), which only ever
 * emits in-app `#/…` routes.
 *
 * Import path uses `../lib/dom.js` (even though we live under lib/) so the
 * AIM-523 import guard, which matches the substring `lib/dom.js`, still
 * passes — same convention as lib/components.js.
 */
import { esc } from '../lib/dom.js';
import { hashFor } from './runtime.js';

function backLink(view, backLabel) {
  return `<a class="back" href="${esc(hashFor(view))}">← ${esc(backLabel)}</a>`;
}

/**
 * Hide and clear a detail panel when no entity is selected.
 *
 * @param {Element|null} el the panel container (e.g. $('#prov-detail'))
 * @param {() => void} [onClear] per-view cleanup run BEFORE the box is
 *   cleared — e.g. destroying a Chart.js instance whose canvas is about to
 *   leave the DOM.
 */
export function hideEntityDetail(el, onClear) {
  if (!el) return;
  onClear?.();
  el.hidden = true;
  el.innerHTML = '';
}

/**
 * Render the failure state of a detail panel: back link + error message.
 * Used for both "entity not in this range/filter" and fetch rejections; the
 * box stays visible so the failure is never a silent blank (AIM-475).
 *
 * @param {Element|null} el
 * @param {object} spec
 * @param {string} spec.view router view name the back link returns to
 * @param {string} spec.backLabel human label for that view ('Providers')
 * @param {string} spec.message raw error text — escaped by the shell
 */
export function entityDetailError(el, { view, backLabel, message }) {
  if (!el) return;
  el.hidden = false;
  el.innerHTML = `<h2>${backLink(view, backLabel)}</h2><div class="err">${esc(message)}</div>`;
}

/**
 * Render the standard detail panel: back-linked heading, cards strip, body.
 * Only the chrome is built here — charts, tables, and forms after the cards
 * are the view's own `body` markup, wired up by the caller afterwards.
 *
 * @param {Element|null} el
 * @param {object} spec
 * @param {string} spec.view router view name the back link returns to
 * @param {string} spec.backLabel human label for that view ('Providers')
 * @param {string} [spec.title] entity name — escaped by the shell
 * @param {string} [spec.titleHtml] trusted heading markup, opt-in by name
 *   (composite titles like repos' mono ref or teams' displayName + key)
 * @param {string[]} [spec.cards] card() markup entries, joined into .cards
 * @param {string} [spec.body] trusted markup after the cards strip
 */
export function entityDetailShell(el, { view, backLabel, title, titleHtml, cards = [], body = '' }) {
  if (!el) return;
  el.hidden = false;
  el.innerHTML = `<h2>${backLink(view, backLabel)} ${titleHtml ?? esc(title)}</h2>`
    + `<div class="cards">${cards.join('')}</div>`
    + body;
}

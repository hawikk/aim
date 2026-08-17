/* The HTML escaping boundary for the dashboard (AIM-523).
 *
 * Every view renders API data through template literals into innerHTML, and
 * much of that data is attacker-influenceable telemetry: tool names, repo
 * names, team names, MCP server names, rule titles. `esc()` is the single
 * control standing between that telemetry and script execution in an
 * analyst's browser.
 *
 * It used to be reimplemented in eleven view modules. Eleven copies is
 * eleven things to audit, and they had already diverged — see the
 * behavioural diff in the AIM-523 PR body. This module is the one copy.
 * The `no-local-esc` test in test/dom.test.js fails the build if a view
 * reintroduces a local definition.
 */

/* Escaped as numeric refs where the named entity is not universal in
 * attribute contexts; `&#39;` is the widest-support spelling of `&apos;`. */
const HTML_ENTITIES = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/**
 * Escape a value for interpolation into HTML text or a quoted attribute.
 *
 * Escapes all five of `& < > " '`. The single quote matters: it is what
 * makes the output safe inside single-quoted attributes (`title='${esc(x)}'`)
 * as well as double-quoted ones. Do not narrow this set.
 *
 * Null and undefined render as the empty string, never the literal text
 * "null" — a security dashboard cell reading `null` is a rendering bug.
 *
 * This is not sufficient for unquoted attributes, `javascript:` URLs, or
 * inline event handlers. Do not use it to build those.
 *
 * @param {unknown} s
 * @returns {string}
 */
export function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => HTML_ENTITIES[c]);
}

/** Document query helper shared by bootstrap and view modules (AIM-527). */
export const $ = (sel) => document.querySelector(sel);

/* AIM-1089: formatters complete the dom kernel surface (esc / $ / formatters)
 * so a new view needs one import for its rendering basics. format.js has no
 * imports of its own, so there is no cycle. */
export * from './format.js';

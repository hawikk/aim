/* Cross-module deep-links (AIM-589).
 *
 * Analysts chase a finding into the user who triggered it, the tool they used,
 * the repo it touched, and fleet coverage when hosts go silent. Every hop must
 * keep the shared range filter (`days`) so the destination answers the same
 * window the operator was looking at — bare `#/users/x` silently resets to 30d.
 *
 * This module is pure URL construction (no DOM). Views render the anchors;
 * `hashFor` from the router owns encoding + filter serialization.
 *
 * Documented map: docs/frontend-deep-links.md (keep in sync with LINK_MAP).
 */

import { hashFor } from './router.js';

/**
 * Canonical entity → destination map.
 *
 * Keys are source modules/entities. Values list destinations an analyst can
 * reach by clicking. `entity` means a DRILL_VIEWS segment; null is list-only.
 * Context columns: which shared filters the hop preserves.
 */
export const LINK_MAP = Object.freeze({
  finding: Object.freeze({
    user: { view: 'users', entity: true, context: ['days'], from: 'subject.user_ref' },
    tool: { view: 'tools', entity: true, context: ['days'], from: 'evidence.context.tool|tool_raw' },
    repo: { view: 'repos', entity: true, context: ['days'], from: 'subject.repo_ref | evidence.context.repo_ref' },
    fleet: { view: 'fleet', entity: false, context: ['days'], from: 'subject.host_ref (list only — fleet has no host drill)' },
  }),
  user: Object.freeze({
    tool: { view: 'tools', entity: true, context: ['days'], from: 'tools[].tool / sessions / flags' },
    team: { view: 'teams', entity: true, context: ['days'], from: 'summary.team' },
    findings: { view: 'findings', entity: false, context: ['days'], from: 'linked findings console' },
  }),
  tool: Object.freeze({
    /* Tool detail is the drill target; outbound user/repo lists are not yet on the API. */
    self: { view: 'tools', entity: true, context: ['days'], from: 'inventory row / security unapproved' },
  }),
  repo: Object.freeze({
    tool: { view: 'tools', entity: true, context: ['days'], from: 'byTool[].tool' },
  }),
  security: Object.freeze({
    user: { view: 'users', entity: true, context: ['days'], from: 'detector detail users' },
    tool: { view: 'tools', entity: true, context: ['days'], from: 'flags / unapproved / detector tools' },
    repo: { view: 'repos', entity: true, context: ['days'], from: 'detector detail repos' },
    provider: { view: 'providers', entity: true, context: ['days', 'source'], from: 'unapproved.provider' },
    findings: { view: 'findings', entity: false, context: ['days'], from: 'triage CTA' },
  }),
  activity: Object.freeze({
    user: { view: 'users', entity: true, context: ['days'], from: 'event.pseudonym' },
    tool: { view: 'tools', entity: true, context: ['days'], from: 'event.tool' },
  }),
  fleet: Object.freeze({
    /* Hosts are not DRILL_VIEWS; fleet is a coverage destination, not a source of entity hops. */
    self: { view: 'fleet', entity: false, context: ['days'], from: 'coverage gap / silent host CTA' },
  }),
  overview: Object.freeze({
    findings: { view: 'findings', entity: false, context: ['days'], from: 'alerts strip / critical KPI' },
    activity: { view: 'activity', entity: false, context: ['days'], from: 'live activity panel' },
    tools: { view: 'tools', entity: true, context: ['days'], from: 'tool split tables' },
    users: { view: 'users', entity: false, context: ['days'], from: 'active users KPI' },
    repos: { view: 'repos', entity: true, context: ['days'], from: 'top repos' },
    teams: { view: 'teams', entity: false, context: ['days'], from: 'spend KPI' },
    security: { view: 'security', entity: false, context: ['days'], from: 'unapproved panel' },
  }),
});

/** Views that accept an entity segment (mirrors router.DRILL_VIEWS). */
const ENTITY_VIEWS = new Set(['providers', 'apps', 'teams', 'tools', 'repos', 'users']);

/**
 * Build a shareable hash for a view/entity under the given range context.
 * Prefer this over string-building `#/${view}/…` so days/source never drop.
 *
 * @param {string} view
 * @param {string|null} [entity]
 * @param {{ days?: number, source?: string }} [ctx]
 * @returns {string}
 */
export function entityHref(view, entity = null, ctx = {}) {
  const days = Number(ctx.days);
  const source = ctx.source;
  const opts = {};
  if (Number.isFinite(days)) opts.days = days;
  if (source != null) opts.source = source;
  const id = entity == null || entity === '' ? null : String(entity);
  // Non-drill views must never carry a stray segment.
  const safeEntity = id && ENTITY_VIEWS.has(view) ? id : null;
  return hashFor(view, safeEntity, opts);
}

/**
 * Pull drill-down entity ids out of a findings row (subject + evidence.context).
 * Missing fields yield null — callers omit the anchor rather than linking junk.
 *
 * @param {object|null|undefined} finding
 * @returns {{ user: string|null, tool: string|null, repo: string|null, host: string|null }}
 */
export function findingEntities(finding) {
  const subject = finding?.subject && typeof finding.subject === 'object' && !Array.isArray(finding.subject)
    ? finding.subject
    : {};
  const evidence = finding?.evidence && typeof finding.evidence === 'object' ? finding.evidence : {};
  const ctx = evidence.context && typeof evidence.context === 'object' ? evidence.context : {};

  const user = str(subject.user_ref ?? subject.userRef ?? subject.pseudonym);
  const host = str(subject.host_ref ?? subject.hostRef);
  const repo = str(
    subject.repo_ref
    ?? subject.repoRef
    ?? ctx.repo_ref
    ?? ctx.repoRef
    ?? ctx.repo,
  );
  // Prefer the human tool name (tool_raw) over schema enum 'other'.
  const tool = str(ctx.tool_raw ?? ctx.toolRaw ?? ctx.tool ?? subject.tool);

  return { user, tool, repo, host };
}

/**
 * Build the cross-module hrefs for one finding under the operator's range.
 *
 * @param {object|null|undefined} finding
 * @param {{ days?: number, source?: string }} [ctx]
 * @returns {{ user: string|null, tool: string|null, repo: string|null, fleet: string|null }}
 */
export function findingHrefs(finding, ctx = {}) {
  const e = findingEntities(finding);
  return {
    user: e.user ? entityHref('users', e.user, ctx) : null,
    tool: e.tool ? entityHref('tools', e.tool, ctx) : null,
    repo: e.repo ? entityHref('repos', e.repo, ctx) : null,
    // Fleet has no host drill-down; land on the coverage list when a host is present.
    fleet: e.host ? entityHref('fleet', null, ctx) : null,
  };
}

/**
 * Inline "entity →" link fragments for a finding detail row.
 * Returns HTML snippets (already escaped labels); empty string when no entity.
 *
 * @param {object|null|undefined} finding
 * @param {{ days?: number, source?: string, esc: (s: string) => string }} opts
 * @returns {string} space-prefixed fragments ready to append after subject text
 */
export function findingLinkHtml(finding, opts) {
  // Bind under a non-`esc` name so the AIM-151 local-esc guard does not trip on
  // `const esc = opts.esc` (that pattern is reserved for XSS reimplementation).
  const escapeHtml = opts.esc;
  if (typeof escapeHtml !== 'function') throw new Error('findingLinkHtml requires opts.esc');
  const hrefs = findingHrefs(finding, opts);
  const bits = [];
  if (hrefs.user) bits.push(`<a href="${escapeHtml(hrefs.user)}">user timeline →</a>`);
  if (hrefs.tool) bits.push(`<a href="${escapeHtml(hrefs.tool)}">tool →</a>`);
  if (hrefs.repo) bits.push(`<a href="${escapeHtml(hrefs.repo)}">repo →</a>`);
  if (hrefs.fleet) bits.push(`<a href="${escapeHtml(hrefs.fleet)}">fleet coverage →</a>`);
  return bits.length ? ` · ${bits.join(' · ')}` : '';
}

function str(v) {
  if (v == null) return null;
  const s = String(v).trim();
  return s.length ? s : null;
}

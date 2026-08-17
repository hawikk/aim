/* Shared list pagination for large inventory tables.
 *
 * Users and Fleet must not re-assemble multi-megabyte full lists client-side
 * once the API supports limit/offset. This module:
 *  - caps the default page at 100 rows
 *  - builds the query string the views pass to /api/users and /api/fleet
 *  - resolves a page from either a server-paginated payload or a legacy
 *    full-list response (window only; never pretends the window is "all")
 *  - renders a Prev / Next pager with an honest range label
 *
 * Truncation that hides rows must never look like a clean fleet/user census.
 */

import { esc } from '../lib/dom.js';

/** Default UI page size. Higher limits only for CSV export (server-gated). */
export const DEFAULT_PAGE_SIZE = 100;

/**
 * @param {object} [opts]
 * @param {number} [opts.page=1] 1-based page index
 * @param {number} [opts.pageSize=DEFAULT_PAGE_SIZE]
 * @returns {{ page: number, pageSize: number, limit: number, offset: number }}
 */
export function pageRequest(opts = {}) {
  const pageSize = clampPageSize(opts.pageSize ?? DEFAULT_PAGE_SIZE);
  const page = Math.max(1, Math.floor(Number(opts.page) || 1));
  const offset = (page - 1) * pageSize;
  return { page, pageSize, limit: pageSize, offset };
}

/**
 * @param {number|string|null|undefined} n
 * @returns {number}
 */
export function clampPageSize(n) {
  const v = Math.floor(Number(n));
  if (!Number.isFinite(v) || v < 1) return DEFAULT_PAGE_SIZE;
  // Hard ceiling so a bad query string cannot re-open multi-MB payloads.
  return Math.min(v, DEFAULT_PAGE_SIZE);
}

/**
 * Append limit/offset to an API path that may already have a query string.
 * @param {string} path
 * @param {{ limit: number, offset: number }} req
 * @returns {string}
 */
export function withPageParams(path, req) {
  const join = path.includes('?') ? '&' : '?';
  return `${path}${join}limit=${encodeURIComponent(req.limit)}&offset=${encodeURIComponent(req.offset)}`;
}

/**
 * Resolve the rows to render and whether more pages exist.
 *
 * Prefer server pagination when `total` is present. If the API ignored limit
 * and returned a larger array (legacy), window client-side of that response
 * only — still ≤ pageSize on screen, with an honest "more may exist" signal.
 *
 * @param {object} opts
 * @param {unknown[]} opts.rows
 * @param {number|null|undefined} [opts.total]
 * @param {number|null|undefined} [opts.limit]  server-reported limit
 * @param {number|null|undefined} [opts.offset] server-reported offset
 * @param {number} opts.requestedLimit
 * @param {number} opts.requestedOffset
 * @param {boolean|null|undefined} [opts.truncated]
 * @returns {{
 *   rows: unknown[],
 *   total: number|null,
 *   limit: number,
 *   offset: number,
 *   page: number,
 *   hasPrev: boolean,
 *   hasNext: boolean,
 *   shownFrom: number,
 *   shownTo: number,
 *   truncated: boolean,
 *   mode: 'server'|'client-window'|'unknown-tail',
 * }}
 */
export function resolvePage(opts) {
  const requestedLimit = clampPageSize(opts.requestedLimit ?? DEFAULT_PAGE_SIZE);
  const requestedOffset = Math.max(0, Math.floor(Number(opts.requestedOffset) || 0));
  const raw = Array.isArray(opts.rows) ? opts.rows : [];

  const serverTotal = finiteNonNeg(opts.total);
  const serverLimit = finiteNonNeg(opts.limit);
  const serverOffset = finiteNonNeg(opts.offset);
  const limit = serverLimit != null ? clampPageSize(serverLimit) : requestedLimit;
  const offset = serverOffset != null ? serverOffset : requestedOffset;

  // Payload larger than one page ⇒ API did not page (legacy full list). Window
  // by offset so the DOM never holds multi-page tables. total falls back to
  // the blob length when the server did not report one.
  if (raw.length > limit) {
    const rows = raw.slice(offset, offset + limit);
    const total = serverTotal != null ? serverTotal : raw.length;
    return pageResult({
      rows,
      total,
      limit,
      offset,
      hasNext: offset + rows.length < total,
      truncated: true,
      mode: 'client-window',
    });
  }

  // Server pagination: rows are already this page; total is authoritative.
  if (serverTotal != null) {
    const rows = raw;
    const total = serverTotal;
    const reachedEnd = offset + rows.length >= total;
    return pageResult({
      rows,
      total,
      limit,
      offset,
      hasNext: !reachedEnd,
      truncated: opts.truncated === true || !reachedEnd,
      mode: 'server',
    });
  }

  // No total, single-page-sized payload: next is possible when the page is
  // full — never claim the fleet/user census is complete.
  const rows = raw;
  const fullPage = rows.length >= limit;
  return pageResult({
    rows,
    total: null,
    limit,
    offset,
    hasNext: fullPage || opts.truncated === true,
    truncated: fullPage || opts.truncated === true,
    mode: 'unknown-tail',
  });
}

/**
 * Status copy for the pager. Never reads as "all clean" when rows are hidden.
 * @param {ReturnType<typeof resolvePage>} page
 * @param {{ noun?: string }} [opts]
 * @returns {string}
 */
export function pageStatusText(page, opts = {}) {
  const noun = opts.noun || 'rows';
  if (!page.rows.length) {
    return page.offset > 0 ? `No more ${noun} on this page` : `No ${noun}`;
  }
  const from = page.shownFrom;
  const to = page.shownTo;
  if (page.total != null) {
    return `Showing ${from}–${to} of ${page.total}`;
  }
  if (page.hasNext || page.truncated) {
    return `Showing ${from}–${to} (more ${noun} may exist beyond this page)`;
  }
  return `Showing ${from}–${to}`;
}

/**
 * Markup for a list pager. Wire with {@link wirePager}.
 * @param {ReturnType<typeof resolvePage>} page
 * @param {{ idPrefix: string, noun?: string, label?: string }} opts
 * @returns {string}
 */
export function pagerHtml(page, opts) {
  const prefix = opts.idPrefix;
  const label = opts.label || 'Table pagination';
  const status = pageStatusText(page, { noun: opts.noun });
  const prevDis = page.hasPrev ? '' : ' disabled';
  const nextDis = page.hasNext ? '' : ' disabled';
  // role=status so screen readers announce page changes; never silent truncation.
  return `<nav class="list-pager" aria-label="${esc(label)}">`
    + `<button type="button" class="btn-control" id="${esc(prefix)}-prev"${prevDis}>Previous</button>`
    + `<span class="list-pager-status" id="${esc(prefix)}-status" role="status">${esc(status)}</span>`
    + `<button type="button" class="btn-control" id="${esc(prefix)}-next"${nextDis}`
    + (page.hasNext ? '' : ' aria-disabled="true"')
    + `>Next page</button>`
    + `</nav>`;
}

/**
 * Attach click handlers. Callbacks receive the 1-based target page.
 * @param {ParentNode|null} root
 * @param {string} idPrefix
 * @param {{ onPrev: () => void, onNext: () => void }} handlers
 */
export function wirePager(root, idPrefix, handlers) {
  if (!root) return;
  root.querySelector(`#${cssIdent(idPrefix)}-prev`)?.addEventListener('click', (ev) => {
    ev.preventDefault();
    handlers.onPrev?.();
  });
  root.querySelector(`#${cssIdent(idPrefix)}-next`)?.addEventListener('click', (ev) => {
    ev.preventDefault();
    handlers.onNext?.();
  });
}

/**
 * Honest banner when the page is a known-incomplete window of a larger set.
 * Distinct from empty states — this is "data exists, not all on screen".
 * @param {ReturnType<typeof resolvePage>} page
 * @param {{ noun?: string }} [opts]
 * @returns {string} HTML or empty string
 */
export function truncationBannerHtml(page, opts = {}) {
  if (!page.truncated && !page.hasNext) return '';
  if (page.total != null && page.total <= page.offset + page.rows.length && !page.hasNext) return '';
  const noun = opts.noun || 'rows';
  let body;
  if (page.total != null) {
    body = `Showing ${page.shownFrom}–${page.shownTo} of ${page.total} ${noun}. `
      + 'Use Next page for the rest — this view does not load the full list into the browser.';
  } else {
    body = `Showing ${page.shownFrom}–${page.shownTo} ${noun}; more may exist beyond this page. `
      + 'Do not treat this window as a complete census.';
  }
  return `<div class="banner warn list-page-truncation" role="status">${esc(body)}</div>`;
}

function pageResult({ rows, total, limit, offset, hasNext, truncated, mode }) {
  const count = rows.length;
  const shownFrom = count === 0 ? 0 : offset + 1;
  const shownTo = offset + count;
  const page = Math.floor(offset / limit) + 1;
  return {
    rows,
    total,
    limit,
    offset,
    page,
    hasPrev: offset > 0,
    hasNext: Boolean(hasNext),
    shownFrom,
    shownTo,
    truncated: Boolean(truncated),
    mode,
  };
}

function finiteNonNeg(v) {
  if (v == null || v === '') return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) return null;
  return Math.floor(n);
}

/** idPrefix values are ours (users-page, fleet-page) — keep CSS.escape optional. */
function cssIdent(id) {
  return String(id).replace(/[^A-Za-z0-9_-]/g, '');
}

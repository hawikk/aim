/* Live feed for the Activity trail (split, extracted from
 * activity.js): short-polling (10 s) with keyset cursor pagination, stream
 * pause/resume, and the loading/empty/error row states.
 *
 * The first load fetches the newest page; polling re-fetches from the top
 * (newest events) and prepends new rows so the newest stay at the top.
 * "Load more" fetches the next page via cursor. */

import { fmtTs } from '../lib/format.js';
import { EMPTY } from '../lib/components.js';
import { actx } from './state.js';
import { buildRow, skeletonRows, stateRow } from './row.js';

const $ = (sel, ctx = document) => ctx.querySelector(sel);

const POLL_MS = 10_000;

export function filters() {
  return {
    tool: $('input#act-filter-tool')?.value.trim() || null,
    event_type: $('input#act-filter-event-type')?.value.trim() || null,
    user: $('input#act-filter-user')?.value.trim() || null,
    minScore: $('input#act-filter-min-score')?.value.trim() || null,
  };
}

function buildUrl(params = {}) {
  const u = new URLSearchParams();
  const f = filters();
  if (f.tool) u.set('tool', f.tool);
  if (f.event_type) u.set('event_type', f.event_type);
  if (f.user) u.set('user', f.user);
  if (f.minScore) u.set('minScore', f.minScore);
  if (params.before) u.set('before', params.before);
  u.set('limit', '50');
  return `/api/activity/feed?${u}`;
}

export function setHint(text) {
  const h = $('#act-hint');
  if (h) h.textContent = text;
}

async function fetchPage(url) {
  const res = await fetch(url, { credentials: 'same-origin' });
  if (!res.ok) throw Object.assign(new Error(res.statusText), { status: res.status });
  return res.json();
}

export async function loadFresh() {
  if (actx.loading) return;
  actx.loading = true;
  const tbody = $('#act-tbody');
  if (actx.firstLoad && tbody) {
    tbody.innerHTML = skeletonRows();
    setHint('loading…');
  }
  try {
    const data = await fetchPage(buildUrl());
    if (!tbody) return;
    const wasFirstLoad = actx.firstLoad;
    if (wasFirstLoad) {
      tbody.innerHTML = '';
      actx.seenIds.clear();
    }
    const newRows = [];
    for (const ev of data.events ?? []) {
      if (actx.seenIds.has(ev.event_id)) continue;
      actx.seenIds.add(ev.event_id);
      const tr = buildRow(ev);
      /* Fade in only rows that arrive on a poll. Fading the initial page would
       * flash the whole table for no information gain — the motion is there to
       * mark what is *new*, so it has to stay rare to mean anything. */
      if (!wasFirstLoad) tr.classList.add('act-new');
      newRows.push(tr);
    }
    if (wasFirstLoad && newRows.length === 0) {
      renderEmpty(tbody);
    } else {
      // Prepend newest to top.
      for (let i = newRows.length - 1; i >= 0; i--) {
        tbody.insertBefore(newRows[i], tbody.firstChild);
      }
      // Cap render at 500 rows for smooth scroll.
      while (tbody.children.length > 500) tbody.removeChild(tbody.lastChild);
    }
    actx.nextCursor = data.nextCursor ?? null;
    actx.hasMore = !!data.hasMore;
    const btn = $('#act-load-more');
    if (btn) btn.hidden = !actx.hasMore;
    actx.lastUpdate = new Date();
    actx.firstLoad = false;
    renderStreamState();
  } catch (err) {
    renderError(tbody, err);
  } finally {
    actx.loading = false;
  }
}

/* Empty state distinguishes "your filters exclude everything" from "the trail
 * itself is empty" — they need different next actions. */
function renderEmpty(tbody) {
  const f = filters();
  const filtered = !!(f.tool || f.event_type || f.user || f.minScore);
  if (filtered) {
    tbody.innerHTML = stateRow({
      reason: 'filtered',
      title: 'No events match these filters',
      body: 'The trail has events in this window, but none match the current filter set.',
    }, '<button type="button" class="btn-control" id="act-clear-filters">Clear filters</button>');
  } else {
    // EMPTY.activity carries setup doc + Fleet CTA.
    tbody.innerHTML = stateRow(EMPTY.activity);
  }
  setHint('0 events');
}

/* Errors are recoverable and say so. A 403 is not an error the analyst can
 * retry out of, so it gets different copy and no retry button. */
function renderError(tbody, err) {
  if (err?.status === 403) {
    setHint('access denied');
    if (actx.firstLoad && tbody) {
      tbody.innerHTML = stateRow({
        reason: 'error',
        title: 'Not authorized for the activity trail',
        body: 'Per-event rows are restricted to the analyst and admin roles. Your session has neither.',
      });
      actx.firstLoad = false;
    }
    stopLive();
    actx.streaming = false;
    renderStreamState();
    return;
  }
  setHint('load failed');
  if (actx.firstLoad && tbody) {
    tbody.innerHTML = stateRow({
      reason: 'error',
      title: 'Could not load the activity trail',
      body: `The feed request failed${err?.status ? ` with status ${err.status}` : ''}. The stream keeps retrying; you can also retry now.`,
    }, '<button type="button" class="btn-control" id="act-retry">Retry</button>');
  }
}

export async function loadMore() {
  if (!actx.nextCursor || actx.loading) return;
  actx.loading = true;
  try {
    const data = await fetchPage(buildUrl({ before: actx.nextCursor }));
    const tbody = $('#act-tbody');
    if (!tbody) return;
    // Remove an empty/error state row if one is standing in for the table.
    tbody.querySelector('.empty-state')?.closest('tr')?.remove();

    for (const ev of data.events ?? []) {
      if (actx.seenIds.has(ev.event_id)) continue;
      actx.seenIds.add(ev.event_id);
      tbody.appendChild(buildRow(ev));
    }
    actx.nextCursor = data.nextCursor ?? null;
    actx.hasMore = !!data.hasMore;
    const btn = $('#act-load-more');
    if (btn) btn.hidden = !actx.hasMore;
    setHint(`${actx.seenIds.size} events loaded`);
  } finally {
    actx.loading = false;
  }
}

export function startLive() {
  stopLive();
  actx.liveTimer = setInterval(() => { loadFresh(); }, POLL_MS);
}

export function stopLive() {
  if (actx.liveTimer) { clearInterval(actx.liveTimer); actx.liveTimer = null; }
}

/* The stream indicator carries the one fact that matters while paused: how
 * stale the view is. A paused trail that looks identical to a live one is how
 * an analyst ends up reasoning about ten-minute-old events. */
export function renderStreamState() {
  const label = $('#act-stream-label');
  const btn = $('#act-stream');
  const tag = $('#act-stream-state');
  if (label) label.textContent = actx.streaming ? 'Pause' : 'Resume';
  if (btn) {
    btn.setAttribute('aria-pressed', String(!actx.streaming));
    btn.title = actx.streaming
      ? 'Pause the stream to inspect a row without it moving'
      : 'Resume streaming — the trail refreshes every 10 s';
  }
  if (tag) {
    tag.dataset.streaming = actx.streaming ? '1' : '0';
    if (actx.streaming) {
      tag.textContent = 'streaming';
    } else {
      tag.textContent = actx.lastUpdate
        ? `paused · ${fmtTs(actx.lastUpdate.toISOString())}`
        : 'paused';
    }
  }
  if (actx.lastUpdate) setHint(`${actx.seenIds.size} events · updated ${fmtTs(actx.lastUpdate.toISOString())}`);
}

export function setStreaming(on) {
  actx.streaming = on;
  if (on) { startLive(); loadFresh(); } else { stopLive(); }
  renderStreamState();
}

export function resetAndLoad() {
  actx.firstLoad = true;
  actx.nextCursor = null;
  actx.hasMore = false;
  actx.seenIds.clear();
  loadFresh();
}

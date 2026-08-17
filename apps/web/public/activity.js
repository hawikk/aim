// Live Activity Trail — per-event security score + cost, real-time tab.
//
// Self-contained module: activates when the view-activity section is present and
// capabilities.userLevel is true (analyst + admin).
//
// Split (mirroring the findings rules /
// mcp splits) — the panels live in sibling modules with clear ownership:
//   ./activity/state.js        shared view-private actx + reset
//   ./activity/row.js          row + skeleton/empty/error renderers (pure)
//   ./activity/feed.js         polling, cursor pagination, stream pause/resume
// ./activity/saved-views.js /api/views saved-filter panel
//
// This file wires the controls, the delegated row interactions, the visibility
// observer, and the panels in order. Keep it thin — new panel code goes in a
// sibling module.

import { actx, resetActivityCtx } from './activity/state.js';
import {
  loadFresh,
  loadMore,
  renderStreamState,
  resetAndLoad,
  setStreaming,
  startLive,
} from './activity/feed.js';
import { bindSavedViews } from './activity/saved-views.js';

const $ = (sel, ctx = document) => ctx.querySelector(sel);

function init() {
  resetActivityCtx();
  const section = $('#view-activity');
  if (!section) return;

  // Reveal the tab once we know the section exists (app.js handles capability gate).
  // Wire controls.
  $('#act-refresh')?.addEventListener('click', resetAndLoad);

  $('#act-stream')?.addEventListener('click', () => setStreaming(!actx.streaming));

  $('#act-load-more')?.addEventListener('click', loadMore);

  // Saved views: bind before the delegated handlers so the
  // clear-filters handoff can reach syncViewUI.
  const views = bindSavedViews();

  /* Actions rendered inside an empty/error state row, delegated because those
   * rows are replaced on every load. */
  $('#act-tbody')?.addEventListener('click', (e) => {
    if (e.target.closest('#act-retry')) { resetAndLoad(); return; }
    if (e.target.closest('#act-clear-filters')) {
      for (const id of ['#act-filter-tool', '#act-filter-event-type', '#act-filter-user', '#act-filter-min-score']) {
        const el = $(id);
        if (el) el.value = '';
      }
      actx.activeViewId = null;
      views.syncViewUI?.();
      resetAndLoad();
    }
  });

  // Click on pseudonym → switch to users tab with filter pre-filled.
  $('#act-tbody')?.addEventListener('click', (e) => {
    const a = e.target.closest('.pseudo-link');
    if (!a) return;
    e.preventDefault();
    const user = a.dataset.user;
    if (!user) return;
    // Dispatch a synthetic navigation to the users tab (mirrors how app.js handles hash routing).
    const btn = $('#tab-users');
    if (btn && !btn.hidden) {
      btn.click();
      // If the users tab has a filter input, pre-fill it.
      const inp = $('input#users-filter');
      if (inp) { inp.value = user; inp.dispatchEvent(new Event('input')); }
    }
  });

  /* Score-factor breakdown expands in place. It is a real <button>, so Enter
   * and Space already activate it — no keydown shim needed. Expanding also
   * pauses the stream: reading a breakdown while rows push in above it is the
   * exact situation the pause control exists for, so do it for the analyst. */
  $('#act-tbody')?.addEventListener('click', (e) => {
    const btn = e.target.closest('.factors-link');
    if (!btn) return;
    const list = btn.nextElementSibling;
    if (!list?.classList.contains('factors-detail')) return;
    const open = btn.getAttribute('aria-expanded') === 'true';
    btn.setAttribute('aria-expanded', String(!open));
    list.hidden = open;
    if (!open && actx.streaming) setStreaming(false);
  });

  // Observe when the activity view becomes visible.
  const observer = new MutationObserver(() => {
    if (!section.classList.contains('active')) return;
    if (actx.firstLoad) { loadFresh(); if (actx.streaming) startLive(); }
  });
  observer.observe(section, { attributes: true, attributeFilter: ['class'] });

  views.loadViews(); // pre-warm (silent on failure)

  renderStreamState();

  // Also load immediately if section already active.
  if (section.classList.contains('active')) { loadFresh(); if (actx.streaming) startLive(); }
}

// Defer until DOM ready.
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

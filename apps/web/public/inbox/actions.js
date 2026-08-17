/* Alerts inbox actions (split): ack / snooze / unack mutations
 * (optimistic, verified) and the filter / pager event bindings. */

import { api } from '../lib/api.js';
import { withBusy } from '../lib/form.js';
import { inboxCtx } from './state.js';
import { render } from './render.js';
import { reload, loadMore, showProblem } from './data.js';

/* ---------- ack / snooze / unack (optimistic, verified) ---------- */

async function mutate(id, apply, request) {
  const { state, me, toast } = inboxCtx;
  const prev = state.states[id];
  apply();
  render();
  try {
    const res = await request();
    if (res.state === 'open') delete state.states[id];
    else state.states[id] = { state: res.state, snooze_until: res.snooze_until ?? null, actor: me.email, updated_at: new Date().toISOString() };
    render();
  } catch (err) {
    // Verified failure: put the old badge back rather than leaving a lie.
    if (prev) state.states[id] = prev;
    else delete state.states[id];
    render();
    toast(`Inbox update failed: ${err.message}`, 'bad');
  }
}

const post = (path, body) => api(path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: body === undefined ? '{}' : JSON.stringify(body),
});

export function bindInboxActions() {
  const { list } = inboxCtx;

  list.addEventListener('click', (e) => {
    const actBtn = e.target.closest('[data-act]');
    if (!actBtn) return;
    const el = actBtn.closest('.inbox-alert');
    const id = el?.dataset.id;
    if (!id) return;
    if (actBtn.dataset.act === 'ack') {
      withBusy(actBtn,
        () => mutate(id, () => { inboxCtx.state.states[id] = { state: 'acknowledged' }; },
          () => post(`/api/alerts/${encodeURIComponent(id)}/ack`)),
        { reenable: 'always' }).catch(() => {}); // mutate surfaces its own toast
    } else if (actBtn.dataset.act === 'unack') {
      withBusy(actBtn,
        () => mutate(id, () => { delete inboxCtx.state.states[id]; },
          () => post(`/api/alerts/${encodeURIComponent(id)}/unack`)),
        { reenable: 'always' }).catch(() => {});
    }
  });

  list.addEventListener('change', (e) => {
    const select = e.target.closest('.a-snooze');
    if (!select) return;
    const el = select.closest('.inbox-alert');
    const id = el?.dataset.id;
    const minutes = Number(select.value);
    select.value = '';
    if (!id || !minutes) return;
    mutate(id, () => { inboxCtx.state.states[id] = { state: 'snoozed' }; },
      () => post(`/api/alerts/${encodeURIComponent(id)}/snooze`, { minutes }));
  });
}

/* ---------- filters (severity/pillar re-query; text filters loaded) ---------- */

function bindToggleGroup(el, set) {
  el.addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    const value = b.dataset.sev ?? b.dataset.pil;
    const on = !set.has(value);
    if (on) set.add(value);
    else set.delete(value);
    b.classList.toggle('active', on);
    b.setAttribute('aria-pressed', String(on));
    reload().catch((err) => showProblem(err));
  });
}

export function bindInboxFilters() {
  const { section, state, moreBtn, toast } = inboxCtx;
  bindToggleGroup(section.querySelector('#inbox-sev'), state.severities);
  bindToggleGroup(section.querySelector('#inbox-pil'), state.pillars);

  section.querySelector('#inbox-text').addEventListener('input', (e) => {
    state.text = e.target.value;
    render();
  });
  section.querySelector('#inbox-refresh').addEventListener('click', () => {
    reload().catch((err) => showProblem(err));
  });
  moreBtn.addEventListener('click', () => {
    withBusy(moreBtn,
      () => loadMore().catch((err) => toast(`Load more failed: ${err.message}`, 'bad')),
      { reenable: 'always' }).catch(() => {});
  });
}

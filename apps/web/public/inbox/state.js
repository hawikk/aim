/* Shared view-private state for the Alerts inbox view (AIM-1181 split).
 * inboxCtx is view-private: zero cross-view surface. The orchestrator
 * (public/inbox.js) calls resetInboxCtx() at the top of init() and every
 * sibling module imports inboxCtx — never re-create it locally. */

export const inboxCtx = {};

export function resetInboxCtx({ section, me, toast }) {
  Object.assign(inboxCtx, {
    section,
    me,
    toast,
    list: section.querySelector('#inbox-list'),
    moreBtn: section.querySelector('#inbox-more'),
    pageHint: section.querySelector('#inbox-page-hint'),
    droppedEl: section.querySelector('#inbox-dropped'),
    /* gatewayHost comes from /api/stack/health; until it answers, evidence
     * refs render as inert text rather than as links built on a guessed host. */
    gatewayHost: null,
    state: {
      severities: new Set(),
      pillars: new Set(),
      text: '',
      alerts: [],          // every page loaded so far, in bus order
      states: {},          // alert_id -> {state, snooze_until, actor, updated_at}
      nextCursor: null,    // cursor to resume from; null until first page
      exhausted: false,
      busProblem: null,    // 503/502 message; a quiet inbox is never "no alerts"
      /** AIM-702: outcome index Map, or null until first load attempt finishes. */
      outcomeIndex: null,
    },
  });
}

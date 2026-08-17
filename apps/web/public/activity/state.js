/* Shared view-private state for the Live Activity trail (AIM-1163 split).
 * actx is view-private: zero cross-view surface. The orchestrator
 * (public/activity.js) calls resetActivityCtx() at the top of init() and every
 * sibling module imports actx — never re-create it locally. */

export const actx = {};

export function resetActivityCtx() {
  Object.assign(actx, {
    nextCursor: null,
    hasMore: false,
    liveTimer: null,
    loading: false,
    firstLoad: true,
    seenIds: new Set(),
    /* The trail streams by default — that is what "Live" means. The control
     * pauses it, so the analyst's mental model is "stop the moving thing",
     * not "opt in to the feature". */
    streaming: true,
    lastUpdate: null,
    activeViewId: null,
  });
}

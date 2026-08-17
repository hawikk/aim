/* Shared view-private state for the custom dashboards builder (split).
 * dctx is view-private: zero cross-view surface. The orchestrator
 * (public/dashboards.js) populates it during init() and every sibling module
 * imports it — never re-create it locally. resetDashboardsCtx() runs at the
 * top of init() so a re-mounted module starts clean. */

export const dctx = {};

export function resetDashboardsCtx() {
  Object.assign(dctx, {
    caps: {},
    store: null,
    editing: false,
    loadGen: 0,
    /** Cache keyed by source+days so multiple widgets sharing an endpoint
     * (e.g. four overview KPIs) hit the network once per activate. */
    dataCache: new Map(),
    section: null,
    selectEl: null,
    builderEl: null,
    catalogEl: null,
    canvasEl: null,
    editBtn: null,
  });
}

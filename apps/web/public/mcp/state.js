/* Shared view-private state for the MCP module (AIM-1157 split).
 * fctx is view-private: zero cross-view surface. The orchestrator
 * (public/mcp.js) populates it during init() and every sibling module
 * imports it — never re-create it locally. resetMcpCtx() runs at the top
 * of init() so a re-mounted module starts clean. */

export const fctx = {};

export function resetMcpCtx() {
  Object.assign(fctx, {
    me: null,
    section: null,
    // Inventory panel
    cards: null,
    table: null,
    detailPanel: null,
    detailTitle: null,
    detailBody: null,
    statusSel: null,
    sourceSel: null,
    filterHint: null,
    // Allowlist manage panel
    chipsEl: null,
    metaEl: null,
    statusEl: null,
    errEl: null,
    inputEl: null,
    // Override + denials + audit panels
    overridePanel: null,
    denyBody: null,
    denyMeta: null,
    denyUrgency: null,
    auditBody: null,
    // Session chain panel
    sessionInput: null,
    sessionBody: null,
    sessionClear: null,
    activeSessionId: null,
    /** @type {string[]} */
    allowlist: [],
    /** @type {boolean} */
    endpointEnforce: false,
    /* Cache last payload so Status/Source filters re-render without a round-trip
     * (same pattern as Security criticality → secState). */
    mcpState: { servers: null, summary: null, policy: null, rangeDays: null },
    /* Set by the orchestrator: reloads every panel derived from the allowlist
     * (inventory status, denials, override audit) after a successful write. */
    refreshDerived: null,
  });
}

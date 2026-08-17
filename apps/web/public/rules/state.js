/* View-private state for the rules module — was file-local in
 * rules.js. Shared across the submodules so the alerts panel can re-stamp
 * per-rule route chips after a destination save without a full rules reload,
 * and so the threshold editor can patch a rule in place. */
export const rulesState = {
  /* Last loaded rule set — PATCH responses replace their rule in place so the
   * list re-renders without a full round-trip. */
  lastRules: [],
  /* Last loaded alerts payload — drives per-rule "Routes to" chips without a
   * second round-trip when the rules list re-renders after a threshold save. */
  lastAlerts: null,
  /* DOM roots, set by init() before any binder runs. */
  section: null,
  list: null,
  alertCards: null,
};

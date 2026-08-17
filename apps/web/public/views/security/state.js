/* Shared view-private state for the Security view (AIM-1135 split of AIM-527).
 * secState is view-private: zero cross-view surface. Import it from the
 * orchestrator and the submodules — never re-create it locally. */
export const secState = { severity: 'all', flags: null, unapproved: null, toolCalls: null, bound: false };

/* — Navigation information architecture.
 *
 * The product accreted ~28 top-level tabs (12 static + 16 capability-gated
 * modules). Operators asked for a single main page plus far fewer permanent
 * tabs — utilities stay addressable under collapsible groups instead of a
 * permanent sidebar (and not as a second tile-rail on Home).
 *
 * Primary (always visible when present): Home, Findings, Alerts, Cases,
 * Security, Fleet, Shadow AI, MCP — the daily operator loop.
 *
 * Collapsible groups (collapsed by default; auto-expand when active):
 *   analysis   — Providers, App-LLM, Apps, Teams, Tools, Repos, Live
 *   ops        — Status, Destinations, Install health, Coverage, Dashboards, Onboarding
 *   control    — Rules, Policy, Runbooks, Compliance, Access review
 *   restricted — Users, Audit
 *
 * Routes are unchanged. A tab that is visually nested still has data-view and
 * is a role=tab; only the group body uses [hidden] when collapsed. Keyboard
 * roving (app.js) already skips [hidden] tabs.
 */

export const NAV_EXPAND_KEY = 'aim.navExpanded';

/** @typedef {'primary' | 'analysis' | 'ops' | 'control' | 'restricted'} NavGroupId */

/**
 * Canonical group membership + preferred order inside each group.
 * Unknown views fall back to `ops` so a future module still lands somewhere.
 */
export const NAV_GROUPS = Object.freeze({
  primary: Object.freeze({
    id: 'primary',
    label: null,
    collapsible: false,
    views: Object.freeze([
      'overview',
      'findings',
      'inbox',
      'cases',
      'security',
      'fleet',
      'shadow-ai',
      'mcp',
    ]),
  }),
  analysis: Object.freeze({
    id: 'analysis',
    label: 'Analysis',
    collapsible: true,
    views: Object.freeze([
      'providers',
      'app-llm',
      'apps',
      'teams',
      'tools',
      'repos',
      'activity',
    ]),
  }),
  ops: Object.freeze({
    id: 'ops',
    label: 'Ops & health',
    collapsible: true,
    views: Object.freeze([
      'status',
      'destination-health',
      'install-health',
      'coverage',
      'dashboards',
      'onboarding',
    ]),
  }),
  control: Object.freeze({
    id: 'control',
    label: 'Control plane',
    collapsible: true,
    views: Object.freeze([
      'rules',
      'policy',
      'runbooks',
      'compliance',
      'access-review',
    ]),
  }),
  restricted: Object.freeze({
    id: 'restricted',
    label: 'Restricted',
    collapsible: true,
    views: Object.freeze(['users', 'audit']),
  }),
});

export const NAV_GROUP_ORDER = Object.freeze([
  'primary',
  'analysis',
  'ops',
  'control',
  'restricted',
]);

const VIEW_TO_GROUP = (() => {
  /** @type {Map<string, NavGroupId>} */
  const m = new Map();
  for (const id of NAV_GROUP_ORDER) {
    for (const view of NAV_GROUPS[id].views) m.set(view, id);
  }
  return m;
})();

/** Group id for a view name (unknown → ops). */
export function groupForView(view) {
  return VIEW_TO_GROUP.get(view) ?? 'ops';
}

/** Preferred index of `view` inside its group (-1 if unknown). */
export function orderInGroup(view) {
  const g = NAV_GROUPS[groupForView(view)];
  return g.views.indexOf(view);
}

function storage() {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

/** @returns {Set<string>} */
export function loadExpandedGroups() {
  try {
    const raw = storage()?.getItem(NAV_EXPAND_KEY);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return new Set();
    return new Set(parsed.filter((id) => NAV_GROUPS[id]?.collapsible));
  } catch {
    return new Set();
  }
}

/** @param {Iterable<string>} ids */
export function saveExpandedGroups(ids) {
  try {
    const list = [...ids].filter((id) => NAV_GROUPS[id]?.collapsible);
    storage()?.setItem(NAV_EXPAND_KEY, JSON.stringify(list));
  } catch {
    /* storage blocked — collapse state is session-only */
  }
}

/**
 * Ensure the group containers exist under `#tabs`. Safe to call multiple times.
 * Static index.html may already ship the structure; this fills gaps so modules
 * that boot before HTML is fully ready still have a place to land.
 *
 * @param {ParentNode} [root]
 */
export function ensureNavStructure(root = document) {
  const tabs = root.querySelector?.('#tabs') ?? root.getElementById?.('tabs');
  if (!tabs) return null;

  for (const id of NAV_GROUP_ORDER) {
    const def = NAV_GROUPS[id];
    if (id === 'primary') {
      if (!tabs.querySelector('[data-nav-slot="primary"]')) {
        const slot = root.createElement
          ? root.createElement('div')
          : document.createElement('div');
        slot.dataset.navSlot = 'primary';
        slot.className = 'nav-slot nav-slot-primary';
        // Primary is not a collapsible body — tabs live as direct visual peers.
        // We still use a slot so placeNavTab has a stable parent.
        tabs.insertBefore(slot, tabs.firstChild);
      }
      continue;
    }

    let wrap = tabs.querySelector(`[data-nav-group="${id}"]`);
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.className = 'nav-group-wrap';
      wrap.dataset.navGroup = id;
      wrap.dataset.collapsed = 'true';

      const toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.className = 'nav-group-toggle';
      toggle.dataset.navToggle = id;
      toggle.setAttribute('aria-expanded', 'false');
      toggle.setAttribute('aria-controls', `nav-body-${id}`);
      toggle.innerHTML =
        `<span class="nav-group-label">${def.label}</span>` +
        `<span class="nav-group-meta" data-nav-count="${id}" hidden></span>` +
        `<svg class="ico nav-group-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>`;

      const body = document.createElement('div');
      body.className = 'nav-group-body';
      body.id = `nav-body-${id}`;
      body.dataset.navBody = id;
      body.hidden = true;

      wrap.append(toggle, body);
      tabs.appendChild(wrap);
    }
  }
  return tabs;
}

/**
 * Place (or re-place) a tab button into its IA group in canonical order.
 * Idempotent: moving an already-placed tab re-sorts within the group.
 *
 * @param {HTMLElement} btn  button[data-view]
 * @param {ParentNode} [root]
 */
export function placeNavTab(btn, root = document) {
  if (!btn?.dataset?.view) return btn;
  const view = btn.dataset.view;
  const tabs = ensureNavStructure(root);
  if (!tabs) return btn;

  const groupId = groupForView(view);
  const parent =
    groupId === 'primary'
      ? tabs.querySelector('[data-nav-slot="primary"]')
      : tabs.querySelector(`[data-nav-body="${groupId}"]`);
  if (!parent) {
    tabs.appendChild(btn);
    return btn;
  }

  // Insert in group order: before the first sibling with a higher order index.
  const myOrder = orderInGroup(view);
  const siblings = [...parent.querySelectorAll(':scope > button[data-view]')];
  let inserted = false;
  for (const sib of siblings) {
    if (sib === btn) continue;
    const theirOrder = orderInGroup(sib.dataset.view);
    if (myOrder >= 0 && (theirOrder < 0 || myOrder < theirOrder)) {
      parent.insertBefore(btn, sib);
      inserted = true;
      break;
    }
  }
  if (!inserted) parent.appendChild(btn);

  refreshGroupVisibility(groupId, root);
  return btn;
}

/**
 * Move every existing data-view tab into its IA group (run once after bootstrap
 * so static index.html buttons land in the right slots).
 */
export function rehomeStaticTabs(root = document) {
  const tabs = ensureNavStructure(root);
  if (!tabs) return;
  const buttons = [...tabs.querySelectorAll('button[data-view]')];
  for (const btn of buttons) placeNavTab(btn, root);
}

/** Count visible (non-hidden) tabs in a group and hide empty collapsible groups. */
export function refreshGroupVisibility(groupId, root = document) {
  const def = NAV_GROUPS[groupId];
  if (!def || !def.collapsible) return;

  const wrap = root.querySelector?.(`[data-nav-group="${groupId}"]`);
  if (!wrap) return;
  const body = wrap.querySelector(`[data-nav-body="${groupId}"]`);
  if (!body) return;

  const visible = [...body.querySelectorAll(':scope > button[data-view]')].filter(
    (b) => !b.hidden,
  );
  wrap.hidden = visible.length === 0;

  const countEl = wrap.querySelector(`[data-nav-count="${groupId}"]`);
  if (countEl) {
    if (visible.length === 0) {
      countEl.hidden = true;
      countEl.textContent = '';
    } else {
      countEl.hidden = false;
      countEl.textContent = String(visible.length);
    }
  }
}

export function refreshAllGroupVisibility(root = document) {
  for (const id of NAV_GROUP_ORDER) {
    if (NAV_GROUPS[id].collapsible) refreshGroupVisibility(id, root);
  }
}

/**
 * Expand / collapse a collapsible group.
 * @param {string} groupId
 * @param {boolean} expanded
 * @param {{ persist?: boolean, root?: ParentNode }} [opts]
 */
export function setGroupExpanded(groupId, expanded, opts = {}) {
  const { persist = true, root = document } = opts;
  const def = NAV_GROUPS[groupId];
  if (!def?.collapsible) return;

  const wrap = root.querySelector?.(`[data-nav-group="${groupId}"]`);
  if (!wrap) return;
  const body = wrap.querySelector(`[data-nav-body="${groupId}"]`);
  const toggle = wrap.querySelector(`[data-nav-toggle="${groupId}"]`);
  wrap.dataset.collapsed = expanded ? 'false' : 'true';
  if (body) body.hidden = !expanded;
  if (toggle) toggle.setAttribute('aria-expanded', String(expanded));

  if (persist) {
    const set = loadExpandedGroups();
    if (expanded) set.add(groupId);
    else set.delete(groupId);
    saveExpandedGroups(set);
  }
}

/** Apply stored expand preferences (collapsed by default). */
export function applyStoredExpansion(root = document) {
  const expanded = loadExpandedGroups();
  for (const id of NAV_GROUP_ORDER) {
    if (!NAV_GROUPS[id].collapsible) continue;
    setGroupExpanded(id, expanded.has(id), { persist: false, root });
  }
}

/**
 * Ensure the group that owns `view` is expanded so the active tab is visible.
 * Does not collapse other groups.
 */
export function revealViewInNav(view, root = document) {
  const groupId = groupForView(view);
  if (!NAV_GROUPS[groupId]?.collapsible) return;
  setGroupExpanded(groupId, true, { persist: true, root });
}

/**
 * Wire toggle clicks + optional external active-view sync.
 * Call once after ensureNavStructure / rehomeStaticTabs.
 *
 * @param {{ getActiveView?: () => string|null, root?: ParentNode }} [opts]
 */
export function initNavIa(opts = {}) {
  const root = opts.root ?? document;
  ensureNavStructure(root);
  rehomeStaticTabs(root);
  applyStoredExpansion(root);
  refreshAllGroupVisibility(root);

  const tabs = root.querySelector?.('#tabs');
  if (!tabs || tabs.dataset.navIaBound === '1') {
    // Still reveal active view on re-init.
    const active = opts.getActiveView?.();
    if (active) revealViewInNav(active, root);
    return tabs;
  }
  tabs.dataset.navIaBound = '1';

  tabs.addEventListener('click', (e) => {
    const toggle = e.target.closest?.('[data-nav-toggle]');
    if (!toggle || !tabs.contains(toggle)) return;
    e.preventDefault();
    e.stopPropagation();
    const id = toggle.dataset.navToggle;
    const expanded = toggle.getAttribute('aria-expanded') === 'true';
    setGroupExpanded(id, !expanded, { root });
  });

  const active = opts.getActiveView?.();
  if (active) revealViewInNav(active, root);
  return tabs;
}



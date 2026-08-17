/* AIM-708 — custom dashboard builder model (pure, DOM-free).
 *
 * Saved views (AIM-94) persist *filter presets* for one console. This module
 * is the next step: named dashboards that compose widgets (KPI tiles, charts,
 * tables) drawn from existing read APIs.
 *
 * Storage is local for the frontend MVP ("Can start now: Frontend"). The
 * schema is deliberately API-shaped so a future /api/dashboards can swap the
 * store without rewriting the UI. No telemetry content is persisted — only
 * layout metadata (widget ids, order, sizes, names).
 */

export const STORAGE_KEY = 'aim.customDashboards';
export const SCHEMA_VERSION = 1;
export const NAME_MAX = 80;
export const MAX_DASHBOARDS = 25;
export const MAX_WIDGETS = 24;
export const WIDGET_SIZES = ['half', 'full'];
export const WIDGET_KINDS = ['kpi', 'chart', 'table'];

/** Catalog of composable widgets. `source` names the data loader the UI uses. */
export const WIDGET_CATALOG = [
  /* ---------- KPIs ---------- */
  {
    id: 'kpi.activeUsers',
    kind: 'kpi',
    label: 'Active users',
    description: 'Distinct users with activity in the selected range.',
    source: 'overview',
    sizeDefault: 'half',
  },
  {
    id: 'kpi.events',
    kind: 'kpi',
    label: 'Events in range',
    description: 'Total collected events for the selected range.',
    source: 'overview',
    sizeDefault: 'half',
  },
  {
    id: 'kpi.costUsd',
    kind: 'kpi',
    label: 'Est. spend',
    description: 'Estimated token spend (list prices) for the range.',
    source: 'overview',
    sizeDefault: 'half',
  },
  {
    id: 'kpi.openCritical',
    kind: 'kpi',
    label: 'Open critical findings',
    description: 'Critical findings still in triage (new + acknowledged).',
    source: 'findingsCritical',
    capability: 'findingsConsole',
    sizeDefault: 'half',
  },
  {
    id: 'kpi.unapproved',
    kind: 'kpi',
    label: 'Unapproved tools',
    description: 'Tools observed that are not on the sanctioned list.',
    source: 'unapproved',
    sizeDefault: 'half',
  },

  /* ---------- Charts ---------- */
  {
    id: 'chart.eventsTrend',
    kind: 'chart',
    chartType: 'line',
    label: 'Events trend',
    description: 'Daily events (or sessions on older backends).',
    source: 'overview',
    sizeDefault: 'full',
  },
  {
    id: 'chart.flagsTrend',
    kind: 'chart',
    chartType: 'line',
    label: 'Guardrail hits trend',
    description: 'Daily detector matches across the fleet.',
    source: 'flags',
    sizeDefault: 'full',
  },
  {
    id: 'chart.toolsBar',
    kind: 'chart',
    chartType: 'bar',
    label: 'Top tools by tokens',
    description: 'Highest-volume tools in the selected range.',
    source: 'tools',
    sizeDefault: 'full',
  },

  /* ---------- Tables ---------- */
  {
    id: 'table.topTools',
    kind: 'table',
    label: 'Top tools',
    description: 'Tool usage ranked by tokens.',
    source: 'tools',
    sizeDefault: 'full',
  },
  {
    id: 'table.unapproved',
    kind: 'table',
    label: 'Unapproved tools',
    description: 'Observed tools outside the sanctioned list.',
    source: 'unapproved',
    sizeDefault: 'half',
  },
  {
    id: 'table.openFindings',
    kind: 'table',
    label: 'Open findings',
    description: 'Critical and high findings currently in triage.',
    source: 'findingsOpen',
    capability: 'findingsConsole',
    sizeDefault: 'full',
  },
  {
    id: 'table.teams',
    kind: 'table',
    label: 'Team usage',
    description: 'Usage attributed to teams in the selected range.',
    source: 'teams',
    sizeDefault: 'full',
  },
];

const CATALOG_BY_ID = new Map(WIDGET_CATALOG.map((w) => [w.id, w]));

export function catalogEntry(widgetId) {
  return CATALOG_BY_ID.get(widgetId) ?? null;
}

export function catalogForCapabilities(capabilities = {}) {
  return WIDGET_CATALOG.filter((w) => !w.capability || capabilities[w.capability]);
}

/* ---------- ids / time (injectable for tests) ---------- */

function defaultId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `d_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

function defaultNow() {
  return new Date().toISOString();
}

/* ---------- validation ---------- */

export function validateName(name) {
  if (typeof name !== 'string') return null;
  const trimmed = name.trim();
  if (trimmed.length < 1 || trimmed.length > NAME_MAX) return null;
  return trimmed;
}

export function validateWidgetPlacement(widget, { capabilities = {} } = {}) {
  if (!widget || typeof widget !== 'object' || Array.isArray(widget)) {
    return { ok: false, error: 'widget must be an object' };
  }
  if (typeof widget.instanceId !== 'string' || !widget.instanceId) {
    return { ok: false, error: 'widget.instanceId is required' };
  }
  const entry = catalogEntry(widget.widgetId);
  if (!entry) return { ok: false, error: `unknown widgetId '${widget.widgetId}'` };
  if (entry.capability && !capabilities[entry.capability]) {
    return { ok: false, error: `widget '${entry.id}' requires capability ${entry.capability}` };
  }
  if (widget.size != null && !WIDGET_SIZES.includes(widget.size)) {
    return { ok: false, error: `widget.size must be one of ${WIDGET_SIZES.join(', ')}` };
  }
  return { ok: true, entry };
}

export function validateDashboard(dash, { capabilities = {} } = {}) {
  if (!dash || typeof dash !== 'object' || Array.isArray(dash)) {
    return { ok: false, errors: ['dashboard must be an object'] };
  }
  const errors = [];
  if (typeof dash.id !== 'string' || !dash.id) errors.push('dashboard.id is required');
  if (!validateName(dash.name)) errors.push(`dashboard.name must be 1–${NAME_MAX} characters`);
  if (!Array.isArray(dash.widgets)) {
    errors.push('dashboard.widgets must be an array');
  } else {
    if (dash.widgets.length > MAX_WIDGETS) {
      errors.push(`dashboard.widgets exceeds max of ${MAX_WIDGETS}`);
    }
    const seen = new Set();
    for (const w of dash.widgets) {
      const r = validateWidgetPlacement(w, { capabilities });
      if (!r.ok) errors.push(r.error);
      else if (seen.has(w.instanceId)) errors.push(`duplicate instanceId '${w.instanceId}'`);
      else seen.add(w.instanceId);
    }
  }
  return { ok: errors.length === 0, errors };
}

/* ---------- empty / default store ---------- */

export function emptyStore() {
  return { version: SCHEMA_VERSION, activeId: null, dashboards: [] };
}

/** First-run starter so the builder is not a blank page. */
export function defaultStarterDashboard({ id = defaultId(), now = defaultNow() } = {}) {
  return {
    id,
    name: 'Security posture',
    createdAt: now,
    updatedAt: now,
    widgets: [
      { instanceId: `${id}-w1`, widgetId: 'kpi.openCritical', size: 'half' },
      { instanceId: `${id}-w2`, widgetId: 'kpi.unapproved', size: 'half' },
      { instanceId: `${id}-w3`, widgetId: 'kpi.activeUsers', size: 'half' },
      { instanceId: `${id}-w4`, widgetId: 'kpi.events', size: 'half' },
      { instanceId: `${id}-w5`, widgetId: 'chart.eventsTrend', size: 'full' },
      { instanceId: `${id}-w6`, widgetId: 'table.openFindings', size: 'full' },
      { instanceId: `${id}-w7`, widgetId: 'table.unapproved', size: 'half' },
      { instanceId: `${id}-w8`, widgetId: 'table.topTools', size: 'half' },
    ],
  };
}

/**
 * Normalize an unknown payload into a valid store.
 * Corrupt/partial localStorage must never blank the builder.
 */
export function normalizeStore(raw, { seedDefault = true, id = defaultId, now = defaultNow } = {}) {
  const store = emptyStore();
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    if (seedDefault) {
      const starter = defaultStarterDashboard({ id: id(), now: typeof now === 'function' ? now() : now });
      store.dashboards = [starter];
      store.activeId = starter.id;
    }
    return store;
  }

  const list = Array.isArray(raw.dashboards) ? raw.dashboards : [];
  for (const d of list.slice(0, MAX_DASHBOARDS)) {
    if (!d || typeof d !== 'object') continue;
    const name = validateName(d.name);
    if (!name || typeof d.id !== 'string' || !d.id) continue;
    const widgets = [];
    if (Array.isArray(d.widgets)) {
      for (const w of d.widgets.slice(0, MAX_WIDGETS)) {
        if (!w || typeof w !== 'object') continue;
        if (typeof w.instanceId !== 'string' || !w.instanceId) continue;
        if (!catalogEntry(w.widgetId)) continue;
        widgets.push({
          instanceId: w.instanceId,
          widgetId: w.widgetId,
          size: WIDGET_SIZES.includes(w.size) ? w.size : (catalogEntry(w.widgetId).sizeDefault || 'full'),
        });
      }
    }
    store.dashboards.push({
      id: d.id,
      name,
      createdAt: typeof d.createdAt === 'string' ? d.createdAt : (typeof now === 'function' ? now() : now),
      updatedAt: typeof d.updatedAt === 'string' ? d.updatedAt : (typeof now === 'function' ? now() : now),
      widgets,
    });
  }

  if (store.dashboards.length === 0 && seedDefault) {
    const starter = defaultStarterDashboard({ id: id(), now: typeof now === 'function' ? now() : now });
    store.dashboards = [starter];
    store.activeId = starter.id;
    return store;
  }

  const activeOk = store.dashboards.some((d) => d.id === raw.activeId);
  store.activeId = activeOk ? raw.activeId : (store.dashboards[0]?.id ?? null);
  return store;
}

/* ---------- mutations (immutable) ---------- */

export function getActive(store) {
  if (!store?.dashboards?.length) return null;
  return store.dashboards.find((d) => d.id === store.activeId) ?? store.dashboards[0] ?? null;
}

export function createDashboard(store, name, {
  id = defaultId(),
  now = defaultNow(),
  widgets = [],
} = {}) {
  const cleaned = validateName(name);
  if (!cleaned) return { ok: false, error: `Name must be 1–${NAME_MAX} characters` };
  if ((store.dashboards?.length ?? 0) >= MAX_DASHBOARDS) {
    return { ok: false, error: `At most ${MAX_DASHBOARDS} dashboards` };
  }
  if (store.dashboards.some((d) => d.name.toLowerCase() === cleaned.toLowerCase())) {
    return { ok: false, error: `A dashboard named “${cleaned}” already exists` };
  }
  const dash = {
    id,
    name: cleaned,
    createdAt: now,
    updatedAt: now,
    widgets: Array.isArray(widgets) ? widgets : [],
  };
  return {
    ok: true,
    store: {
      ...store,
      activeId: id,
      dashboards: [...store.dashboards, dash],
    },
    dashboard: dash,
  };
}

export function renameDashboard(store, dashboardId, name, { now = defaultNow() } = {}) {
  const cleaned = validateName(name);
  if (!cleaned) return { ok: false, error: `Name must be 1–${NAME_MAX} characters` };
  const clash = store.dashboards.find(
    (d) => d.id !== dashboardId && d.name.toLowerCase() === cleaned.toLowerCase(),
  );
  if (clash) return { ok: false, error: `A dashboard named “${cleaned}” already exists` };
  let found = false;
  const dashboards = store.dashboards.map((d) => {
    if (d.id !== dashboardId) return d;
    found = true;
    return { ...d, name: cleaned, updatedAt: now };
  });
  if (!found) return { ok: false, error: 'Dashboard not found' };
  return { ok: true, store: { ...store, dashboards } };
}

export function deleteDashboard(store, dashboardId) {
  const dashboards = store.dashboards.filter((d) => d.id !== dashboardId);
  if (dashboards.length === store.dashboards.length) {
    return { ok: false, error: 'Dashboard not found' };
  }
  let activeId = store.activeId;
  if (activeId === dashboardId) activeId = dashboards[0]?.id ?? null;
  return { ok: true, store: { ...store, dashboards, activeId } };
}

export function setActiveDashboard(store, dashboardId) {
  if (!store.dashboards.some((d) => d.id === dashboardId)) {
    return { ok: false, error: 'Dashboard not found' };
  }
  return { ok: true, store: { ...store, activeId: dashboardId } };
}

export function addWidget(store, dashboardId, widgetId, {
  instanceId = defaultId(),
  size,
  now = defaultNow(),
  capabilities = {},
} = {}) {
  const entry = catalogEntry(widgetId);
  if (!entry) return { ok: false, error: `Unknown widget “${widgetId}”` };
  if (entry.capability && !capabilities[entry.capability]) {
    return { ok: false, error: `“${entry.label}” requires a higher role` };
  }
  let found = false;
  let error = null;
  let placement = null;
  const dashboards = store.dashboards.map((d) => {
    if (d.id !== dashboardId) return d;
    found = true;
    if (d.widgets.length >= MAX_WIDGETS) {
      error = `At most ${MAX_WIDGETS} widgets per dashboard`;
      return d;
    }
    placement = {
      instanceId,
      widgetId,
      size: WIDGET_SIZES.includes(size) ? size : entry.sizeDefault,
    };
    return { ...d, updatedAt: now, widgets: [...d.widgets, placement] };
  });
  if (!found) return { ok: false, error: 'Dashboard not found' };
  if (error) return { ok: false, error };
  return { ok: true, store: { ...store, dashboards }, placement };
}

export function removeWidget(store, dashboardId, instanceId, { now = defaultNow() } = {}) {
  let found = false;
  let removed = false;
  const dashboards = store.dashboards.map((d) => {
    if (d.id !== dashboardId) return d;
    found = true;
    const widgets = d.widgets.filter((w) => w.instanceId !== instanceId);
    if (widgets.length === d.widgets.length) return d;
    removed = true;
    return { ...d, updatedAt: now, widgets };
  });
  if (!found) return { ok: false, error: 'Dashboard not found' };
  if (!removed) return { ok: false, error: 'Widget not found' };
  return { ok: true, store: { ...store, dashboards } };
}

export function moveWidget(store, dashboardId, instanceId, direction, { now = defaultNow() } = {}) {
  const delta = direction === 'up' ? -1 : direction === 'down' ? 1 : 0;
  if (!delta) return { ok: false, error: 'direction must be up or down' };
  let found = false;
  let moved = false;
  const dashboards = store.dashboards.map((d) => {
    if (d.id !== dashboardId) return d;
    found = true;
    const idx = d.widgets.findIndex((w) => w.instanceId === instanceId);
    if (idx < 0) return d;
    const next = idx + delta;
    if (next < 0 || next >= d.widgets.length) return d;
    const widgets = d.widgets.slice();
    const [item] = widgets.splice(idx, 1);
    widgets.splice(next, 0, item);
    moved = true;
    return { ...d, updatedAt: now, widgets };
  });
  if (!found) return { ok: false, error: 'Dashboard not found' };
  if (!moved) return { ok: false, error: 'Cannot move widget' };
  return { ok: true, store: { ...store, dashboards } };
}

export function setWidgetSize(store, dashboardId, instanceId, size, { now = defaultNow() } = {}) {
  if (!WIDGET_SIZES.includes(size)) {
    return { ok: false, error: `size must be one of ${WIDGET_SIZES.join(', ')}` };
  }
  let found = false;
  let updated = false;
  const dashboards = store.dashboards.map((d) => {
    if (d.id !== dashboardId) return d;
    found = true;
    const widgets = d.widgets.map((w) => {
      if (w.instanceId !== instanceId) return w;
      updated = true;
      return { ...w, size };
    });
    return updated ? { ...d, updatedAt: now, widgets } : d;
  });
  if (!found) return { ok: false, error: 'Dashboard not found' };
  if (!updated) return { ok: false, error: 'Widget not found' };
  return { ok: true, store: { ...store, dashboards } };
}

/* ---------- persistence ---------- */

function storage() {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

export function loadStore(opts = {}) {
  const s = storage();
  if (!s) return normalizeStore(null, opts);
  try {
    const raw = s.getItem(STORAGE_KEY);
    if (!raw) return normalizeStore(null, opts);
    return normalizeStore(JSON.parse(raw), opts);
  } catch {
    return normalizeStore(null, opts);
  }
}

export function saveStore(store) {
  const s = storage();
  if (!s) return false;
  try {
    s.setItem(STORAGE_KEY, JSON.stringify({
      version: SCHEMA_VERSION,
      activeId: store.activeId,
      dashboards: store.dashboards,
    }));
    return true;
  } catch {
    return false;
  }
}

/** Group consecutive KPI widgets into card rows for layout. */
export function layoutRows(widgets) {
  const rows = [];
  let kpiBuf = [];
  const flushKpi = () => {
    if (!kpiBuf.length) return;
    rows.push({ type: 'kpi-row', widgets: kpiBuf });
    kpiBuf = [];
  };
  for (const w of widgets) {
    const entry = catalogEntry(w.widgetId);
    if (entry?.kind === 'kpi') {
      kpiBuf.push(w);
      if (kpiBuf.length >= 4) flushKpi();
    } else {
      flushKpi();
      rows.push({ type: 'block', widget: w, size: w.size || entry?.sizeDefault || 'full' });
    }
  }
  flushKpi();
  return rows;
}

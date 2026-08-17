// First-party vendor admin feed status.
// Read-only aggregates for Overview / Tools / Apps empty-state copy.
// Fail-open: a missing table (pre-migration) returns dark feeds, never 500.

export const VENDOR_FEED_CATALOG = [
  {
    id: 'claude_otel',
    label: 'Claude Code OpenTelemetry',
    tool: 'claude_code',
    kind: 'push',
    setup: 'docs/ops/vendor-admin-telemetry.md',
  },
  {
    id: 'copilot_metrics',
    label: 'GitHub Copilot usage metrics',
    tool: 'github_copilot',
    kind: 'pull',
    setup: 'docs/ops/vendor-admin-telemetry.md',
  },
  {
    id: 'cursor_analytics',
    label: 'Cursor Analytics',
    tool: 'cursor',
    kind: 'pull',
    setup: 'docs/ops/vendor-admin-telemetry.md',
  },
];

const num = (v) => Number(v ?? 0);

function darkReason(id, state) {
  if (id === 'claude_otel') {
    return 'no Claude Code OTel events in this range — point the exporter at POST /v1/metrics (or /v1/traces with service.name=claude-code)';
  }
  if (state?.last_error_class === 'credential_missing' || state?.configured === false) {
    return state?.detail || `${id} credential unset — feed dark; ingest continues`;
  }
  if (state?.last_error_class === 'upstream_error') {
    return state?.detail || `${id} upstream error — last poll failed`;
  }
  return `no ${id} rollup in this range`;
}

/**
 * @param {{ query: Function }} db
 * @param {number} days
 */
export async function loadVendorFeeds(db, days) {
  const feeds = VENDOR_FEED_CATALOG.map((c) => ({
    id: c.id,
    label: c.label,
    tool: c.tool,
    kind: c.kind,
    status: 'dark',
    configured: c.kind === 'push',
    reason: darkReason(c.id, null),
    lastSeen: null,
    lastDay: null,
    events: 0,
    activeUsers: 0,
    sessions: 0,
    tokens: 0,
    costUsd: 0,
    locAccepted: 0,
    locSuggested: 0,
  }));
  const byId = Object.fromEntries(feeds.map((f) => [f.id, f]));

  try {
    const { rows } = await db.query(
      `SELECT COUNT(*) AS events,
              COALESCE(SUM(tokens_in + tokens_out), 0) AS tokens,
              COALESCE(SUM(cost_estimate_usd), 0) AS cost,
              MAX(ts) AS last_seen
         FROM events
        WHERE source = 'otel' AND tool = 'claude_code'
          AND ts >= now() - ($1 || ' days')::interval`,
      [days],
    );
    const r = rows[0] ?? {};
    const events = num(r.events);
    if (events > 0) {
      Object.assign(byId.claude_otel, {
        status: 'live',
        configured: true,
        reason: null,
        lastSeen: r.last_seen,
        events,
        tokens: num(r.tokens),
        costUsd: num(r.cost),
      });
    }
  } catch {
    /* events query failed — leave Claude dark */
  }

  let stateRows = [];
  try {
    const res = await db.query(
      `SELECT feed, configured, last_attempt_at, last_success_at,
              last_error_class, last_day, detail
         FROM vendor_admin_feeds`,
    );
    stateRows = res.rows ?? [];
  } catch {
    stateRows = [];
  }
  const stateByFeed = Object.fromEntries(stateRows.map((r) => [r.feed, r]));

  let dailyRows = [];
  try {
    const res = await db.query(
      `SELECT feed,
              COALESCE(SUM(active_users), 0) AS active_users,
              COALESCE(SUM(sessions), 0) AS sessions,
              COALESCE(SUM(tokens_in + tokens_out), 0) AS tokens,
              COALESCE(SUM(cost_usd), 0) AS cost,
              COALESCE(SUM(loc_accepted), 0) AS loc_accepted,
              COALESCE(SUM(loc_suggested), 0) AS loc_suggested,
              MAX(day) AS last_day
         FROM vendor_admin_daily
        WHERE day >= (CURRENT_DATE - ($1::int))
        GROUP BY feed`,
      [days],
    );
    dailyRows = res.rows ?? [];
  } catch {
    dailyRows = [];
  }

  for (const row of dailyRows) {
    const feed = byId[row.feed];
    if (!feed) continue;
    const has = num(row.active_users) > 0 || num(row.sessions) > 0
      || num(row.tokens) > 0 || num(row.loc_accepted) > 0 || num(row.loc_suggested) > 0;
    if (!has && feed.id === 'claude_otel' && feed.status === 'live') {
      feed.locAccepted = num(row.loc_accepted);
      feed.locSuggested = num(row.loc_suggested);
      feed.lastDay = row.last_day;
      continue;
    }
    if (has) {
      feed.status = 'live';
      feed.reason = null;
      feed.activeUsers = num(row.active_users);
      feed.sessions = num(row.sessions);
      feed.tokens = num(row.tokens);
      feed.costUsd = num(row.cost);
      feed.locAccepted = num(row.loc_accepted);
      feed.locSuggested = num(row.loc_suggested);
      feed.lastDay = row.last_day;
    }
  }

  for (const feed of feeds) {
    const st = stateByFeed[feed.id];
    if (!st) continue;
    feed.configured = Boolean(st.configured) || feed.kind === 'push';
    if (feed.status !== 'live') {
      feed.reason = darkReason(feed.id, st);
    }
  }

  return { rangeDays: days, feeds };
}

export function vendorToolsFromFeeds(feeds) {
  const extra = [];
  for (const f of feeds ?? []) {
    if (f.status !== 'live') continue;
    if (f.id === 'copilot_metrics') {
      extra.push({
        tool: 'github_copilot',
        toolRaw: 'github_copilot',
        sanctioned: false,
        users: f.activeUsers,
        hosts: 0,
        sessions: f.sessions,
        proxyEvents: 0,
        endpointEvents: 0,
        otelEvents: 0,
        tokens: f.tokens,
        costUsd: f.costUsd,
        firstSeen: f.lastDay,
        lastSeen: f.lastDay,
        vendorAdmin: true,
        feed: f.id,
      });
    }
  }
  return extra;
}

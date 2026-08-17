// Dashboard read API, reading the canonical event store (
// unified). Events live in the ingest schema: keyed by event_id,
// pseudonymous host_ref/user_ref (HMAC), source in {proxy, endpoint}, nullable
// tokens/model/provider. Network-path (proxy) events have no resolved user, so
// no query here may depend on a NOT-NULL user identity.
//
// All endpoints are metadata-only aggregates. No prompt/response content exists
// in the DB by design (content policy).
import { query } from '../db.js';
import { COST_SQL } from '../pricing.js';
import { isSanctioned, listSanctionedToolNames } from '../sanctioned.js';
import { canSeeUsers, hasRole, requireRoles } from '../auth.js';
import { wantsCsv, checkFormat, sendCsv } from '../csv.js';
import { audit } from '../audit.js';
import {
  evaluateAttribution,
  attributionRate,
  ATTRIBUTION_TARGET_PCT,
} from './pipeline.js';

function parseDays(q, def = 30, max = 365) {
  const d = Number(q?.days ?? def);
  if (!Number.isFinite(d) || d < 1) return def;
  return Math.min(Math.floor(d), max);
}

// offset pagination for /api/users (path-to-5k). UI default ≤ 100;
// higher limits only on the already-gated CSV export path.
const USERS_DEFAULT_LIMIT = 100;
const USERS_MAX_LIMIT = 100;
const USERS_CSV_DEFAULT_LIMIT = 10_000;
const USERS_CSV_MAX_LIMIT = 10_000;

function parseUsersLimit(q, { csv = false } = {}) {
  const def = csv ? USERS_CSV_DEFAULT_LIMIT : USERS_DEFAULT_LIMIT;
  const max = csv ? USERS_CSV_MAX_LIMIT : USERS_MAX_LIMIT;
  const n = Number(q?.limit ?? def);
  if (!Number.isFinite(n) || n < 1) return def;
  return Math.min(Math.floor(n), max);
}

function parseOffset(q) {
  const n = Number(q?.offset ?? 0);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

// Optional ?source=proxy|endpoint filter. Returns { clause, params } where
// clause is '' or ' AND e.source = $N' with N = paramIndex.
function sourceFilter(q, paramIndex) {
  const s = q?.source;
  if (s === 'proxy' || s === 'endpoint') return { clause: ` AND e.source = $${paramIndex}`, param: s };
  return { clause: '', param: null };
}

const num = (v) => Number(v ?? 0);

// CSV column layouts. Keys match the JSON field names of each
// endpoint's row objects so the export mirrors the on-screen table.
const TOOLS_CSV_COLS = [
  { key: 'tool', label: 'tool' },
  { key: 'sanctioned', label: 'sanctioned' },
  { key: 'users', label: 'users' },
  { key: 'hosts', label: 'hosts' },
  { key: 'sessions', label: 'sessions' },
  { key: 'proxyEvents', label: 'proxy_events' },
  { key: 'endpointEvents', label: 'endpoint_events' },
  { key: 'tokens', label: 'tokens' },
  { key: 'costUsd', label: 'cost_usd' },
  { key: 'firstSeen', label: 'first_seen' },
];
const PROVIDERS_CSV_COLS = [
  { key: 'provider', label: 'provider' },
  { key: 'events', label: 'events' },
  { key: 'tools', label: 'tools' },
  { key: 'sessions', label: 'sessions' },
  { key: 'hosts', label: 'hosts' },
  { key: 'users', label: 'users' },
  { key: 'tokens', label: 'tokens' },
  { key: 'costUsd', label: 'cost_usd' },
  { key: 'firstSeen', label: 'first_seen' },
  { key: 'lastSeen', label: 'last_seen' },
];
// Providers whose direct API is matched by `provider-api` rules in
// collectors/proxy/endpoints.json: usable by BOTH
// employee tools and company-built applications — attribution comes from
// traffic_class. Keep in sync with category=provider-api rule providers
// (see docs/app-llm-provider-catalogue.md). Sorted for stable API output.
const PROVIDER_API_PROVIDERS = new Set([
  // Keep sorted by product priority, then alpha. CI:
  // scripts/check_provider_catalogue_drift.py fails when this set drifts from
  // collectors/proxy/endpoints.json category=provider-api.
  'anthropic',
  'openai',
  'azure_openai',
  'aws_bedrock',
  'google',
  'mistral',
  'cohere',
  'groq',
  'xai',
  'openrouter',
  'moonshot',
  'together',
  'fireworks',
]);
const APP_LLM_CSV_COLS = [
  { key: 'provider', label: 'provider' },
  { key: 'trafficClass', label: 'traffic_class' },
  { key: 'events', label: 'events' },
  { key: 'hosts', label: 'hosts' },
  { key: 'sessions', label: 'sessions' },
  { key: 'bytesUp', label: 'bytes_up' },
  { key: 'bytesDown', label: 'bytes_down' },
  { key: 'status2xx', label: 'status_2xx' },
  { key: 'status4xx', label: 'status_4xx' },
  { key: 'status5xx', label: 'status_5xx' },
  { key: 'firstSeen', label: 'first_seen' },
  { key: 'lastSeen', label: 'last_seen' },
];
const TEAMS_CSV_COLS = [
  { key: 'team', label: 'team' },
  { key: 'activeUsers', label: 'active_users' },
  { key: 'activeHosts', label: 'active_hosts' },
  { key: 'sessions', label: 'sessions' },
  { key: 'tokens', label: 'tokens' },
  { key: 'costUsd', label: 'cost_usd' },
  { key: 'sanctionedToolCount', label: 'sanctioned_tool_count' },
  { key: 'unsanctionedToolCount', label: 'unsanctioned_tool_count' },
  { key: 'unsanctionedEvents', label: 'unsanctioned_events' },
];
const MODELS_CSV_COLS = [
  { key: 'model', label: 'model' },
  { key: 'events', label: 'events' },
  { key: 'tokensInput', label: 'tokens_input' },
  { key: 'tokensOutput', label: 'tokens_output' },
  { key: 'costUsd', label: 'cost_usd' },
];
const UNAPPROVED_CSV_COLS = [
  { key: 'tool', label: 'tool' },
  { key: 'provider', label: 'provider' },
  { key: 'firstSeen', label: 'first_seen' },
  { key: 'lastSeen', label: 'last_seen' },
  { key: 'events', label: 'events' },
  { key: 'users', label: 'users' },
  { key: 'hosts', label: 'hosts' },
  { key: 'teams', label: 'teams' },
  { key: 'sessions', label: 'sessions' },
  { key: 'tokens', label: 'tokens' },
  { key: 'costUsd', label: 'cost_usd' },
];
const SEVERITY_BY_RANK = { 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' };

/* Fallback severity when no event carried one. Keyed to the detection category
   because that is the only signal available: a leaked credential is materially
   worse than a policy-list match, and rendering them identically would flatten
   the one distinction the Security view exists to make. */
const CATEGORY_SEVERITY = {
  secret: 'critical',
  injection: 'high',
  pii: 'medium',
  policy: 'low',
};

const FLAGS_CSV_COLS = [
  { key: 'detector', label: 'detector' },
  { key: 'category', label: 'category' },
  { key: 'severity', label: 'severity' },
  { key: 'severitySource', label: 'severity_source' },
  { key: 'hits', label: 'hits' },
  { key: 'users', label: 'users' },
  { key: 'tools', label: 'tools' },
  { key: 'firstSeen', label: 'first_seen' },
  { key: 'lastSeen', label: 'last_seen' },
];
const USERS_CSV_COLS = [
  { key: 'pseudonym', label: 'pseudonym' },
  { key: 'team', label: 'team' },
  { key: 'sessions', label: 'sessions' },
  { key: 'tools', label: 'tools' },
  { key: 'tokens', label: 'tokens' },
  { key: 'costUsd', label: 'cost_usd' },
  { key: 'lastActive', label: 'last_active' },
  { key: 'flagHits', label: 'flag_hits' },
];
const REPOS_CSV_COLS = [
  { key: 'repo', label: 'repo_pseudonym' },
  { key: 'events', label: 'events' },
  { key: 'users', label: 'users' },
  { key: 'hosts', label: 'hosts' },
  { key: 'sessions', label: 'sessions' },
  { key: 'tools', label: 'tools' },
  { key: 'tokens', label: 'tokens' },
  { key: 'costUsd', label: 'cost_usd' },
  { key: 'firstSeen', label: 'first_seen' },
  { key: 'lastSeen', label: 'last_seen' },
];

// opts.db is injectable for tests; defaults to the real pg pool.
export async function dashboardRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  // Role gates: org-level aggregates are open to all three roles,
  // user-level rows stay analyst+, repo label writes are admin only.
  const anyRole = requireRoles('admin', 'analyst', 'auditor', 'viewer');
  const userLevel = requireRoles('analyst', 'admin');
  const adminOnly = requireRoles('admin');
  // ---- org overview: who uses which AI tools, how much, trend over time ----
  fastify.get('/api/overview', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const days = parseDays(req.query);
    const sanctionedTools = await listSanctionedToolNames(db);
    const sf = sourceFilter(req.query, 2);
    const params = sf.param ? [days, sf.param] : [days];
    const range = `e.ts >= now() - ($1 || ' days')::interval`;
    // the KPI strip shows a delta vs. the immediately preceding window
    // of equal length. Distinct counts (users, hosts, sessions) cannot be
    // derived by subtracting a wider window, so the prior period is its own
    // aggregate rather than arithmetic on the current one.
    const priorRange = `e.ts >= now() - ((2 * $1) || ' days')::interval
                        AND e.ts < now() - ($1 || ' days')::interval`;
    const TOTALS_SELECT = `SELECT
           COUNT(DISTINCT e.user_ref)  AS active_users,
           COUNT(DISTINCT e.host_ref)  AS active_hosts,
           COUNT(DISTINCT e.session_id) AS sessions,
           COUNT(*)                    AS events,
           COALESCE(SUM(e.tokens_in),0)  AS tokens_input,
           COALESCE(SUM(e.tokens_out),0) AS tokens_output,
           COALESCE(SUM(${COST_SQL}),0)  AS cost
         FROM events e`;
    // attributed vs unattributed is a first-class Overview metric.
    // Same range as the usage KPIs so the numbers answer the same window the
    // operator is looking at. Split by tool and host so a single dark tool
    // or host cannot hide inside a green fleet average.
    const ATTR_TOTALS_SQL = `SELECT
           COUNT(*) AS total,
           COUNT(e.user_pseudonym) AS attributed,
           COUNT(*) FILTER (WHERE e.user_pseudonym IS NOT NULL
                            AND e.principal_kind = 'service') AS service_attributed
         FROM events e`;
    const [totals, tools, trend, prior, attrTotals, attrTrend, attrByTool, attrByHost] = await Promise.all([
      db.query(`${TOTALS_SELECT} WHERE ${range}${sf.clause}`, params),
      db.query(
        `SELECT
           e.tool,
           COUNT(DISTINCT e.user_ref)  AS users,
           COUNT(DISTINCT e.host_ref)  AS hosts,
           COUNT(DISTINCT e.session_id) AS sessions,
           COUNT(*) FILTER (WHERE e.source = 'proxy')    AS proxy_events,
           COUNT(*) FILTER (WHERE e.source = 'endpoint') AS endpoint_events,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           COALESCE(SUM(${COST_SQL}),0) AS cost,
           MIN(e.ts) AS first_seen
         FROM events e
         WHERE ${range}${sf.clause}
         GROUP BY e.tool ORDER BY tokens DESC`,
        params
      ),
      db.query(
        `SELECT
           date_trunc('day', e.ts)::date AS day,
           COUNT(DISTINCT e.user_ref)  AS active_users,
           COUNT(DISTINCT e.host_ref)  AS active_hosts,
           COUNT(DISTINCT e.session_id) AS sessions,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           COALESCE(SUM(${COST_SQL}),0)  AS cost
         FROM events e
         WHERE ${range}${sf.clause}
         GROUP BY date_trunc('day', e.ts)::date ORDER BY 1`,
        params
      ),
      db.query(`${TOTALS_SELECT} WHERE ${priorRange}${sf.clause}`, params),
      db.query(`${ATTR_TOTALS_SQL} WHERE ${range}${sf.clause}`, params),
      db.query(
        `SELECT
           date_trunc('day', e.ts)::date AS day,
           COUNT(*) AS total,
           COUNT(e.user_pseudonym) AS attributed
         FROM events e
         WHERE ${range}${sf.clause}
         GROUP BY date_trunc('day', e.ts)::date
         ORDER BY 1`,
        params
      ),
      db.query(
        `SELECT
           e.tool,
           COUNT(*) AS total,
           COUNT(e.user_pseudonym) AS attributed
         FROM events e
         WHERE ${range}${sf.clause}
         GROUP BY e.tool
         ORDER BY (COUNT(*) - COUNT(e.user_pseudonym)) DESC, COUNT(*) DESC`,
        params
      ),
      db.query(
        `SELECT
           e.host_ref,
           COUNT(*) AS total,
           COUNT(e.user_pseudonym) AS attributed
         FROM events e
         WHERE ${range}${sf.clause}
         GROUP BY e.host_ref
         ORDER BY (COUNT(*) - COUNT(e.user_pseudonym)) DESC, COUNT(*) DESC
         LIMIT 50`,
        params
      ),
    ]);
    const t = totals.rows[0];
    const p = prior.rows[0] ?? {};
    const toolRows = tools.rows.map((r) => ({
      tool: r.tool,
      sanctioned: isSanctioned(r.tool),
      users: num(r.users),
      hosts: num(r.hosts),
      sessions: num(r.sessions),
      proxyEvents: num(r.proxy_events),
      endpointEvents: num(r.endpoint_events),
      tokens: num(r.tokens),
      costUsd: num(r.cost),
      firstSeen: r.first_seen,
    }));
    // CSV export: the on-screen "Tools in use" table, verbatim.
    if (wantsCsv(req)) {
      return sendCsv(reply, `aim-overview-tools-${days}d.csv`, TOOLS_CSV_COLS, toolRows);
    }
    const lastVerifiedAt = new Date().toISOString();
    const windowSeconds = days * 24 * 60 * 60;
    const attRow = attrTotals.rows[0] ?? {};
    const evaluated = evaluateAttribution({
      total: attRow.total ?? 0,
      attributed: attRow.attributed ?? 0,
      service: attRow.service_attributed ?? 0,
      windowSeconds,
    });
    const overallRate = attributionRate(attRow.total ?? 0, attRow.attributed ?? 0);
    return {
      rangeDays: days,
      source: sf.param ?? 'all',
      // auditability: when this response's coverage numbers were
      // verified end-to-end against the event store.
      lastVerifiedAt,
      totals: {
        activeUsers: num(t.active_users),
        activeHosts: num(t.active_hosts),
        sessions: num(t.sessions),
        events: num(t.events),
        tokensInput: num(t.tokens_input),
        tokensOutput: num(t.tokens_output),
        costUsd: num(t.cost),
      },
      // Same shape as `totals`, over the window immediately before it. The UI
      // renders "no prior data" rather than a delta when this is all zero, so a
      // freshly-enrolled pilot never shows a fabricated +100%.
      previousTotals: {
        activeUsers: num(p.active_users),
        activeHosts: num(p.active_hosts),
        sessions: num(p.sessions),
        events: num(p.events),
        tokensInput: num(p.tokens_input),
        tokensOutput: num(p.tokens_output),
        costUsd: num(p.cost),
      },
      tools: toolRows,
      trend: trend.rows.map((r) => ({
        day: r.day,
        activeUsers: num(r.active_users),
        activeHosts: num(r.active_hosts),
        sessions: num(r.sessions),
        tokens: num(r.tokens),
        costUsd: num(r.cost),
      })),
      // First-class identity coverage. Threshold matches the
      // pipeline/system-status alert (ATTRIBUTION_TARGET_PCT).
      attribution: {
        lastVerifiedAt,
        windowDays: days,
        windowSeconds,
        targetPct: ATTRIBUTION_TARGET_PCT,
        status: evaluated.status,
        message: evaluated.message,
        ...overallRate,
        serviceAttributedEvents: evaluated.serviceAttributedEvents,
        humanAttributedEvents: evaluated.humanAttributedEvents,
        alert: evaluated.status === 'degraded' || evaluated.status === 'none_attributed',
        trend: attrTrend.rows.map((r) => {
          const rate = attributionRate(r.total, r.attributed);
          return {
            day: r.day,
            ...rate,
          };
        }),
        byTool: attrByTool.rows.map((r) => ({
          tool: r.tool,
          ...attributionRate(r.total, r.attributed),
        })),
        byHost: attrByHost.rows.map((r) => ({
          hostRef: r.host_ref,
          ...attributionRate(r.total, r.attributed),
        })),
      },
      sanctionedTools,
    };
  });

  // ---- org-level provider view: volumes by AI provider,
  // filterable by collection path (proxy = network, endpoint = device agent).
  // This is the day-1 pilot view: it works with proxy-only data, no endpoint
  // agent and no identity resolution required.
  fastify.get('/api/providers', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const days = parseDays(req.query);
    const sf = sourceFilter(req.query, 2);
    const params = sf.param ? [days, sf.param] : [days];
    const range = `e.ts >= now() - ($1 || ' days')::interval`;
    const [byProvider, bySource, trend] = await Promise.all([
      db.query(
        `SELECT
           COALESCE(e.provider, 'unknown') AS provider,
           COUNT(*)                    AS events,
           COUNT(DISTINCT e.tool)      AS tools,
           COUNT(DISTINCT e.session_id) AS sessions,
           COUNT(DISTINCT e.host_ref)  AS hosts,
           COUNT(DISTINCT e.user_ref)  AS users,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           COALESCE(SUM(${COST_SQL}),0) AS cost,
           MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen
         FROM events e
         WHERE ${range}${sf.clause}
         GROUP BY 1 ORDER BY events DESC`,
        params
      ),
      db.query(
        `SELECT
           e.source,
           COUNT(*)                    AS events,
           COUNT(DISTINCT e.provider)  AS providers,
           COUNT(DISTINCT e.session_id) AS sessions,
           COUNT(DISTINCT e.host_ref)  AS hosts,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           COALESCE(SUM(${COST_SQL}),0) AS cost
         FROM events e
         WHERE ${range}
         GROUP BY e.source ORDER BY e.source`,
        [days]
      ),
      db.query(
        `SELECT
           date_trunc('day', e.ts)::date AS day,
           COALESCE(e.provider, 'unknown') AS provider,
           COUNT(*) AS events,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens
         FROM events e
         WHERE ${range}${sf.clause}
         GROUP BY 1, 2 ORDER BY 1`,
        params
      ),
    ]);
    const providerRows = byProvider.rows.map((r) => ({
      provider: r.provider,
      events: num(r.events),
      tools: num(r.tools),
      sessions: num(r.sessions),
      hosts: num(r.hosts),
      users: num(r.users),
      tokens: num(r.tokens),
      costUsd: num(r.cost),
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
    }));
    if (wantsCsv(req)) {
      return sendCsv(reply, `aim-providers-${days}d.csv`, PROVIDERS_CSV_COLS, providerRows);
    }
    return {
      rangeDays: days,
      source: sf.param ?? 'all',
      providers: providerRows,
      // Per-path totals are never source-filtered: the split proxy vs endpoint
      // is the point of the view (network-path visibility without agents).
      bySource: bySource.rows.map((r) => ({
        source: r.source,
        events: num(r.events),
        providers: num(r.providers),
        sessions: num(r.sessions),
        hosts: num(r.hosts),
        tokens: num(r.tokens),
        costUsd: num(r.cost),
      })),
      trend: trend.rows.map((r) => ({ day: r.day, provider: r.provider, events: num(r.events), tokens: num(r.tokens) })),
    };
  });

  // ---- app-LLM view (approved phase 1) ----
  // Provider-API metering with source-class attribution: which company
  // applications vs employee tools call OpenAI/Anthropic/Azure/OpenRouter,
  // with volume (bytes), status mix, and time patterns. Metadata only — no
  // tokens/models at the network path (phase 2 / OTel covers those).
  // The provider set mirrors the `provider-api` rules in
  // collectors/proxy/endpoints.json (catalogue: OpenAI/
  // Anthropic/Azure OpenAI/Bedrock/Vertex+Gemini API/Mistral/Cohere/Groq/
  // xAI/OpenRouter/Moonshot/Together/Fireworks). traffic_class is NULL on
  // events predating schema v1.4 and on endpoint/otel events — bucketed as
  // 'unknown' here, which matches the collector's fail-safe semantics.
  fastify.get('/api/app-llm', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const days = parseDays(req.query);
    const range = `e.ts >= now() - ($1 || ' days')::interval`;
    const scope = `e.source = 'proxy' AND e.provider = ANY($2)`;
    const [byProviderClass, trend, newSources] = await Promise.all([
      db.query(
        `SELECT
           e.provider,
           COALESCE(e.traffic_class, 'unknown') AS traffic_class,
           COUNT(*) AS events,
           COUNT(DISTINCT e.host_ref) AS hosts,
           COUNT(DISTINCT e.session_id) AS sessions,
           COALESCE(SUM(e.bytes_up),0) AS bytes_up,
           COALESCE(SUM(e.bytes_down),0) AS bytes_down,
           COUNT(*) FILTER (WHERE e.http_status BETWEEN 200 AND 299) AS status_2xx,
           COUNT(*) FILTER (WHERE e.http_status BETWEEN 400 AND 499) AS status_4xx,
           COUNT(*) FILTER (WHERE e.http_status >= 500) AS status_5xx,
           MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen
         FROM events e
         WHERE ${range} AND ${scope}
         GROUP BY 1, 2
         ORDER BY 1, 2`,
        [days, [...PROVIDER_API_PROVIDERS]]
      ),
      db.query(
        `SELECT
           date_trunc('day', e.ts)::date AS day,
           e.provider,
           COALESCE(e.traffic_class, 'unknown') AS traffic_class,
           COUNT(*) AS events,
           COALESCE(SUM(e.bytes_down),0) AS bytes_down
         FROM events e
         WHERE ${range} AND ${scope}
         GROUP BY 1, 2, 3
         ORDER BY 1`,
        [days, [...PROVIDER_API_PROVIDERS]]
      ),
      // Key signal: a source whose FIRST-EVER provider-API call
      // falls inside the window — shadow-AI in built software. host_ref is a
      // pseudonym; the security group pivots on it via existing workflows.
      db.query(
        `SELECT host_ref, provider, first_seen FROM (
           SELECT e.host_ref, e.provider, MIN(e.ts) AS first_seen
           FROM events e
           WHERE ${scope}
           GROUP BY 1, 2
         ) f
         WHERE f.first_seen >= now() - ($1 || ' days')::interval
         ORDER BY first_seen DESC
         LIMIT 50`,
        [days, [...PROVIDER_API_PROVIDERS]]
      ),
    ]);
    const rows = byProviderClass.rows.map((r) => ({
      provider: r.provider,
      trafficClass: r.traffic_class,
      events: num(r.events),
      hosts: num(r.hosts),
      sessions: num(r.sessions),
      bytesUp: num(r.bytes_up),
      bytesDown: num(r.bytes_down),
      status2xx: num(r.status_2xx),
      status4xx: num(r.status_4xx),
      status5xx: num(r.status_5xx),
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
    }));
    if (wantsCsv(req)) {
      return sendCsv(reply, `aim-app-llm-${days}d.csv`, APP_LLM_CSV_COLS, rows);
    }
    return {
      rangeDays: days,
      note: 'Proxy-path provider-API metering (metadata only: volume/bytes/status — no tokens, models, or content). traffic_class=unknown covers events predating subnet attribution; application-classified sources are company software, not employee tools.',
      providers: [...PROVIDER_API_PROVIDERS],
      byProviderClass: rows,
      trend: trend.rows.map((r) => ({
        day: r.day,
        provider: r.provider,
        trafficClass: r.traffic_class,
        events: num(r.events),
        bytesDown: num(r.bytes_down),
      })),
      newSources: newSources.rows.map((r) => ({
        hostRef: r.host_ref,
        provider: r.provider,
        firstSeen: r.first_seen,
      })),
    };
  });

  // ---- per-team breakdown: usage, cost, sanctioned vs unsanctioned ----
  // Team attribution comes from ingest-time identity enrichment;
  // events without a resolved identity bucket into '(unattributed)'. Display
  // names come from team_aliases — the attribution key stays stable
  // in drill-down URLs; renames never rewrite historical events.
  fastify.get('/api/teams', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const days = parseDays(req.query);
    const sanctionedTools = await listSanctionedToolNames(db);
    const [{ rows }, aliasesRes, attrRes] = await Promise.all([
      db.query(
        `SELECT
           COALESCE(e.team, '(unattributed)') AS team,
           COUNT(DISTINCT e.user_ref)  AS active_users,
           COUNT(DISTINCT e.host_ref)  AS active_hosts,
           COUNT(DISTINCT e.session_id) AS sessions,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           COALESCE(SUM(${COST_SQL}),0) AS cost,
           COUNT(DISTINCT e.tool) FILTER (WHERE e.tool = ANY($2)) AS sanctioned_tool_count,
           COUNT(DISTINCT e.tool) FILTER (WHERE NOT (e.tool = ANY($2))) AS unsanctioned_tool_count,
           COUNT(*) FILTER (WHERE NOT (e.tool = ANY($2))) AS unsanctioned_events
         FROM events e
         WHERE e.ts >= now() - ($1 || ' days')::interval
           -- genai_app (v1.3) is app/service telemetry, not employee usage.
           AND e.tool <> 'genai_app'
         GROUP BY COALESCE(e.team, '(unattributed)')
         ORDER BY cost DESC`,
        [days, sanctionedTools]
      ),
      db.query('SELECT team_key, display_name, updated_by, updated_at FROM team_aliases').catch(() => ({ rows: [] })),
      db.query(
        `SELECT
           COUNT(*) AS events,
           COUNT(*) FILTER (WHERE e.team IS NULL) AS unattributed
         FROM events e
         WHERE e.ts >= now() - ($1 || ' days')::interval
           AND e.tool <> 'genai_app'`,
        [days]
      ).catch(() => ({ rows: [{ events: 0, unattributed: 0 }] })),
    ]);
    const aliases = new Map((aliasesRes.rows ?? []).map((a) => [a.team_key, a]));
    const teamRows = rows.map((r) => {
      const alias = aliases.get(r.team);
      return {
        team: r.team,
        displayName: alias?.display_name ?? r.team,
        renamed: Boolean(alias),
        activeUsers: num(r.active_users),
        activeHosts: num(r.active_hosts),
        sessions: num(r.sessions),
        tokens: num(r.tokens),
        costUsd: num(r.cost),
        sanctionedToolCount: num(r.sanctioned_tool_count),
        unsanctionedToolCount: num(r.unsanctioned_tool_count),
        unsanctionedEvents: num(r.unsanctioned_events),
      };
    });
    if (wantsCsv(req)) {
      // Export keeps the stable attribution key; display names are operator-only.
      return sendCsv(reply, `aim-teams-${days}d.csv`, TEAMS_CSV_COLS, teamRows);
    }
    const events = num(attrRes.rows[0]?.events);
    const unattributed = num(attrRes.rows[0]?.unattributed);
    const unattributedPct = events > 0 ? Math.round((1000 * unattributed) / events) / 10 : 0;
    return {
      rangeDays: days,
      note: 'Team attribution requires identity resolution; unresolved events bucket into (unattributed). Display names are operator aliases and do not rewrite event history.',
      attribution: {
        events,
        unattributed,
        unattributedPct,
        // device_mappings lives in identity-sync, not the event store. A high
        // unattributed share is the dashboard-side signal that mapping is thin.
        warning: unattributedPct >= 50
          ? 'More than half of events in range have no team. Check identity-sync directory coverage and device_mappings (0 mapped devices yields seed/unattributed buckets that look hard-coded).'
          : null,
      },
      canManage: hasRole(req, 'admin'),
      teams: teamRows,
    };
  });

  // ---- team detail + members ----
  // Members are pseudonyms observed on events in range, with optional
  // team_member_overrides applied for display. Overrides never rewrite events.
  fastify.get('/api/teams/:team', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const teamKey = String(req.params.team ?? '');
    if (!teamKey || teamKey.length > 256) {
      return reply.code(400).send({ error: 'bad_request', detail: 'team key required (max 256 chars)' });
    }
    const days = parseDays(req.query);
    const teamFilter = teamKey === '(unattributed)'
      ? 'e.team IS NULL'
      : 'e.team = $2';
    const params = teamKey === '(unattributed)' ? [days] : [days, teamKey];
    const [summary, members, aliasRes, overridesRes, auditRes] = await Promise.all([
      db.query(
        `SELECT
           COUNT(DISTINCT e.user_ref)  AS active_users,
           COUNT(DISTINCT e.host_ref)  AS active_hosts,
           COUNT(DISTINCT e.session_id) AS sessions,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           COALESCE(SUM(${COST_SQL}),0) AS cost,
           COUNT(DISTINCT e.tool) FILTER (WHERE e.tool = ANY($${params.length + 1})) AS sanctioned_tool_count,
           COUNT(DISTINCT e.tool) FILTER (WHERE NOT (e.tool = ANY($${params.length + 1}))) AS unsanctioned_tool_count,
           COUNT(*) FILTER (WHERE NOT (e.tool = ANY($${params.length + 1}))) AS unsanctioned_events
         FROM events e
         WHERE e.ts >= now() - ($1 || ' days')::interval
           AND e.tool <> 'genai_app'
           AND ${teamFilter}`,
        [...params, await listSanctionedToolNames(db)]
      ),
      db.query(
        `SELECT
           COALESCE(e.user_pseudonym, e.user_ref) AS pseudonym,
           COUNT(DISTINCT e.session_id) AS sessions,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           MAX(e.ts) AS last_active
         FROM events e
         WHERE e.ts >= now() - ($1 || ' days')::interval
           AND e.tool <> 'genai_app'
           AND ${teamFilter}
           AND COALESCE(e.user_pseudonym, e.user_ref) IS NOT NULL
         GROUP BY 1
         ORDER BY tokens DESC
         LIMIT 200`,
        params
      ),
      db.query('SELECT team_key, display_name, updated_by, updated_at FROM team_aliases WHERE team_key = $1', [teamKey])
        .catch(() => ({ rows: [] })),
      db.query(
        `SELECT o.pseudonym, o.team_key, o.updated_by, o.updated_at
         FROM team_member_overrides o
         WHERE o.team_key = $1
         ORDER BY o.updated_at DESC
         LIMIT 200`,
        [teamKey]
      ).catch(() => ({ rows: [] })),
      db.query(
        `SELECT id, ts, actor, action, team_key, detail
         FROM team_identity_audit
         WHERE team_key = $1
         ORDER BY ts DESC
         LIMIT 50`,
        [teamKey]
      ).catch(() => ({ rows: [] })),
    ]);
    const s = summary.rows[0] ?? {};
    const alias = aliasRes.rows[0] ?? null;
    const memberRows = members.rows.map((r) => ({
      pseudonym: r.pseudonym,
      sessions: num(r.sessions),
      tokens: num(r.tokens),
      lastActive: r.last_active,
      source: 'events',
    }));
    // Overrides assigned TO this team that have no event activity in-range still show up.
    const seen = new Set(memberRows.map((m) => m.pseudonym));
    for (const o of overridesRes.rows ?? []) {
      if (seen.has(o.pseudonym)) {
        const m = memberRows.find((x) => x.pseudonym === o.pseudonym);
        if (m) m.source = 'events+override';
        continue;
      }
      memberRows.push({
        pseudonym: o.pseudonym,
        sessions: 0,
        tokens: 0,
        lastActive: o.updated_at,
        source: 'override',
      });
    }
    if (num(s.active_users) === 0 && memberRows.length === 0 && !alias) {
      return reply.code(404).send({ error: 'not_found', detail: `no team '${teamKey}' in the last ${days} days` });
    }
    return {
      team: teamKey,
      displayName: alias?.display_name ?? teamKey,
      renamed: Boolean(alias),
      alias: alias
        ? { displayName: alias.display_name, updatedBy: alias.updated_by, updatedAt: alias.updated_at }
        : null,
      rangeDays: days,
      canManage: hasRole(req, 'admin'),
      summary: {
        activeUsers: num(s.active_users),
        activeHosts: num(s.active_hosts),
        sessions: num(s.sessions),
        tokens: num(s.tokens),
        costUsd: num(s.cost),
        sanctionedToolCount: num(s.sanctioned_tool_count),
        unsanctionedToolCount: num(s.unsanctioned_tool_count),
        unsanctionedEvents: num(s.unsanctioned_events),
      },
      members: memberRows,
      audit: (auditRes.rows ?? []).map((r) => ({
        id: num(r.id),
        ts: r.ts,
        actor: r.actor,
        action: r.action,
        teamKey: r.team_key,
        detail: r.detail ?? {},
      })),
    };
  });

  // ---- rename a team (display alias only; attribution key stays stable) ----
  fastify.put('/api/teams/:team/name', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const teamKey = String(req.params.team ?? '');
    if (!teamKey || teamKey.length > 256) {
      return reply.code(400).send({ error: 'bad_request', detail: 'team key required (max 256 chars)' });
    }
    if (teamKey === '(unattributed)') {
      return reply.code(400).send({ error: 'bad_request', detail: 'cannot rename the (unattributed) bucket — fix device_mappings instead' });
    }
    const displayName = req.body?.displayName ?? req.body?.name ?? null;
    if (displayName !== null && (typeof displayName !== 'string' || displayName.trim().length === 0 || displayName.length > 200)) {
      return reply.code(400).send({ error: 'bad_request', detail: 'displayName must be a non-empty string (max 200 chars) or null to clear' });
    }
    const actor = req.identity?.email ?? 'unknown';
    if (displayName === null) {
      await db.query('DELETE FROM team_aliases WHERE team_key = $1', [teamKey]);
      await db.query(
        `INSERT INTO team_identity_audit (actor, action, team_key, detail) VALUES ($1, 'team.rename.clear', $2, $3::jsonb)`,
        [actor, teamKey, JSON.stringify({})]
      ).catch(() => null);
      audit(actor, 'team.rename.clear', `teams/${teamKey}`);
      return { team: teamKey, displayName: teamKey, renamed: false };
    }
    const trimmed = displayName.trim();
    await db.query(
      `INSERT INTO team_aliases (team_key, display_name, updated_by) VALUES ($1, $2, $3)
       ON CONFLICT (team_key) DO UPDATE
         SET display_name = EXCLUDED.display_name, updated_by = EXCLUDED.updated_by, updated_at = now()`,
      [teamKey, trimmed, actor]
    );
    await db.query(
      `INSERT INTO team_identity_audit (actor, action, team_key, detail) VALUES ($1, 'team.rename', $2, $3::jsonb)`,
      [actor, teamKey, JSON.stringify({ displayName: trimmed })]
    ).catch(() => null);
    audit(actor, 'team.rename', `teams/${teamKey}`, { displayName: trimmed });
    return { team: teamKey, displayName: trimmed, renamed: true };
  });

  // ---- assign/move a pseudonym to a team (override; no event rewrite) ----
  fastify.put('/api/teams/members/:pseudonym', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const pseudonym = String(req.params.pseudonym ?? '');
    if (!pseudonym || pseudonym.length > 256) {
      return reply.code(400).send({ error: 'bad_request', detail: 'pseudonym required (max 256 chars)' });
    }
    const teamKey = req.body?.team ?? req.body?.teamKey;
    if (typeof teamKey !== 'string' || teamKey.trim().length === 0 || teamKey.length > 256) {
      return reply.code(400).send({ error: 'bad_request', detail: 'body.team must be a non-empty team key (max 256 chars)' });
    }
    if (teamKey === '(unattributed)') {
      return reply.code(400).send({ error: 'bad_request', detail: 'assign to a real team key; clear the override to fall back to event attribution' });
    }
    const actor = req.identity?.email ?? 'unknown';
    const key = teamKey.trim();
    await db.query(
      `INSERT INTO team_member_overrides (pseudonym, team_key, updated_by) VALUES ($1, $2, $3)
       ON CONFLICT (pseudonym) DO UPDATE
         SET team_key = EXCLUDED.team_key, updated_by = EXCLUDED.updated_by, updated_at = now()`,
      [pseudonym, key, actor]
    );
    await db.query(
      `INSERT INTO team_identity_audit (actor, action, team_key, detail) VALUES ($1, 'team.member.assign', $2, $3::jsonb)`,
      [actor, key, JSON.stringify({ pseudonym })]
    ).catch(() => null);
    audit(actor, 'team.member.assign', `teams/${key}`, { pseudonym });
    return { pseudonym, team: key };
  });

  fastify.delete('/api/teams/members/:pseudonym', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const pseudonym = String(req.params.pseudonym ?? '');
    if (!pseudonym || pseudonym.length > 256) {
      return reply.code(400).send({ error: 'bad_request', detail: 'pseudonym required (max 256 chars)' });
    }
    const actor = req.identity?.email ?? 'unknown';
    const { rows } = await db.query(
      'DELETE FROM team_member_overrides WHERE pseudonym = $1 RETURNING team_key',
      [pseudonym]
    );
    const prev = rows[0]?.team_key ?? null;
    if (prev) {
      await db.query(
        `INSERT INTO team_identity_audit (actor, action, team_key, detail) VALUES ($1, 'team.member.clear', $2, $3::jsonb)`,
        [actor, prev, JSON.stringify({ pseudonym })]
      ).catch(() => null);
      audit(actor, 'team.member.clear', `teams/${prev}`, { pseudonym });
    }
    return { pseudonym, team: null, cleared: Boolean(prev) };
  });

  // ---- tools list: clickable inventory with metadata, no dead-end rows ----
  fastify.get('/api/tools', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const days = parseDays(req.query);
    const sanctionedTools = await listSanctionedToolNames(db);
    const { rows } = await db.query(
      `SELECT
         e.tool,
         COUNT(DISTINCT e.user_ref)  AS users,
         COUNT(DISTINCT e.host_ref)  AS hosts,
         COUNT(DISTINCT e.session_id) AS sessions,
         COUNT(*) FILTER (WHERE e.source = 'proxy')    AS proxy_events,
         COUNT(*) FILTER (WHERE e.source = 'endpoint') AS endpoint_events,
         COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
         COALESCE(SUM(${COST_SQL}),0) AS cost,
         MIN(e.ts) AS first_seen,
         MAX(e.ts) AS last_seen,
         (ARRAY_AGG(e.tool_version ORDER BY e.ts DESC)
            FILTER (WHERE e.tool_version IS NOT NULL))[1] AS latest_version,
         COUNT(DISTINCT e.tool_version) FILTER (WHERE e.tool_version IS NOT NULL) AS version_count
       FROM events e
       WHERE e.ts >= now() - ($1 || ' days')::interval
         AND e.tool <> 'genai_app'
       GROUP BY e.tool
       ORDER BY tokens DESC`,
      [days]
    );
    const toolRows = rows.map((r) => ({
      tool: r.tool,
      sanctioned: isSanctioned(r.tool),
      users: num(r.users),
      hosts: num(r.hosts),
      sessions: num(r.sessions),
      proxyEvents: num(r.proxy_events),
      endpointEvents: num(r.endpoint_events),
      tokens: num(r.tokens),
      costUsd: num(r.cost),
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
      latestVersion: r.latest_version ?? null,
      versionCount: num(r.version_count),
    }));
    if (wantsCsv(req)) {
      return sendCsv(reply, `aim-tools-${days}d.csv`, [
        ...TOOLS_CSV_COLS,
        { key: 'lastSeen', label: 'last_seen' },
        { key: 'latestVersion', label: 'latest_version' },
      ], toolRows);
    }
    return { rangeDays: days, tools: toolRows, sanctionedTools };
  });

  // ---- tool detail: models, token volumes, session counts, versions ----
  fastify.get('/api/tools/:tool', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const days = parseDays(req.query);
    const tool = req.params.tool;
    await listSanctionedToolNames(db); // keep isSanctioned current
    const [summary, models, trend, versions] = await Promise.all([
      db.query(
        `SELECT
           COUNT(DISTINCT user_ref)  AS users,
           COUNT(DISTINCT host_ref)  AS hosts,
           COUNT(DISTINCT session_id) AS sessions,
           COUNT(*)                  AS events,
           COALESCE(SUM(tokens_in),0)  AS tokens_input,
           COALESCE(SUM(tokens_out),0) AS tokens_output,
           COALESCE(SUM(${COST_SQL}),0) AS cost,
           MIN(ts) AS first_seen, MAX(ts) AS last_seen
         FROM events WHERE tool = $1 AND ts >= now() - ($2 || ' days')::interval`,
        [tool, days]
      ),
      db.query(
        `SELECT model,
           COUNT(*) AS events,
           COALESCE(SUM(tokens_in),0)  AS tokens_input,
           COALESCE(SUM(tokens_out),0) AS tokens_output,
           COALESCE(SUM(${COST_SQL}),0) AS cost
         FROM events
         WHERE tool = $1 AND model IS NOT NULL AND ts >= now() - ($2 || ' days')::interval
         GROUP BY model ORDER BY tokens_output DESC`,
        [tool, days]
      ),
      db.query(
        `SELECT date_trunc('day', ts)::date AS day,
           COUNT(DISTINCT user_ref)  AS active_users,
           COUNT(DISTINCT session_id) AS sessions,
           COALESCE(SUM(tokens_in + tokens_out),0) AS tokens
         FROM events WHERE tool = $1 AND ts >= now() - ($2 || ' days')::interval
         GROUP BY 1 ORDER BY 1`,
        [tool, days]
      ),
      db.query(
        `SELECT tool_version AS version,
           COUNT(*) AS events,
           COUNT(DISTINCT host_ref) AS hosts,
           MAX(ts) AS last_seen
         FROM events
         WHERE tool = $1
           AND tool_version IS NOT NULL
           AND ts >= now() - ($2 || ' days')::interval
         GROUP BY tool_version
         ORDER BY last_seen DESC
         LIMIT 20`,
        [tool, days]
      ),
    ]);
    const s = summary.rows[0];
    const modelRows = models.rows.map((m) => ({
      model: m.model,
      events: num(m.events),
      tokensInput: num(m.tokens_input),
      tokensOutput: num(m.tokens_output),
      costUsd: num(m.cost),
    }));
    if (wantsCsv(req)) {
      return sendCsv(reply, `aim-tool-${tool}-models-${days}d.csv`, MODELS_CSV_COLS, modelRows);
    }
    return {
      tool,
      sanctioned: isSanctioned(tool),
      rangeDays: days,
      users: num(s.users),
      hosts: num(s.hosts),
      sessions: num(s.sessions),
      events: num(s.events),
      tokensInput: num(s.tokens_input),
      tokensOutput: num(s.tokens_output),
      costUsd: num(s.cost),
      firstSeen: s.first_seen,
      lastSeen: s.last_seen,
      latestVersion: versions.rows[0]?.version ?? null,
      versions: versions.rows.map((r) => ({
        version: r.version,
        events: num(r.events),
        hosts: num(r.hosts),
        lastSeen: r.last_seen,
      })),
      models: modelRows,
      trend: trend.rows.map((r) => ({ day: r.day, activeUsers: num(r.active_users), sessions: num(r.sessions), tokens: num(r.tokens) })),
    };
  });

  // ---- unapproved-tool discovery: new/unsanctioned tools on the network ----
  // Deliberately shows counts only, NOT user pseudonyms (privacy gate).
  // Grouped by tool_raw when present: network-path events carry tool='other'
  // with the detected tool name in tool_raw (collector contract), so
  // grouping by tool alone would collapse every unsanctioned tool into one row.
  fastify.get('/api/unapproved', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const days = parseDays(req.query, 90);
    const sanctionedTools = await listSanctionedToolNames(db);
    const { rows } = await db.query(
      `SELECT
         COALESCE(e.tool_raw, e.tool) AS tool,
         MIN(e.provider) AS provider,
         MIN(e.ts)  AS first_seen,
         MAX(e.ts)  AS last_seen,
         COUNT(*)   AS events,
         COUNT(DISTINCT e.user_ref)  AS users,
         COUNT(DISTINCT e.host_ref)  AS hosts,
         COUNT(DISTINCT e.session_id) AS sessions,
         COUNT(DISTINCT e.team)      AS teams,
         COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
         COALESCE(SUM(${COST_SQL}),0) AS cost
       FROM events e
       WHERE NOT (e.tool = ANY($2))
         -- genai_app (v1.3) is first-party app telemetry, not an employee
         -- tool; it has its own view (/api/apps/llm) and must not show up
         -- here as an "unapproved tool".
         AND e.tool <> 'genai_app'
         AND e.ts >= now() - ($1 || ' days')::interval
       GROUP BY 1
       ORDER BY first_seen DESC`,
      [days, sanctionedTools]
    );
    const unapprovedRows = rows.map((r) => ({
      tool: r.tool,
      provider: r.provider,
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
      events: num(r.events),
      users: num(r.users),
      hosts: num(r.hosts),
      teams: num(r.teams),
      sessions: num(r.sessions),
      tokens: num(r.tokens),
      costUsd: num(r.cost),
    }));
    if (wantsCsv(req)) {
      return sendCsv(reply, `aim-unapproved-tools-${days}d.csv`, UNAPPROVED_CSV_COLS, unapprovedRows);
    }
    return {
      rangeDays: days,
      note: 'User identities withheld at this level; use /api/users (security group) for attribution.',
      unapproved: unapprovedRows,
    };
  });

  // ---- guardrail match flags by detector (security view) ----
  // Aggregate counts only — no user attribution here (privacy gate); matched
  // content is never stored by design. match_flags entries are objects
  // ({detector, category, severity}); the detector id looks like
  // 'secret:aws-access-key'. Empty array = detectors ran and nothing fired.
  fastify.get('/api/flags', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const days = parseDays(req.query, 30);
    /*: optional detector drill-down for the Security detail panel.
       Aggregate list stays anyRole; per-user rows stay analyst+ (same bar as
       /api/users). Matched content is never returned — only refs + counts. */
    const detectorFilter = typeof req.query?.detector === 'string' ? req.query.detector.trim() : '';
    if (detectorFilter && detectorFilter.length > 200) {
      return reply.code(400).send({ error: 'bad_request', detail: 'detector must be ≤200 chars' });
    }
    const [byDetector, trend, byTool] = await Promise.all([
      db.query(
        /* severity_rank: the WORST severity ever recorded for this detector in
           the window, not an average — a detector that fired 'critical' once
           must not be softened by a hundred 'low' hits. Severity is optional
           in the event schema, so 0 means "no event carried one" and
           the client falls back to a category default rather than inventing a
           measured-looking value. */
        `SELECT flag ->> 'detector' AS detector,
           COUNT(*)                    AS hits,
           COUNT(DISTINCT e.user_ref)  AS users,
           COUNT(DISTINCT e.tool)      AS tools,
           MAX(CASE flag ->> 'severity'
                 WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                 WHEN 'medium'   THEN 2 WHEN 'low'  THEN 1
                 ELSE 0 END)           AS severity_rank,
           MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen
         FROM events e, LATERAL jsonb_array_elements(e.match_flags) AS flag
         WHERE e.ts >= now() - ($1 || ' days')::interval
         GROUP BY 1 ORDER BY hits DESC`,
        [days]
      ),
      db.query(
        `SELECT date_trunc('day', e.ts)::date AS day, flag ->> 'detector' AS detector, COUNT(*) AS hits
         FROM events e, LATERAL jsonb_array_elements(e.match_flags) AS flag
         WHERE e.ts >= now() - ($1 || ' days')::interval
         GROUP BY 1, 2 ORDER BY 1`,
        [days]
      ),
      db.query(
        `SELECT e.tool, flag ->> 'detector' AS detector, COUNT(*) AS hits
         FROM events e, LATERAL jsonb_array_elements(e.match_flags) AS flag
         WHERE e.ts >= now() - ($1 || ' days')::interval
         GROUP BY 1, 2 ORDER BY 1, hits DESC`,
        [days]
      ),
    ]);
    const mapDetector = (r) => {
      const category = String(r.detector).split(':')[0];
      const rank = num(r.severity_rank);
      return {
        detector: r.detector,
        category,
        hits: num(r.hits),
        users: num(r.users),
        tools: num(r.tools),
        severity: rank > 0 ? SEVERITY_BY_RANK[rank] : CATEGORY_SEVERITY[category] ?? 'medium',
        /* Whether the severity was reported by the detector or defaulted from
           the category. The UI marks defaults so nobody reads one as measured. */
        severitySource: rank > 0 ? 'reported' : 'category-default',
        firstSeen: r.first_seen,
        lastSeen: r.last_seen,
      };
    };
    const detectorRows = byDetector.rows.map(mapDetector);
    if (wantsCsv(req)) {
      return sendCsv(reply, `aim-flags-${days}d.csv`, FLAGS_CSV_COLS, detectorRows);
    }
    const list = {
      rangeDays: days,
      totalHits: detectorRows.reduce((a, r) => a + r.hits, 0),
      detectors: detectorRows,
      trend: trend.rows.map((r) => ({ day: r.day, detector: r.detector, hits: num(r.hits) })),
      byTool: byTool.rows.map((r) => ({ tool: r.tool, detector: r.detector, hits: num(r.hits) })),
    };
    if (!detectorFilter) return list;

    const showUsers = canSeeUsers(req);
    const detParams = [days, detectorFilter];
    const detClause = `e.ts >= now() - ($1 || ' days')::interval
         AND flag ->> 'detector' = $2`;
    const [toolsForDet, sessionsForDet, reposForDet, usersForDet] = await Promise.all([
      db.query(
        `SELECT e.tool AS tool, COUNT(*) AS hits
         FROM events e, LATERAL jsonb_array_elements(e.match_flags) AS flag
         WHERE ${detClause}
         GROUP BY 1 ORDER BY hits DESC LIMIT 20`,
        detParams,
      ),
      db.query(
        `SELECT e.session_id AS session_id, e.tool AS tool, COUNT(*) AS hits, MAX(e.ts) AS last_seen
         FROM events e, LATERAL jsonb_array_elements(e.match_flags) AS flag
         WHERE ${detClause} AND e.session_id IS NOT NULL
         GROUP BY 1, 2 ORDER BY hits DESC LIMIT 20`,
        detParams,
      ),
      db.query(
        `SELECT e.repo_ref AS repo_ref, COUNT(*) AS hits, MAX(e.ts) AS last_seen
         FROM events e, LATERAL jsonb_array_elements(e.match_flags) AS flag
         WHERE ${detClause} AND e.repo_ref IS NOT NULL
         GROUP BY 1 ORDER BY hits DESC LIMIT 20`,
        detParams,
      ),
      showUsers
        ? db.query(
          `SELECT COALESCE(e.user_pseudonym, e.user_ref) AS user_ref, COUNT(*) AS hits, MAX(e.ts) AS last_seen
           FROM events e, LATERAL jsonb_array_elements(e.match_flags) AS flag
           WHERE ${detClause} AND e.user_ref IS NOT NULL
           GROUP BY 1 ORDER BY hits DESC LIMIT 20`,
          detParams,
        )
        : Promise.resolve({ rows: [] }),
    ]);
    if (showUsers) {
      audit(req.identity?.email ?? 'unknown', 'flags.detector.detail', detectorFilter, { rangeDays: days });
    }
    const summary = detectorRows.find((d) => d.detector === detectorFilter) ?? null;
    return {
      ...list,
      detail: {
        detector: detectorFilter,
        summary,
        tools: toolsForDet.rows.map((r) => ({ tool: r.tool, hits: num(r.hits) })),
        sessions: sessionsForDet.rows.map((r) => ({
          sessionId: r.session_id,
          tool: r.tool,
          hits: num(r.hits),
          lastSeen: r.last_seen,
        })),
        repos: reposForDet.rows.map((r) => ({
          repo: r.repo_ref,
          hits: num(r.hits),
          lastSeen: r.last_seen,
        })),
        /* null users = withheld by policy (viewer/auditor without user-level).
           Empty array = allowed but no attributed users in the window. */
        users: showUsers
          ? usersForDet.rows.map((r) => ({
            user: r.user_ref,
            hits: num(r.hits),
            lastSeen: r.last_seen,
          }))
          : null,
        usersWithheld: !showUsers,
      },
    };
  });

  // ---- repo-level visibility ----
  // repo_ref is a salted-HMAC pseudonym (schema v1), so per-repo aggregates are
  // the same privacy tier as team/provider views — any authenticated employee.
  // The optional repo_labels mapping (migration 006) is the ONLY
  // de-pseudonymization path: labels are joined in ONLY for the security group
  // and every labeled read is audited. The guardrail restricted-repo-access
  // rule matches these refs engine-side (policies/guardrail/v1/core.yaml).
  fastify.get('/api/repos', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const days = parseDays(req.query);
    const showLabels = canSeeUsers(req);
    const { rows } = await db.query(
      `SELECT
         e.repo_ref,
         COUNT(*) AS events,
         COUNT(DISTINCT e.session_id) AS sessions,
         COUNT(DISTINCT e.tool)       AS tools,
         COUNT(DISTINCT e.user_ref)   AS users,
         COUNT(DISTINCT e.host_ref)   AS hosts,
         COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
         COALESCE(SUM(${COST_SQL}),0) AS cost,
         COALESCE(SUM(jsonb_array_length(e.match_flags)),0) AS flag_hits,
         MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen
         ${showLabels ? ', l.label' : ''}
       FROM events e
       ${showLabels ? 'LEFT JOIN repo_labels l ON l.repo_ref = e.repo_ref' : ''}
       WHERE e.repo_ref IS NOT NULL
         AND e.ts >= now() - ($1 || ' days')::interval
       GROUP BY e.repo_ref${showLabels ? ', l.label' : ''}
       ORDER BY last_seen DESC
       LIMIT 500`,
      [days]
    );
    if (showLabels) {
      audit(req.identity?.email ?? 'unknown', 'repo.labels.view', 'repos', { rangeDays: days });
    }
    const repoRows = rows.map((r) => ({
      repo: r.repo_ref,
      events: num(r.events),
      sessions: num(r.sessions),
      tools: num(r.tools),
      users: num(r.users),
      hosts: num(r.hosts),
      tokens: num(r.tokens),
      costUsd: num(r.cost),
      flagHits: num(r.flag_hits),
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
      ...(showLabels ? { label: r.label ?? null } : {}),
    }));
    if (wantsCsv(req)) {
      // Labels stay out of the CSV layout (REPOS_CSV_COLS) — de-pseudonymized
      // data is an on-screen, audited view, not a bulk export.
      return sendCsv(reply, `aim-repos-${days}d.csv`, REPOS_CSV_COLS, repoRows);
    }
    return {
      rangeDays: days,
      note: 'Repository identifiers are HMAC pseudonyms; labels (if any) are visible to the security group only.',
      repos: repoRows,
    };
  });

  // ---- per-repo drill-down: same gating as /api/repos ----
  fastify.get('/api/repos/:repoRef', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const repoRef = req.params.repoRef;
    if (!/^[0-9a-f]{64}$/.test(repoRef)) {
      return reply.code(400).send({ error: 'bad_request', detail: 'repoRef must be the 64-hex pseudonym from /api/repos' });
    }
    const days = parseDays(req.query);
    const showLabels = canSeeUsers(req);
    const range = `e.ts >= now() - ($2 || ' days')::interval`;
    const [summary, byTool, trend, flags] = await Promise.all([
      db.query(
        `SELECT
           COUNT(*) AS events,
           COUNT(DISTINCT e.session_id) AS sessions,
           COUNT(DISTINCT e.tool)       AS tools,
           COUNT(DISTINCT e.user_ref)   AS users,
           COUNT(DISTINCT e.host_ref)   AS hosts,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           COALESCE(SUM(${COST_SQL}),0) AS cost,
           COALESCE(SUM(jsonb_array_length(e.match_flags)),0) AS flag_hits,
           MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen
         FROM events e
         WHERE e.repo_ref = $1 AND ${range}`,
        [repoRef, days]
      ),
      db.query(
        `SELECT
           e.tool,
           COUNT(*) AS events,
           COUNT(DISTINCT e.session_id) AS sessions,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           COALESCE(SUM(jsonb_array_length(e.match_flags)),0) AS flag_hits,
           MAX(e.ts) AS last_seen
         FROM events e
         WHERE e.repo_ref = $1 AND ${range}
         GROUP BY e.tool ORDER BY tokens DESC`,
        [repoRef, days]
      ),
      db.query(
        `SELECT
           date_trunc('day', e.ts)::date AS day,
           COUNT(*) AS events,
           COUNT(DISTINCT e.session_id) AS sessions,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           COALESCE(SUM(jsonb_array_length(e.match_flags)),0) AS flag_hits
         FROM events e
         WHERE e.repo_ref = $1 AND ${range}
         GROUP BY 1 ORDER BY 1`,
        [repoRef, days]
      ),
      db.query(
        `SELECT flag ->> 'detector' AS detector, COUNT(*) AS hits,
           MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen
         FROM events e, LATERAL jsonb_array_elements(e.match_flags) AS flag
         WHERE e.repo_ref = $1 AND ${range}
         GROUP BY 1 ORDER BY hits DESC`,
        [repoRef, days]
      ),
    ]);
    const s = summary.rows[0];
    if (num(s.events) === 0) {
      return reply.code(404).send({ error: 'not_found', detail: `no activity for repo '${repoRef}' in the last ${days} days` });
    }
    let label = null;
    if (showLabels) {
      const { rows } = await db.query('SELECT l.label FROM repo_labels l WHERE l.repo_ref = $1', [repoRef]);
      label = rows[0]?.label ?? null;
      audit(req.identity?.email ?? 'unknown', 'repo.labels.view', `repos/${repoRef}`, { rangeDays: days });
    }
    return {
      repo: repoRef,
      rangeDays: days,
      ...(showLabels ? { label } : {}),
      summary: {
        events: num(s.events),
        sessions: num(s.sessions),
        tools: num(s.tools),
        users: num(s.users),
        hosts: num(s.hosts),
        tokens: num(s.tokens),
        costUsd: num(s.cost),
        flagHits: num(s.flag_hits),
        firstSeen: s.first_seen,
        lastSeen: s.last_seen,
      },
      byTool: byTool.rows.map((r) => ({
        tool: r.tool,
        events: num(r.events),
        sessions: num(r.sessions),
        tokens: num(r.tokens),
        flagHits: num(r.flag_hits),
        lastSeen: r.last_seen,
      })),
      trend: trend.rows.map((r) => ({
        day: r.day,
        events: num(r.events),
        sessions: num(r.sessions),
        tokens: num(r.tokens),
        flagHits: num(r.flag_hits),
      })),
      flags: flags.rows.map((r) => ({
        detector: r.detector,
        category: String(r.detector).split(':')[0],
        hits: num(r.hits),
        firstSeen: r.first_seen,
        lastSeen: r.last_seen,
      })),
    };
  });

  // ---- repo label mapping: the ONLY de-pseudonymization write path.
  // GATED to admin; every set/remove hits the immutable audit
  // trail. Body: { label: string } to set, { label: null } to remove.
  fastify.put('/api/repos/:repoRef/label', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const repoRef = req.params.repoRef;
    if (!/^[0-9a-f]{64}$/.test(repoRef)) {
      return reply.code(400).send({ error: 'bad_request', detail: 'repoRef must be the 64-hex pseudonym from /api/repos' });
    }
    const label = req.body?.label;
    if (label !== null && (typeof label !== 'string' || label.trim().length === 0 || label.length > 200)) {
      return reply.code(400).send({ error: 'bad_request', detail: 'label must be a non-empty string (max 200 chars) or null to remove' });
    }
    const actor = req.identity?.email ?? 'unknown';
    if (label === null) {
      await db.query('DELETE FROM repo_labels WHERE repo_ref = $1', [repoRef]);
      audit(actor, 'repo.label.remove', `repos/${repoRef}`);
      return { repo: repoRef, label: null };
    }
    const trimmed = label.trim();
    await db.query(
      `INSERT INTO repo_labels (repo_ref, label, created_by) VALUES ($1, $2, $3)
       ON CONFLICT (repo_ref) DO UPDATE SET label = EXCLUDED.label, updated_at = now()`,
      [repoRef, trimmed, actor]
    );
    audit(actor, 'repo.label.set', `repos/${repoRef}`, { label: trimmed });
    return { repo: repoRef, label: trimmed };
  });

  // ---- user-level usage: GATED to the security group (privacy gate) ----
  // Pseudonyms only (user_pseudonym enrichment, else the raw HMAC
  // user_ref). Real identity reveal stays behind identity-sync's role-gated
  // endpoint — the dashboard never joins a cleartext directory.
  //
  // limit/offset + total (path-to-5k). Replaces silent LIMIT 500 with
  // honest pagination. Default page ≤ 100 for JSON/UI; CSV keeps a higher
  // gated export cap. p95 latency budget ≤ 400 ms @ 700 seats / page
  // (docs/frontend-performance-budget.md §4.1; docs/api-read-path-pagination.md).
  fastify.get('/api/users', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const days = parseDays(req.query);
    const csv = wantsCsv(req);
    const limit = parseUsersLimit(req.query, { csv });
    const offset = parseOffset(req.query);
    const userWhere = `e.ts >= now() - ($1 || ' days')::interval
           AND COALESCE(e.user_pseudonym, e.user_ref) IS NOT NULL`;
    const userAgg = `SELECT
           COALESCE(e.user_pseudonym, e.user_ref) AS pseudonym,
           MIN(e.team) AS team,
           COUNT(DISTINCT e.session_id) AS sessions,
           COUNT(DISTINCT e.tool)       AS tools,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           COALESCE(SUM(${COST_SQL}),0) AS cost,
           MAX(e.ts) AS last_active,
           COALESCE(SUM(jsonb_array_length(e.match_flags)),0) AS flag_hits
         FROM events e
         WHERE ${userWhere}
         GROUP BY 1`;
    const [totalRes, { rows }, overridesRes] = await Promise.all([
      db.query(
        `SELECT COUNT(*) AS n FROM (
           SELECT 1
             FROM events e
            WHERE ${userWhere}
            GROUP BY COALESCE(e.user_pseudonym, e.user_ref)
         ) t`,
        [days]
      ),
      db.query(
        `${userAgg}
         ORDER BY tokens DESC
         LIMIT $2 OFFSET $3`,
        [days, limit, offset]
      ),
      db.query('SELECT pseudonym, team_key FROM team_member_overrides').catch(() => ({ rows: [] })),
    ]);
    const total = Number(totalRes.rows[0]?.n ?? 0);
    const overrides = new Map((overridesRes.rows ?? []).map((o) => [o.pseudonym, o.team_key]));
    const userRows = rows.map((r) => {
      const overrideTeam = overrides.get(r.pseudonym) ?? null;
      return {
        pseudonym: r.pseudonym,
        team: overrideTeam ?? r.team,
        teamFromEvents: r.team,
        teamOverride: overrideTeam,
        sessions: num(r.sessions),
        tools: num(r.tools),
        tokens: num(r.tokens),
        costUsd: num(r.cost),
        lastActive: r.last_active,
        flagHits: num(r.flag_hits),
      };
    });
    if (csv) {
      return sendCsv(reply, `aim-users-${days}d.csv`, USERS_CSV_COLS, userRows);
    }
    return {
      rangeDays: days,
      total,
      limit,
      offset,
      truncated: offset + userRows.length < total,
      note: 'Pseudonymous identifiers only; identity reveal is role-gated in identity-sync.',
      users: userRows,
    };
  });

  // ---- per-user drill-down: GATED to the security group, same as
  // /api/users. This is the triage view behind a pseudonym: sessions over time,
  // tools/models, token volume, the match-flag timeline, and linked findings.
  // Findings link via their triggering event's user (findings.subject holds the
  // raw user_ref; the events join also covers user_pseudonym-keyed users).
  // Still metadata-only: detector names, never matched content. Every access
  // (including 403s) hits the global audit hook in server.js.
  fastify.get('/api/users/:pseudonym', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const days = parseDays(req.query);
    const pseudonym = req.params.pseudonym;
    // Resolve by display pseudonym OR raw user_ref: findings.subject carries the
    // raw ref, so finding → user navigation keys on that even when identity
    // enrichment has stamped a user_pseudonym onto the events.
    const who = `(COALESCE(e.user_pseudonym, e.user_ref) = $1 OR e.user_ref = $1)`;
    const range = `e.ts >= now() - ($2 || ' days')::interval`;
    const [summary, tools, trend, sessions, flags, findings] = await Promise.all([
      db.query(
        `SELECT
           COALESCE(MIN(e.user_pseudonym), MIN(e.user_ref)) AS canonical,
           MIN(e.team) AS team,
           COUNT(DISTINCT e.session_id) AS sessions,
           COUNT(DISTINCT e.tool)       AS tools,
           COUNT(DISTINCT e.host_ref)   AS hosts,
           COUNT(*)                     AS events,
           COALESCE(SUM(e.tokens_in),0)  AS tokens_input,
           COALESCE(SUM(e.tokens_out),0) AS tokens_output,
           COALESCE(SUM(${COST_SQL}),0)  AS cost,
           MIN(e.ts) AS first_seen, MAX(e.ts) AS last_active,
           COALESCE(SUM(jsonb_array_length(e.match_flags)),0) AS flag_hits
         FROM events e
         WHERE ${who} AND ${range}`,
        [pseudonym, days]
      ),
      db.query(
        `SELECT
           e.tool,
           array_agg(DISTINCT e.model) FILTER (WHERE e.model IS NOT NULL) AS models,
           COUNT(DISTINCT e.session_id) AS sessions,
           COUNT(*)                     AS events,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           COALESCE(SUM(${COST_SQL}),0) AS cost,
           COALESCE(SUM(jsonb_array_length(e.match_flags)),0) AS flag_hits,
           MAX(e.ts) AS last_seen
         FROM events e
         WHERE ${who} AND ${range}
         GROUP BY e.tool ORDER BY tokens DESC`,
        [pseudonym, days]
      ),
      db.query(
        `SELECT
           date_trunc('day', e.ts)::date AS day,
           COUNT(*)                     AS events,
           COUNT(DISTINCT e.session_id) AS sessions,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           COALESCE(SUM(jsonb_array_length(e.match_flags)),0) AS flag_hits
         FROM events e
         WHERE ${who} AND ${range}
         GROUP BY 1 ORDER BY 1`,
        [pseudonym, days]
      ),
      db.query(
        `SELECT
           e.session_id,
           MIN(e.ts) AS started, MAX(e.ts) AS ended,
           array_agg(DISTINCT e.tool) AS tools,
           COUNT(*) AS events,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           COALESCE(SUM(jsonb_array_length(e.match_flags)),0) AS flag_hits
         FROM events e
         WHERE ${who} AND ${range}
         GROUP BY 1
         ORDER BY ended DESC
         LIMIT 50`,
        [pseudonym, days]
      ),
      db.query(
        `SELECT
           e.ts, e.tool, e.session_id,
           flag ->> 'detector' AS detector
         FROM events e, LATERAL jsonb_array_elements(e.match_flags) AS flag
         WHERE ${who} AND ${range}
         ORDER BY e.ts DESC
         LIMIT 100`,
        [pseudonym, days]
      ),
      db.query(
        `SELECT
           f.finding_id, f.ts, f.detected_at, f.rule_id, f.severity, f.title,
           f.status, f.triaged_by, f.triaged_at
         FROM findings f
         JOIN events e ON e.event_id = f.event_id
         WHERE ${who} AND f.ts >= now() - ($2 || ' days')::interval
         ORDER BY f.detected_at DESC
         LIMIT 50`,
        [pseudonym, days]
      ),
    ]);
    const s = summary.rows[0];
    if (num(s.events) === 0) {
      return reply.code(404).send({ error: 'not_found', detail: `no activity for user '${pseudonym}' in the last ${days} days` });
    }
    return {
      pseudonym: s.canonical ?? pseudonym,
      requestedPseudonym: pseudonym,
      rangeDays: days,
      note: 'Pseudonymous identifier; metadata only — matched content is never stored. Identity reveal is role-gated in identity-sync.',
      summary: {
        team: s.team,
        sessions: num(s.sessions),
        tools: num(s.tools),
        hosts: num(s.hosts),
        events: num(s.events),
        tokensInput: num(s.tokens_input),
        tokensOutput: num(s.tokens_output),
        costUsd: num(s.cost),
        firstSeen: s.first_seen,
        lastActive: s.last_active,
        flagHits: num(s.flag_hits),
      },
      tools: tools.rows.map((r) => ({
        tool: r.tool,
        sanctioned: isSanctioned(r.tool),
        models: r.models ?? [],
        sessions: num(r.sessions),
        events: num(r.events),
        tokens: num(r.tokens),
        costUsd: num(r.cost),
        flagHits: num(r.flag_hits),
        lastSeen: r.last_seen,
      })),
      trend: trend.rows.map((r) => ({
        day: r.day,
        events: num(r.events),
        sessions: num(r.sessions),
        tokens: num(r.tokens),
        flagHits: num(r.flag_hits),
      })),
      sessions: sessions.rows.map((r) => ({
        sessionId: r.session_id,
        started: r.started,
        ended: r.ended,
        tools: r.tools ?? [],
        events: num(r.events),
        tokens: num(r.tokens),
        flagHits: num(r.flag_hits),
      })),
      flags: flags.rows.map((r) => ({
        ts: r.ts,
        tool: r.tool,
        sessionId: r.session_id,
        detector: r.detector,
        category: String(r.detector).split(':')[0],
      })),
      findings: findings.rows.map((r) => ({
        findingId: r.finding_id,
        ts: r.ts,
        detectedAt: r.detected_at,
        ruleId: r.rule_id,
        severity: r.severity,
        title: r.title,
        status: r.status,
        triagedBy: r.triaged_by,
        triagedAt: r.triaged_at,
      })),
    };
  });

  // ---- tool-call mix: aggregates over schema v1.1 tool_use events.
  // Rows with event_type='tool_use' carry tool_calls[] aggregates for one
  // session window; entries are metadata-only by ingest contract (tool name,
  // action class, count, duration — never arguments/paths/output, enforced by
  // additionalProperties:false in the event schema). Three rollups:
  //   * byActionClass — the mix (shell / fs_write / fs_read / network / mcp)
  //   * topTools      — most-invoked tools (name × class × server, top 20)
  //   * mcpServers    — mcp_call entries grouped by mcp_server: this is where
  //     unapproved-MCP findings correlate (server allowlist check).
  // Privacy gate: unfiltered org-level aggregates are open to all three roles
  // (same tier as /api/flags); the `user`/`session` filters surface per-person
  // data and require analyst+ (same gate as /api/users).
  fastify.get('/api/tool-calls', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const user = req.query?.user;
    const session = req.query?.session;
    if ((user !== undefined || session !== undefined) && !userLevel(req, reply)) return reply;
    const days = parseDays(req.query);
    const params = [days];
    let filter = `e.event_type = 'tool_use' AND e.ts >= now() - ($1 || ' days')::interval`;
    // Resolve a user by display pseudonym OR raw user_ref, same as the
    // /api/users/:pseudonym drill-down (findings link via the raw ref).
    if (user !== undefined) {
      params.push(user);
      filter += ` AND (COALESCE(e.user_pseudonym, e.user_ref) = $${params.length} OR e.user_ref = $${params.length})`;
    }
    if (session !== undefined) {
      params.push(session);
      filter += ` AND e.session_id = $${params.length}`;
    }
    const [totals, byActionClass, topTools, mcpServers] = await Promise.all([
      db.query(
        `SELECT
           COUNT(DISTINCT e.event_id)     AS windows,
           COALESCE(SUM((tc ->> 'count')::int),0) AS calls,
           COUNT(DISTINCT e.session_id)   AS sessions
         FROM events e, LATERAL jsonb_array_elements(e.tool_calls) AS tc
         WHERE ${filter}`,
        params
      ),
      db.query(
        `SELECT
           tc ->> 'action_class' AS action_class,
           COALESCE(SUM((tc ->> 'count')::int),0) AS calls,
           COALESCE(SUM((tc ->> 'duration_ms')::bigint),0) AS duration_ms,
           COUNT(DISTINCT e.session_id) AS sessions
         FROM events e, LATERAL jsonb_array_elements(e.tool_calls) AS tc
         WHERE ${filter}
         GROUP BY 1
         ORDER BY calls DESC`,
        params
      ),
      db.query(
        `SELECT
           tc ->> 'tool_name'    AS tool_name,
           tc ->> 'action_class' AS action_class,
           tc ->> 'mcp_server'   AS mcp_server,
           COALESCE(SUM((tc ->> 'count')::int),0) AS calls,
           COALESCE(SUM((tc ->> 'duration_ms')::bigint),0) AS duration_ms
         FROM events e, LATERAL jsonb_array_elements(e.tool_calls) AS tc
         WHERE ${filter}
         GROUP BY 1, 2, 3
         ORDER BY calls DESC
         LIMIT 20`,
        params
      ),
      db.query(
        `SELECT
           tc ->> 'mcp_server' AS mcp_server,
           COALESCE(SUM((tc ->> 'count')::int),0) AS calls,
           COUNT(DISTINCT tc ->> 'tool_name')  AS tools,
           COUNT(DISTINCT e.session_id)        AS sessions,
           COUNT(DISTINCT e.user_ref)          AS users,
           MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen
         FROM events e, LATERAL jsonb_array_elements(e.tool_calls) AS tc
         WHERE ${filter}
           AND tc ->> 'action_class' = 'mcp_call'
           AND tc ->> 'mcp_server' IS NOT NULL
         GROUP BY 1
         ORDER BY calls DESC
         LIMIT 50`,
        params
      ),
    ]);
    const t = totals.rows[0];
    return {
      rangeDays: days,
      user: user ?? null,
      session: session ?? null,
      note: 'Metadata only — tool arguments, paths and output are never stored (schema v1.1 ingest contract).',
      totals: {
        windows: num(t?.windows),
        calls: num(t?.calls),
        sessions: num(t?.sessions),
      },
      byActionClass: byActionClass.rows.map((r) => ({
        actionClass: r.action_class,
        calls: num(r.calls),
        durationMs: num(r.duration_ms),
        sessions: num(r.sessions),
      })),
      topTools: topTools.rows.map((r) => ({
        tool: r.tool_name,
        actionClass: r.action_class,
        mcpServer: r.mcp_server,
        calls: num(r.calls),
        durationMs: num(r.duration_ms),
      })),
      mcpServers: mcpServers.rows.map((r) => ({
        mcpServer: r.mcp_server,
        calls: num(r.calls),
        tools: num(r.tools),
        sessions: num(r.sessions),
        users: num(r.users),
        firstSeen: r.first_seen,
        lastSeen: r.last_seen,
      })),
    };
  });
}

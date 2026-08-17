// Flexible aggregation API: one endpoint that answers ad-hoc
// "metrics by X × Y per bucket" questions (e.g. "tokens by team × tool per
// day") without exposing arbitrary SQL. Group-by fields come from a small
// allowlist mapping to fixed SQL expressions — user input never reaches the
// query text.
//
// Privacy gate: grouping by `user` or `host` surfaces pseudonymous per-person
// / per-device rows, so those fields require the security group (same gate as
// /api/users). Org-level fields (team/tool/provider/model/source/repo/bucket)
// stay open to any authenticated employee, consistent with the other
// aggregate views. All reads hit the global audit hook in server.js.
import { query } from '../db.js';
import { COST_SQL } from '../pricing.js';
import { requireRoles } from '../auth.js';
import { wantsCsv, checkFormat, sendCsv } from '../csv.js';

// Allowlisted group-by fields → fixed SQL expressions (metadata only).
const GROUP_FIELDS = {
  team: `COALESCE(e.team, '(unattributed)')`,
  tool: `e.tool`,
  provider: `COALESCE(e.provider, 'unknown')`,
  model: `COALESCE(e.model, 'unknown')`,
  source: `e.source`,
  repo: `e.repo_ref`,
  user: `COALESCE(e.user_pseudonym, e.user_ref)`,
  host: `e.host_ref`,
};
// Fields that reveal per-person / per-device breakdowns (privacy gate).
const GATED_FIELDS = new Set(['user', 'host']);

const BUCKETS = new Set(['day', 'week', 'month']);
const MAX_ROWS = 10000;

function parseDays(q, def = 30, max = 365) {
  const d = Number(q?.days ?? def);
  if (!Number.isFinite(d) || d < 1) return def;
  return Math.min(Math.floor(d), max);
}

// opts.db is injectable for tests; defaults to the real pg pool.
export async function aggregateRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  // Org-level breakdowns are open to all three roles; per-user/host
  // breakdowns stay analyst+ (privacy gate, same as /api/users).
  const anyRole = requireRoles('admin', 'analyst', 'auditor', 'viewer');
  const userLevel = requireRoles('analyst', 'admin');

  // GET /api/aggregate?group_by=team,tool&bucket=day&days=30[&source=proxy][&format=csv]
  fastify.get('/api/aggregate', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const raw = String(req.query?.group_by ?? '');
    const groupBy = [...new Set(raw.split(',').map((s) => s.trim()).filter(Boolean))];
    if (groupBy.length === 0) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: `group_by is required; allowed fields: ${Object.keys(GROUP_FIELDS).join(', ')}`,
      });
    }
    const bad = groupBy.filter((f) => !(f in GROUP_FIELDS));
    if (bad.length > 0) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: `group_by field(s) not allowed: ${bad.join(', ')}. Allowed: ${Object.keys(GROUP_FIELDS).join(', ')}`,
      });
    }
    // Privacy gate before any query: per-user/host breakdowns are analyst+.
    if (groupBy.some((f) => GATED_FIELDS.has(f))) {
      if (!userLevel(req, reply)) return reply;
    }
    const bucket = req.query?.bucket;
    if (bucket !== undefined && !BUCKETS.has(bucket)) {
      return reply.code(400).send({ error: 'bad_request', detail: `bucket must be one of ${[...BUCKETS].join(', ')}` });
    }
    const source = req.query?.source;
    if (source !== undefined && source !== 'proxy' && source !== 'endpoint') {
      return reply.code(400).send({ error: 'bad_request', detail: "source must be 'proxy' or 'endpoint'" });
    }
    const days = parseDays(req.query);

    const dims = groupBy.map((f) => ({ name: f, expr: GROUP_FIELDS[f] }));
    if (bucket) dims.push({ name: 'bucket', expr: `date_trunc('${bucket}', e.ts)::date` });
    const selectDims = dims.map((d) => `${d.expr} AS ${d.name}`).join(',\n           ');
    // Explicit expressions (not ordinals) — identical semantics, and friendly
    // to in-memory Postgres clones used in tests.
    const groupByClause = dims.map((d) => d.expr).join(', ');
    const orderByClause = dims.map((d) => d.name).join(', ');
    const params = [days];
    let srcClause = '';
    if (source) {
      params.push(source);
      srcClause = ` AND e.source = $${params.length}`;
    }
    const { rows } = await db.query(
      `SELECT
           ${selectDims},
           COUNT(*)                    AS events,
           COUNT(DISTINCT e.session_id) AS sessions,
           COUNT(DISTINCT e.user_ref)  AS users,
           COUNT(DISTINCT e.host_ref)  AS hosts,
           COALESCE(SUM(e.tokens_in),0)  AS tokens_input,
           COALESCE(SUM(e.tokens_out),0) AS tokens_output,
           COALESCE(SUM(e.tokens_in + e.tokens_out),0) AS tokens,
           COALESCE(SUM(${COST_SQL}),0)  AS cost
         FROM events e
         WHERE e.ts >= now() - ($1 || ' days')::interval${srcClause}
         GROUP BY ${groupByClause}
         ORDER BY ${orderByClause}
         LIMIT ${MAX_ROWS + 1}`,
      params
    );
    const truncated = rows.length > MAX_ROWS;
    const dimNames = dims.map((d) => d.name);
    const out = rows.slice(0, MAX_ROWS).map((r) => {
      const row = {};
      for (const n of dimNames) row[n] = r[n];
      row.events = Number(r.events);
      row.sessions = Number(r.sessions);
      row.users = Number(r.users);
      row.hosts = Number(r.hosts);
      row.tokensInput = Number(r.tokens_input);
      row.tokensOutput = Number(r.tokens_output);
      row.tokens = Number(r.tokens);
      row.costUsd = Number(r.cost);
      return row;
    });
    if (wantsCsv(req)) {
      const cols = [
        ...dimNames.map((n) => ({ key: n, label: n })),
        { key: 'events', label: 'events' },
        { key: 'sessions', label: 'sessions' },
        { key: 'users', label: 'users' },
        { key: 'hosts', label: 'hosts' },
        { key: 'tokensInput', label: 'tokens_input' },
        { key: 'tokensOutput', label: 'tokens_output' },
        { key: 'tokens', label: 'tokens' },
        { key: 'costUsd', label: 'cost_usd' },
      ];
      return sendCsv(reply, `aim-aggregate-${groupBy.join('_')}-${days}d.csv`, cols, out);
    }
    return {
      rangeDays: days,
      groupBy,
      bucket: bucket ?? null,
      source: source ?? 'all',
      truncated,
      rows: out,
    };
  });
}

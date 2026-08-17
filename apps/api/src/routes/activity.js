// Live Activity Trail feed. A reverse-chronological stream of
// individual events, each carrying a deterministic per-event security score
// (1–10) and an estimated USD cost, for the dashboard's live Activity tab.
//
// Reads the canonical event store (metadata-only by contract). No new
// data collection: every field here already exists in the schema. Cost reuses
// the versioned price table in pricing.js (COST_SQL) — no third price table.
// The score is computed in JS by the pure, config-driven scorer in
// activity-score.js so the row can ship its factor breakdown ("why").
//
// Privacy gate: rows are per-event and carry a user pseudonym plus detector
// flags — this is USER-LEVEL data, so the feed is analyst + admin
// only, the same gate as /api/users and the ?user= drill-downs. Auditor
// (dashboards + compliance, no user-level rows) is intentionally excluded.
//
// Pagination is index-backed keyset pagination on (ts, event_id) DESC, backed
// by idx_events_ts — never a full-table scan, and `limit` is capped
// server-side. minScore is a post-score filter applied to the fetched page
// window (score is not an SQL column); the cursor advances by the scanned
// boundary row regardless, so paging stays correct — a high minScore just
// yields sparser pages, never an unbounded scan.
import { query } from '../db.js';
import { COST_SQL } from '../pricing.js';
import { requireRoles } from '../auth.js';
import { scoreEvent, SCORE_CONFIG } from '../activity-score.js';
import { listSanctionedToolNames } from '../sanctioned.js';

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

function parseLimit(q) {
  const n = Number(q?.limit ?? DEFAULT_LIMIT);
  if (!Number.isFinite(n) || n < 1) return DEFAULT_LIMIT;
  return Math.min(Math.floor(n), MAX_LIMIT);
}

// Opaque keyset cursor: base64url("<iso ts>|<event_id>"). Returns
// { ts, id } or null (absent/malformed cursors page from the newest event).
export function decodeCursor(before) {
  if (typeof before !== 'string' || before.length === 0) return null;
  try {
    const raw = Buffer.from(before, 'base64url').toString('utf8');
    const sep = raw.lastIndexOf('|');
    if (sep < 1) return null;
    const ts = raw.slice(0, sep);
    const id = raw.slice(sep + 1);
    if (!ts || !id) return null;
    return { ts, id };
  } catch {
    return null;
  }
}

export function encodeCursor(ts, id) {
  const iso = ts instanceof Date ? ts.toISOString() : String(ts);
  return Buffer.from(`${iso}|${id}`, 'utf8').toString('base64url');
}

const toIso = (v) => (v instanceof Date ? v.toISOString() : v == null ? null : String(v));
const num = (v) => (v == null ? 0 : Number(v));

// tool_calls[] -> compact summary the UI renders without unpacking payload.
function summarizeToolCalls(calls) {
  if (!Array.isArray(calls)) return [];
  return calls.map((c) => ({
    tool_name: c?.tool_name ?? null,
    action_class: c?.action_class ?? null,
    count: num(c?.count),
    mcp_server: c?.mcp_server ?? null,
  }));
}

// opts.db is injectable for tests; defaults to the real pg pool.
export async function activityRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  // User-level data (pseudonyms + per-event flags): analyst + admin,
  // matching the ?user= drill gate in dashboard.js / mcp.js.
  const userLevel = requireRoles('analyst', 'admin');

  fastify.get('/api/activity/feed', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    // refresh allow-list before scoring so unapproved-tool factors
    // match the live sanctioned list without a process restart.
    await listSanctionedToolNames(db);

    const limit = parseLimit(req.query);
    const cursor = decodeCursor(req.query?.before);
    const minScoreRaw = Number(req.query?.minScore);
    const minScore = Number.isFinite(minScoreRaw) ? Math.max(1, Math.min(10, minScoreRaw)) : null;

    // SQL-expressible filters — parameterized. Score/minScore are applied in
    // JS after scoring (score is not a column).
    const where = [];
    const params = [];
    const p = (v) => {
      params.push(v);
      return `$${params.length}`;
    };
    if (cursor) where.push(`(e.ts, e.event_id) < (${p(cursor.ts)}::timestamptz, ${p(cursor.id)}::uuid)`);
    if (typeof req.query?.tool === 'string' && req.query.tool) where.push(`e.tool = ${p(req.query.tool)}`);
    if (typeof req.query?.event_type === 'string' && req.query.event_type)
      where.push(`e.event_type = ${p(req.query.event_type)}`);
    if (typeof req.query?.user === 'string' && req.query.user)
      where.push(`COALESCE(e.user_pseudonym, e.user_ref) = ${p(req.query.user)}`);

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    // Fetch limit+1 to detect a next page; the extra row is the keyset
    // boundary. LEFT JOIN LATERAL pulls the highest-severity finding raised on
    // the event (bounded to this page window).
    const limitParam = p(limit + 1);
    const sql = `
      SELECT e.event_id, e.ts, e.tool, e.model, e.event_type, e.source,
             COALESCE(e.user_pseudonym, e.user_ref) AS pseudonym,
             e.team,
             e.tokens_in, e.tokens_out,
             e.match_flags, e.tool_calls,
             e.payload -> 'enforcement' AS enforcement,
             ${COST_SQL} AS est_cost_usd,
             f.severity AS finding_severity
        FROM events e
        LEFT JOIN LATERAL (
          SELECT severity FROM findings
           WHERE event_id = e.event_id
           ORDER BY CASE severity
                      WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                      WHEN 'medium' THEN 2 ELSE 1 END DESC
           LIMIT 1
        ) f ON true
        ${whereSql}
       ORDER BY e.ts DESC, e.event_id DESC
       LIMIT ${limitParam}`;

    const { rows } = await db.query(sql, params);

    // The (limit+1)th row, if present, tells us there's more and gives the
    // next cursor at the page boundary (the limit-th row we return).
    const hasMore = rows.length > limit;
    const pageRows = hasMore ? rows.slice(0, limit) : rows;
    const nextCursor = hasMore && pageRows.length ? encodeCursor(pageRows[pageRows.length - 1].ts, pageRows[pageRows.length - 1].event_id) : null;

    const events = [];
    for (const r of pageRows) {
      const enforcement = r.enforcement && typeof r.enforcement === 'object' ? r.enforcement : null;
      const { score, band, factors } = scoreEvent(
        {
          tool: r.tool,
          model: r.model,
          event_type: r.event_type,
          match_flags: r.match_flags,
          tool_calls: r.tool_calls,
          enforcement,
        },
        { findingSeverity: r.finding_severity ?? null }
      );
      if (minScore !== null && score < minScore) continue; // post-score filter
      events.push({
        event_id: String(r.event_id),
        ts: toIso(r.ts),
        pseudonym: r.pseudonym ?? null,
        team: r.team ?? null,
        tool: r.tool,
        model: r.model ?? null,
        event_type: r.event_type,
        source: r.source ?? null,
        tokens_in: r.tokens_in == null ? null : num(r.tokens_in),
        tokens_out: r.tokens_out == null ? null : num(r.tokens_out),
        tool_calls: summarizeToolCalls(r.tool_calls),
        match_flags: Array.isArray(r.match_flags) ? r.match_flags : [],
        enforcement,
        finding_severity: r.finding_severity ?? null,
        est_cost_usd: num(r.est_cost_usd),
        security_score: score,
        score_band: band,
        score_factors: factors,
      });
    }

    return {
      limit,
      minScore,
      // Echo the band thresholds so the UI colors badges from server config,
      // never hard-coded client-side.
      bands: SCORE_CONFIG.bands,
      events,
      nextCursor,
      hasMore,
    };
  });
}

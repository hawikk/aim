// Endpoint enforcement surfaces (combined).
//
// AIM-612  GET /api/enforcement                 — daily trend
// AIM-789  GET /api/enforcement/coverage        — install-path + honor (Security panel)
// AIM-788  GET /api/enforcement/rules[|/evidence] — mode matrix
// AIM-567  GET /api/enforcement/break-glass     — analyst override trail
// AIM-784  grants lifecycle under /break-glass/grants*
//
// AIM-781 fleet coverage (fail-open inventory) lives in enforcement-coverage.js
// at GET /api/enforcement/fleet-coverage (path split after concurrent merge).
//
// Privacy: metadata only — action, rule_id, policy_hash, grant lifecycle.
// Never prompt text or secret content. Pseudonyms → analyst + admin.

import { randomUUID } from 'node:crypto';
import { query } from '../db.js';
import { requireRoles } from '../auth.js';
import { audit } from '../audit.js';
import { wantsCsv, checkFormat, sendCsv, toCsv } from '../csv.js';
import {
  loadEnforcementPolicy,
  buildModeMatrix,
  mergeDispositionCounts,
  attachCounts,
  modeCounts,
  totalsLast7d,
  buildEvidencePack,
  emptyCounts,
  ENDPOINT_RAILS,
} from '../enforcement-policy.js';

const ACTIONS = ['blocked', 'would_block', 'confirmed'];

const num = (v) => Number(v ?? 0);

/** Round a ratio to 3 decimals; null when the denominator is zero. */
export function rate(numerator, denominator) {
  const n = num(numerator);
  const d = num(denominator);
  if (d <= 0) return null;
  return Math.round((n / d) * 1000) / 1000;
}

/** Normalize a day key to UTC midnight ISO (matches AIM-588 fixture contract). */
export function dayIso(v) {
  if (v == null) return null;
  if (v instanceof Date) {
    return new Date(Date.UTC(v.getUTCFullYear(), v.getUTCMonth(), v.getUTCDate())).toISOString();
  }
  const s = String(v);
  // Postgres date often arrives as 'YYYY-MM-DD'
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return `${s}T00:00:00.000Z`;
  const d = new Date(s);
  if (!Number.isFinite(d.getTime())) return s;
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate())).toISOString();
}

/**
 * Collapse per-(day, action) rows into the fixture shape:
 *   { totals: { blocked, would_block, confirmed }, trend: [{ day, … }] }
 *
 * @param {Array<{ day: unknown, action: string|null, n: unknown }>} rows
 */
export function rollupEnforcement(rows) {
  const totals = { blocked: 0, would_block: 0, confirmed: 0 };
  const byDay = new Map();
  for (const r of rows) {
    const action = r.action;
    if (!ACTIONS.includes(action)) continue;
    const n = num(r.n);
    totals[action] += n;
    const day = dayIso(r.day);
    if (!day) continue;
    if (!byDay.has(day)) {
      byDay.set(day, { day, blocked: 0, would_block: 0, confirmed: 0 });
    }
    byDay.get(day)[action] += n;
  }
  const trend = [...byDay.values()].sort((a, b) => a.day.localeCompare(b.day));
  return { totals, trend };
}

/**
 * Build install-path + honor coverage from query row sets.
 * Pure so unit tests can pin honesty math without a database.
 *
 * @param {{
 *   posture: Record<string, unknown>,
 *   enrolled: number,
 *   byMode: Array<{ mode: string|null, events: unknown, hosts: unknown }>,
 *   byPolicyHash: Array<{ policy_hash: string|null, mode: string|null, events: unknown, hosts: unknown }>,
 *   honorRows: Array<{ rule_id: string|null, policy_hash: string|null, action: string|null, n: unknown }>,
 *   now?: Date,
 *   rangeDays?: number,
 * }} input
 */
export function buildCoverage(input) {
  const now = input.now ?? new Date();
  const rangeDays = input.rangeDays ?? 7;
  const p = input.posture ?? {};
  const eventsTotal = num(p.events_total);
  const withPosture = num(p.with_posture);
  const policyLoaded = num(p.policy_loaded);
  const policyAbsent = num(p.policy_absent);
  const evaluated = num(p.evaluated);
  const hostsSeen = num(p.hosts_seen);
  const hostsPolicyLoaded = num(p.hosts_policy_loaded);
  const enrolled = num(input.enrolled);

  const covered = policyLoaded > 0;
  const eventCoverageRate = rate(policyLoaded, eventsTotal);
  const hostCoverageRate = rate(hostsPolicyLoaded, hostsSeen);

  const byMode = (input.byMode ?? []).map((r) => ({
    mode: r.mode ?? null,
    events: num(r.events),
    hosts: num(r.hosts),
  })).sort((a, b) => b.events - a.events || String(a.mode).localeCompare(String(b.mode)));

  const byPolicyHash = (input.byPolicyHash ?? []).map((r) => ({
    policyHash: r.policy_hash ?? null,
    mode: r.mode ?? null,
    events: num(r.events),
    hosts: num(r.hosts),
  })).sort((a, b) => b.events - a.events
    || String(a.policyHash ?? '').localeCompare(String(b.policyHash ?? ''))
    || String(a.mode ?? '').localeCompare(String(b.mode ?? '')));

  // Honor rate only counts decisions emitted while posture.mode=enforce.
  // would_block under enforce is fail-open or delivery skew — alertable.
  const totals = { blocked: 0, would_block: 0, confirmed: 0 };
  const ruleMap = new Map();
  for (const r of input.honorRows ?? []) {
    const action = r.action;
    if (!ACTIONS.includes(action)) continue;
    const n = num(r.n);
    totals[action] += n;
    const key = `${r.rule_id ?? ''}\0${r.policy_hash ?? ''}`;
    if (!ruleMap.has(key)) {
      ruleMap.set(key, {
        ruleId: r.rule_id ?? null,
        policyHash: r.policy_hash ?? null,
        blocked: 0,
        would_block: 0,
        confirmed: 0,
      });
    }
    ruleMap.get(key)[action] += n;
  }

  const byRule = [...ruleMap.values()]
    .map((row) => {
      const honorDenom = row.blocked + row.would_block;
      const bgDenom = row.blocked + row.confirmed;
      return {
        ...row,
        honorRate: rate(row.blocked, honorDenom),
        breakGlassRate: rate(row.confirmed, bgDenom),
        alertable: row.would_block > 0,
      };
    })
    .sort((a, b) => (b.blocked + b.would_block + b.confirmed) - (a.blocked + a.would_block + a.confirmed)
      || String(a.ruleId ?? '').localeCompare(String(b.ruleId ?? '')));

  const honorDenom = totals.blocked + totals.would_block;
  const bgDenom = totals.blocked + totals.confirmed;
  const honorRate = rate(totals.blocked, honorDenom);
  const breakGlassRate = rate(totals.confirmed, bgDenom);
  const alertable = totals.would_block > 0;

  let installNote;
  if (eventsTotal === 0) {
    installNote = 'No events in this window — coverage is unknown, not zero.';
  } else if (!covered) {
    installNote =
      'No event carried enforcement_posture.policy=loaded. Zero blocks means no coverage, not a clean fleet ' +
      '(AIM-110 doctrine). Bundle delivery / collector install path is dark.';
  } else {
    installNote =
      `${policyLoaded}/${eventsTotal} events (${eventCoverageRate}) and ` +
      `${hostsPolicyLoaded}/${hostsSeen} event-hosts (${hostCoverageRate}) report a loaded enforcement bundle. ` +
      `${enrolled} enrolled devices (host_id) — not joinable to event host_ref (HMAC).`;
  }

  let honorNote;
  if (!covered) {
    honorNote = 'Honor rate is undefined without a loaded enforce posture — no coverage.';
  } else if (honorDenom === 0 && totals.confirmed === 0) {
    honorNote =
      'Endpoints reported mode=enforce but no enforcement decisions fired in this window. ' +
      'Honor rate has no denominator (not 1.0).';
  } else if (alertable) {
    honorNote =
      `would_block=${totals.would_block} under mode=enforce — fail-open or delivery skew (alertable). ` +
      `Honor rate blocked/(blocked+would_block)=${honorRate}.`;
  } else {
    honorNote =
      `Honor rate blocked/(blocked+would_block)=${honorRate}; ` +
      `break-glass confirmed/(blocked+confirmed)=${breakGlassRate}.`;
  }

  const statement = covered
    ? `Install-path: ${hostsPolicyLoaded}/${hostsSeen || 0} event-hosts loaded ` +
      `(${eventCoverageRate ?? 0} of events). Honor: ${honorRate ?? 'n/a'}` +
      (alertable ? ' — ALERT would_block under enforce.' : '.')
    : 'NO COVERAGE — no loaded enforcement_posture in window. Do not read zeros as clean.';

  return {
    asOf: now.toISOString(),
    rangeDays,
    installPath: {
      covered,
      events: {
        total: eventsTotal,
        withPosture,
        policyLoaded,
        policyAbsent,
        evaluated,
        coverageRate: eventCoverageRate,
      },
      hosts: {
        enrolled,
        seen: hostsSeen,
        policyLoaded: hostsPolicyLoaded,
        coverageRate: hostCoverageRate,
      },
      byMode,
      byPolicyHash,
      note: installNote,
    },
    honor: {
      scope: "events with enforcement_posture.mode='enforce' and payload.enforcement present",
      totals,
      honorRate,
      breakGlassRate,
      alertable,
      byRule,
      note: honorNote,
    },
    statement,
  };
}

const WINDOW_DAYS = 7;

async function last7dDispositions(db, fromIso) {
  const { rows } = await db.query(
    `SELECT payload->'enforcement'->>'rule_id' AS rule_id,
            payload->'enforcement'->>'action' AS action,
            COUNT(*)::int AS n
       FROM events
      WHERE ts >= $1
        AND payload ? 'enforcement'
      GROUP BY 1, 2`,
    [fromIso],
  );
  return mergeDispositionCounts(rows);
}

function windowBounds(now = new Date()) {
  const to = new Date(now);
  const from = new Date(to.getTime() - WINDOW_DAYS * 86400_000);
  return {
    days: WINDOW_DAYS,
    from: from.toISOString(),
    to: to.toISOString(),
    fromIso: from.toISOString(),
  };
}

function matrixPayload(policyMeta, rules, window) {
  return {
    windowDays: window.days,
    windowFrom: window.from,
    windowTo: window.to,
    policy: {
      loaded: policyMeta.loaded,
      path: policyMeta.path,
      policyHash: policyMeta.policy?.policy_hash ?? null,
      mode: policyMeta.policy?.mode ?? null,
      version: policyMeta.policy?.version ?? null,
      error: policyMeta.error,
    },
    modeCounts: modeCounts(rules),
    totalsLast7d: totalsLast7d(rules),
    railsCatalog: ENDPOINT_RAILS.map((r) => r.id),
    rules,
  };
}

const _DEFAULT_DAYS = 30;
const _MAX_DAYS = 365;
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;
const BREAK_GLASS_ACTIONS = new Set(['confirmed', 'blocked', 'would_block', 'all']);
const GRANT_STATUSES = new Set(['pending', 'approved', 'denied', 'revoked', 'expired', 'all', 'active']);
const DEFAULT_RULE = 'secret-pattern-in-prompt';
const DEFAULT_TTL_HOURS = 4;
const MAX_TTL_HOURS = 168; // 7d
const MIN_TTL_HOURS = 1;

const CSV_COLS = [
  { key: 'ts', label: 'ts' },
  { key: 'kind', label: 'kind' },
  { key: 'action', label: 'action' },
  { key: 'ruleId', label: 'rule_id' },
  { key: 'policyHash', label: 'policy_hash' },
  { key: 'pseudonym', label: 'user' },
  { key: 'team', label: 'team' },
  { key: 'hostRef', label: 'host_ref' },
  { key: 'tool', label: 'tool' },
  { key: 'sessionId', label: 'session_id' },
  { key: 'eventId', label: 'event_id' },
];

const GRANT_CSV_COLS = [
  { key: 'id', label: 'id' },
  { key: 'status', label: 'status' },
  { key: 'ruleId', label: 'rule_id' },
  { key: 'subjectUserRef', label: 'subject_user_ref' },
  { key: 'subjectEmail', label: 'subject_email' },
  { key: 'team', label: 'team' },
  { key: 'reason', label: 'reason' },
  { key: 'ticketRef', label: 'ticket_ref' },
  { key: 'requestedBy', label: 'requested_by' },
  { key: 'requestedAt', label: 'requested_at' },
  { key: 'decidedBy', label: 'decided_by' },
  { key: 'decidedAt', label: 'decided_at' },
  { key: 'expiresAt', label: 'expires_at' },
  { key: 'revokedBy', label: 'revoked_by' },
  { key: 'revokedAt', label: 'revoked_at' },
  { key: 'requestedTtlHours', label: 'requested_ttl_hours' },
  { key: 'policyHash', label: 'policy_hash' },
];

const GRANT_EVENT_CSV_COLS = [
  { key: 'id', label: 'event_id' },
  { key: 'grantId', label: 'grant_id' },
  { key: 'eventType', label: 'event_type' },
  { key: 'actor', label: 'actor' },
  { key: 'createdAt', label: 'created_at' },
  { key: 'detail', label: 'detail' },
];

function parseDays(q, def = 30, max = 365) {
  const d = Number(q?.days ?? def);
  if (!Number.isFinite(d) || d < 1) return def;
  return Math.min(Math.floor(d), max);
}

function parseLimit(q) {
  const n = Number(q?.limit ?? DEFAULT_LIMIT);
  if (!Number.isFinite(n) || n < 1) return DEFAULT_LIMIT;
  return Math.min(Math.floor(n), MAX_LIMIT);
}

const toIso = (v) => (v instanceof Date ? v.toISOString() : v == null ? null : String(v));

function actorEmail(req) {
  return req.identity?.email ?? null;
}

function isMissingTable(err) {
  const msg = String(err?.message || err);
  return msg.includes('break_glass_grants') || msg.includes('break_glass_grant_events');
}

function missingTableReply(reply) {
  return reply.code(503).send({
    error: 'unavailable',
    detail: 'break_glass_grants table missing — apply migration 035_break_glass_grants.sql',
  });
}

/** Classify a confirmed disposition for analyst copy. */
export function overrideKind(action, ruleId) {
  if (action !== 'confirmed') return action;
  if (ruleId === 'secret-pattern-in-prompt') return 'break_glass';
  if (ruleId === 'pii-in-prompt') return 'pii_confirm';
  return 'override';
}

function shapeRow(r) {
  const action = r.action ?? null;
  const ruleId = r.rule_id ?? null;
  return {
    eventId: r.event_id == null ? null : String(r.event_id),
    ts: toIso(r.ts),
    action,
    ruleId,
    policyHash: r.policy_hash ?? null,
    kind: overrideKind(action, ruleId),
    pseudonym: r.pseudonym ?? null,
    team: r.team ?? null,
    hostRef: r.host_ref ?? null,
    tool: r.tool ?? null,
    sessionId: r.session_id ?? null,
  };
}

function shapeGrant(r, now = new Date()) {
  let status = r.status;
  // Lazy expiry: approved past expires_at is presented as expired even before
  // the sweep lands, so list/export never advertise a dead grant as active.
  if (status === 'approved' && r.expires_at && new Date(r.expires_at) <= now) {
    status = 'expired';
  }
  return {
    id: r.id == null ? null : String(r.id),
    ruleId: r.rule_id ?? null,
    subjectUserRef: r.subject_user_ref ?? null,
    subjectEmail: r.subject_email ?? null,
    team: r.team ?? null,
    status,
    reason: r.reason ?? null,
    ticketRef: r.ticket_ref ?? null,
    policyHash: r.policy_hash ?? null,
    requestedBy: r.requested_by ?? null,
    requestedAt: toIso(r.requested_at),
    decidedBy: r.decided_by ?? null,
    decidedAt: toIso(r.decided_at),
    decisionNote: r.decision_note ?? null,
    expiresAt: toIso(r.expires_at),
    revokedBy: r.revoked_by ?? null,
    revokedAt: toIso(r.revoked_at),
    revokeReason: r.revoke_reason ?? null,
    requestedTtlHours: r.requested_ttl_hours == null ? null : Number(r.requested_ttl_hours),
    createdAt: toIso(r.created_at),
    updatedAt: toIso(r.updated_at),
  };
}

function shapeGrantEvent(r) {
  return {
    id: r.id == null ? null : String(r.id),
    grantId: r.grant_id == null ? null : String(r.grant_id),
    eventType: r.event_type ?? null,
    actor: r.actor ?? null,
    detail: r.detail ?? {},
    createdAt: toIso(r.created_at),
  };
}

function normalizeText(v, { required = false, max = 2000, field = 'value' } = {}) {
  if (v == null || v === '') {
    if (required) return { error: `${field} is required` };
    return { value: null };
  }
  if (typeof v !== 'string') return { error: `${field} must be a string` };
  const t = v.trim();
  if (!t) {
    if (required) return { error: `${field} is required` };
    return { value: null };
  }
  if (t.length > max) return { error: `${field} must be ≤ ${max} chars` };
  return { value: t };
}

function parseTtlHours(raw, fallback = DEFAULT_TTL_HOURS) {
  if (raw == null || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n)) return null;
  const h = Math.floor(n);
  if (h < MIN_TTL_HOURS || h > MAX_TTL_HOURS) return null;
  return h;
}

async function appendGrantEvent(db, grantId, eventType, actor, detail = {}) {
  await db.query(
    `INSERT INTO break_glass_grant_events (grant_id, event_type, actor, detail)
     VALUES ($1::uuid, $2, $3, $4::jsonb)`,
    [grantId, eventType, actor, JSON.stringify(detail ?? {})],
  );
}

/** Mark approved-but-past-expiry rows as expired (best-effort). */
export async function expireStaleGrants(db, now = new Date()) {
  const { rows } = await db.query(
    `UPDATE break_glass_grants
        SET status = 'expired', updated_at = $1
      WHERE status = 'approved'
        AND expires_at IS NOT NULL
        AND expires_at <= $1
      RETURNING id`,
    [now.toISOString()],
  );
  for (const r of rows) {
    await appendGrantEvent(db, r.id, 'expired', 'system:expiry', {
      at: now.toISOString(),
    });
  }
  return rows.length;
}


// opts.db / opts.appendAudit / opts.loadPolicy / opts.now injectable for tests.
export async function enforcementRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const appendAudit = opts?.appendAudit ?? audit;
  const loadPolicy = opts?.loadPolicy ?? loadEnforcementPolicy;
  const nowFn = opts?.now ?? (() => new Date());
  const userLevel = requireRoles('analyst', 'admin');
  const adminOnly = requireRoles('admin');

  // GET /api/enforcement?days=N  (AIM-612)
  fastify.get('/api/enforcement', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const days = parseDays(req.query, 30);
    const { rows } = await db.query(
      `SELECT date_trunc('day', ts)::date AS day,
              payload->'enforcement'->>'action' AS action,
              COUNT(*)::int AS n
         FROM events
        WHERE ts >= now() - ($1 || ' days')::interval
          AND payload ? 'enforcement'
        GROUP BY 1, 2
        ORDER BY 1, 2`,
      [days],
    );
    const body = rollupEnforcement(rows);
    return {
      rangeDays: days,
      totals: body.totals,
      trend: body.trend,
    };
  });

  // GET /api/enforcement/coverage?days=N  (AIM-789)
  // Default window is 7d — install-path freshness for fleet posture, not a
  // month-long bake. Max 90 keeps the JSONB scans bounded for pilot scale.
  fastify.get('/api/enforcement/coverage', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const days = parseDays(req.query, 7, 90);

    const [postureRes, enrolledRes, modeRes, hashRes, honorRes] = await Promise.all([
      db.query(
        `SELECT COUNT(*)::int AS events_total,
                COUNT(*) FILTER (WHERE payload ? 'enforcement_posture')::int AS with_posture,
                COUNT(*) FILTER (WHERE payload->'enforcement_posture'->>'policy' = 'loaded')::int AS policy_loaded,
                COUNT(*) FILTER (WHERE payload->'enforcement_posture'->>'policy' = 'absent')::int AS policy_absent,
                COUNT(*) FILTER (WHERE payload->'enforcement_posture'->>'evaluated' = 'true')::int AS evaluated,
                COUNT(DISTINCT host_ref)::int AS hosts_seen,
                COUNT(DISTINCT host_ref) FILTER (
                  WHERE payload->'enforcement_posture'->>'policy' = 'loaded'
                )::int AS hosts_policy_loaded
           FROM events
          WHERE ts >= now() - ($1 || ' days')::interval`,
        [days],
      ),
      db.query(
        `SELECT COUNT(*)::int AS enrolled
           FROM devices
          WHERE revoked_at IS NULL`,
        [],
      ),
      db.query(
        `SELECT payload->'enforcement_posture'->>'mode' AS mode,
                COUNT(*)::int AS events,
                COUNT(DISTINCT host_ref)::int AS hosts
           FROM events
          WHERE ts >= now() - ($1 || ' days')::interval
            AND payload->'enforcement_posture'->>'policy' = 'loaded'
          GROUP BY 1
          ORDER BY 2 DESC`,
        [days],
      ),
      db.query(
        `SELECT payload->'enforcement_posture'->>'policy_hash' AS policy_hash,
                payload->'enforcement_posture'->>'mode' AS mode,
                COUNT(*)::int AS events,
                COUNT(DISTINCT host_ref)::int AS hosts
           FROM events
          WHERE ts >= now() - ($1 || ' days')::interval
            AND payload->'enforcement_posture'->>'policy' = 'loaded'
          GROUP BY 1, 2
          ORDER BY 3 DESC, 1, 2`,
        [days],
      ),
      db.query(
        `SELECT payload->'enforcement'->>'rule_id' AS rule_id,
                payload->'enforcement'->>'policy_hash' AS policy_hash,
                payload->'enforcement'->>'action' AS action,
                COUNT(*)::int AS n
           FROM events
          WHERE ts >= now() - ($1 || ' days')::interval
            AND payload ? 'enforcement'
            AND payload->'enforcement_posture'->>'mode' = 'enforce'
          GROUP BY 1, 2, 3
          ORDER BY 1, 2, 3`,
        [days],
      ),
    ]);

    return buildCoverage({
      posture: postureRes.rows[0] ?? {},
      enrolled: enrolledRes.rows[0]?.enrolled ?? 0,
      byMode: modeRes.rows,
      byPolicyHash: hashRes.rows,
      honorRows: honorRes.rows,
      now: nowFn(),
      rangeDays: days,
    });
  });

  fastify.get('/api/enforcement/rules', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;

    const window = windowBounds(nowFn());
    const policyMeta = loadPolicy();
    const matrix = buildModeMatrix(policyMeta.policy);

    let countMap;
    try {
      countMap = await last7dDispositions(db, window.fromIso);
    } catch (err) {
      req.log.error(err, 'enforcement disposition query failed');
      // Still serve declared modes; zero counts rather than 500 — the matrix
      // is usable without telemetry (declared intent still answers "where").
      countMap = new Map();
      for (const r of matrix) countMap.set(r.id, emptyCounts());
    }

    const rules = attachCounts(matrix, countMap);
    return matrixPayload(policyMeta, rules, window);
  });

  fastify.get('/api/enforcement/rules/evidence', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;

    const window = windowBounds(nowFn());
    const policyMeta = loadPolicy();
    const matrix = buildModeMatrix(policyMeta.policy);

    let countMap;
    try {
      countMap = await last7dDispositions(db, window.fromIso);
    } catch (err) {
      req.log.error(err, 'enforcement evidence disposition query failed');
      countMap = new Map();
    }

    const rules = attachCounts(matrix, countMap);
    const pack = buildEvidencePack({
      policyMeta,
      rules,
      window: { days: window.days, from: window.from, to: window.to },
    });

    // Optional download filename for scorecard pack consumers.
    reply.header(
      'content-disposition',
      `inline; filename="aim-788-enforcement-mode-matrix.json"`,
    );
    return pack;
  });

  /* ---------- AIM-567: endpoint override trail ---------- */

  fastify.get('/api/enforcement/break-glass', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;

    const days = parseDays(req.query);
    const limit = parseLimit(req.query);
    const actionRaw = typeof req.query?.action === 'string' ? req.query.action.trim() : 'confirmed';
    const action = BREAK_GLASS_ACTIONS.has(actionRaw) ? actionRaw : null;
    if (!action) {
      return reply.code(400).send({
        error: `action must be one of ${[...BREAK_GLASS_ACTIONS].join(', ')}`,
      });
    }
    const ruleId = typeof req.query?.rule_id === 'string' && req.query.rule_id.trim()
      ? req.query.rule_id.trim().slice(0, 64)
      : null;

    const params = [days];
    const p = (v) => {
      params.push(v);
      return `$${params.length}`;
    };

    const filters = [
      `e.ts >= now() - ($1::int * interval '1 day')`,
      `e.payload ? 'enforcement'`,
    ];
    if (action !== 'all') {
      filters.push(`e.payload->'enforcement'->>'action' = ${p(action)}`);
    }
    if (ruleId) {
      filters.push(`e.payload->'enforcement'->>'rule_id' = ${p(ruleId)}`);
    }

    const summarySql = `
      SELECT e.payload->'enforcement'->>'action' AS action,
             e.payload->'enforcement'->>'rule_id' AS rule_id,
             COUNT(*)::int AS n
        FROM events e
       WHERE e.ts >= now() - ($1::int * interval '1 day')
         AND e.payload ? 'enforcement'
       GROUP BY 1, 2
       ORDER BY n DESC, action, rule_id`;

    const listSql = `
      SELECT e.event_id, e.ts, e.tool, e.session_id, e.host_ref,
             COALESCE(e.user_pseudonym, e.user_ref) AS pseudonym,
             e.team,
             e.payload->'enforcement'->>'action' AS action,
             e.payload->'enforcement'->>'rule_id' AS rule_id,
             e.payload->'enforcement'->>'policy_hash' AS policy_hash
        FROM events e
       WHERE ${filters.join(' AND ')}
       ORDER BY e.ts DESC, e.event_id DESC
       LIMIT ${p(limit)}`;

    const [summaryRes, listRes] = await Promise.all([
      db.query(summarySql, [days]),
      db.query(listSql, params),
    ]);

    const byAction = { blocked: 0, would_block: 0, confirmed: 0 };
    const byRule = [];
    for (const row of summaryRes.rows) {
      const a = row.action;
      if (a && Object.prototype.hasOwnProperty.call(byAction, a)) {
        byAction[a] += Number(row.n) || 0;
      }
      byRule.push({
        action: row.action,
        ruleId: row.rule_id,
        count: Number(row.n) || 0,
      });
    }

    const events = listRes.rows.map(shapeRow);
    const breakGlassCount = byRule
      .filter((r) => r.action === 'confirmed' && r.ruleId === 'secret-pattern-in-prompt')
      .reduce((s, r) => s + r.count, 0);

    const body = {
      days,
      limit,
      action,
      ruleId,
      breakGlassCount,
      summary: {
        byAction,
        byRule,
        listed: events.length,
        truncated: events.length >= limit,
      },
      events,
      note:
        'Break-glass = enforcement.action=confirmed for secret-pattern-in-prompt '
        + '(identical-prompt resubmit within secret_override_ttl_seconds, or '
        + 'manager-approved grant when secret_override_requires_manager). '
        + 'Metadata only: action + rule_id + policy_hash; no prompt or secret content.',
    };

    if (wantsCsv(req)) {
      return sendCsv(reply, `aim-break-glass-${days}d.csv`, CSV_COLS, events);
    }
    return body;
  });

  /* ---------- AIM-784: grant control plane ---------- */

  fastify.get('/api/enforcement/break-glass/grants', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;

    const days = parseDays(req.query);
    const limit = parseLimit(req.query);
    const statusRaw = typeof req.query?.status === 'string' ? req.query.status.trim() : 'all';
    if (!GRANT_STATUSES.has(statusRaw)) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: `status must be one of ${[...GRANT_STATUSES].join(', ')}`,
      });
    }
    const ruleId = typeof req.query?.rule_id === 'string' && req.query.rule_id.trim()
      ? req.query.rule_id.trim().slice(0, 64)
      : null;
    const subject = typeof req.query?.subject === 'string' && req.query.subject.trim()
      ? req.query.subject.trim().slice(0, 256)
      : null;

    const now = nowFn();
    try {
      await expireStaleGrants(db, now);
    } catch (err) {
      if (isMissingTable(err)) return missingTableReply(reply);
      throw err;
    }

    const params = [days];
    const p = (v) => {
      params.push(v);
      return `$${params.length}`;
    };
    const filters = [`g.requested_at >= now() - ($1::int * interval '1 day')`];
    if (statusRaw === 'active') {
      filters.push(`g.status = 'approved'`);
      filters.push(`g.expires_at IS NOT NULL AND g.expires_at > now()`);
    } else if (statusRaw !== 'all') {
      filters.push(`g.status = ${p(statusRaw)}`);
    }
    if (ruleId) filters.push(`g.rule_id = ${p(ruleId)}`);
    if (subject) filters.push(`g.subject_user_ref = ${p(subject)}`);

    let rows;
    try {
      ({ rows } = await db.query(
        `SELECT * FROM break_glass_grants g
          WHERE ${filters.join(' AND ')}
          ORDER BY g.requested_at DESC, g.id DESC
          LIMIT ${p(limit)}`,
        params,
      ));
    } catch (err) {
      if (isMissingTable(err)) return missingTableReply(reply);
      throw err;
    }

    const grants = rows.map((r) => shapeGrant(r, now));
    const summary = {
      pending: 0, approved: 0, denied: 0, revoked: 0, expired: 0, active: 0,
    };
    for (const g of grants) {
      if (summary[g.status] !== undefined) summary[g.status] += 1;
      if (g.status === 'approved') summary.active += 1;
    }

    if (wantsCsv(req)) {
      return sendCsv(reply, `aim-break-glass-grants-${days}d.csv`, GRANT_CSV_COLS, grants);
    }
    return {
      days,
      limit,
      status: statusRaw,
      ruleId,
      subject,
      summary,
      grants,
      note:
        'Enterprise break-glass grants (AIM-784). Default pilot path does not '
        + 'require manager approval (secret_override_requires_manager=false). '
        + 'Approve/deny/revoke require admin. No prompt or secret content stored.',
    };
  });

  // Endpoint sync: only currently usable grants (approved + not expired).
  // Designed for config-mgmt / agent pull into break_glass_grants.json.
  fastify.get('/api/enforcement/break-glass/active-grants', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const now = nowFn();
    try {
      await expireStaleGrants(db, now);
      const { rows } = await db.query(
        `SELECT id, rule_id, subject_user_ref, expires_at, policy_hash, status
           FROM break_glass_grants
          WHERE status = 'approved'
            AND expires_at IS NOT NULL
            AND expires_at > $1
          ORDER BY expires_at ASC`,
        [now.toISOString()],
      );
      const grants = rows.map((r) => ({
        id: String(r.id),
        rule_id: r.rule_id,
        subject_user_ref: r.subject_user_ref,
        expires_at: toIso(r.expires_at),
        policy_hash: r.policy_hash ?? null,
        status: 'approved',
      }));
      return {
        generatedAt: now.toISOString(),
        grants,
        note:
          'Deploy as state-dir break_glass_grants.json (or AIM_BREAK_GLASS_GRANTS_FILE) '
          + 'when secret_override_requires_manager is true. Metadata only.',
      };
    } catch (err) {
      if (isMissingTable(err)) return missingTableReply(reply);
      throw err;
    }
  });

  fastify.post('/api/enforcement/break-glass/grants', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const actor = actorEmail(req);
    if (!actor) {
      return reply.code(401).send({
        error: 'unauthenticated',
        detail: 'verified session required for grant mutations',
      });
    }

    const body = req.body ?? {};
    const subjectR = normalizeText(body.subjectUserRef ?? body.subject_user_ref, {
      required: true, max: 256, field: 'subjectUserRef',
    });
    if (subjectR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: subjectR.error });
    }
    const reasonR = normalizeText(body.reason, { required: true, max: 2000, field: 'reason' });
    if (reasonR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: reasonR.error });
    }
    const emailR = normalizeText(body.subjectEmail ?? body.subject_email, {
      max: 320, field: 'subjectEmail',
    });
    if (emailR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: emailR.error });
    }
    const teamR = normalizeText(body.team, { max: 128, field: 'team' });
    if (teamR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: teamR.error });
    }
    const ticketR = normalizeText(body.ticketRef ?? body.ticket_ref, {
      max: 256, field: 'ticketRef',
    });
    if (ticketR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: ticketR.error });
    }
    const policyR = normalizeText(body.policyHash ?? body.policy_hash, {
      max: 128, field: 'policyHash',
    });
    if (policyR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: policyR.error });
    }
    const ruleR = normalizeText(body.ruleId ?? body.rule_id ?? DEFAULT_RULE, {
      required: true, max: 64, field: 'ruleId',
    });
    if (ruleR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: ruleR.error });
    }
    const ttl = parseTtlHours(body.requestedTtlHours ?? body.requested_ttl_hours);
    if (ttl == null) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: `requestedTtlHours must be ${MIN_TTL_HOURS}..${MAX_TTL_HOURS}`,
      });
    }

    // Admin may auto-approve at request time (skip pending queue).
    let doAuto = false;
    if (body.autoApprove) {
      const role = req.identity?.role;
      doAuto = role === 'admin' || role === 'security-admin';
      if (!doAuto) {
        return reply.code(403).send({
          error: 'forbidden',
          detail: 'autoApprove requires admin',
        });
      }
    }

    const id = randomUUID();
    const now = nowFn();
    let expiresAt = null;
    let status = 'pending';
    let decidedBy = null;
    let decidedAt = null;
    let decisionNote = null;
    if (doAuto) {
      status = 'approved';
      decidedBy = actor;
      decidedAt = now;
      decisionNote = normalizeText(body.decisionNote ?? body.decision_note, {
        max: 2000, field: 'decisionNote',
      }).value;
      const hours = parseTtlHours(body.ttlHours ?? body.ttl_hours, ttl);
      if (hours == null) {
        return reply.code(400).send({
          error: 'bad_request',
          detail: `ttlHours must be ${MIN_TTL_HOURS}..${MAX_TTL_HOURS}`,
        });
      }
      expiresAt = new Date(now.getTime() + hours * 3600_000);
    }

    let row;
    try {
      const res = await db.query(
        `INSERT INTO break_glass_grants
           (id, rule_id, subject_user_ref, subject_email, team, status, reason,
            ticket_ref, policy_hash, requested_by, requested_at, decided_by,
            decided_at, decision_note, expires_at, requested_ttl_hours,
            created_at, updated_at)
         VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $11, $11)
         RETURNING *`,
        [
          id,
          ruleR.value,
          subjectR.value,
          emailR.value,
          teamR.value,
          status,
          reasonR.value,
          ticketR.value,
          policyR.value,
          actor,
          now.toISOString(),
          decidedBy,
          decidedAt ? decidedAt.toISOString() : null,
          decisionNote,
          expiresAt ? expiresAt.toISOString() : null,
          ttl,
        ],
      );
      row = res.rows[0];
      await appendGrantEvent(db, id, 'requested', actor, {
        reason: reasonR.value,
        ticketRef: ticketR.value,
        requestedTtlHours: ttl,
        autoApprove: doAuto,
      });
      if (doAuto) {
        await appendGrantEvent(db, id, 'approved', actor, {
          expiresAt: expiresAt.toISOString(),
          decisionNote,
        });
      }
    } catch (err) {
      if (isMissingTable(err)) return missingTableReply(reply);
      throw err;
    }

    appendAudit(actor, 'break_glass.grant.request', `break-glass/grants/${id}`, {
      grantId: id,
      status,
      subjectUserRef: subjectR.value,
      ruleId: ruleR.value,
      autoApprove: doAuto,
    });

    return reply.code(201).send({
      grant: shapeGrant(row, now),
      note: doAuto
        ? 'Grant approved immediately (admin autoApprove). Deploy active-grants to endpoints if manager-required mode is on.'
        : 'Grant pending manager approval. Admin must approve before the endpoint will honor it under secret_override_requires_manager.',
    });
  });

  async function loadGrant(id) {
    const { rows } = await db.query(
      `SELECT * FROM break_glass_grants WHERE id = $1::uuid`,
      [id],
    );
    return rows[0] ?? null;
  }

  fastify.post('/api/enforcement/break-glass/grants/:id/approve', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const actor = actorEmail(req);
    if (!actor) {
      return reply.code(401).send({ error: 'unauthenticated' });
    }
    const id = req.params.id;
    const body = req.body ?? {};
    const noteR = normalizeText(body.decisionNote ?? body.decision_note, {
      max: 2000, field: 'decisionNote',
    });
    if (noteR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: noteR.error });
    }

    const now = nowFn();
    let row;
    try {
      row = await loadGrant(id);
    } catch (err) {
      if (isMissingTable(err)) return missingTableReply(reply);
      throw err;
    }
    if (!row) return reply.code(404).send({ error: 'not_found' });
    if (row.status === 'approved') {
      const shaped = shapeGrant(row, now);
      if (shaped.status === 'expired') {
        return reply.code(409).send({
          error: 'conflict',
          detail: 'grant already expired; create a new request',
          grant: shaped,
        });
      }
      return { grant: shaped, status: 'already_approved' };
    }
    if (row.status !== 'pending') {
      return reply.code(409).send({
        error: 'conflict',
        detail: `cannot approve grant in status ${row.status}`,
        grant: shapeGrant(row, now),
      });
    }

    const hours = parseTtlHours(
      body.ttlHours ?? body.ttl_hours,
      row.requested_ttl_hours ?? DEFAULT_TTL_HOURS,
    );
    if (hours == null) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: `ttlHours must be ${MIN_TTL_HOURS}..${MAX_TTL_HOURS}`,
      });
    }
    const expiresAt = new Date(now.getTime() + hours * 3600_000);

    const { rows } = await db.query(
      `UPDATE break_glass_grants
          SET status = 'approved',
              decided_by = $2,
              decided_at = $3,
              decision_note = $4,
              expires_at = $5,
              updated_at = $3
        WHERE id = $1::uuid AND status = 'pending'
        RETURNING *`,
      [id, actor, now.toISOString(), noteR.value, expiresAt.toISOString()],
    );
    if (!rows[0]) {
      return reply.code(409).send({ error: 'conflict', detail: 'grant status changed concurrently' });
    }
    await appendGrantEvent(db, id, 'approved', actor, {
      expiresAt: expiresAt.toISOString(),
      ttlHours: hours,
      decisionNote: noteR.value,
    });
    appendAudit(actor, 'break_glass.grant.approve', `break-glass/grants/${id}`, {
      grantId: id,
      subjectUserRef: rows[0].subject_user_ref,
      expiresAt: expiresAt.toISOString(),
      ttlHours: hours,
    });
    return { grant: shapeGrant(rows[0], now), status: 'approved' };
  });

  fastify.post('/api/enforcement/break-glass/grants/:id/deny', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const actor = actorEmail(req);
    if (!actor) return reply.code(401).send({ error: 'unauthenticated' });
    const id = req.params.id;
    const body = req.body ?? {};
    const noteR = normalizeText(body.decisionNote ?? body.decision_note ?? body.reason, {
      required: true, max: 2000, field: 'decisionNote',
    });
    if (noteR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: noteR.error });
    }
    const now = nowFn();
    let row;
    try {
      row = await loadGrant(id);
    } catch (err) {
      if (isMissingTable(err)) return missingTableReply(reply);
      throw err;
    }
    if (!row) return reply.code(404).send({ error: 'not_found' });
    if (row.status !== 'pending') {
      return reply.code(409).send({
        error: 'conflict',
        detail: `cannot deny grant in status ${row.status}`,
        grant: shapeGrant(row, now),
      });
    }
    const { rows } = await db.query(
      `UPDATE break_glass_grants
          SET status = 'denied',
              decided_by = $2,
              decided_at = $3,
              decision_note = $4,
              updated_at = $3
        WHERE id = $1::uuid AND status = 'pending'
        RETURNING *`,
      [id, actor, now.toISOString(), noteR.value],
    );
    if (!rows[0]) {
      return reply.code(409).send({ error: 'conflict', detail: 'grant status changed concurrently' });
    }
    await appendGrantEvent(db, id, 'denied', actor, { decisionNote: noteR.value });
    appendAudit(actor, 'break_glass.grant.deny', `break-glass/grants/${id}`, {
      grantId: id,
      subjectUserRef: rows[0].subject_user_ref,
    });
    return { grant: shapeGrant(rows[0], now), status: 'denied' };
  });

  fastify.post('/api/enforcement/break-glass/grants/:id/revoke', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const actor = actorEmail(req);
    if (!actor) return reply.code(401).send({ error: 'unauthenticated' });
    const id = req.params.id;
    const body = req.body ?? {};
    const reasonR = normalizeText(body.reason ?? body.revokeReason ?? body.revoke_reason, {
      required: true, max: 2000, field: 'reason',
    });
    if (reasonR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: reasonR.error });
    }
    const now = nowFn();
    let row;
    try {
      row = await loadGrant(id);
    } catch (err) {
      if (isMissingTable(err)) return missingTableReply(reply);
      throw err;
    }
    if (!row) return reply.code(404).send({ error: 'not_found' });
    const shaped = shapeGrant(row, now);
    if (shaped.status === 'revoked') {
      return { grant: shaped, status: 'already_revoked' };
    }
    if (shaped.status !== 'approved') {
      return reply.code(409).send({
        error: 'conflict',
        detail: `cannot revoke grant in status ${shaped.status}`,
        grant: shaped,
      });
    }
    const { rows } = await db.query(
      `UPDATE break_glass_grants
          SET status = 'revoked',
              revoked_by = $2,
              revoked_at = $3,
              revoke_reason = $4,
              updated_at = $3
        WHERE id = $1::uuid AND status = 'approved'
        RETURNING *`,
      [id, actor, now.toISOString(), reasonR.value],
    );
    if (!rows[0]) {
      return reply.code(409).send({ error: 'conflict', detail: 'grant status changed concurrently' });
    }
    await appendGrantEvent(db, id, 'revoked', actor, { reason: reasonR.value });
    appendAudit(actor, 'break_glass.grant.revoke', `break-glass/grants/${id}`, {
      grantId: id,
      subjectUserRef: rows[0].subject_user_ref,
      reason: reasonR.value,
    });
    return { grant: shapeGrant(rows[0], now), status: 'revoked' };
  });

  fastify.get('/api/enforcement/break-glass/grants/:id/events', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const id = req.params.id;
    try {
      const grant = await loadGrant(id);
      if (!grant) return reply.code(404).send({ error: 'not_found' });
      const { rows } = await db.query(
        `SELECT * FROM break_glass_grant_events
          WHERE grant_id = $1::uuid
          ORDER BY created_at ASC, id ASC`,
        [id],
      );
      return {
        grant: shapeGrant(grant, nowFn()),
        events: rows.map(shapeGrantEvent),
      };
    } catch (err) {
      if (isMissingTable(err)) return missingTableReply(reply);
      throw err;
    }
  });

  // Compliance evidence pack: grants + lifecycle events (+ optional endpoint
  // confirmed summary) for a window. format=json (default) | csv | bundle.
  fastify.get('/api/enforcement/break-glass/audit-export', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    if (!checkFormat(req, reply, ['bundle'])) return reply;

    const days = parseDays(req.query);
    const now = nowFn();
    const from = new Date(now.getTime() - days * 86400_000);

    try {
      await expireStaleGrants(db, now);
    } catch (err) {
      if (isMissingTable(err)) return missingTableReply(reply);
      throw err;
    }

    let grants = [];
    let lifecycle = [];
    try {
      const gRes = await db.query(
        `SELECT * FROM break_glass_grants
          WHERE requested_at >= $1
          ORDER BY requested_at ASC, id ASC`,
        [from.toISOString()],
      );
      grants = gRes.rows.map((r) => shapeGrant(r, now));
      const eRes = await db.query(
        `SELECT e.*
           FROM break_glass_grant_events e
           JOIN break_glass_grants g ON g.id = e.grant_id
          WHERE e.created_at >= $1
          ORDER BY e.created_at ASC, e.id ASC`,
        [from.toISOString()],
      );
      lifecycle = eRes.rows.map(shapeGrantEvent);
    } catch (err) {
      if (isMissingTable(err)) return missingTableReply(reply);
      throw err;
    }

    // Optional endpoint confirmed summary (same window) — best-effort.
    let endpointSummary = null;
    try {
      const { rows } = await db.query(
        `SELECT e.payload->'enforcement'->>'action' AS action,
                e.payload->'enforcement'->>'rule_id' AS rule_id,
                COUNT(*)::int AS n
           FROM events e
          WHERE e.ts >= $1
            AND e.payload ? 'enforcement'
          GROUP BY 1, 2
          ORDER BY n DESC`,
        [from.toISOString()],
      );
      endpointSummary = {
        byRule: rows.map((r) => ({
          action: r.action,
          ruleId: r.rule_id,
          count: Number(r.n) || 0,
        })),
        breakGlassCount: rows
          .filter((r) => r.action === 'confirmed' && r.rule_id === 'secret-pattern-in-prompt')
          .reduce((s, r) => s + (Number(r.n) || 0), 0),
      };
    } catch {
      endpointSummary = { note: 'events table unavailable; grant lifecycle only' };
    }

    const pack = {
      kind: 'aim.break_glass.audit_export',
      version: 1,
      generatedAt: now.toISOString(),
      period: { from: from.toISOString(), to: now.toISOString(), days },
      grants,
      lifecycleEvents: lifecycle,
      endpointSummary,
      policyNote:
        'secret_override_requires_manager defaults to false (pilot resubmit path). '
        + 'Do not enable manager-required mode without CEO/Security sign-off. '
        + 'No prompt text or secret content is present in this pack.',
    };

    appendAudit(
      actorEmail(req) ?? 'unknown',
      'break_glass.audit_export',
      'break-glass/audit-export',
      { days, grants: grants.length, lifecycleEvents: lifecycle.length },
    );

    if (wantsCsv(req)) {
      // Multi-section CSV: grants then lifecycle (section markers as comment rows).
      const gPart = toCsv(GRANT_CSV_COLS, grants);
      const ePart = toCsv(GRANT_EVENT_CSV_COLS, lifecycle.map((e) => ({
        ...e,
        detail: JSON.stringify(e.detail ?? {}),
      })));
      const body = [
        `# aim.break_glass.audit_export grants days=${days}`,
        gPart.trimEnd(),
        '',
        `# lifecycle_events`,
        ePart.trimEnd(),
        '',
      ].join('\r\n') + '\r\n';
      return reply
        .header('content-type', 'text/csv; charset=utf-8')
        .header('content-disposition', `attachment; filename="aim-break-glass-audit-${days}d.csv"`)
        .send(body);
    }

    if (req.query?.format === 'bundle') {
      // Same JSON with explicit evidence-pack framing for compliance binders.
      return reply
        .header('content-disposition', `attachment; filename="aim-break-glass-audit-${days}d.json"`)
        .send(pack);
    }
    return pack;
  });
}

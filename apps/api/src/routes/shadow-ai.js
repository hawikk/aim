// Shadow AI discovery API (AIM-300 / AIM-504 / AIM-776 / AIM-778).
//
// Views over tables written by services/shadow-ai:
//   shadow_ai_tools            — aggregate tool inventory (no per-user fields)
//   shadow_ai_grants           — IdP OAuth grants (pseudonym only)
//   shadow_ai_findings         — unapproved_ai_saas_grant findings (pseudonym only)
//   shadow_ai_discovery_queue  — uncatalogued IdP apps awaiting catalogue PR
//   shadow_ai_dispositions     — append-only analyst allow/watch/propose_enforce/known_non_ai
//
// Honesty rules the frontend depends on:
//   * identity_count passes through NULL (unattributed → adoption unknown);
//     it is never estimated or zero-filled.
//   * sanctioned passes through NULL (unknown/uncatalogued) — three states,
//     not a boolean.
//   * grants list exposes user_ref (HMAC pseudonym) only; reveal is the
//     identity-sync /reveal path (audited, separate grant).
import { randomUUID } from 'node:crypto';
import { query } from '../db.js';
import { requireRoles } from '../auth.js';
import { audit } from '../audit.js';
import { wantsCsv, checkFormat, sendCsv } from '../csv.js';

const DISPOSITION_TARGET_KINDS = new Set(['finding', 'app', 'tool']);
const DISPOSITION_ACTIONS = new Set([
  'allow',
  'watch',
  'propose_enforce',
  'known_non_ai',
  'catalogue',
]);

// AIM-776 discovery-queue statuses + legal transitions (open is the default).
const DISCOVERY_STATUSES = new Set([
  'open',
  'proposed',
  'catalogued',
  'dismissed',
  'known_non_ai',
]);
const DISCOVERY_TRANSITIONS = {
  open: new Set(['proposed', 'catalogued', 'dismissed', 'known_non_ai']),
  proposed: new Set(['open', 'catalogued', 'dismissed', 'known_non_ai']),
  catalogued: new Set(['open', 'proposed']),
  dismissed: new Set(['open', 'proposed']),
  known_non_ai: new Set(['open', 'proposed']),
};

const jsonb = (v, fallback) => {
  if (v == null) return fallback;
  if (typeof v === 'string') {
    try {
      return JSON.parse(v);
    } catch {
      return fallback;
    }
  }
  return v;
};

const toIso = (v) => (v == null ? null : v instanceof Date ? v.toISOString() : String(v));

function toTool(r) {
  return {
    toolId: String(r.tool_id),
    name: String(r.name),
    vendor: r.vendor ?? null,
    catalogued: Boolean(r.catalogued),
    sanctioned: r.sanctioned ?? null,
    dataAccessClass: r.data_access_class ?? null,
    sources: jsonb(r.sources, []),
    attribution: String(r.attribution),
    identityCount: r.identity_count ?? null,
    scopes: jsonb(r.scopes, []),
    scopeClasses: jsonb(r.scope_classes, []),
    firstSeen: toIso(r.first_seen),
    lastSeen: toIso(r.last_seen),
    riskScore: Number(r.risk_score) || 0,
    riskBand: String(r.risk_band),
    riskComponents: jsonb(r.risk_components, []),
    computedAt: toIso(r.computed_at),
  };
}

function toGrant(r) {
  return {
    userRef: String(r.user_pseudonym),
    appName: String(r.app_name),
    toolId: r.tool_id ?? null,
    clientId: r.client_id ?? null,
    idpSource: String(r.idp_source),
    scopes: jsonb(r.scopes, []),
    firstSeen: toIso(r.first_seen),
    lastSeen: toIso(r.last_seen),
    lastAction: String(r.last_action),
    sanctioned: r.sanctioned ?? null,
    catalogued: r.catalogued == null ? null : Boolean(r.catalogued),
    findingType: r.finding_type ?? null,
    findingId: r.finding_id ?? null,
    severity: r.severity ?? null,
  };
}

const SHADOW_AI_CSV_COLS = [
  { key: 'tool_id', label: 'tool_id' },
  { key: 'name', label: 'name' },
  { key: 'vendor', label: 'vendor' },
  { key: 'catalogued', label: 'catalogued' },
  { key: 'sanctioned', label: 'sanctioned' },
  { key: 'data_access_class', label: 'data_access_class' },
  { key: 'attribution', label: 'attribution' },
  { key: 'identity_count', label: 'identity_count' },
  { key: 'scope_classes', label: 'scope_classes' },
  { key: 'first_seen', label: 'first_seen' },
  { key: 'last_seen', label: 'last_seen' },
  { key: 'risk_score', label: 'risk_score' },
  { key: 'risk_band', label: 'risk_band' },
];

const GRANTS_CSV_COLS = [
  { key: 'user_ref', label: 'user_ref' },
  { key: 'app_name', label: 'app_name' },
  { key: 'tool_id', label: 'tool_id' },
  { key: 'idp_source', label: 'idp_source' },
  { key: 'client_id', label: 'client_id' },
  { key: 'scopes', label: 'scopes' },
  { key: 'first_seen', label: 'first_seen' },
  { key: 'last_seen', label: 'last_seen' },
  { key: 'sanctioned', label: 'sanctioned' },
  { key: 'catalogued', label: 'catalogued' },
  { key: 'finding_type', label: 'finding_type' },
  { key: 'severity', label: 'severity' },
];

function toCsvRow(t) {
  return {
    tool_id: t.toolId,
    name: t.name,
    vendor: t.vendor,
    catalogued: t.catalogued,
    sanctioned: t.sanctioned,
    data_access_class: t.dataAccessClass,
    attribution: t.attribution,
    identity_count: t.identityCount,
    scope_classes: t.scopeClasses.join(';'),
    first_seen: t.firstSeen,
    last_seen: t.lastSeen,
    risk_score: t.riskScore,
    risk_band: t.riskBand,
  };
}

function toGrantCsvRow(g) {
  return {
    user_ref: g.userRef,
    app_name: g.appName,
    tool_id: g.toolId,
    idp_source: g.idpSource,
    client_id: g.clientId,
    scopes: (g.scopes || []).join(';'),
    first_seen: g.firstSeen,
    last_seen: g.lastSeen,
    sanctioned: g.sanctioned,
    catalogued: g.catalogued,
    finding_type: g.findingType,
    severity: g.severity,
  };
}

function toDisposition(r) {
  return {
    dispositionId: String(r.disposition_id),
    targetKind: String(r.target_kind),
    targetKey: String(r.target_key),
    action: String(r.action),
    reason: String(r.reason),
    actor: String(r.actor),
    findingId: r.finding_id ?? null,
    appName: r.app_name ?? null,
    toolId: r.tool_id ?? null,
    clientId: r.client_id ?? null,
    metadata: jsonb(r.metadata, {}),
    createdAt: toIso(r.created_at),
  };
}

function toDiscoveryCandidate(r) {
  return {
    queueId: String(r.queue_id),
    appName: String(r.app_name),
    clientId: r.client_id ? String(r.client_id) : null,
    idpSources: jsonb(r.idp_sources, []),
    identityCount: Number(r.identity_count) || 0,
    grantCount: Number(r.grant_count) || 0,
    firstSeen: toIso(r.first_seen),
    lastSeen: toIso(r.last_seen),
    proposedToolId: r.proposed_tool_id ?? null,
    proposedEntry: jsonb(r.proposed_entry, null),
    status: String(r.status),
    updatedAt: toIso(r.updated_at),
  };
}

/** Age of oldest open discovery candidate in seconds (null when queue empty). */
function oldestOpenAgeSeconds(firstSeenIso) {
  if (!firstSeenIso) return null;
  const t = Date.parse(firstSeenIso);
  if (!Number.isFinite(t)) return null;
  return Math.max(0, Math.floor((Date.now() - t) / 1000));
}

function normalizeDispositionBody(body) {
  const b = body && typeof body === 'object' ? body : {};
  const targetKind = String(b.targetKind ?? b.target_kind ?? '')
    .trim()
    .toLowerCase();
  const action = String(b.action ?? '')
    .trim()
    .toLowerCase();
  let targetKey = String(b.targetKey ?? b.target_key ?? '').trim();
  if (targetKind === 'app') targetKey = targetKey.toLowerCase();
  const reason = String(b.reason ?? '').trim();
  const findingId = b.findingId ?? b.finding_id ?? null;
  const appName = b.appName ?? b.app_name ?? null;
  const toolId = b.toolId ?? b.tool_id ?? null;
  const clientId = b.clientId ?? b.client_id ?? null;
  const metadata =
    b.metadata && typeof b.metadata === 'object' && !Array.isArray(b.metadata)
      ? b.metadata
      : {};

  if (!DISPOSITION_TARGET_KINDS.has(targetKind)) {
    return {
      error: `targetKind must be one of ${[...DISPOSITION_TARGET_KINDS].join(', ')}`,
    };
  }
  if (!DISPOSITION_ACTIONS.has(action)) {
    return {
      error: `action must be one of ${[...DISPOSITION_ACTIONS].join(', ')}`,
    };
  }
  if (!targetKey) {
    return { error: 'targetKey is required' };
  }
  if (!reason) {
    return { error: 'reason is required' };
  }

  return {
    targetKind,
    targetKey,
    action,
    reason,
    findingId: findingId != null ? String(findingId) : targetKind === 'finding' ? targetKey : null,
    appName:
      appName != null
        ? String(appName)
        : targetKind === 'app'
          ? String(b.targetKey ?? b.target_key ?? '').trim() || null
          : null,
    toolId: toolId != null ? String(toolId) : targetKind === 'tool' ? targetKey : null,
    clientId: clientId != null ? String(clientId) : null,
    metadata,
  };
}

// opts.db is injectable for tests; defaults to the real pg pool.
export async function shadowAiRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  // Shadow AI inventory is operator/security data: analyst+ (same gate as
  // /api/fleet and the findings console, AIM-95).
  const userLevel = requireRoles('analyst', 'security-admin', 'admin');

  // ---- discovered AI tools, worst risk first ----
  fastify.get('/api/shadow-ai/tools', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const { rows } = await db.query(
      `SELECT tool_id, name, vendor, catalogued, sanctioned, data_access_class,
              sources, attribution, identity_count, scopes, scope_classes,
              first_seen, last_seen, risk_score, risk_band, risk_components,
              computed_at
         FROM shadow_ai_tools
        ORDER BY risk_score DESC, name ASC`
    );
    const tools = rows.map(toTool);
    if (wantsCsv(req)) {
      return sendCsv(reply, 'aim-shadow-ai-tools.csv', SHADOW_AI_CSV_COLS, tools.map(toCsvRow));
    }
    return { tools };
  });

  // ---- AIM-504: AI SaaS apps authorized via corporate IdP (pseudonyms) ----
  // Left-join findings so ChatGPT-class grants surface with finding_type =
  // unapproved_ai_saas_grant when the sync job emitted one.
  fastify.get('/api/shadow-ai/grants', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const idp = typeof req.query?.idp === 'string' ? req.query.idp.trim() : '';
    const app = typeof req.query?.app === 'string' ? req.query.app.trim() : '';
    const findingsOnly = req.query?.findings === '1' || req.query?.findings === 'true';

    const params = [];
    const where = ["g.last_action = 'authorize'"];
    if (idp) {
      params.push(idp);
      where.push(`g.idp_source = $${params.length}`);
    }
    if (app) {
      params.push(app);
      where.push(`g.app_name ILIKE $${params.length}`);
      params[params.length - 1] = `%${app}%`;
    }
    if (findingsOnly) {
      where.push('f.finding_id IS NOT NULL');
    }

    const { rows } = await db.query(
      `SELECT g.user_pseudonym, g.app_name, g.client_id, g.idp_source, g.scopes,
              g.first_seen, g.last_seen, g.last_action,
              f.finding_id, f.rule_id AS finding_type, f.severity,
              f.tool_id, f.sanctioned, f.catalogued
         FROM shadow_ai_grants g
         LEFT JOIN shadow_ai_findings f
           ON f.user_pseudonym = g.user_pseudonym
          AND f.app_name = g.app_name
          AND f.idp_source = g.idp_source
        WHERE ${where.join(' AND ')}
        ORDER BY g.last_seen DESC, g.app_name ASC
        LIMIT 2000`,
      params
    );
    const grants = rows.map(toGrant);
    if (wantsCsv(req)) {
      return sendCsv(reply, 'aim-shadow-ai-grants.csv', GRANTS_CSV_COLS, grants.map(toGrantCsvRow));
    }
    return { grants };
  });

  // ---- headline counts for the summary strip ----
  fastify.get('/api/shadow-ai/summary', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const { rows } = await db.query(
      `SELECT sanctioned, catalogued, risk_band, computed_at
         FROM shadow_ai_tools`
    );
    let grantCount = 0;
    let findingCount = 0;
    let chatgptGrants = 0;
    // AIM-777: multi-IdP inventory must surface per-source grant counts so
    // operators can see Entra vs Okta vs Google coverage at pilot/prod scale.
    let grantsByIdpSource = {};
    // AIM-776: catalogue-ops lag — open discovery candidates + oldest age.
    let discoveryQueueOpen = 0;
    let discoveryQueueOldestOpenAgeSeconds = null;
    let discoveryQueueOldestOpenFirstSeen = null;
    try {
      const g = await db.query(
        `SELECT
           COUNT(*) FILTER (WHERE last_action = 'authorize') AS grants,
           (SELECT COUNT(*) FROM shadow_ai_findings WHERE rule_id = 'unapproved_ai_saas_grant') AS findings,
           COUNT(*) FILTER (
             WHERE last_action = 'authorize'
               AND lower(app_name) LIKE '%chatgpt%'
           ) AS chatgpt
         FROM shadow_ai_grants`
      );
      grantCount = Number(g.rows[0]?.grants) || 0;
      findingCount = Number(g.rows[0]?.findings) || 0;
      chatgptGrants = Number(g.rows[0]?.chatgpt) || 0;

      const byIdp = await db.query(
        `SELECT idp_source, COUNT(*)::int AS n
           FROM shadow_ai_grants
          WHERE last_action = 'authorize'
          GROUP BY idp_source
          ORDER BY idp_source`
      );
      grantsByIdpSource = Object.fromEntries(
        (byIdp.rows || []).map((r) => [String(r.idp_source), Number(r.n) || 0]),
      );

      const lag = await db.query(
        `SELECT COUNT(*)::int AS open_count,
                MIN(first_seen) AS oldest_first_seen
           FROM shadow_ai_discovery_queue
          WHERE status = 'open'`
      );
      discoveryQueueOpen = Number(lag.rows[0]?.open_count) || 0;
      const oldest = toIso(lag.rows[0]?.oldest_first_seen);
      discoveryQueueOldestOpenFirstSeen = oldest;
      discoveryQueueOldestOpenAgeSeconds = oldestOpenAgeSeconds(oldest);
    } catch {
      // tables may be empty/missing in unit tests that only seed tools
    }
    const summary = {
      total: rows.length,
      sanctioned: 0,
      unsanctioned: 0,
      uncatalogued: 0,
      by_band: { critical: 0, high: 0, medium: 0, low: 0 },
      computed_at: null,
      active_grants: grantCount,
      // snake_case to match existing summary fields (active_grants, by_band).
      grants_by_idp_source: grantsByIdpSource,
      unapproved_ai_saas_grant_findings: findingCount,
      chatgpt_grants: chatgptGrants,
      discovery_queue_open: discoveryQueueOpen,
      discovery_queue_oldest_open_age_seconds: discoveryQueueOldestOpenAgeSeconds,
      discovery_queue_oldest_open_first_seen: discoveryQueueOldestOpenFirstSeen,
    };
    for (const r of rows) {
      if (r.sanctioned === true) summary.sanctioned += 1;
      else if (r.sanctioned === false) summary.unsanctioned += 1;
      if (!r.catalogued) summary.uncatalogued += 1;
      if (r.risk_band in summary.by_band) summary.by_band[r.risk_band] += 1;
      const at = toIso(r.computed_at);
      if (at && (!summary.computed_at || at > summary.computed_at)) summary.computed_at = at;
    }
    return summary;
  });

  // ---- AIM-776: continuous catalogue ops discovery queue ----
  // Uncatalogued IdP apps waiting for a catalogue PR. Draft entry lives in
  // proposed_entry. Status transitions: open → proposed|catalogued|dismissed|known_non_ai.
  fastify.get('/api/shadow-ai/discovery-queue', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const status = typeof req.query?.status === 'string' ? req.query.status.trim().toLowerCase() : '';
    if (status && !DISCOVERY_STATUSES.has(status)) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: `status must be one of ${[...DISCOVERY_STATUSES].join(', ')}`,
      });
    }
    const params = [];
    let where = '';
    if (status) {
      params.push(status);
      where = `WHERE status = $${params.length}`;
    }
    let rows = [];
    let openCount = 0;
    let oldestFirstSeen = null;
    try {
      const result = await db.query(
        `SELECT queue_id, app_name, client_id, idp_sources, identity_count, grant_count,
                first_seen, last_seen, proposed_tool_id, proposed_entry, status, updated_at
           FROM shadow_ai_discovery_queue
           ${where}
          ORDER BY last_seen DESC, app_name ASC
          LIMIT 2000`,
        params
      );
      rows = result.rows || [];
      const lag = await db.query(
        `SELECT COUNT(*)::int AS open_count,
                MIN(first_seen) AS oldest_first_seen
           FROM shadow_ai_discovery_queue
          WHERE status = 'open'`
      );
      openCount = Number(lag.rows[0]?.open_count) || 0;
      oldestFirstSeen = toIso(lag.rows[0]?.oldest_first_seen);
    } catch {
      // table may be missing in unit tests that only seed tools
    }
    return {
      candidates: rows.map(toDiscoveryCandidate),
      discovery_queue_open: openCount,
      discovery_queue_oldest_open_age_seconds: oldestOpenAgeSeconds(oldestFirstSeen),
      discovery_queue_oldest_open_first_seen: oldestFirstSeen,
    };
  });

  fastify.patch('/api/shadow-ai/discovery-queue/:queueId', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const queueId = String(req.params?.queueId || '').trim();
    if (!queueId) {
      return reply.code(400).send({ error: 'bad_request', detail: 'queueId is required' });
    }
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const newStatus = String(body.status ?? '').trim().toLowerCase();
    if (!DISCOVERY_STATUSES.has(newStatus)) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: `status must be one of ${[...DISCOVERY_STATUSES].join(', ')}`,
      });
    }
    try {
      const cur = await db.query(
        `SELECT queue_id, app_name, client_id, idp_sources, identity_count, grant_count,
                first_seen, last_seen, proposed_tool_id, proposed_entry, status, updated_at
           FROM shadow_ai_discovery_queue
          WHERE queue_id = $1`,
        [queueId]
      );
      if (!cur.rows?.length) {
        return reply.code(404).send({ error: 'not_found', detail: 'queue candidate not found' });
      }
      const current = cur.rows[0];
      if (current.status === newStatus) {
        return toDiscoveryCandidate(current);
      }
      const allowed = DISCOVERY_TRANSITIONS[current.status] || new Set();
      if (!allowed.has(newStatus)) {
        return reply.code(400).send({
          error: 'bad_request',
          detail: `cannot transition ${current.status} → ${newStatus}`,
        });
      }
      const upd = await db.query(
        `UPDATE shadow_ai_discovery_queue
            SET status = $2, updated_at = now()
          WHERE queue_id = $1
          RETURNING queue_id, app_name, client_id, idp_sources, identity_count, grant_count,
                    first_seen, last_seen, proposed_tool_id, proposed_entry, status, updated_at`,
        [queueId, newStatus]
      );
      const row = upd.rows[0];
      const actor = req.identity?.email ?? 'unknown';
      audit(actor, 'shadow_ai.discovery_queue.status', `shadow-ai/discovery-queue/${queueId}`, {
        from: current.status,
        to: newStatus,
        appName: row?.app_name,
      });
      return toDiscoveryCandidate(row);
    } catch (err) {
      req.log?.error?.({ err }, 'shadow-ai.discovery_queue transition failed');
      return reply.code(500).send({ error: 'internal_error', detail: 'status transition failed' });
    }
  });

  // ---- AIM-778: append-only analyst dispositions (allow / watch / enforce) ----
  // Latest row per (target_kind, target_key) is the active disposition.
  // Findings builder (services/shadow-ai) honors allow / known_non_ai on re-sync.
  fastify.get('/api/shadow-ai/dispositions', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const action = typeof req.query?.action === 'string' ? req.query.action.trim().toLowerCase() : '';
    const limitRaw = Number(req.query?.limit);
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(1, Math.trunc(limitRaw)), 1000) : 200;
    const params = [];
    let where = '';
    if (action) {
      if (!DISPOSITION_ACTIONS.has(action)) {
        return reply.code(400).send({
          error: 'bad_request',
          detail: `action must be one of ${[...DISPOSITION_ACTIONS].join(', ')}`,
        });
      }
      params.push(action);
      where = `WHERE action = $${params.length}`;
    }
    params.push(limit);
    const { rows } = await db.query(
      `SELECT disposition_id, target_kind, target_key, action, reason, actor,
              finding_id, app_name, tool_id, client_id, metadata, created_at
         FROM shadow_ai_dispositions
         ${where}
        ORDER BY created_at DESC
        LIMIT $${params.length}`,
      params
    );
    return { dispositions: rows.map(toDisposition) };
  });

  fastify.post('/api/shadow-ai/dispositions', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const parsed = normalizeDispositionBody(req.body);
    if (parsed.error) {
      return reply.code(400).send({ error: 'bad_request', detail: parsed.error });
    }
    const actor = req.identity?.email ?? 'unknown';
    const dispositionId = randomUUID();
    try {
      const { rows } = await db.query(
        `INSERT INTO shadow_ai_dispositions (
           disposition_id, target_kind, target_key, action, reason, actor,
           finding_id, app_name, tool_id, client_id, metadata
         ) VALUES (
           $1, $2, $3, $4, $5, $6,
           $7, $8, $9, $10, $11::jsonb
         )
         RETURNING disposition_id, target_kind, target_key, action, reason, actor,
                   finding_id, app_name, tool_id, client_id, metadata, created_at`,
        [
          dispositionId,
          parsed.targetKind,
          parsed.targetKey,
          parsed.action,
          parsed.reason,
          actor,
          parsed.findingId,
          parsed.appName,
          parsed.toolId,
          parsed.clientId,
          JSON.stringify(parsed.metadata),
        ]
      );
      const row = rows[0];
      audit(actor, 'shadow_ai.disposition', `shadow-ai/dispositions/${dispositionId}`, {
        targetKind: parsed.targetKind,
        targetKey: parsed.targetKey,
        action: parsed.action,
      });
      return reply.code(201).send(toDisposition(row));
    } catch (err) {
      req.log?.error?.({ err }, 'shadow-ai.disposition failed');
      return reply.code(500).send({ error: 'internal_error', detail: 'disposition insert failed' });
    }
  });

  // Active propose_enforce rows for blocklist export (latest action wins).
  fastify.get('/api/shadow-ai/blocklist-candidates', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    // Distinct on (target_kind, target_key) keeping the newest row; filter to
    // propose_enforce only. DISTINCT ON requires ORDER BY to start with the
    // distinct columns (Postgres).
    const { rows } = await db.query(
      `SELECT disposition_id, target_kind, target_key, action, reason, actor,
              finding_id, app_name, tool_id, client_id, metadata, created_at
         FROM (
           SELECT DISTINCT ON (target_kind, target_key)
                  disposition_id, target_kind, target_key, action, reason, actor,
                  finding_id, app_name, tool_id, client_id, metadata, created_at
             FROM shadow_ai_dispositions
            ORDER BY target_kind, target_key, created_at DESC
         ) latest
        WHERE action = 'propose_enforce'
        ORDER BY COALESCE(app_name, target_key), created_at`
    );
    const candidates = rows.map(toDisposition);
    if (wantsCsv(req)) {
      return sendCsv(
        reply,
        'aim-shadow-ai-blocklist-candidates.csv',
        [
          { key: 'target_kind', label: 'target_kind' },
          { key: 'target_key', label: 'target_key' },
          { key: 'app_name', label: 'app_name' },
          { key: 'tool_id', label: 'tool_id' },
          { key: 'client_id', label: 'client_id' },
          { key: 'reason', label: 'reason' },
          { key: 'actor', label: 'actor' },
          { key: 'created_at', label: 'created_at' },
        ],
        candidates.map((c) => ({
          target_kind: c.targetKind,
          target_key: c.targetKey,
          app_name: c.appName,
          tool_id: c.toolId,
          client_id: c.clientId,
          reason: c.reason,
          actor: c.actor,
          created_at: c.createdAt,
        }))
      );
    }
    return { candidates };
  });
}

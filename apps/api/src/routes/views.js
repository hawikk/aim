// Saved views API. Per-user persisted filter sets for the
// findings console and the activity trail: a named filter combination the
// dashboard can restore across sessions.
//
// Privacy posture: rows are per-user UI preferences (owner_email + filter
// criteria) — no telemetry content, no pseudonyms, no finding payloads.
// Any authenticated user may manage THEIR OWN views (no security-group gate);
// the data APIs the views point at keep their own gates.
// Existence of another user's view is never leaked (404 on foreign ids).
// Mutations are recorded in the immutable audit trail.
import { query } from '../db.js';
import { audit } from '../audit.js';

const NAME_MAX = 80;
const MAX_VIEWS_PER_USER = 50;
const STRING_MAX = 200;
const VIEW_KINDS = ['findings', 'activity'];
const FILTER_STATUSES = ['open', 'new', 'acknowledged', 'resolved', 'false_positive', 'all'];
const FILTER_SEVERITIES = ['all', 'critical', 'high', 'medium', 'low'];
const FILTER_DAYS = [7, 30, 90];
const FINDINGS_KEYS = ['view', 'status', 'severity', 'ruleId', 'days'];
const ACTIVITY_KEYS = ['view', 'tool', 'event_type', 'user', 'minScore'];

// Server-side contract for a saved filter set. `view` is required and selects
// the allowed key set; every other key is optional. Unknown keys, wrong types,
// and out-of-enum values are all rejected (400) so a bad client can never
// persist a filter the dashboard can't interpret.
// Returns an error detail string, or null when valid.
function validateFilters(filters) {
  if (!filters || typeof filters !== 'object' || Array.isArray(filters)) {
    return 'filters must be an object';
  }
  if (!VIEW_KINDS.includes(filters.view)) {
    return `filters.view must be one of ${VIEW_KINDS.join(', ')}`;
  }

  if (filters.view === 'findings') {
    for (const key of Object.keys(filters)) {
      if (!FINDINGS_KEYS.includes(key)) {
        return `unknown filters key '${key}' (allowed: ${FINDINGS_KEYS.join(', ')})`;
      }
    }
    if (filters.status !== undefined && !FILTER_STATUSES.includes(filters.status)) {
      return `filters.status must be one of ${FILTER_STATUSES.join(', ')}`;
    }
    if (filters.severity !== undefined && !FILTER_SEVERITIES.includes(filters.severity)) {
      return `filters.severity must be one of ${FILTER_SEVERITIES.join(', ')}`;
    }
    if (filters.ruleId !== undefined && filters.ruleId !== null && typeof filters.ruleId !== 'string') {
      return 'filters.ruleId must be a string or null';
    }
    if (filters.days !== undefined && !FILTER_DAYS.includes(filters.days)) {
      return `filters.days must be one of ${FILTER_DAYS.join(', ')}`;
    }
    return null;
  }

  // activity
  for (const key of Object.keys(filters)) {
    if (!ACTIVITY_KEYS.includes(key)) {
      return `unknown filters key '${key}' (allowed: ${ACTIVITY_KEYS.join(', ')})`;
    }
  }
  for (const key of ['tool', 'event_type', 'user']) {
    if (filters[key] === undefined || filters[key] === null) continue;
    if (typeof filters[key] !== 'string') return `filters.${key} must be a string or null`;
    if (filters[key].length > STRING_MAX) return `filters.${key} must be at most ${STRING_MAX} chars`;
  }
  if (filters.minScore !== undefined && filters.minScore !== null) {
    const n = filters.minScore;
    if (!Number.isInteger(n) || n < 1 || n > 10) {
      return 'filters.minScore must be an integer 1–10 or null';
    }
  }
  return null;
}

// Returns the trimmed name, or null when invalid.
function validateName(name) {
  if (typeof name !== 'string') return null;
  const trimmed = name.trim();
  return trimmed.length >= 1 && trimmed.length <= NAME_MAX ? trimmed : null;
}

function toView(r) {
  return {
    viewId: r.view_id,
    name: r.name,
    filters: r.filters,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

function isUniqueViolation(err) {
  return err?.code === '23505';
}

// opts.db is injectable for tests; defaults to the real pg pool.
export async function viewsRoutes(fastify, opts) {
  const db = opts?.db ?? { query };

  // ---- list the caller's own views, ordered by name ----
  fastify.get('/api/views', async (req) => {
    const owner = req.identity?.email ?? 'unknown';
    const { rows } = await db.query(
      `SELECT view_id, name, filters, created_at, updated_at
         FROM saved_views WHERE owner_email = $1 ORDER BY name`,
      [owner]
    );
    return { views: rows.map(toView) };
  });

  // ---- create a view. Duplicate name for the same user is a 409; a user
  // may hold at most MAX_VIEWS_PER_USER views. ----
  fastify.post('/api/views', async (req, reply) => {
    const owner = req.identity?.email ?? 'unknown';
    const body = req.body ?? {};
    const name = validateName(body.name);
    if (!name) {
      return reply.code(400).send({ error: 'bad_request', detail: `name must be a string of 1..${NAME_MAX} chars` });
    }
    const filterError = validateFilters(body.filters);
    if (filterError) {
      return reply.code(400).send({ error: 'bad_request', detail: filterError });
    }
    const { rows: countRows } = await db.query(
      'SELECT COUNT(*) AS n FROM saved_views WHERE owner_email = $1',
      [owner]
    );
    if (Number(countRows[0].n) >= MAX_VIEWS_PER_USER) {
      return reply.code(400).send({ error: 'bad_request', detail: `view limit reached (${MAX_VIEWS_PER_USER} per user)` });
    }
    let rows;
    try {
      ({ rows } = await db.query(
        `INSERT INTO saved_views (owner_email, name, filters)
         VALUES ($1, $2, $3) RETURNING view_id, name, filters, created_at, updated_at`,
        [owner, name, JSON.stringify(body.filters)]
      ));
    } catch (err) {
      if (isUniqueViolation(err)) {
        return reply.code(409).send({ error: 'conflict', detail: `you already have a view named '${name}'` });
      }
      throw err;
    }
    audit(owner, 'view.create', `views/${rows[0].view_id}`, { name });
    return reply.code(201).send(toView(rows[0]));
  });

  // ---- update name and/or filters. Owner only — 404 (not 403) when the id
  // is unknown or belongs to someone else, so existence is never leaked. ----
  fastify.put('/api/views/:id', async (req, reply) => {
    const owner = req.identity?.email ?? 'unknown';
    const body = req.body ?? {};
    let name;
    if (body.name !== undefined) {
      name = validateName(body.name);
      if (!name) {
        return reply.code(400).send({ error: 'bad_request', detail: `name must be a string of 1..${NAME_MAX} chars` });
      }
    }
    if (body.filters !== undefined) {
      const filterError = validateFilters(body.filters);
      if (filterError) {
        return reply.code(400).send({ error: 'bad_request', detail: filterError });
      }
    }
    let rows;
    try {
      ({ rows } = await db.query(
        `UPDATE saved_views
            SET name = COALESCE($3, name),
                filters = COALESCE($4, filters),
                updated_at = now()
          WHERE view_id = $1 AND owner_email = $2
          RETURNING view_id, name, filters, created_at, updated_at`,
        [req.params.id, owner, name ?? null, body.filters !== undefined ? JSON.stringify(body.filters) : null]
      ));
    } catch (err) {
      if (isUniqueViolation(err)) {
        return reply.code(409).send({ error: 'conflict', detail: `you already have a view named '${name}'` });
      }
      throw err;
    }
    if (rows.length === 0) {
      return reply.code(404).send({ error: 'not_found', detail: `no view ${req.params.id}` });
    }
    audit(owner, 'view.update', `views/${req.params.id}`, { name: rows[0].name });
    return toView(rows[0]);
  });

  // ---- delete a view. Owner only, same no-leak 404 as PUT. ----
  fastify.delete('/api/views/:id', async (req, reply) => {
    const owner = req.identity?.email ?? 'unknown';
    const { rows } = await db.query(
      'DELETE FROM saved_views WHERE view_id = $1 AND owner_email = $2 RETURNING view_id',
      [req.params.id, owner]
    );
    if (rows.length === 0) {
      return reply.code(404).send({ error: 'not_found', detail: `no view ${req.params.id}` });
    }
    audit(owner, 'view.delete', `views/${req.params.id}`, {});
    return reply.code(204).send();
  });
}

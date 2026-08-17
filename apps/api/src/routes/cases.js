// Investigation cases API (AIM-706).
//
// Cases are the unit of investigation beyond the findings list: open a case,
// attach findings / users / tools (refs only), track status, export a package.
//
// Privacy gate: analyst+ (same tier as /api/findings). Attachments store
// finding UUIDs, user_ref HMAC pseudonyms, and tool names only — never matched
// content or cleartext identity. Mutations are audited (AIM-27).
//
// Validation vocabulary lives in apps/web/public/lib/cases.js and is re-used
// here so the status machine cannot drift between UI and API.

import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { query } from '../db.js';
import { requireRoles } from '../auth.js';
import { audit } from '../audit.js';
import { wantsCsv, checkFormat, sendCsv } from '../csv.js';

const here = dirname(fileURLToPath(import.meta.url));
const casesModelPath = join(here, '..', '..', '..', 'web', 'public', 'lib', 'cases.js');
const {
  CASE_STATUSES,
  CASE_SEVERITIES,
  canTransition,
  validateCreate,
  validatePatch,
  validateAttachment,
  validateNote,
  buildCaseExport,
  caseExportCsvRows,
  CASE_CSV_COLS,
  sortCases,
} = await import(pathToFileURL(casesModelPath).href);

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

function parseLimit(q) {
  const n = Number(q?.limit ?? DEFAULT_LIMIT);
  if (!Number.isFinite(n) || n < 1) return DEFAULT_LIMIT;
  return Math.min(Math.floor(n), MAX_LIMIT);
}

function parseOffset(q) {
  const n = Number(q?.offset ?? 0);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

function actorOf(req) {
  return req.identity?.email ?? 'unknown';
}

function toCase(r) {
  return {
    caseId: r.case_id,
    title: r.title,
    description: r.description ?? null,
    severity: r.severity,
    status: r.status,
    createdBy: r.created_by,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    closedAt: r.closed_at ?? null,
    closedBy: r.closed_by ?? null,
    attachmentCount: r.attachment_count != null ? Number(r.attachment_count) : undefined,
  };
}

function toAttachment(r) {
  return {
    attachmentId: r.attachment_id,
    caseId: r.case_id,
    kind: r.kind,
    ref: r.ref,
    label: r.label ?? null,
    attachedBy: r.attached_by,
    attachedAt: r.attached_at,
  };
}

function toEvent(r) {
  return {
    eventId: r.event_id,
    caseId: r.case_id,
    kind: r.kind,
    body: r.body ?? null,
    actor: r.actor,
    meta: r.meta ?? null,
    createdAt: r.created_at,
  };
}

async function insertEvent(db, { caseId, kind, body, actor, meta }) {
  const { rows } = await db.query(
    `INSERT INTO case_events (case_id, kind, body, actor, meta)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING event_id, case_id, kind, body, actor, meta, created_at`,
    [caseId, kind, body ?? null, actor, meta ? JSON.stringify(meta) : null],
  );
  return toEvent(rows[0]);
}

async function loadCase(db, caseId) {
  const { rows } = await db.query(
    `SELECT c.*,
            (SELECT COUNT(*)::int FROM case_attachments a WHERE a.case_id = c.case_id) AS attachment_count
     FROM investigation_cases c
     WHERE c.case_id = $1`,
    [caseId],
  );
  return rows[0] ? toCase(rows[0]) : null;
}

async function loadAttachments(db, caseId) {
  const { rows } = await db.query(
    `SELECT attachment_id, case_id, kind, ref, label, attached_by, attached_at
     FROM case_attachments
     WHERE case_id = $1
     ORDER BY attached_at ASC, attachment_id`,
    [caseId],
  );
  return rows.map(toAttachment);
}

async function loadEvents(db, caseId) {
  const { rows } = await db.query(
    `SELECT event_id, case_id, kind, body, actor, meta, created_at
     FROM case_events
     WHERE case_id = $1
     ORDER BY created_at ASC, event_id`,
    [caseId],
  );
  return rows.map(toEvent);
}

async function attachOne(db, { caseId, kind, ref, label, actor }) {
  try {
    const { rows } = await db.query(
      `INSERT INTO case_attachments (case_id, kind, ref, label, attached_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING attachment_id, case_id, kind, ref, label, attached_by, attached_at`,
      [caseId, kind, ref, label, actor],
    );
    const att = toAttachment(rows[0]);
    await insertEvent(db, {
      caseId,
      kind: 'attach',
      body: `Attached ${kind}: ${ref}`,
      actor,
      meta: { attachmentId: att.attachmentId, kind, ref, label },
    });
    return { ok: true, attachment: att };
  } catch (err) {
    if (err?.code === '23505') {
      return { ok: false, conflict: true, detail: `${kind} '${ref}' is already attached to this case` };
    }
    throw err;
  }
}

export async function casesRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const userLevel = requireRoles('analyst', 'admin');

  fastify.get('/api/cases', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const clauses = [];
    const params = [];
    if (req.query?.status) {
      const statuses = String(req.query.status).split(',').map((s) => s.trim()).filter(Boolean);
      const bad = statuses.filter((s) => !CASE_STATUSES.includes(s));
      if (statuses.length === 0 || bad.length > 0) {
        return reply.code(400).send({ error: 'bad_request', detail: `status must be one of ${CASE_STATUSES.join(', ')}` });
      }
      params.push(statuses);
      clauses.push(`c.status = ANY($${params.length})`);
    }
    if (req.query?.severity) {
      if (!CASE_SEVERITIES.includes(req.query.severity)) {
        return reply.code(400).send({ error: 'bad_request', detail: `severity must be one of ${CASE_SEVERITIES.join(', ')}` });
      }
      params.push(req.query.severity);
      clauses.push(`c.severity = $${params.length}`);
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = parseLimit(req.query);
    const offset = parseOffset(req.query);
    const [total, rows] = await Promise.all([
      db.query(`SELECT COUNT(*) AS n FROM investigation_cases c ${where}`, params),
      db.query(
        `SELECT c.*,
                (SELECT COUNT(*)::int FROM case_attachments a WHERE a.case_id = c.case_id) AS attachment_count
         FROM investigation_cases c ${where}
         ORDER BY c.updated_at DESC, c.case_id
         LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, limit, offset],
      ),
    ]);
    const cases = sortCases(rows.rows.map(toCase));
    if (wantsCsv(req)) {
      const flat = cases.map((c) => ({
        caseId: c.caseId,
        title: c.title,
        severity: c.severity,
        status: c.status,
        createdBy: c.createdBy,
        createdAt: c.createdAt,
        updatedAt: c.updatedAt,
        closedAt: c.closedAt,
        closedBy: c.closedBy,
        attachKind: '',
        attachRef: '',
        attachLabel: '',
      }));
      return sendCsv(reply, 'aim-cases.csv', CASE_CSV_COLS, flat);
    }
    return {
      total: Number(total.rows[0].n),
      limit,
      offset,
      cases,
    };
  });

  fastify.post('/api/cases', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const parsed = validateCreate(req.body ?? {});
    if (!parsed.ok) return reply.code(400).send({ error: 'bad_request', detail: parsed.detail });
    const actor = actorOf(req);
    const v = parsed.value;
    const { rows } = await db.query(
      `INSERT INTO investigation_cases (title, description, severity, status, created_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING case_id, title, description, severity, status, created_by, created_at, updated_at, closed_at, closed_by`,
      [v.title, v.description, v.severity, v.status, actor],
    );
    const created = toCase({ ...rows[0], attachment_count: 0 });
    await insertEvent(db, {
      caseId: created.caseId,
      kind: 'created',
      body: `Case opened: ${v.title}`,
      actor,
      meta: { severity: v.severity, status: v.status },
    });

    const seedPairs = [
      ...v.findingIds.map((ref) => ({ kind: 'finding', ref, label: null })),
      ...v.userRefs.map((ref) => ({ kind: 'user', ref, label: null })),
      ...v.tools.map((ref) => ({ kind: 'tool', ref, label: null })),
    ];
    for (const seed of seedPairs) {
      await attachOne(db, { caseId: created.caseId, ...seed, actor });
    }

    await db.query(`UPDATE investigation_cases SET updated_at = now() WHERE case_id = $1`, [created.caseId]);
    const full = await loadCase(db, created.caseId);
    audit(actor, 'case.create', `cases/${created.caseId}`, { title: v.title, severity: v.severity });
    return reply.code(201).send(full);
  });

  fastify.get('/api/cases/:id', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const c = await loadCase(db, req.params.id);
    if (!c) return reply.code(404).send({ error: 'not_found', detail: 'case not found' });
    const [attachments, events] = await Promise.all([
      loadAttachments(db, c.caseId),
      loadEvents(db, c.caseId),
    ]);
    return { case: c, attachments, events };
  });

  fastify.get('/api/cases/:id/export', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const c = await loadCase(db, req.params.id);
    if (!c) return reply.code(404).send({ error: 'not_found', detail: 'case not found' });
    const [attachments, events] = await Promise.all([
      loadAttachments(db, c.caseId),
      loadEvents(db, c.caseId),
    ]);
    const detail = { case: c, attachments, events };
    if (wantsCsv(req)) {
      return sendCsv(reply, `aim-case-${c.caseId}.csv`, CASE_CSV_COLS, caseExportCsvRows(detail));
    }
    const pkg = buildCaseExport(detail);
    pkg.exportedAt = new Date().toISOString();
    pkg.exportedBy = actorOf(req);
    audit(actorOf(req), 'case.export', `cases/${c.caseId}`, { format: 'json' });
    return pkg;
  });

  fastify.patch('/api/cases/:id', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const existing = await loadCase(db, req.params.id);
    if (!existing) return reply.code(404).send({ error: 'not_found', detail: 'case not found' });
    const parsed = validatePatch(req.body ?? {});
    if (!parsed.ok) return reply.code(400).send({ error: 'bad_request', detail: parsed.detail });
    const v = parsed.value;
    if (v.status !== undefined && v.status !== existing.status) {
      if (!canTransition(existing.status, v.status)) {
        return reply.code(400).send({
          error: 'bad_request',
          detail: `cannot transition from '${existing.status}' to '${v.status}'`,
        });
      }
    }
    const actor = actorOf(req);
    const title = v.title ?? existing.title;
    const description = v.description !== undefined ? v.description : existing.description;
    const severity = v.severity ?? existing.severity;
    const status = v.status ?? existing.status;
    const closing = status === 'closed' && existing.status !== 'closed';
    const reopening = existing.status === 'closed' && status !== 'closed';

    const { rows } = await db.query(
      `UPDATE investigation_cases
       SET title = $2,
           description = $3,
           severity = $4,
           status = $5,
           updated_at = now(),
           closed_at = CASE
             WHEN $5 = 'closed' AND status <> 'closed' THEN now()
             WHEN $5 <> 'closed' AND status = 'closed' THEN NULL
             ELSE closed_at
           END,
           closed_by = CASE
             WHEN $5 = 'closed' AND status <> 'closed' THEN $6
             WHEN $5 <> 'closed' AND status = 'closed' THEN NULL
             ELSE closed_by
           END
       WHERE case_id = $1
       RETURNING case_id, title, description, severity, status, created_by, created_at, updated_at, closed_at, closed_by`,
      [existing.caseId, title, description, severity, status, actor],
    );
    const updated = toCase({ ...rows[0], attachment_count: existing.attachmentCount });

    if (v.status !== undefined && v.status !== existing.status) {
      await insertEvent(db, {
        caseId: existing.caseId,
        kind: 'status_change',
        body: `Status ${existing.status} → ${status}`,
        actor,
        meta: { from: existing.status, to: status },
      });
    } else if (v.title !== undefined || v.description !== undefined || v.severity !== undefined) {
      await insertEvent(db, {
        caseId: existing.caseId,
        kind: 'updated',
        body: 'Case fields updated',
        actor,
        meta: {
          title: v.title !== undefined,
          description: v.description !== undefined,
          severity: v.severity !== undefined,
        },
      });
    }

    audit(actor, 'case.update', `cases/${existing.caseId}`, {
      status: updated.status,
      closing,
      reopening,
    });
    return updated;
  });

  fastify.post('/api/cases/:id/attachments', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const existing = await loadCase(db, req.params.id);
    if (!existing) return reply.code(404).send({ error: 'not_found', detail: 'case not found' });
    const parsed = validateAttachment(req.body ?? {});
    if (!parsed.ok) return reply.code(400).send({ error: 'bad_request', detail: parsed.detail });
    const actor = actorOf(req);
    const result = await attachOne(db, {
      caseId: existing.caseId,
      kind: parsed.value.kind,
      ref: parsed.value.ref,
      label: parsed.value.label,
      actor,
    });
    if (!result.ok) {
      return reply.code(409).send({ error: 'conflict', detail: result.detail });
    }
    await db.query(`UPDATE investigation_cases SET updated_at = now() WHERE case_id = $1`, [existing.caseId]);
    audit(actor, 'case.attach', `cases/${existing.caseId}`, {
      kind: parsed.value.kind,
      ref: parsed.value.ref,
    });
    return reply.code(201).send(result.attachment);
  });

  fastify.delete('/api/cases/:id/attachments/:attachmentId', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const existing = await loadCase(db, req.params.id);
    if (!existing) return reply.code(404).send({ error: 'not_found', detail: 'case not found' });
    const { rows } = await db.query(
      `DELETE FROM case_attachments
       WHERE case_id = $1 AND attachment_id = $2
       RETURNING attachment_id, case_id, kind, ref, label, attached_by, attached_at`,
      [existing.caseId, req.params.attachmentId],
    );
    if (!rows[0]) return reply.code(404).send({ error: 'not_found', detail: 'attachment not found' });
    const att = toAttachment(rows[0]);
    const actor = actorOf(req);
    await insertEvent(db, {
      caseId: existing.caseId,
      kind: 'detach',
      body: `Detached ${att.kind}: ${att.ref}`,
      actor,
      meta: { attachmentId: att.attachmentId, kind: att.kind, ref: att.ref },
    });
    await db.query(`UPDATE investigation_cases SET updated_at = now() WHERE case_id = $1`, [existing.caseId]);
    audit(actor, 'case.detach', `cases/${existing.caseId}`, {
      kind: att.kind,
      ref: att.ref,
    });
    return reply.code(204).send();
  });

  fastify.post('/api/cases/:id/notes', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const existing = await loadCase(db, req.params.id);
    if (!existing) return reply.code(404).send({ error: 'not_found', detail: 'case not found' });
    const parsed = validateNote(req.body ?? {});
    if (!parsed.ok) return reply.code(400).send({ error: 'bad_request', detail: parsed.detail });
    const actor = actorOf(req);
    const event = await insertEvent(db, {
      caseId: existing.caseId,
      kind: 'note',
      body: parsed.value.body,
      actor,
      meta: null,
    });
    await db.query(`UPDATE investigation_cases SET updated_at = now() WHERE case_id = $1`, [existing.caseId]);
    audit(actor, 'case.note', `cases/${existing.caseId}`, {});
    return reply.code(201).send(event);
  });
}

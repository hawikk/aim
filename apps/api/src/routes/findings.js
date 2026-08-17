// Security findings triage API. Findings are written post-ingest by
// `guardrail evaluate-db` (services/guardrail) from the same metadata-only
// event store the dashboard reads — detector names and pseudonyms only,
// never matched content.
//
// All endpoints are GATED to the security group, same as /api/users
// (privacy gate): findings carry user/host pseudonyms and rule evidence.
// Triage transitions are recorded in the immutable audit trail.
//
// every transition is ALSO persisted as an append-only row in
// finding_transitions (migration 018) — who, when, from_status -> to_status,
// reason — queryable per finding at GET /api/findings/:id/transitions. The
// finding row itself keeps only the latest disposition. Resolving without a
// non-empty reason is rejected (400): "we resolved it but can't say who or
// why" is the failure this closes.
//
// F1: the status UPDATE and the transition INSERT(s) share one
// transaction on one connection. A crash mid-write rolls both back — a
// disposition without a log row is the silent failure this closes. Bulk
// triage inserts all transition rows in a single multi-row statement.
//
// GET /api/findings/summary surfaces aging + unhandled-critical
// count + SLA posture so "20 untouched criticals" is impossible to miss.
// POST /api/findings/apply-suppressions auto-closes proven-noise classes
// with the suppression reason recorded on finding_transitions.
//
// high/critical findings carry complianceEvidence — control refs
// from framework-map.yaml — so triage and the auditor path share one map.
import { query, withTransaction } from '../db.js';
import { requireRoles } from '../auth.js';
import { audit } from '../audit.js';
import { wantsCsv, checkFormat, sendCsv } from '../csv.js';
import { toFinding } from '../findings-shape.js';
import {
  loadFindingsBacklogSummary,
  applyNoiseSuppressions,
  NOISE_SUPPRESSIONS,
  evaluateFindingSla,
} from '../finding-sla.js';
import { loadComplianceMap, complianceMapPath } from '../compliance-map.js';
import { attachComplianceEvidence } from '../finding-compliance-evidence.js';

const FINDINGS_CSV_COLS = [
  { key: 'findingId', label: 'finding_id' },
  { key: 'detectedAt', label: 'detected_at' },
  { key: 'ruleId', label: 'rule_id' },
  { key: 'severity', label: 'severity' },
  { key: 'title', label: 'title' },
  { key: 'status', label: 'status' },
  { key: 'subject', label: 'subject' },
  { key: 'decision', label: 'decision' },
  { key: 'eventId', label: 'event_id' },
  { key: 'triagedBy', label: 'triaged_by' },
  { key: 'triagedAt', label: 'triaged_at' },
  { key: 'triageNote', label: 'triage_note' },
];

const STATUSES = ['new', 'acknowledged', 'resolved', 'false_positive'];
const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

/*: statuses that are a final disposition and therefore REQUIRE a
 * non-empty reason. 'false_positive' stays optional — it is usually applied
 * in bulk during rule tuning, and the detector evidence on the finding is
 * the record of why. */
const REASON_REQUIRED = new Set(['resolved']);

// Returns the trimmed note, or null when empty/missing.
function noteOf(body) {
  if (body.note === undefined || body.note === null) return null;
  if (typeof body.note !== 'string') return false; // sentinel: bad type
  const trimmed = body.note.trim();
  return trimmed === '' ? null : trimmed;
}

// Error string when the transition is not allowed, else null.
function transitionError(status, note) {
  if (note === false) return 'note must be a string';
  if (REASON_REQUIRED.has(status) && !note) {
    return `a reason is required to mark a finding ${status}`;
  }
  return null;
}

// Append transition rows in a single multi-row INSERT (F1). The
// finding_transitions table is append-only (migration 018 / 020) — this
// module is its only writer. Empty rows is a no-op.
async function recordTransitions(client, rows, toStatus, actor, note) {
  if (rows.length === 0) return;
  const params = [];
  const values = [];
  let i = 1;
  for (const row of rows) {
    values.push(`($${i++}, $${i++}, $${i++}, $${i++}, $${i++})`);
    params.push(row.finding_id, row.from_status, toStatus, actor, note);
  }
  await client.query(
    `INSERT INTO finding_transitions (finding_id, from_status, to_status, actor, reason)
     VALUES ${values.join(', ')}`,
    params
  );
}

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

// wrap the canonical shape with age + SLA flags so the
// inbox can sort/badge without a second round-trip. Closed findings never
// "breach" (evaluateFindingSla only applies to critical+new).
// Named findingWithSla (not toFinding) so the single-source contract
// stays true: only findings-shape.js defines toFinding.
// high/critical also get complianceEvidence (read-time map attach).
function findingWithSla(r, map = null) {
  const base = toFinding(r);
  const sla = evaluateFindingSla(base);
  const withSla = {
    ...base,
    ageMs: sla.ageMs,
    ageHours: sla.ageHours,
    ageBucket: sla.ageBucket,
    slaBreached: sla.breached,
  };
  return map ? attachComplianceEvidence(withSla, map) : withSla;
}

// opts.db is injectable for tests; defaults to the real pg pool.
// opts.db.withTransaction(fn) must run fn on one connection inside a txn.
// opts.mapPath / opts.getMap inject the compliance map (tests).
export async function findingsRoutes(fastify, opts) {
  const db = opts?.db ?? { query, withTransaction };
  // Findings carry user/host pseudonyms and rule evidence: analyst+ (privacy
  // gate, same tier as /api/users).
  const userLevel = requireRoles('analyst', 'admin');
  // Noise suppressions rewrite many rows — admin only (same bar as policy edits).
  const adminOnly = requireRoles('admin');
  // Compliance map is loaded per request from disk (same no-drift rule as
  // the compliance report). Failures leave findings without evidence rather
  // than 500 the triage inbox — map load errors are logged.
  const getMap = opts?.getMap
    ?? (() => loadComplianceMap(opts?.mapPath ?? complianceMapPath()));
  function mapOrNull(req) {
    try {
      return getMap();
    } catch (err) {
      req?.log?.error?.({ err }, 'findings.compliance_map_load_failed');
      return null;
    }
  }

  // ---- list findings, filterable by status / severity / rule_id ----
  // ?format=csv exports the same filtered rows as an attachment,
  // capped by the same limit/offset pagination params.
  fastify.get('/api/findings', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const clauses = [];
    const params = [];
    if (req.query?.status) {
      // Comma-separated list allowed (CSV export mirrors the UI's
      // "open" = new+acknowledged filter); every value must be a valid status.
      const statuses = String(req.query.status).split(',').map((s) => s.trim()).filter(Boolean);
      const bad = statuses.filter((s) => !STATUSES.includes(s));
      if (statuses.length === 0 || bad.length > 0) {
        return reply.code(400).send({ error: 'bad_request', detail: `status must be one of ${STATUSES.join(', ')}` });
      }
      params.push(statuses);
      clauses.push(`f.status = ANY($${params.length})`);
    }
    if (req.query?.severity) {
      if (!SEVERITIES.includes(req.query.severity)) {
        return reply.code(400).send({ error: 'bad_request', detail: `severity must be one of ${SEVERITIES.join(', ')}` });
      }
      params.push(req.query.severity);
      clauses.push(`f.severity = $${params.length}`);
    }
    if (req.query?.rule_id) {
      params.push(req.query.rule_id);
      clauses.push(`f.rule_id = $${params.length}`);
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = parseLimit(req.query);
    const offset = parseOffset(req.query);
    const [total, rows] = await Promise.all([
      db.query(`SELECT COUNT(*) AS n FROM findings f ${where}`, params),
      db.query(
        `SELECT f.* FROM findings f ${where}
         ORDER BY f.detected_at DESC, f.finding_id
         LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, limit, offset]
      ),
    ]);
    const map = mapOrNull(req);
    const mapped = rows.rows.map((r) => findingWithSla(r, map));
    if (wantsCsv(req)) {
      return sendCsv(reply, 'aim-findings.csv', FINDINGS_CSV_COLS, mapped);
    }
    return {
      total: Number(total.rows[0].n),
      limit,
      offset,
      findings: mapped,
    };
  });

  // ---- backlog + SLA summary: aging buckets, unhandled criticals,
  // and breach sample. Analyst+. Registered before /:id so "summary" is not
  // captured as a finding id. ----
  fastify.get('/api/findings/summary', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    try {
      const summary = await loadFindingsBacklogSummary(db);
      return {
        ...summary,
        suppressions: NOISE_SUPPRESSIONS.map((s) => ({
          id: s.id,
          ruleId: s.ruleId,
          reason: s.reason,
        })),
      };
    } catch (err) {
      req.log?.error?.({ err }, 'findings.summary failed');
      return reply.code(500).send({ error: 'internal_error', detail: 'findings summary failed' });
    }
  });

  // ---- apply proven-noise suppressions (admin). dryRun=1 previews.
  // Each suppression writes false_positive + a transition row with the fixed
  // reason so the audit trail shows *why* a class was closed. ----
  fastify.post('/api/findings/apply-suppressions', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const body = req.body ?? {};
    const dryRun = body.dryRun === true || body.dry_run === true;
    const actor = req.identity?.email ?? 'unknown';
    try {
      const result = await applyNoiseSuppressions(db, {
        actor: dryRun ? actor : `${actor} (noise-suppressor)`,
        dryRun,
      });
      if (!dryRun && result.updated > 0) {
        audit(actor, 'finding.apply_suppressions', 'findings', {
          updated: result.updated,
          byClass: result.byClass,
        });
      }
      return result;
    } catch (err) {
      req.log?.error?.({ err }, 'findings.apply_suppressions failed');
      return reply.code(500).send({ error: 'internal_error', detail: 'apply-suppressions failed' });
    }
  });

  // ---- bulk triage: apply one status (+ optional note) to up to
  // 200 findings in a single UPDATE. Audited once per batch, not per row;
  // the per-finding record is the transition row. The CTE captures
  // each finding's pre-update status so the log records a real from->to.
  // F1: UPDATE + multi-row INSERT run in one transaction. ----
  fastify.post('/api/findings/triage', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const body = req.body ?? {};
    if (!Array.isArray(body.ids) || body.ids.length < 1 || body.ids.length > 200 ||
        body.ids.some((id) => typeof id !== 'string')) {
      return reply.code(400).send({ error: 'bad_request', detail: 'ids must be an array of 1..200 finding_id strings' });
    }
    if (!STATUSES.includes(body.status)) {
      return reply.code(400).send({ error: 'bad_request', detail: `status must be one of ${STATUSES.join(', ')}` });
    }
    const note = noteOf(body);
    const bad = transitionError(body.status, note);
    if (bad) return reply.code(400).send({ error: 'bad_request', detail: bad });
    const actor = req.identity?.email ?? 'unknown';
    try {
      const rows = await db.withTransaction(async (client) => {
        const { rows: updated } = await client.query(
          `WITH old AS (
             SELECT finding_id, status FROM findings WHERE finding_id = ANY($1)
           )
           UPDATE findings f
              SET status = $2,
                  triage_note = $3,
                  triaged_by = $4,
                  triaged_at = now()
             FROM old
            WHERE f.finding_id = old.finding_id
           RETURNING f.finding_id, old.status AS from_status`,
          [body.ids, body.status, note, actor]
        );
        await recordTransitions(client, updated, body.status, actor, note);
        return updated;
      });
      audit(actor, 'finding.bulk_triage', 'findings', { status: body.status, count: rows.length });
      return { updated: rows.length };
    } catch (err) {
      req.log?.error?.({ err }, 'findings.bulk_triage failed');
      return reply.code(500).send({ error: 'internal_error', detail: 'triage transaction failed' });
    }
  });

  // ---- transition history: the full append-only disposition log
  // for one finding, chronological. 404 when the finding does not exist — an
  // empty list must mean "no transitions yet", never "no such finding". ----
  fastify.get('/api/findings/:id/transitions', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const { rows: found } = await db.query(
      'SELECT 1 FROM findings WHERE finding_id = $1',
      [req.params.id]
    );
    if (found.length === 0) {
      return reply.code(404).send({ error: 'not_found', detail: `no finding ${req.params.id}` });
    }
    const { rows } = await db.query(
      `SELECT from_status, to_status, actor, reason, created_at
         FROM finding_transitions
        WHERE finding_id = $1
        ORDER BY created_at, transition_id`,
      [req.params.id]
    );
    return {
      findingId: req.params.id,
      transitions: rows.map((r) => ({
        from: r.from_status,
        to: r.to_status,
        actor: r.actor,
        reason: r.reason,
        at: new Date(r.created_at).toISOString(),
      })),
    };
  });

  // ---- triage a finding: set status (+ optional note; required on resolve,
  //). Any transition is allowed; the audit trail and the append-only
  // transition log preserve who moved what, from what, when, and why.
  // F1: UPDATE + INSERT share one transaction. ----
  fastify.patch('/api/findings/:id', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const body = req.body ?? {};
    if (!STATUSES.includes(body.status)) {
      return reply.code(400).send({ error: 'bad_request', detail: `status must be one of ${STATUSES.join(', ')}` });
    }
    const note = noteOf(body);
    const bad = transitionError(body.status, note);
    if (bad) return reply.code(400).send({ error: 'bad_request', detail: bad });
    const actor = req.identity?.email ?? 'unknown';
    try {
      const row = await db.withTransaction(async (client) => {
        const { rows } = await client.query(
          `WITH old AS (
             SELECT status FROM findings WHERE finding_id = $1
           )
           UPDATE findings f
              SET status = $2,
                  triage_note = $3,
                  triaged_by = $4,
                  triaged_at = now()
             FROM old
            WHERE f.finding_id = $1
           RETURNING f.*, old.status AS from_status`,
          [req.params.id, body.status, note, actor]
        );
        if (rows.length === 0) return null;
        await recordTransitions(client, rows, body.status, actor, note);
        return rows[0];
      });
      if (!row) {
        return reply.code(404).send({ error: 'not_found', detail: `no finding ${req.params.id}` });
      }
      audit(actor, 'finding.triage', `findings/${req.params.id}`, {
        from: row.from_status,
        to: body.status,
      });
      return findingWithSla(row, mapOrNull(req));
    } catch (err) {
      req.log?.error?.({ err }, 'findings.triage failed');
      return reply.code(500).send({ error: 'internal_error', detail: 'triage transaction failed' });
    }
  });
}

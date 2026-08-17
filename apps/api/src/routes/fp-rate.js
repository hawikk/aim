// AIM-672: HTTP surface for the live pilot detector FP-rate SLO.
//
//   GET  /api/security/fp-rate              — live trailing-window evaluation
//   GET  /api/security/fp-rate/snapshots    — stored weekly/on-demand history
//   GET  /api/security/fp-rate/snapshots/:id
//   POST /api/security/fp-rate/snapshots    — on-demand snapshot (admin/analyst)
//
// Alert publishing is deliberately NOT on the request path (see
// startFpRateAlerter in fp-rate.js).

import { requireRoles } from '../auth.js';
import { query } from '../db.js';
import {
  loadSessionFpRate,
  storeFpRateSnapshot,
  listFpRateSnapshots,
  getFpRateSnapshot,
  sessionFpSloPct,
  FP_RATE_RULES,
} from '../fp-rate.js';

function parseDays(raw, fallback = 7) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(Math.floor(n), 90);
}

export async function fpRateRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const reader = requireRoles('admin', 'analyst', 'auditor', 'viewer');
  const writer = requireRoles('admin', 'analyst');

  fastify.get('/api/security/fp-rate', async (req, reply) => {
    if (!reader(req, reply)) return reply;
    const days = parseDays(req.query?.days, 7);
    const evaluation = await loadSessionFpRate(db, { days });
    return {
      ...evaluation,
      sloMaxPct: evaluation.slo?.maxSessionFpPct ?? sessionFpSloPct(),
      windowDays: days,
      rules: evaluation.rules ?? [...FP_RATE_RULES],
    };
  });

  fastify.get('/api/security/fp-rate/snapshots', async (req, reply) => {
    if (!reader(req, reply)) return reply;
    const limit = Math.min(Math.max(1, Number(req.query?.limit) || 20), 100);
    const kind = req.query?.kind === 'weekly' || req.query?.kind === 'on_demand'
      ? req.query.kind
      : null;
    const snapshots = await listFpRateSnapshots(db, { limit, kind });
    return { snapshots, count: snapshots.length };
  });

  fastify.get('/api/security/fp-rate/snapshots/:id', async (req, reply) => {
    if (!reader(req, reply)) return reply;
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) {
      return reply.code(400).send({ error: 'invalid_id', message: 'Snapshot id must be a positive integer' });
    }
    const snap = await getFpRateSnapshot(db, id);
    if (!snap) {
      return reply.code(404).send({ error: 'not_found', message: `No FP-rate snapshot ${id}` });
    }
    return snap;
  });

  // On-demand publish: compute + store so the weekly series is not the only
  // durable record (useful after a matcher change or pilot readout).
  fastify.post('/api/security/fp-rate/snapshots', async (req, reply) => {
    if (!writer(req, reply)) return reply;
    const days = parseDays(req.body?.days ?? req.query?.days, 7);
    const evaluation = await loadSessionFpRate(db, { days });
    try {
      const stored = await storeFpRateSnapshot(db, evaluation, { kind: 'on_demand' });
      return reply.code(201).send({
        id: stored.id,
        createdAt: stored.createdAt,
        reportHash: stored.reportHash,
        report: stored.report,
      });
    } catch (err) {
      // Missing migration surfaces as a clean 503 rather than a 500 stack.
      if (err?.code === '42P01') {
        return reply.code(503).send({
          error: 'not_ready',
          message: 'fp_rate_snapshots table missing — apply ingest migration 029_fp_rate_snapshots.sql',
        });
      }
      throw err;
    }
  });
}

export default fpRateRoutes;

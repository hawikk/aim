// Executive AI-governance report routes.
//
// Scheduled + on-demand reports answering "what did AI tools do last month?"
// as stored, hashed, HTML/PDF-exportable, and diffable artifacts. Built only
// from stored events/findings/devices — no new collection.
//
// Gated to the same security-group roles as compliance evidence
// (security-admin / analyst / auditor). Per-person rows stay behind the
// analyst+ aggregate API; this surface is org-level only.
//
// Endpoints:
//   GET  /api/governance/report          live report (json|html|pdf|text)
//   GET  /api/governance/reports         list retained reports
//   POST /api/governance/reports         store an on-demand report
//   GET  /api/governance/reports/:id     one stored report (+ format=)
//   GET  /api/governance/reports/:id/diff?against=:otherId
// GET /api/governance/enforcement-latency endpoint decision latency p50/p95
//
// Schedulers (restart-safe, state in the table):
//   weekly  — every 7 days when GOVERNANCE_REPORTS is not 'off'
//   monthly — every ~30 days (same env gate)
//
// Retention: purge rows older than GOVERNANCE_REPORT_RETENTION_DAYS (default
// 100 ≈ one quarter + buffer) but always keep the newest
// GOVERNANCE_REPORT_MIN_KEEP (default 14) so a stalled scheduler cannot
// silently erase history into looking complete.

import { query } from '../db.js';
import { requireRoles } from '../auth.js';
import { audit, verifyAuditChain } from '../audit.js';
import { checkFormat } from '../csv.js';
import {
  buildReport,
  sealReport,
  renderHtml,
  renderText,
  diffReports,
} from '../governance-report.js';
import { textToPdf } from '../pdf.js';

const DAY_MS = 86400_000;
const WEEKLY_DAYS = 7;
const MONTHLY_DAYS = 30;
const DEFAULT_DAYS = 30;
const DEFAULT_RETENTION_DAYS = 100;
const DEFAULT_MIN_KEEP = 14;
// Design budget from docs/inline-enforcement-design-2026-07.md § latency.
// Fail-open hard timeout (500 ms) is a separate budget — do not conflate.
export const ENFORCEMENT_LATENCY_SLO_MS = 200;
const LATENCY_DEFAULT_DAYS = 7;
const LATENCY_MAX_DAYS = 90;

function parsePeriod(q, defaultDays = DEFAULT_DAYS) {
  const to = q?.to ? new Date(q.to) : new Date();
  const from = q?.from ? new Date(q.from) : new Date(to.getTime() - defaultDays * DAY_MS);
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) return null;
  if (from >= to) return null;
  return { from, to };
}

function retentionDays() {
  const n = Number(process.env.GOVERNANCE_REPORT_RETENTION_DAYS);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_RETENTION_DAYS;
}

function minKeep() {
  const n = Number(process.env.GOVERNANCE_REPORT_MIN_KEEP);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_MIN_KEEP;
}

function filenameFor(report, ext) {
  const from = (report.period?.from ?? 'unknown').slice(0, 10);
  const to = (report.period?.to ?? 'unknown').slice(0, 10);
  return `aim-governance-report-${from}_to_${to}.${ext}`;
}

export async function governanceRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  // Same audience as compliance evidence.
  const anyRole = requireRoles('security-admin', 'analyst', 'auditor');
  const adminOnly = requireRoles('security-admin');
  const verifyChain = opts?.verifyChain ?? verifyAuditChain;
  const appendAudit = opts?.appendAudit ?? audit;
  const nowFn = opts?.now ?? (() => new Date());

  async function generate(period) {
    const raw = await buildReport(period, {
      db,
      verifyChain,
      now: nowFn(),
    });
    return sealReport(raw);
  }

  async function takeReport(kind, period, actor) {
    const report = await generate(period);
    const html = renderHtml(report);
    const { rows } = await db.query(
      `INSERT INTO governance_reports
         (kind, period_from, period_to, report, html, report_hash, audit_chain_ok,
          events_total, findings_total, findings_open, spend_usd)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10, $11)
       RETURNING id, created_at`,
      [
        kind,
        period.from,
        period.to,
        JSON.stringify(report),
        html,
        report.reportHash,
        report.auditChain?.ok ?? null,
        report.headline.events,
        report.headline.findingsTotal,
        report.headline.findingsOpen,
        report.headline.costUsd,
      ],
    );
    appendAudit(actor, 'governance.report', 'governance/report', {
      reportId: rows[0].id,
      kind,
      reportHash: report.reportHash,
      periodDays: report.period.days,
      blind: report.blind,
    });
    await purgeReports();
    return { id: rows[0].id, createdAt: rows[0].created_at, reportHash: report.reportHash, report };
  }

  // Keep ≥ minKeep newest rows always; among the rest, drop anything older
  // than the retention window. A gap left by a stalled scheduler must remain
  // visible as fewer rows, not as a quietly complete history.
  async function purgeReports() {
    const days = retentionDays();
    const keep = minKeep();
    await db.query(
      `DELETE FROM governance_reports
        WHERE id NOT IN (
          SELECT id FROM governance_reports ORDER BY created_at DESC LIMIT $1
        )
        AND created_at < now() - make_interval(days => $2)`,
      [keep, days],
    );
  }

  function renderReply(reply, report, format, { storedHtml } = {}) {
    if (format === 'html') {
      const html = storedHtml ?? renderHtml(report);
      return reply
        .header('content-type', 'text/html; charset=utf-8')
        .header('content-disposition', `inline; filename="${filenameFor(report, 'html')}"`)
        .send(html);
    }
    if (format === 'text') {
      return reply
        .header('content-type', 'text/plain; charset=utf-8')
        .header('content-disposition', `inline; filename="${filenameFor(report, 'txt')}"`)
        .send(renderText(report).join('\n') + '\n');
    }
    if (format === 'pdf') {
      const lines = renderText(report);
      const pdf = textToPdf(lines, {
        title: `AI Governance Report ${report.period.from.slice(0, 10)} to ${report.period.to.slice(0, 10)}`,
      });
      return reply
        .header('content-type', 'application/pdf')
        .header('content-disposition', `attachment; filename="${filenameFor(report, 'pdf')}"`)
        .send(pdf);
    }
    return report;
  }

  /* ---------- schedulers (weekly + monthly) ---------- */

  const schedCfg = opts?.scheduler ?? {};
  const schedulerEnabled = schedCfg.enabled ?? process.env.GOVERNANCE_REPORTS !== 'off';
  if (schedulerEnabled) {
    const checkEveryMs = schedCfg.checkEveryMs ?? 6 * 3600_000;
    const weeklyEveryMs = schedCfg.weeklyEveryMs ?? WEEKLY_DAYS * DAY_MS;
    const monthlyEveryMs = schedCfg.monthlyEveryMs ?? MONTHLY_DAYS * DAY_MS;

    const ensureScheduled = async (kind, everyMs, periodDays) => {
      try {
        const { rows } = await db.query(
          `SELECT created_at FROM governance_reports WHERE kind = $1 ORDER BY created_at DESC LIMIT 1`,
          [kind],
        );
        const last = rows[0]?.created_at;
        if (!last || Date.now() - new Date(last).getTime() >= everyMs) {
          const to = nowFn();
          await takeReport(kind, { from: new Date(to.getTime() - periodDays * DAY_MS), to }, 'governance-scheduler');
          fastify.log.info({ kind }, 'governance report stored');
        }
      } catch (err) {
        // Table may not be migrated yet on first boot after deploy — log and
        // retry next tick rather than taking the API down.
        fastify.log.error({ err, kind }, 'governance report schedule failed');
      }
    };

    const tick = async () => {
      await ensureScheduled('weekly', weeklyEveryMs, WEEKLY_DAYS);
      await ensureScheduled('monthly', monthlyEveryMs, MONTHLY_DAYS);
    };
    const timer = setInterval(tick, checkEveryMs);
    timer.unref?.();
    fastify.addHook('onClose', async () => clearInterval(timer));
    tick();
  }

  /* ---------- routes ---------- */


  // endpoint enforcement decision-path latency rollup.
  // Reads metadata-only enforcement_posture.enforcement_latency_ms samples
  // (schema v1.10) from events.payload JSONB. Surfaces p50/p95 against the
  // 200 ms design SLO so breaches are visible without a content field.
  fastify.get('/api/governance/enforcement-latency', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const rawDays = Number(req.query?.days ?? LATENCY_DEFAULT_DAYS);
    const days = Number.isFinite(rawDays) && rawDays >= 1
      ? Math.min(Math.floor(rawDays), LATENCY_MAX_DAYS)
      : LATENCY_DEFAULT_DAYS;
    const sloMs = ENFORCEMENT_LATENCY_SLO_MS;

    const { rows } = await db.query(
      `SELECT
         COUNT(*)::int AS samples,
         percentile_cont(0.50) WITHIN GROUP (ORDER BY lat_ms) AS p50_ms,
         percentile_cont(0.95) WITHIN GROUP (ORDER BY lat_ms) AS p95_ms,
         MAX(lat_ms)::int AS max_ms,
         COUNT(*) FILTER (WHERE lat_ms > $2)::int AS breaches
       FROM (
         SELECT (e.payload->'enforcement_posture'->>'enforcement_latency_ms')::int AS lat_ms
           FROM events e
          WHERE e.ts >= now() - ($1 || ' days')::interval
            AND e.source = 'endpoint'
            AND e.payload->'enforcement_posture' ? 'enforcement_latency_ms'
            AND (e.payload->'enforcement_posture'->>'evaluated') = 'true'
            AND (e.payload->'enforcement_posture'->>'enforcement_latency_ms') ~ '^[0-9]+$'
       ) s`,
      [days, sloMs],
    );
    const r = rows[0] ?? {};
    const samples = Number(r.samples ?? 0);
    const p50 = r.p50_ms === null || r.p50_ms === undefined ? null : Math.round(Number(r.p50_ms));
    const p95 = r.p95_ms === null || r.p95_ms === undefined ? null : Math.round(Number(r.p95_ms));
    const maxMs = r.max_ms === null || r.max_ms === undefined ? null : Number(r.max_ms);
    const breaches = Number(r.breaches ?? 0);
    // No samples ⇒ cannot claim within SLO (coverage-absent, same honesty as posture).
    const withinSlo = samples > 0 && p95 !== null && p95 <= sloMs;

    appendAudit(req.identity?.email ?? 'unknown', 'governance.view',
      'governance/enforcement-latency', { days, samples, p95, withinSlo });

    return {
      kind: 'aim-enforcement-latency',
      sloMs,
      failOpenTimeoutMs: 500,
      days,
      samples,
      p50Ms: p50,
      p95Ms: p95,
      maxMs,
      breaches,
      withinSlo,
      note: samples === 0
        ? 'No endpoint events carried enforcement_latency_ms in this window — not a clean result; collectors may predate or the decision path did not run.'
        : withinSlo
          ? `p95 ${p95} ms ≤ ${sloMs} ms design budget over ${samples} evaluated samples.`
          : `p95 ${p95} ms exceeds ${sloMs} ms design budget (${breaches} sample(s) over budget). Fail-open hard timeout (${500} ms) is a separate budget.`,
    };
  });

  // Live report: re-aggregates stored data for the requested period. Does not
  // persist unless the caller POSTs /api/governance/reports.
  fastify.get('/api/governance/report', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    if (!checkFormat(req, reply, ['html', 'pdf', 'text'])) return reply;
    const period = parsePeriod(req.query);
    if (!period) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'from/to must be valid ISO dates with from < to',
      });
    }
    const report = await generate(period);
    appendAudit(req.identity?.email ?? 'unknown', 'governance.view', 'governance/report', {
      reportHash: report.reportHash,
      periodDays: report.period.days,
      live: true,
    });
    return renderReply(reply, report, req.query?.format);
  });

  // History: most recent first, summaries only.
  fastify.get('/api/governance/reports', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const limit = Math.min(Math.max(Number(req.query?.limit) || 52, 1), 200);
    const { rows } = await db.query(
      `SELECT id, created_at, kind, period_from, period_to, report_hash,
              audit_chain_ok, events_total, findings_total, findings_open, spend_usd
         FROM governance_reports
        ORDER BY created_at DESC
        LIMIT $1`,
      [limit],
    );
    return {
      reports: rows.map((r) => ({
        id: r.id,
        createdAt: r.created_at,
        kind: r.kind,
        period: { from: r.period_from, to: r.period_to },
        reportHash: r.report_hash,
        auditChainOk: r.audit_chain_ok,
        eventsTotal: r.events_total,
        findings: { total: r.findings_total, open: r.findings_open },
        spendUsd: Number(r.spend_usd),
      })),
      retention: {
        days: retentionDays(),
        minKeep: minKeep(),
        note:
          'One quarter of scheduled reports is retained (default 100 days) and always at least the newest 14, so history stays diffable even if the scheduler stalls.',
      },
    };
  });

  // One stored report. format=html reuses the stored HTML so the printed
  // artifact is byte-stable with what was retained; pdf/text re-render from
  // the stored JSON (deterministic pure functions).
  fastify.get('/api/governance/reports/:id', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    if (!checkFormat(req, reply, ['html', 'pdf', 'text'])) return reply;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return reply.code(400).send({ error: 'bad_request', detail: 'report id must be a positive integer' });
    }
    const { rows } = await db.query(
      `SELECT id, created_at, kind, period_from, period_to, report, html, report_hash
         FROM governance_reports WHERE id = $1`,
      [id],
    );
    if (!rows[0]) return reply.code(404).send({ error: 'not_found', detail: `no governance report with id ${id}` });
    const r = rows[0];
    const report = r.report;
    const format = req.query?.format;
    if (format) return renderReply(reply, report, format, { storedHtml: r.html });
    return {
      id: r.id,
      createdAt: r.created_at,
      kind: r.kind,
      period: { from: r.period_from, to: r.period_to },
      reportHash: r.report_hash,
      report,
    };
  });

  // Diff two retained reports (this id vs ?against=). Diffable history is
  // the acceptance criterion that turns a dashboard screenshot into an
  // audit artifact.
  fastify.get('/api/governance/reports/:id/diff', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const id = Number(req.params.id);
    const against = Number(req.query?.against);
    if (!Number.isInteger(id) || id < 1 || !Number.isInteger(against) || against < 1) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'id and against must be positive integers (against is the earlier report)',
      });
    }
    if (id === against) {
      return reply.code(400).send({ error: 'bad_request', detail: 'cannot diff a report against itself' });
    }
    const { rows } = await db.query(
      `SELECT id, report, report_hash, created_at FROM governance_reports WHERE id = ANY($1::bigint[])`,
      [[id, against]],
    );
    const byId = new Map(rows.map((r) => [Number(r.id), r]));
    if (!byId.has(id) || !byId.has(against)) {
      return reply.code(404).send({ error: 'not_found', detail: 'one or both report ids not found' });
    }
    const beforeRow = byId.get(against);
    const afterRow = byId.get(id);
    const before = { ...beforeRow.report, reportHash: beforeRow.report_hash };
    const after = { ...afterRow.report, reportHash: afterRow.report_hash };
    return {
      beforeId: against,
      afterId: id,
      ...diffReports(before, after),
    };
  });

  // On-demand store (security-admin). Weekly/monthly rows come from the
  // scheduler under actor 'governance-scheduler'.
  fastify.post('/api/governance/reports', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const period = parsePeriod(req.query ?? {});
    if (!period) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'from/to must be valid ISO dates with from < to',
      });
    }
    const stored = await takeReport('on_demand', period, req.identity?.email ?? 'unknown');
    return reply.code(201).send({
      id: stored.id,
      createdAt: stored.createdAt,
      reportHash: stored.reportHash,
      report: stored.report,
    });
  });
}

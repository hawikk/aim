// Compliance evidence report (AIM-87, extended by AIM-99).
//
// Maps live guardrail findings onto compliance framework controls
// (EU AI Act articles, OWASP LLM Top 10, NIST AI RMF subcategories,
// ISO/IEC 42001 controls) from the version-controlled mapping table
// (policies/compliance/framework-map.yaml) and emits a regulator-ready
// snapshot: period, findings by control, audit-chain verification result,
// policy + mapping content hashes, and an honest scoping note (we evidence
// oversight of AI tool usage; we do not claim the platform itself is an
// AI Act high-risk system).
//
// GATED to the security group like /api/findings — the report aggregates
// the same findings. ?format=csv exports the same numbers (AIM-82
// pattern). Generating a report runs a full audit-chain verification and
// records that run in the audit trail itself (audit.verify action).
//
// AIM-99 additions:
//   * ?format=bundle — signed, immutable JSON evidence bundle hash-linked
//     to the audit chain (see compliance-bundle.js for the construction).
//   * Weekly posture snapshots persisted to compliance_snapshots so
//     history is queryable (GET /api/compliance/snapshots[/:id]), plus
//     on-demand snapshots (POST /api/compliance/snapshots). Snapshot
//     retention is purged per the retention: section of the framework map.
//
// AIM-694 continuous control monitoring:
//   * Every mapped framework control carries live status pass|fail|unknown
//     (see control-status.js). Report rollup is controlStatus.
//   * Weekly + on-demand snapshots still store the full report (including
//     those live statuses at capture time).
import { query } from '../db.js';
import { requireRoles } from '../auth.js';
import { audit, auditHead, verifyAuditChain } from '../audit.js';
import { wantsCsv, checkFormat, toCsv } from '../csv.js';
import { loadPolicy, policyPath } from '../guardrail-policy.js';
import { loadComplianceMap, complianceMapPath, coverageReport } from '../compliance-map.js';
import { buildBundle, hashEvidencePayload, SNAPSHOT_KIND } from '../compliance-bundle.js';
import { evaluateControlStatus, summarizeControlStatuses } from '../control-status.js';

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const OPEN_STATUSES = new Set(['new', 'acknowledged']);
const DEFAULT_DAYS = 30;
const WEEKLY_DAYS = 7;
const DAY_MS = 86400_000;

function emptyCounts() {
  return { total: 0, open: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0 } };
}

function parsePeriod(q, defaultDays = DEFAULT_DAYS) {
  const to = q?.to ? new Date(q.to) : new Date();
  const from = q?.from ? new Date(q.from) : new Date(to.getTime() - defaultDays * DAY_MS);
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) return null;
  if (from >= to) return null;
  return { from, to };
}

const META_COLS = [{ key: 'key', label: 'key' }, { key: 'value', label: 'value' }];
const CONTROL_COLS = [
  { key: 'framework', label: 'framework' },
  { key: 'control_ref', label: 'control_ref' },
  { key: 'control_title', label: 'control_title' },
  { key: 'status', label: 'status' },
  { key: 'status_reason', label: 'status_reason' },
  { key: 'mapped_rules', label: 'mapped_rules' },
  { key: 'findings_total', label: 'findings_total' },
  { key: 'findings_open', label: 'findings_open' },
  { key: 'critical', label: 'critical' },
  { key: 'high', label: 'high' },
  { key: 'medium', label: 'medium' },
  { key: 'low', label: 'low' },
];

// opts.db / opts.policyPath / opts.mapPath / opts.verifyChain /
// opts.appendAudit / opts.getAuditHead / opts.signKey / opts.snapshots are
// injectable for tests; defaults are the real pg pool, live policy dir,
// live map file, the real AuditLog.verify/append/head, AUDIT_HMAC_KEY, and
// the weekly scheduler on (COMPLIANCE_SNAPSHOTS=off disables).
export async function complianceRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  // Compliance evidence reads are open to all three roles (auditors included,
  // AIM-95); snapshot writes stay admin only.
  const anyRole = requireRoles('admin', 'analyst', 'auditor', 'viewer');
  const adminOnly = requireRoles('admin');
  const getPolicy = () => loadPolicy(opts?.policyPath ?? policyPath());
  const getMap = () => loadComplianceMap(opts?.mapPath ?? complianceMapPath());
  const verifyChain = opts?.verifyChain ?? verifyAuditChain;
  const appendAudit = opts?.appendAudit ?? audit;
  const getAuditHead = opts?.getAuditHead ?? auditHead;
  const signKey = opts?.signKey ?? process.env.AUDIT_HMAC_KEY ?? null;

  /* ---------- report builder (shared by live report, bundle, snapshots) ---------- */

  async function buildReport(period, actor) {
    const [policy, map, { rows }] = await Promise.all([
      Promise.resolve().then(getPolicy),
      Promise.resolve().then(getMap),
      db.query(
        `SELECT rule_id, severity, status, COUNT(*)::int AS n
           FROM findings
          WHERE detected_at >= $1 AND detected_at < $2
          GROUP BY rule_id, severity, status`,
        [period.from, period.to]
      ),
    ]);

    // Per-rule finding counts.
    const byRule = new Map();
    for (const r of rows) {
      if (!byRule.has(r.rule_id)) byRule.set(r.rule_id, emptyCounts());
      const c = byRule.get(r.rule_id);
      c.total += r.n;
      if (OPEN_STATUSES.has(r.status)) c.open += r.n;
      if (c.bySeverity[r.severity] !== undefined) c.bySeverity[r.severity] += r.n;
    }

    const liveRuleIds = policy.rules.map((r) => r.id);

    // Coverage: every live rule mapped (or justified n/a) per framework.
    const coverageRows = coverageReport(map, liveRuleIds);
    const gaps = coverageRows.filter((r) => !r.ok);

    // Findings attributed to rules no longer in the map (stale/removed rules).
    const unmappedFindingRules = [...byRule.keys()].filter((id) => !map.rules[id]).sort();

    // Per-framework, per-control aggregation.
    const addCounts = (a, b) => {
      a.total += b.total;
      a.open += b.open;
      for (const s of SEVERITIES) a.bySeverity[s] += b.bySeverity[s];
    };
    // AIM-694: every catalogued control gets a live pass/fail/unknown status
    // from mapped rules + open findings. Snapshots store this report as-is.
    const frameworks = Object.values(map.frameworks).map((fw) => {
      const controls = Object.values(fw.controls).map((ctrl) => {
        const counts = emptyCounts();
        const ruleIds = [];
        for (const ruleId of liveRuleIds) {
          const m = map.rules[ruleId]?.[fw.id];
          if (!m || !m.controls.includes(ctrl.id)) continue;
          ruleIds.push(ruleId);
          addCounts(counts, byRule.get(ruleId) ?? emptyCounts());
        }
        const { status, reason: statusReason } = evaluateControlStatus({
          ruleIds,
          findings: counts,
        });
        return { ...ctrl, rules: ruleIds, findings: counts, status, statusReason };
      });
      return { id: fw.id, name: fw.name, controls };
    });
    const controlStatus = summarizeControlStatuses(frameworks);

    const auditChain = verifyChain();
    appendAudit(actor, 'audit.verify', 'compliance/report', {
      ok: auditChain.ok,
      records: auditChain.records,
      periodDays: Math.round((period.to - period.from) / DAY_MS),
    });

    return {
      generatedAt: new Date().toISOString(),
      period: { from: period.from.toISOString(), to: period.to.toISOString() },
      scopingNote: map.scopingNote,
      policy: { version: policy.version, contentHash: policy.contentHash, sources: policy.sources.map((s) => s.split('/').slice(-3).join('/')) },
      mapping: { version: map.version, contentHash: map.contentHash, source: map.source.split('/').slice(-3).join('/') },
      auditChain,
      coverage: { ok: gaps.length === 0, rules: liveRuleIds.length, checks: coverageRows.length, gaps },
      // Live continuous-monitoring rollup (AIM-694); weekly snapshots still run.
      controlStatus,
      frameworks,
      rules: policy.rules.map((r) => ({
        id: r.id,
        title: r.title,
        severity: r.severity,
        mappings: map.rules[r.id] ?? null,
        findings: byRule.get(r.id) ?? emptyCounts(),
      })),
      unmappedFindingRules,
    };
  }

  function chainAnchorFor(report) {
    const head = getAuditHead();
    return { ...report.auditChain, headSeq: head.headSeq, headSeal: head.headSeal };
  }

  /* ---------- snapshots: store, purge, scheduler (AIM-99) ---------- */

  async function takeSnapshot(kind, period, actor) {
    const report = await buildReport(period, actor);
    const payload = { kind: SNAPSHOT_KIND, version: 1, report, chainAnchor: chainAnchorFor(report) };
    const bundleHash = hashEvidencePayload(payload);
    const totals = report.rules.reduce((a, r) => ({ total: a.total + r.findings.total, open: a.open + r.findings.open }), { total: 0, open: 0 });
    const { rows } = await db.query(
      `INSERT INTO compliance_snapshots (kind, period_from, period_to, report, bundle_hash, audit_chain_ok, findings_total, findings_open)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)
       RETURNING id, created_at`,
      [kind, period.from, period.to, JSON.stringify(report), bundleHash, report.auditChain.ok ?? null, totals.total, totals.open]
    );
    appendAudit(actor, 'compliance.snapshot', 'compliance/snapshot', {
      snapshotId: rows[0].id,
      kind,
      bundleHash,
      periodDays: Math.round((period.to - period.from) / DAY_MS),
    });
    await purgeSnapshots();
    return { ...rows[0], bundleHash };
  }

  // Evidence retention per report type (retention: in framework-map.yaml).
  async function purgeSnapshots() {
    const map = getMap();
    await db.query(
      `DELETE FROM compliance_snapshots WHERE kind = 'weekly' AND created_at < now() - make_interval(days => $1)`,
      [map.retention.weeklySnapshotDays]
    );
    await db.query(
      `DELETE FROM compliance_snapshots WHERE kind = 'on_demand' AND created_at < now() - make_interval(days => $1)`,
      [map.retention.onDemandSnapshotDays]
    );
  }

  // Weekly scheduler: catch-up check at boot, then re-check on an interval.
  // Restart-safe (state lives in the table, not the process). Errors (e.g.
  // table not migrated yet) are logged and retried on the next tick.
  const snapCfg = opts?.snapshots ?? {};
  const snapshotsEnabled = snapCfg.enabled ?? process.env.COMPLIANCE_SNAPSHOTS !== 'off';
  if (snapshotsEnabled) {
    const weeklyEveryMs = snapCfg.weeklyEveryMs ?? WEEKLY_DAYS * DAY_MS;
    const checkEveryMs = snapCfg.checkEveryMs ?? 6 * 3600_000;
    const ensureWeekly = async () => {
      try {
        const { rows } = await db.query(
          `SELECT created_at FROM compliance_snapshots WHERE kind = 'weekly' ORDER BY created_at DESC LIMIT 1`
        );
        const last = rows[0]?.created_at;
        if (!last || Date.now() - new Date(last).getTime() >= weeklyEveryMs) {
          const to = new Date();
          await takeSnapshot('weekly', { from: new Date(to.getTime() - WEEKLY_DAYS * DAY_MS), to }, 'compliance-scheduler');
          fastify.log.info('weekly compliance snapshot stored');
        }
      } catch (err) {
        fastify.log.error({ err }, 'weekly compliance snapshot failed');
      }
    };
    const timer = setInterval(ensureWeekly, checkEveryMs);
    timer.unref?.();
    fastify.addHook('onClose', async () => clearInterval(timer));
    // Boot check is fire-and-forget: never block startup on the snapshot.
    ensureWeekly();
  }

  /* ---------- routes ---------- */

  fastify.get('/api/compliance/report', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    if (!checkFormat(req, reply, ['bundle'])) return reply;
    const period = parsePeriod(req.query);
    if (!period) {
      return reply.code(400).send({ error: 'bad_request', detail: 'from/to must be valid ISO dates with from < to' });
    }

    const actor = req.identity?.email ?? 'unknown';
    const report = await buildReport(period, actor);

    if (wantsCsv(req)) {
      // Regulator-ready CSV: a metadata header block (period, hashes,
      // audit-chain verdict) followed by the findings-by-control table —
      // same numbers as the JSON, per the AIM-82 no-drift rule.
      const auditChain = report.auditChain;
      const gaps = report.coverage.gaps;
      const meta = [
        { key: 'report', value: 'AI Monitoring — compliance evidence report (AIM-87/AIM-99)' },
        { key: 'generated_at', value: report.generatedAt },
        { key: 'period_from', value: report.period.from },
        { key: 'period_to', value: report.period.to },
        { key: 'policy_version', value: report.policy.version },
        { key: 'policy_hash', value: report.policy.contentHash },
        { key: 'mapping_version', value: report.mapping.version },
        { key: 'mapping_hash', value: report.mapping.contentHash },
        { key: 'audit_chain_status', value: auditChain.enabled ? (auditChain.ok ? 'verified' : `FAILED — ${auditChain.reason}`) : 'not configured' },
        { key: 'audit_chain_records', value: auditChain.records },
        { key: 'coverage', value: report.coverage.ok ? `complete (${report.coverage.rules} rules)` : `GAPS: ${gaps.map((g) => `${g.ruleId}/${g.framework}`).join('; ')}` },
        {
          key: 'control_status_summary',
          value: `pass=${report.controlStatus.pass} fail=${report.controlStatus.fail} unknown=${report.controlStatus.unknown} total=${report.controlStatus.total}`,
        },
        { key: 'scoping_note', value: report.scopingNote },
      ];
      const controlRows = [];
      for (const fw of report.frameworks) {
        for (const c of fw.controls) {
          controlRows.push({
            framework: fw.name,
            control_ref: c.ref,
            control_title: c.title,
            status: c.status,
            status_reason: c.statusReason,
            mapped_rules: c.rules.join(' '),
            findings_total: c.findings.total,
            findings_open: c.findings.open,
            critical: c.findings.bySeverity.critical,
            high: c.findings.bySeverity.high,
            medium: c.findings.bySeverity.medium,
            low: c.findings.bySeverity.low,
          });
        }
      }
      const csv = toCsv(META_COLS, meta) + '\r\n' + toCsv(CONTROL_COLS, controlRows);
      return reply
        .header('content-type', 'text/csv; charset=utf-8')
        .header('content-disposition', 'attachment; filename="aim-compliance-report.csv"')
        .send(csv);
    }

    if (req.query?.format === 'bundle') {
      // Signed, immutable evidence bundle (AIM-99) — hash-linked into the
      // audit chain. Verify offline with scripts/verify-compliance-bundle.mjs.
      const bundle = buildBundle({
        report,
        chainAnchor: chainAnchorFor(report),
        actor,
        appendAudit,
        signKey,
      });
      return reply
        .header('content-type', 'application/json; charset=utf-8')
        .header('content-disposition', 'attachment; filename="aim-compliance-bundle.json"')
        .send(bundle);
    }

    return report;
  });

  // Snapshot history (AIM-99): most recent first, summaries only.
  fastify.get('/api/compliance/snapshots', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const limit = Math.min(Math.max(Number(req.query?.limit) || 52, 1), 200);
    const [{ rows }, map] = await Promise.all([
      db.query(
        `SELECT id, created_at, kind, period_from, period_to, bundle_hash, audit_chain_ok, findings_total, findings_open
           FROM compliance_snapshots ORDER BY created_at DESC LIMIT $1`,
        [limit]
      ),
      Promise.resolve().then(getMap),
    ]);
    return {
      snapshots: rows.map((r) => ({
        id: r.id,
        createdAt: r.created_at,
        kind: r.kind,
        period: { from: r.period_from, to: r.period_to },
        bundleHash: r.bundle_hash,
        auditChainOk: r.audit_chain_ok,
        findings: { total: r.findings_total, open: r.findings_open },
      })),
      retention: {
        weeklySnapshotDays: map.retention.weeklySnapshotDays,
        onDemandSnapshotDays: map.retention.onDemandSnapshotDays,
        note: map.retention.note,
      },
    };
  });

  // One stored snapshot: the exact report JSON captured at snapshot time.
  fastify.get('/api/compliance/snapshots/:id', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return reply.code(400).send({ error: 'bad_request', detail: 'snapshot id must be a positive integer' });
    }
    const { rows } = await db.query(
      `SELECT id, created_at, kind, bundle_hash, report FROM compliance_snapshots WHERE id = $1`,
      [id]
    );
    if (!rows[0]) return reply.code(404).send({ error: 'not_found', detail: `no snapshot with id ${id}` });
    const r = rows[0];
    return {
      id: r.id,
      createdAt: r.created_at,
      kind: r.kind,
      bundleHash: r.bundle_hash,
      report: r.report,
    };
  });

  // On-demand snapshot (AIM-99): same builder as the weekly job, kind
  // 'on_demand', shorter retention per the framework-map retention policy.
  fastify.post('/api/compliance/snapshots', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const period = parsePeriod(req.query ?? {});
    if (!period) {
      return reply.code(400).send({ error: 'bad_request', detail: 'from/to must be valid ISO dates with from < to' });
    }
    const snap = await takeSnapshot('on_demand', period, req.identity?.email ?? 'unknown');
    return reply.code(201).send({ id: snap.id, createdAt: snap.created_at, bundleHash: snap.bundleHash });
  });
}

// live pilot false-positive rate SLO for secret/PII detectors.
//
// Acceptance: publish weekly FP rate; SLO e.g. <0.5% of sessions; page when
// breached. Telemetry (events + findings + triage) already collected —
// this module only measures and alerts.
//
// Primary metric (session_fp_rate):
//   distinct sessions with ≥1 finding on secret-pattern-in-prompt /
//   pii-in-prompt currently status=false_positive
//   ─────────────────────────────────────────────────────────────
//   distinct sessions with ≥1 event in the same period
//
// Pure evaluators live above the DB so unit tests need no Postgres/Redis.
// Background alerter XADDs onto the same security.alert/v1 bus as
// system-status / finding-SLA. Never on the request path.
//
// Env (compose defaults ON for the alerter + weekly snapshot):
//   DETECTOR_FP_SESSION_SLO_PCT=0.5
//   DETECTOR_FP_RATE_ALERTS=1
//   DETECTOR_FP_RATE_ALERT_INTERVAL_SEC=300
//   DETECTOR_FP_RATE_SNAPSHOTS=1   (weekly; off disables scheduler)

import { createHash } from 'node:crypto';
import { query } from './db.js';
import { hashEvidencePayload } from './compliance-bundle.js';

const DAY_MS = 86_400_000;
const WEEKLY_DAYS = 7;

/** Rules counted as secret/PII detector findings for this SLO. */
export const FP_RATE_RULES = Object.freeze([
  'secret-pattern-in-prompt',
  'pii-in-prompt',
]);

export const DEFAULT_SESSION_FP_SLO_PCT = 0.5; // < 0.5% of sessions

function envNum(name, fallback) {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function envInt(name, def) {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : def;
}

function num(v) {
  return Number(v ?? 0);
}

/** Max allowed session FP rate as a percentage (0.5 = half a percent). */
export function sessionFpSloPct() {
  const n = envNum('DETECTOR_FP_SESSION_SLO_PCT', DEFAULT_SESSION_FP_SLO_PCT);
  // Cap at 100 so a typo cannot silence breaches with a 5000% SLO.
  return Math.min(n, 100);
}

/**
 * Pure: compute session FP rate and SLO posture from aggregate counts.
 *
 * @param {{
 *   sessions: number,
 *   fpSessions: number,
 *   findings?: { ruleId: string, status: string, count: number }[],
 *   period?: { from: string|Date, to: string|Date },
 * }} counts
 * @param {{ maxSessionFpPct?: number, now?: Date }} [opts]
 */
export function evaluateSessionFpRate(counts, {
  maxSessionFpPct = sessionFpSloPct(),
  now = new Date(),
} = {}) {
  const sessions = Math.max(0, Math.floor(num(counts?.sessions)));
  const fpSessions = Math.max(0, Math.floor(num(counts?.fpSessions)));
  const cappedFp = Math.min(fpSessions, sessions);
  const rate = sessions > 0 ? cappedFp / sessions : 0;
  const ratePct = Math.round(rate * 10000) / 100; // two decimal places of a percent
  const maxRate = maxSessionFpPct / 100;
  const breached = sessions > 0 && rate > maxRate;

  // Roll up findings by rule + status for the published report.
  const byRule = {};
  let findingsTotal = 0;
  let findingsFp = 0;
  let findingsResolved = 0;
  let findingsOpen = 0;
  for (const row of counts?.findings ?? []) {
    const rid = row.ruleId ?? row.rule_id;
    if (!rid) continue;
    if (!byRule[rid]) {
      byRule[rid] = {
        ruleId: rid,
        new: 0,
        acknowledged: 0,
        resolved: 0,
        false_positive: 0,
        total: 0,
      };
    }
    const st = row.status;
    const c = Math.max(0, Math.floor(num(row.count)));
    if (byRule[rid][st] != null) byRule[rid][st] += c;
    byRule[rid].total += c;
    findingsTotal += c;
    if (st === 'false_positive') findingsFp += c;
    else if (st === 'resolved') findingsResolved += c;
    else if (st === 'new' || st === 'acknowledged') findingsOpen += c;
  }

  const triaged = findingsFp + findingsResolved;
  const triageCoverage = findingsTotal > 0 ? triaged / findingsTotal : null;
  // Finding-level FP share among triaged findings (diagnostic, not the SLO).
  const findingFpAmongTriaged = triaged > 0 ? findingsFp / triaged : null;

  let state;
  if (sessions === 0) {
    state = 'never_configured';
  } else if (breached) {
    state = 'broken';
  } else if (findingsTotal > 0 && triageCoverage != null && triageCoverage < 0.1) {
    // Rate is under SLO but almost nothing has been triaged — publish as
    // degraded so operators do not read a green 0% as "precision proven".
    state = 'degraded';
  } else {
    state = 'ok';
  }

  const period = counts?.period
    ? {
      from: iso(counts.period.from),
      to: iso(counts.period.to),
    }
    : null;

  const message = sessions === 0
    ? 'No sessions in the measurement window — FP rate is undefined.'
    : breached
      ? `Session FP rate ${ratePct}% exceeds SLO of <${maxSessionFpPct}% `
        + `(${cappedFp}/${sessions} sessions with a false-positive secret/PII finding).`
      : state === 'degraded'
        ? `Session FP rate ${ratePct}% is under SLO of <${maxSessionFpPct}%, `
          + `but only ${Math.round((triageCoverage ?? 0) * 100)}% of secret/PII findings are triaged — `
          + 'rate is not yet label-backed.'
        : `Session FP rate ${ratePct}% of sessions `
          + `(${cappedFp}/${sessions}) is under SLO of <${maxSessionFpPct}%.`;

  return {
    metric: 'session_fp_rate',
    period,
    sessions,
    fpSessions: cappedFp,
    sessionFpRate: rate,
    sessionFpRatePct: ratePct,
    slo: {
      text: `Secret/PII detector false-positive sessions <${maxSessionFpPct}% of sessions (trailing window)`,
      maxSessionFpPct,
      maxSessionFpRate: maxRate,
    },
    state,
    breach: breached || state === 'never_configured',
    message,
    findings: {
      total: findingsTotal,
      falsePositive: findingsFp,
      resolved: findingsResolved,
      open: findingsOpen,
      triageCoverage,
      findingFpAmongTriaged,
      byRule: Object.values(byRule).sort((a, b) => a.ruleId.localeCompare(b.ruleId)),
    },
    rules: [...FP_RATE_RULES],
    generatedAt: iso(now),
  };
}

function iso(v) {
  if (v == null) return null;
  if (v instanceof Date) return v.toISOString();
  const d = new Date(v);
  return Number.isFinite(d.getTime()) ? d.toISOString() : String(v);
}

function stableAlertId(dedupeHex) {
  const hexed = dedupeHex.slice(0, 32).padEnd(32, '0');
  const variant = '89ab'[parseInt(hexed[16], 16) % 4];
  return `${hexed.slice(0, 8)}-${hexed.slice(8, 12)}-4${hexed.slice(13, 16)}-${variant}${hexed.slice(17, 20)}-${hexed.slice(20, 32)}`;
}

function dedupeHex(parts) {
  return createHash('sha256').update(parts.join('|')).digest('hex');
}

/**
 * Pure: map a breached FP-rate evaluation → security.alert/v1 payload.
 * Only state=broken (rate above SLO) pages. never_configured / degraded
 * are install/triage gaps, not FP-rate incidents.
 */
export function fpRateBreachAlert(evaluation, { now = new Date() } = {}) {
  // Only page on hard SLO breach (state=broken). never_configured / degraded
  // are install or triage-coverage gaps, not FP-rate incidents.
  if (!evaluation || evaluation.state !== 'broken') return null;

  const stamp = now instanceof Date
    ? now.toISOString().replace(/\.\d{3}Z$/, 'Z')
    : String(now);
  const pct = evaluation.sessionFpRatePct;
  const max = evaluation.slo?.maxSessionFpPct ?? sessionFpSloPct();
  // Band by rate so re-pages fire when the rate climbs, not every tick.
  const band = pct < 1 ? '0.5-1' : pct < 2 ? '1-2' : pct < 5 ? '2-5' : '5+';
  const dedupe = dedupeHex(['detector-fp-rate', 'session', band, String(max)]);
  const title = `Secret/PII detector FP rate ${pct}% exceeds ${max}% session SLO`;

  return {
    schema_version: '1.1',
    alert_id: stableAlertId(dedupe),
    dedupe_key: dedupe,
    pillar: 'ai_usage',
    producer: { name: 'aim-detector-fp-rate', version: '1.0.0' },
    finding_type: 'ai_usage.detector_fp_rate_breach',
    title: title.slice(0, 200),
    severity: 'high',
    severity_id: 4,
    status: 'new',
    observed_at: stamp,
    first_seen_at: stamp,
    last_seen_at: stamp,
    resource: {
      kind: 'host',
      ref: 'aim:security/fp-rate',
      display: 'Detector FP rate SLO',
      provider: null,
      account_ref: null,
      region: null,
    },
    subject_ref: null,
    evidence: {
      source_uri: 'aim:/security/fp-rate',
      detail_count: evaluation.fpSessions ?? 0,
      summary: String(evaluation.message || title).slice(0, 240),
    },
    labels: {
      session_fp_rate_pct: String(pct).slice(0, 128),
      slo_max_pct: String(max).slice(0, 128),
      sessions: String(evaluation.sessions ?? 0).slice(0, 128),
      fp_sessions: String(evaluation.fpSessions ?? 0).slice(0, 128),
      breach_band: band,
    },
    remediation_hint: (
      'Open GET /api/security/fp-rate and #/findings filtered to '
      + 'rule_id=secret-pattern-in-prompt|pii-in-prompt&status=false_positive. '
      + 'Tune matchers or suppress proven noise classes '
      + 'before the rate erodes operator trust in enforce mode.'
    ).slice(0, 500),
  };
}

/**
 * Load trailing-window counts from Postgres and evaluate the SLO.
 * Window defaults to the last 7 days ending at `now`.
 */
export async function loadSessionFpRate(db = { query }, {
  days = WEEKLY_DAYS,
  now = new Date(),
  maxSessionFpPct = sessionFpSloPct(),
  rules = FP_RATE_RULES,
} = {}) {
  const to = now instanceof Date ? now : new Date(now);
  const from = new Date(to.getTime() - Math.max(1, days) * DAY_MS);

  const [sessionsRes, fpSessionsRes, findingsRes] = await Promise.all([
    db.query(
      `SELECT COUNT(DISTINCT session_id)::int AS sessions
         FROM events
        WHERE ts >= $1 AND ts < $2`,
      [from, to],
    ),
    // Session identity: prefer the joined event; fall back to the
    // metadata-only evidence.context.session_id so findings whose event
    // row was retained/purged still count.
    db.query(
      `SELECT COUNT(DISTINCT session_id)::int AS fp_sessions
         FROM (
           SELECT COALESCE(e.session_id, f.evidence #>> '{context,session_id}') AS session_id
             FROM findings f
             LEFT JOIN events e ON e.event_id = f.event_id
            WHERE f.rule_id = ANY($1)
              AND f.status = 'false_positive'
              AND f.ts >= $2 AND f.ts < $3
         ) s
        WHERE session_id IS NOT NULL AND session_id <> ''`,
      [rules, from, to],
    ),
    db.query(
      `SELECT rule_id, status, COUNT(*)::int AS count
         FROM findings
        WHERE rule_id = ANY($1)
          AND ts >= $2 AND ts < $3
        GROUP BY rule_id, status
        ORDER BY rule_id, status`,
      [rules, from, to],
    ),
  ]);

  const sessions = num(sessionsRes.rows[0]?.sessions);
  const fpSessions = num(fpSessionsRes.rows[0]?.fp_sessions);
  const findings = (findingsRes.rows ?? []).map((r) => ({
    ruleId: r.rule_id,
    status: r.status,
    count: num(r.count),
  }));

  return evaluateSessionFpRate(
    { sessions, fpSessions, findings, period: { from, to } },
    { maxSessionFpPct, now: to },
  );
}

/** Seal a report with a stable content hash (same construction as compliance). */
export function sealFpRateReport(evaluation) {
  const reportHash = hashEvidencePayload({
    kind: 'aim-detector-fp-rate',
    version: 1,
    metric: evaluation.metric,
    period: evaluation.period,
    sessions: evaluation.sessions,
    fpSessions: evaluation.fpSessions,
    sessionFpRate: evaluation.sessionFpRate,
    slo: evaluation.slo,
    state: evaluation.state,
    findings: evaluation.findings,
    rules: evaluation.rules,
  });
  return { ...evaluation, reportHash, version: 1, kind: 'aim-detector-fp-rate' };
}

/**
 * Persist a snapshot. kind is 'weekly' (scheduler) or 'on_demand'.
 * Returns the inserted row id + hash.
 */
export async function storeFpRateSnapshot(db, evaluation, {
  kind = 'on_demand',
} = {}) {
  const sealed = sealFpRateReport(evaluation);
  const period = sealed.period ?? { from: null, to: null };
  const { rows } = await db.query(
    `INSERT INTO fp_rate_snapshots
       (kind, period_from, period_to, report, sessions, fp_sessions,
        session_fp_rate, slo_max_pct, breached, report_hash)
     VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10)
     RETURNING id, created_at, report_hash`,
    [
      kind,
      period.from,
      period.to,
      JSON.stringify(sealed),
      sealed.sessions,
      sealed.fpSessions,
      sealed.sessionFpRate,
      sealed.slo?.maxSessionFpPct ?? sessionFpSloPct(),
      sealed.state === 'broken',
      sealed.reportHash,
    ],
  );
  return {
    id: rows[0].id,
    createdAt: iso(rows[0].created_at),
    reportHash: rows[0].report_hash,
    report: sealed,
  };
}

export async function listFpRateSnapshots(db = { query }, {
  limit = 20,
  kind = null,
} = {}) {
  const lim = Math.min(Math.max(1, Math.floor(limit)), 100);
  if (kind) {
    const { rows } = await db.query(
      `SELECT id, created_at, kind, period_from, period_to, sessions,
              fp_sessions, session_fp_rate, slo_max_pct, breached, report_hash
         FROM fp_rate_snapshots
        WHERE kind = $1
        ORDER BY created_at DESC
        LIMIT $2`,
      [kind, lim],
    );
    return rows.map(mapSnapshotRow);
  }
  const { rows } = await db.query(
    `SELECT id, created_at, kind, period_from, period_to, sessions,
            fp_sessions, session_fp_rate, slo_max_pct, breached, report_hash
       FROM fp_rate_snapshots
      ORDER BY created_at DESC
      LIMIT $1`,
    [lim],
  );
  return rows.map(mapSnapshotRow);
}

function mapSnapshotRow(r) {
  return {
    id: r.id,
    createdAt: iso(r.created_at),
    kind: r.kind,
    period: { from: iso(r.period_from), to: iso(r.period_to) },
    sessions: num(r.sessions),
    fpSessions: num(r.fp_sessions),
    sessionFpRate: num(r.session_fp_rate),
    sessionFpRatePct: Math.round(num(r.session_fp_rate) * 10000) / 100,
    sloMaxPct: num(r.slo_max_pct),
    breached: Boolean(r.breached),
    reportHash: r.report_hash,
  };
}

export async function getFpRateSnapshot(db = { query }, id) {
  const { rows } = await db.query(
    `SELECT id, created_at, kind, period_from, period_to, report,
            sessions, fp_sessions, session_fp_rate, slo_max_pct,
            breached, report_hash
       FROM fp_rate_snapshots WHERE id = $1`,
    [id],
  );
  if (!rows[0]) return null;
  const r = rows[0];
  return {
    ...mapSnapshotRow(r),
    report: r.report,
  };
}

/**
 * Background publisher: standing session-FP-rate SLO breaches → alert bus.
 * Opt-in via DETECTOR_FP_RATE_ALERTS=1. Never XADDs on the request path.
 */
export function startFpRateAlerter({
  db = { query },
  publish,
  intervalMs,
  log = console,
  days = WEEKLY_DAYS,
  maxSessionFpPct = sessionFpSloPct(),
} = {}) {
  if (process.env.DETECTOR_FP_RATE_ALERTS !== '1'
    && process.env.DETECTOR_FP_RATE_ALERTS !== 'true') {
    return { stop() {}, enabled: false };
  }
  if (typeof publish !== 'function') {
    log.warn?.('DETECTOR_FP_RATE_ALERTS set but no publish function — alerter idle');
    return { stop() {}, enabled: false };
  }
  const ms = intervalMs
    ?? (envInt('DETECTOR_FP_RATE_ALERT_INTERVAL_SEC', 300) * 1000);
  const seen = new Map();
  const TTL = 6 * 60 * 60 * 1000; // re-emit standing breaches every 6h

  let timer = null;
  let running = false;

  async function tick() {
    if (running) return;
    running = true;
    try {
      const evaluation = await loadSessionFpRate(db, { days, maxSessionFpPct });
      const alert = fpRateBreachAlert(evaluation);
      const now = Date.now();
      if (alert) {
        const last = seen.get(alert.dedupe_key) ?? 0;
        if (now - last >= TTL) {
          await publish(alert);
          seen.set(alert.dedupe_key, now);
          log.info?.(
            {
              sessionFpRatePct: evaluation.sessionFpRatePct,
              sessions: evaluation.sessions,
              fpSessions: evaluation.fpSessions,
              dedupe: alert.dedupe_key,
            },
            'detector FP rate breach alert published',
          );
        }
      }
      const live = alert ? new Set([alert.dedupe_key]) : new Set();
      for (const k of seen.keys()) {
        if (!live.has(k)) seen.delete(k);
      }
    } catch (err) {
      log.error?.({ err }, 'detector FP rate alerter tick failed');
    } finally {
      running = false;
    }
  }

  timer = setInterval(tick, ms);
  const boot = setTimeout(tick, Math.min(ms, 15_000));
  return {
    enabled: true,
    stop() {
      clearInterval(timer);
      clearTimeout(boot);
    },
    _tick: tick,
    _seen: seen,
  };
}

/**
 * Weekly snapshot scheduler. Opt-in via DETECTOR_FP_RATE_SNAPSHOTS=1 (default
 * on when env unset in compose; explicit 'off' disables).
 */
export function startFpRateSnapshotScheduler({
  db = { query },
  intervalMs,
  log = console,
  days = WEEKLY_DAYS,
} = {}) {
  const flag = process.env.DETECTOR_FP_RATE_SNAPSHOTS;
  if (flag === '0' || flag === 'false' || flag === 'off') {
    return { stop() {}, enabled: false };
  }
  // Default on when unset (pilot wants the weekly series). Explicit 0/off above.
  const ms = intervalMs
    ?? (envInt('DETECTOR_FP_RATE_SNAPSHOT_CHECK_SEC', 3600) * 1000);
  const weeklyEveryMs = envInt('DETECTOR_FP_RATE_WEEKLY_DAYS', WEEKLY_DAYS) * DAY_MS;

  let timer = null;
  let running = false;

  async function tick() {
    if (running) return;
    running = true;
    try {
      const { rows } = await db.query(
        `SELECT created_at FROM fp_rate_snapshots
          WHERE kind = 'weekly'
          ORDER BY created_at DESC LIMIT 1`,
      );
      const last = rows[0]?.created_at ? new Date(rows[0].created_at).getTime() : 0;
      if (last && Date.now() - last < weeklyEveryMs) return;
      const evaluation = await loadSessionFpRate(db, { days });
      const stored = await storeFpRateSnapshot(db, evaluation, { kind: 'weekly' });
      log.info?.(
        {
          id: stored.id,
          sessionFpRatePct: evaluation.sessionFpRatePct,
          breached: evaluation.state === 'broken',
          reportHash: stored.reportHash,
        },
        'weekly detector FP rate snapshot stored',
      );
    } catch (err) {
      log.error?.({ err }, 'weekly detector FP rate snapshot failed');
    } finally {
      running = false;
    }
  }

  timer = setInterval(tick, ms);
  const boot = setTimeout(tick, Math.min(ms, 30_000));
  return {
    enabled: true,
    stop() {
      clearInterval(timer);
      clearTimeout(boot);
    },
    _tick: tick,
  };
}

export default {
  FP_RATE_RULES,
  sessionFpSloPct,
  evaluateSessionFpRate,
  fpRateBreachAlert,
  loadSessionFpRate,
  sealFpRateReport,
  storeFpRateSnapshot,
  listFpRateSnapshots,
  getFpRateSnapshot,
  startFpRateAlerter,
  startFpRateSnapshotScheduler,
};

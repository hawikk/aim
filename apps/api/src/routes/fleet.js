// Fleet / collector coverage API (AIM-80 / AIM-439 / AIM-645). Reads the device
// registry written by ingest enrollment + heartbeats (AIM-28) from the same
// Postgres the dashboard already reads. Health semantics mirror ingest's
// coverage rollup (services/ingest/src/device-store.ts): healthy = last
// heartbeat within 1x the device's own heartbeat interval, stale = within 3x,
// dead = older, never_seen = no heartbeat yet; revoked devices are excluded
// entirely.
//
// AIM-452: a device that stops reporting becomes a coverage *gap* within one
// heartbeat interval (stale), not a silent disappearance. Every coverage
// claim carries lastVerifiedAt so a stale number is visibly stale.
//
// AIM-619 / AIM-588: optional `trend` is a multi-day series from
// fleet_coverage_daily — real daily snapshots, never a single live rollup
// repeated across days. Scheduler + on-read upsert keep "today" current;
// prior days freeze at their last capture. Frontend soft-fails when trend is
// empty/missing.
// AIM-612 / AIM-588: optional `trend` (daily coverage rollup for the Fleet
// chart) is intentionally omitted. There is no coverage history store —
// devices only hold the live snapshot (last_heartbeat_at). Do not invent a
// multi-day series from the current snapshot alone. The frontend soft-fails
// to an honest empty state until a real daily rollup (snapshot table or
// heartbeat-derived history) lands.
//
// AIM-645: collector coverage SLO — ≥99% of enrolled fleet is SLO-healthy.
// SLO-healthy is stricter than the green heartbeat bucket: version present,
// last_event_at (liveness heartbeat) fresh within 1× interval, and no active
// client-side errors. Enrollment grace (24h) excludes brand-new never_seen
// devices from the denominator so a weekend enroll does not page. See
// docs/deployment/collector-coverage-slo.md.
//
// GATED to the security group, same as /api/findings (privacy gate): fleet
// inventory is operator/security data. device_token_hash is never selected.
// Raw last_counters JSON never leaves the API either — AIM-439 projects the
// drop-health fields collectors already report on heartbeat (events_rejected,
// events_spooled, batches_fully_rejected, last_rejection_at) so silent
// client-side loss is first-class, not buried in an opaque blob.
import { query } from '../db.js';
import { requireRoles } from '../auth.js';

// Health thresholds in multiples of the device's own heartbeat interval
// (mirror services/ingest/src/device-store.ts).
// STALE_INTERVALS = 1 means a missed heartbeat is a coverage gap within one
// interval (AIM-452 AC4), not after three.
const STALE_INTERVALS = 1;
const DEAD_INTERVALS = 3;

// AIM-439: a drop is "active" when the collector last recorded a rejection
// within this many seconds (default 2× the usual 5m heartbeat interval).
// Lifetime counters stay visible forever; only the active window pages.
const DEFAULT_DROP_RECENT_SEC = 900;

const _DAY_MS = 86_400_000;
const DEFAULT_TREND_DAYS = 30;
const DEFAULT_HISTORY_RETENTION_DAYS = 365;
const DEFAULT_SNAPSHOT_CHECK_MS = 3600_000; // hourly
// AIM-866: offset pagination for /api/fleet (path-to-5k). Default page ≤ 100
// for UI; rollup counts (deployed/healthy/…) stay fleet-wide. p95 latency
// budget ≤ 400 ms @ 700 seats / page (docs/frontend-performance-budget.md §4.1;
// docs/api-read-path-pagination.md).
const FLEET_DEFAULT_LIMIT = 100;
const FLEET_MAX_LIMIT = 100;

function parseFleetLimit(q) {
  const n = Number(q?.limit ?? FLEET_DEFAULT_LIMIT);
  if (!Number.isFinite(n) || n < 1) return FLEET_DEFAULT_LIMIT;
  return Math.min(Math.floor(n), FLEET_MAX_LIMIT);
}

function parseFleetOffset(q) {
  const n = Number(q?.offset ?? 0);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

// AIM-645 collector coverage SLO defaults.
/** Target share of enrolled (grace-adjusted) devices that must be SLO-healthy. */
export const DEFAULT_COVERAGE_SLO_TARGET_PCT = 99;
/** Enrollment grace: never_seen devices younger than this are out of denom. */
export const DEFAULT_COVERAGE_SLO_WINDOW_SECONDS = 24 * 60 * 60;

function healthOf(lastHeartbeat, intervalSec, nowMs) {
  if (!lastHeartbeat) return 'never_seen';
  const ageSec = (nowMs - lastHeartbeat.getTime()) / 1000;
  if (ageSec <= intervalSec * STALE_INTERVALS) return 'healthy';
  if (ageSec <= intervalSec * DEAD_INTERVALS) return 'stale';
  return 'dead';
}

const toIso = (v) => (v instanceof Date ? v.toISOString() : String(v));

function envInt(name, fallback) {
  const raw = process.env[name];
  if (raw == null || raw === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
}

function parseDays(q, def = DEFAULT_TREND_DAYS, max = 365) {
  const d = Number(q?.days ?? def);
  if (!Number.isFinite(d) || d < 1) return def;
  return Math.min(Math.floor(d), max);
}

/**
 * UTC calendar day as midnight ISO (AIM-588 fixture contract).
 * @param {Date|string|number} [when]
 */
export function utcDayIso(when = new Date()) {
  const d = when instanceof Date ? when : new Date(when);
  if (!Number.isFinite(d.getTime())) {
    const s = String(when);
    if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return `${s}T00:00:00.000Z`;
    return s;
  }
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate())).toISOString();
}

/** YYYY-MM-DD for Postgres DATE keys. */
export function utcDayKey(when = new Date()) {
  return utcDayIso(when).slice(0, 10);
}

/**
 * healthy/deployed * 100 to one decimal (fixture: 120/135 → 88.9).
 * @param {number} healthy
 * @param {number} deployed
 */
export function healthyPct(healthy, deployed) {
  const dep = Number(deployed) || 0;
  const h = Number(healthy) || 0;
  if (dep <= 0) return 0;
  return Math.round((h / dep) * 1000) / 10;
}

export function coverageSloTargetPct(env = process.env) {
  const raw = Number(env.COLLECTOR_COVERAGE_SLO_TARGET_PCT);
  return Number.isFinite(raw) && raw >= 0 && raw <= 100
    ? raw
    : DEFAULT_COVERAGE_SLO_TARGET_PCT;
}

export function coverageSloWindowSeconds(env = process.env) {
  const raw = Number(env.COLLECTOR_COVERAGE_SLO_WINDOW_SECONDS);
  return Number.isFinite(raw) && raw > 0
    ? Math.floor(raw)
    : DEFAULT_COVERAGE_SLO_WINDOW_SECONDS;
}

/**
 * AIM-645: per-device SLO health.
 *
 * A device is SLO-healthy when ALL of:
 *   1. version — non-empty collector_version
 *   2. last_event_at — last_heartbeat_at within 1× heartbeat_interval_sec
 *      (heartbeat is the coverage liveness event; field alias last_event_at)
 *   3. errors — no active client-side drop (drop_active === false)
 *
 * Pure and unit-testable. `drops` is the projectDropHealth() result.
 *
 * @returns {{ sloHealthy: boolean, last_event_at: string|null, unhealthyReasons: string[] }}
 */
export function evaluateDeviceSloHealth({
  collector_version: version,
  last_heartbeat_at: lastHb,
  heartbeat_interval_sec: intervalSec,
  drops,
  health,
  nowMs = Date.now(),
} = {}) {
  const reasons = [];
  const interval = Math.max(1, Number(intervalSec) || 300);
  const ver = version == null ? '' : String(version).trim();
  if (!ver) reasons.push('missing_version');

  let lastEventAt = null;
  if (lastHb) {
    const ms = lastHb instanceof Date ? lastHb.getTime() : new Date(lastHb).getTime();
    if (Number.isFinite(ms)) {
      lastEventAt = new Date(ms).toISOString();
      const ageSec = (nowMs - ms) / 1000;
      if (ageSec > interval * STALE_INTERVALS) reasons.push('stale_last_event_at');
    } else {
      reasons.push('missing_last_event_at');
    }
  } else {
    reasons.push('missing_last_event_at');
  }

  if (drops?.drop_active) reasons.push('active_errors');

  // Mirror bucket for callers that only have the coarse health label.
  if (health === 'never_seen' && !reasons.includes('missing_last_event_at')) {
    reasons.push('missing_last_event_at');
  }

  return {
    sloHealthy: reasons.length === 0,
    last_event_at: lastEventAt,
    unhealthyReasons: reasons,
  };
}

/**
 * AIM-645: fleet-level collector coverage SLO.
 *
 * Coverage = sloHealthy / inScope, where inScope is enrolled non-revoked
 * devices minus never_seen enrollments still inside the 24h grace window.
 * Alert when inScope > 0 and healthyPct < targetPct.
 *
 * @param {Array<object>} devices device rows already projected (health, drops, enrolled_at, …)
 * @param {{ targetPct?: number, windowSeconds?: number, nowMs?: number }} [opts]
 */
export function evaluateCollectorCoverageSlo(devices, opts = {}) {
  const targetPct = opts.targetPct ?? DEFAULT_COVERAGE_SLO_TARGET_PCT;
  const windowSeconds = opts.windowSeconds ?? DEFAULT_COVERAGE_SLO_WINDOW_SECONDS;
  const nowMs = opts.nowMs ?? Date.now();
  const enrolled = (devices ?? []).length;
  let inScope = 0;
  let sloHealthy = 0;
  let graceExcluded = 0;
  let missingVersion = 0;
  let missingOrStaleEvent = 0;
  let activeErrors = 0;

  for (const d of devices ?? []) {
    const enrolledAt = d.enrolled_at ? new Date(d.enrolled_at).getTime() : NaN;
    // never_seen = no heartbeat yet. Do not use unhealthyReasons alone —
    // missing_version on a live host is not grace-eligible.
    const neverSeen = d.health === 'never_seen' || d.last_heartbeat_at == null;
    const withinGrace = Number.isFinite(enrolledAt)
      && (nowMs - enrolledAt) / 1000 < windowSeconds;
    // Brand-new never_seen enrollments do not count against coverage.
    if (neverSeen && withinGrace) {
      graceExcluded += 1;
      continue;
    }
    inScope += 1;
    const reasons = d.unhealthyReasons
      ?? evaluateDeviceSloHealth({
        collector_version: d.collector_version,
        last_heartbeat_at: d.last_heartbeat_at,
        heartbeat_interval_sec: d.heartbeat_interval_sec,
        drops: { drop_active: d.drop_active },
        health: d.health,
        nowMs,
      }).unhealthyReasons;
    const healthy = d.sloHealthy != null
      ? Boolean(d.sloHealthy)
      : reasons.length === 0;
    if (healthy) {
      sloHealthy += 1;
    } else {
      if (reasons.includes('missing_version')) missingVersion += 1;
      if (reasons.includes('missing_last_event_at') || reasons.includes('stale_last_event_at')) {
        missingOrStaleEvent += 1;
      }
      if (reasons.includes('active_errors')) activeErrors += 1;
    }
  }

  // One decimal; a single unhealthy host in a large fleet must not round to 100%.
  let healthyPct = null;
  if (inScope === 0) {
    healthyPct = null;
  } else if (sloHealthy === inScope) {
    healthyPct = 100;
  } else {
    const exact = Math.round((sloHealthy / inScope) * 1000) / 10;
    healthyPct = Math.min(exact, 99.9);
  }
  const alert = inScope > 0 && healthyPct != null && healthyPct < targetPct;
  const status = enrolled === 0
    ? 'no_collectors'
    : (inScope === 0
      ? 'pending_grace'
      : (alert ? 'breach' : 'ok'));
  const message = status === 'no_collectors'
    ? 'No collectors enrolled — coverage SLO is undefined.'
    : status === 'pending_grace'
      ? `${graceExcluded} enrolled device(s) still in the ${Math.round(windowSeconds / 3600)}h grace window; coverage SLO waits for first heartbeat or grace expiry.`
      : alert
        ? `Collector coverage ${healthyPct}% of ${inScope} in-scope enrolled device(s) is below the ${targetPct}% SLO (24h grace window).`
        : `Collector coverage ${healthyPct}% of ${inScope} in-scope enrolled device(s) meets the ${targetPct}% SLO.`;

  return {
    targetPct,
    windowSeconds,
    enrolled,
    inScope,
    graceExcluded,
    sloHealthy,
    unhealthy: Math.max(0, inScope - sloHealthy),
    healthyPct,
    alert,
    status,
    message,
    breakdown: {
      missingVersion,
      missingOrStaleEvent,
      activeErrors,
    },
  };
}

/**
 * Project safe, typed drop-health fields from a heartbeat counters object.
 * Pure so fleet + system-status share the same semantics (AIM-439).
 *
 * @param {unknown} counters raw last_counters JSON (object or null)
 * @param {number} nowMs
 * @param {{ recentSec?: number }} [opts]
 */
export function projectDropHealth(counters, nowMs = Date.now(), opts = {}) {
  const c = counters && typeof counters === 'object' && !Array.isArray(counters)
    ? counters
    : {};
  const eventsRejected = Math.max(0, Math.floor(Number(c.events_rejected) || 0));
  const eventsSpooled = Math.max(0, Math.floor(Number(c.events_spooled) || 0));
  const batchesFullyRejected = Math.max(0, Math.floor(Number(c.batches_fully_rejected) || 0));
  // Collectors send unix seconds; tolerate ms if a future build ever does.
  let lastRejectionAt = null;
  const rawAt = c.last_rejection_at;
  if (rawAt != null && rawAt !== '') {
    const n = Number(rawAt);
    if (Number.isFinite(n) && n > 0) {
      const ms = n > 1e12 ? n : n * 1000;
      lastRejectionAt = new Date(ms).toISOString();
    }
  }
  const recentSec = opts.recentSec ?? envInt('COLLECTOR_DROP_RECENT_SEC', DEFAULT_DROP_RECENT_SEC);
  let dropActive = false;
  if (lastRejectionAt && (eventsRejected > 0 || batchesFullyRejected > 0)) {
    const ageSec = (nowMs - new Date(lastRejectionAt).getTime()) / 1000;
    if (Number.isFinite(ageSec) && ageSec >= 0 && ageSec <= recentSec) {
      dropActive = true;
    }
  }
  // Ratio of rejected events to (rejected + would-have-been-sent proxy).
  // Spooled is "waiting", not successfully sent — still useful as denominator
  // when both are non-zero; null when we cannot form a meaningful ratio.
  let rejectedRatio = null;
  const denom = eventsRejected + eventsSpooled;
  if (denom > 0 && eventsRejected > 0) {
    rejectedRatio = Math.round((eventsRejected / denom) * 1000) / 1000;
  } else if (eventsRejected > 0 && eventsSpooled === 0) {
    rejectedRatio = 1;
  }
  return {
    events_rejected: eventsRejected,
    events_spooled: eventsSpooled,
    batches_fully_rejected: batchesFullyRejected,
    last_rejection_at: lastRejectionAt,
    rejected_ratio: rejectedRatio,
    drop_active: dropActive,
  };
}

/**
 * Map device rows → inventory devices + live rollup counts (no DB).
 * @param {Array<Record<string, unknown>>} rows
 * @param {number} nowMs
 * @param {{ recentSec?: number }} [opts]
 */
export function buildFleetSummary(rows, nowMs = Date.now(), opts = {}) {
  const recentSec = opts.recentSec ?? envInt('COLLECTOR_DROP_RECENT_SEC', DEFAULT_DROP_RECENT_SEC);
  const devices = (rows ?? []).map((r) => {
    const intervalSec = Number(r.heartbeat_interval_sec) || 300;
    const lastHb = r.last_heartbeat_at ? new Date(toIso(r.last_heartbeat_at)) : null;
    const health = healthOf(lastHb, intervalSec, nowMs);
    const coverageGap = health !== 'healthy';
    const silent = health === 'stale' || health === 'dead';
    const drops = projectDropHealth(r.last_counters, nowMs, { recentSec });
    return {
      device_id: String(r.device_id),
      host_id: String(r.host_id),
      hostname: r.hostname ?? null,
      os: r.os ?? null,
      ring: r.ring ?? null,
      collector_version: r.collector_version ?? null,
      enrolled_at: toIso(r.enrolled_at),
      last_heartbeat_at: lastHb ? lastHb.toISOString() : null,
      heartbeat_interval_sec: intervalSec,
      health,
      silent,
      coverageGap,
      events_rejected: drops.events_rejected,
      events_spooled: drops.events_spooled,
      batches_fully_rejected: drops.batches_fully_rejected,
      last_rejection_at: drops.last_rejection_at,
      rejected_ratio: drops.rejected_ratio,
      drop_active: drops.drop_active,
    };
  });
  const summary = {
    deployed: devices.length,
    healthy: 0,
    stale: 0,
    dead: 0,
    never_seen: 0,
    silent: 0,
    coverageGaps: 0,
    lastVerifiedAt: new Date(nowMs).toISOString(),
    dropping: 0,
    devices,
  };
  for (const d of devices) {
    summary[d.health] += 1;
    if (d.silent) summary.silent += 1;
    if (d.coverageGap) summary.coverageGaps += 1;
    if (d.drop_active) summary.dropping += 1;
  }
  return summary;
}

/**
 * Snapshot counts for fleet_coverage_daily / trend point (no devices list).
 * @param {{ deployed: number, healthy: number, stale: number, dead: number, never_seen: number, silent: number, coverageGaps: number, dropping: number }} summary
 * @param {Date|string|number} [when]
 */
export function coverageRollupFromSummary(summary, when = new Date()) {
  const deployed = Number(summary.deployed) || 0;
  const healthy = Number(summary.healthy) || 0;
  return {
    day: utcDayIso(when),
    deployed,
    healthy,
    stale: Number(summary.stale) || 0,
    dead: Number(summary.dead) || 0,
    never_seen: Number(summary.never_seen) || 0,
    silent: Number(summary.silent) || 0,
    coverageGaps: Number(summary.coverageGaps) || 0,
    dropping: Number(summary.dropping) || 0,
    healthyPct: healthyPct(healthy, deployed),
  };
}

/**
 * Map DB history rows → AIM-588 trend points (sorted ascending by day).
 * @param {Array<Record<string, unknown>>} rows
 */
export function historyRowsToTrend(rows) {
  const out = [];
  for (const r of rows ?? []) {
    const day = utcDayIso(r.day);
    if (!day) continue;
    const deployed = Number(r.deployed) || 0;
    const healthy = Number(r.healthy) || 0;
    const pctRaw = r.healthy_pct ?? r.healthyPct;
    const pct = pctRaw != null && Number.isFinite(Number(pctRaw))
      ? Math.round(Number(pctRaw) * 10) / 10
      : healthyPct(healthy, deployed);
    out.push({
      day,
      deployed,
      healthy,
      stale: Number(r.stale) || 0,
      dead: Number(r.dead) || 0,
      never_seen: Number(r.never_seen) || 0,
      silent: Number(r.silent) || 0,
      coverageGaps: Number(r.coverage_gaps ?? r.coverageGaps) || 0,
      dropping: Number(r.dropping) || 0,
      healthyPct: pct,
    });
  }
  return out.sort((a, b) => a.day.localeCompare(b.day));
}

/**
 * Upsert today's coverage rollup. Idempotent per UTC day.
 * @param {{ query: Function }} db
 * @param {ReturnType<typeof coverageRollupFromSummary>} rollup
 * @param {number} [nowMs]
 */
export async function upsertCoverageDay(db, rollup, nowMs = Date.now()) {
  const dayKey = utcDayKey(rollup.day);
  await db.query(
    `INSERT INTO fleet_coverage_daily
       (day, captured_at, deployed, healthy, stale, dead, never_seen,
        silent, coverage_gaps, dropping, healthy_pct)
     VALUES ($1::date, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
     ON CONFLICT (day) DO UPDATE SET
       captured_at   = EXCLUDED.captured_at,
       deployed      = EXCLUDED.deployed,
       healthy       = EXCLUDED.healthy,
       stale         = EXCLUDED.stale,
       dead          = EXCLUDED.dead,
       never_seen    = EXCLUDED.never_seen,
       silent        = EXCLUDED.silent,
       coverage_gaps = EXCLUDED.coverage_gaps,
       dropping      = EXCLUDED.dropping,
       healthy_pct   = EXCLUDED.healthy_pct`,
    [
      dayKey,
      new Date(nowMs).toISOString(),
      rollup.deployed,
      rollup.healthy,
      rollup.stale,
      rollup.dead,
      rollup.never_seen,
      rollup.silent,
      rollup.coverageGaps,
      rollup.dropping,
      rollup.healthyPct,
    ],
  );
}

/**
 * Load last N calendar days of stored coverage (real history only).
 * @param {{ query: Function }} db
 * @param {number} days
 */
export async function loadCoverageTrend(db, days = DEFAULT_TREND_DAYS) {
  const { rows } = await db.query(
    `SELECT day, deployed, healthy, stale, dead, never_seen, silent,
            coverage_gaps, dropping, healthy_pct
       FROM fleet_coverage_daily
      WHERE day >= (CURRENT_DATE - ($1::int - 1))
      ORDER BY day ASC`,
    [days],
  );
  return historyRowsToTrend(rows);
}

async function purgeOldCoverage(db, keepDays) {
  await db.query(
    `DELETE FROM fleet_coverage_daily
      WHERE day < (CURRENT_DATE - $1::int)`,
    [keepDays],
  );
}

/**
 * Snapshot devices → upsert today. Returns the rollup or null on failure.
 * @param {{ query: Function }} db
 * @param {{ nowMs?: number, recentSec?: number, log?: { error?: Function, info?: Function } }} [opts]
 */
export async function snapshotFleetCoverage(db, opts = {}) {
  const nowMs = opts.nowMs ?? Date.now();
  const recentSec = opts.recentSec ?? envInt('COLLECTOR_DROP_RECENT_SEC', DEFAULT_DROP_RECENT_SEC);
  const { rows } = await db.query(
    `SELECT device_id, host_id, hostname, os, ring, collector_version,
            enrolled_at, last_heartbeat_at, heartbeat_interval_sec,
            last_counters
       FROM devices
      WHERE revoked_at IS NULL`,
  );
  const summary = buildFleetSummary(rows, nowMs, { recentSec });
  const rollup = coverageRollupFromSummary(summary, nowMs);
  await upsertCoverageDay(db, rollup, nowMs);
  const keepDays = envInt('FLEET_COVERAGE_HISTORY_DAYS', DEFAULT_HISTORY_RETENTION_DAYS);
  await purgeOldCoverage(db, keepDays);
  return rollup;
}

// opts.db is injectable for tests; defaults to the real pg pool.
// opts.history / opts.snapshots control the AIM-619 daily history path.
export async function fleetRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const userLevel = requireRoles('analyst', 'admin');

  const snapCfg = opts?.snapshots ?? {};
  const snapshotsEnabled = snapCfg.enabled ?? process.env.FLEET_COVERAGE_SNAPSHOTS !== 'off';
  if (snapshotsEnabled) {
    const checkEveryMs = snapCfg.checkEveryMs ?? envInt('FLEET_COVERAGE_SNAPSHOT_MS', DEFAULT_SNAPSHOT_CHECK_MS);
    const tick = async () => {
      try {
        await snapshotFleetCoverage(db);
        fastify.log?.info?.('fleet coverage daily snapshot stored');
      } catch (err) {
        fastify.log?.error?.({ err }, 'fleet coverage daily snapshot failed');
      }
    };
    const timer = setInterval(tick, checkEveryMs);
    timer.unref?.();
    fastify.addHook('onClose', async () => clearInterval(timer));
    tick();
  }

  fastify.get('/api/fleet', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const limit = parseFleetLimit(req.query);
    const offset = parseFleetOffset(req.query);
    const { rows } = await db.query(
      `SELECT device_id, host_id, hostname, os, ring, collector_version,
              enrolled_at, last_heartbeat_at, heartbeat_interval_sec,
              last_counters
         FROM devices
        WHERE revoked_at IS NULL
        ORDER BY enrolled_at ASC`,
    );
    const nowMs = Date.now();
    const recentSec = envInt('COLLECTOR_DROP_RECENT_SEC', DEFAULT_DROP_RECENT_SEC);
    const sloTarget = coverageSloTargetPct();
    const sloWindow = coverageSloWindowSeconds();
    const lastVerifiedAt = new Date(nowMs).toISOString();

    const devices = rows.map((r) => {
      const intervalSec = Number(r.heartbeat_interval_sec) || 300;
      const lastHb = r.last_heartbeat_at ? new Date(toIso(r.last_heartbeat_at)) : null;
      const health = healthOf(lastHb, intervalSec, nowMs);
      const coverageGap = health !== 'healthy';
      const silent = health === 'stale' || health === 'dead';
      const drops = projectDropHealth(r.last_counters, nowMs, { recentSec });
      const slo = evaluateDeviceSloHealth({
        collector_version: r.collector_version,
        last_heartbeat_at: lastHb,
        heartbeat_interval_sec: intervalSec,
        drops,
        health,
        nowMs,
      });
      return {
        device_id: String(r.device_id),
        host_id: String(r.host_id),
        hostname: r.hostname ?? null,
        os: r.os ?? null,
        ring: r.ring ?? null,
        collector_version: r.collector_version ?? null,
        enrolled_at: toIso(r.enrolled_at),
        last_heartbeat_at: lastHb ? lastHb.toISOString() : null,
        last_event_at: slo.last_event_at,
        heartbeat_interval_sec: intervalSec,
        health,
        silent,
        coverageGap,
        sloHealthy: slo.sloHealthy,
        unhealthyReasons: slo.unhealthyReasons,
        events_rejected: drops.events_rejected,
        events_spooled: drops.events_spooled,
        batches_fully_rejected: drops.batches_fully_rejected,
        last_rejection_at: drops.last_rejection_at,
        rejected_ratio: drops.rejected_ratio,
        drop_active: drops.drop_active,
      };
    });

    const coverageSlo = evaluateCollectorCoverageSlo(devices, {
      targetPct: sloTarget,
      windowSeconds: sloWindow,
      nowMs,
    });

    const summary = {
      deployed: devices.length,
      total: devices.length,
      limit,
      offset,
      healthy: 0,
      stale: 0,
      dead: 0,
      never_seen: 0,
      silent: 0,
      coverageGaps: 0,
      lastVerifiedAt,
      dropping: 0,
      coverageSlo,
      devices: devices.slice(offset, offset + limit),
    };
    for (const d of devices) {
      if (Object.prototype.hasOwnProperty.call(summary, d.health)) summary[d.health] += 1;
      if (d.silent) summary.silent += 1;
      if (d.coverageGap) summary.coverageGaps += 1;
      if (d.drop_active) summary.dropping += 1;
    }

    const historyCfg = opts?.history ?? {};
    const persistToday = historyCfg.persistOnRead ?? process.env.FLEET_COVERAGE_PERSIST_ON_READ !== 'off';
    if (persistToday) {
      try {
        await upsertCoverageDay(db, coverageRollupFromSummary(summary, nowMs), nowMs);
      } catch (err) {
        fastify.log?.warn?.({ err }, 'fleet coverage history upsert skipped');
      }
    }

    const trendDays = parseDays(req.query, DEFAULT_TREND_DAYS);
    try {
      const trend = await loadCoverageTrend(db, trendDays);
      // AIM-612: omit trend entirely when history is empty — never invent a
      // single-day series from the live snapshot.
      if (Array.isArray(trend) && trend.length > 0) {
        summary.trend = trend;
      }
    } catch (err) {
      fastify.log?.warn?.({ err }, 'fleet coverage history load skipped');
    }

    return summary;
  });
}

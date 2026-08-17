// Product system status (AIM-290): one API that answers "is it working and is
// it covering everything?" across both pillars.
//
// Design constraints from the charter:
//   1. One aggregate view — ingest lag, throughput, DLQ, device liveness,
//      CNAPP scan freshness / coverage gaps, gate/guardrail health.
//   2. Every tile carries an explicit SLO and a breach flag — no green by
//      default. Missing data is never "ok".
//   3. Four states only: ok | degraded | broken | never_configured.
//      These mean different things and must never collapse into each other.
//   4. Real sources (Postgres + service probes + optional CNAPP API), not a
//      mock.
//   5. Alert candidates use the same security.alert/v1 contract and alert-bus
//      path Sentinel already consumes — not a parallel notifier.
//
// Pure evaluators live above the route so unit tests do not need Postgres,
// Redis, or a network. The route wires them; a background publisher (see
// startSystemStatusAlerter) XADDs breach alerts onto the bus when enabled.
import { createHash } from 'node:crypto';
import { query } from '../db.js';
import { requireRoles } from '../auth.js';
import {
  evaluateLiveness,
  evaluateAttribution,
  idleThresholdSeconds,
  attributionWindowSeconds,
} from './pipeline.js';
import {
  projectDropHealth,
  evaluateCollectorCoverageSlo,
  evaluateDeviceSloHealth,
  coverageSloTargetPct,
  DEFAULT_COVERAGE_SLO_TARGET_PCT,
} from './fleet.js';
import {
  tileEnforceCoverage,
  loadEnforceCoverageSummary,
  DEFAULT_MIN_COVERAGE_PCT,
} from './enforcement-coverage.js';

// Device silence + DLQ summary live here rather than pipeline.js so this
// feature lands on main without depending on AIM-293 export surface. Semantics
// match the AIM-293 pure evaluators when both are present.

const MAX_SILENT_DEVICES = 50;
const MAX_DROPPING_DEVICES = 50;

/** Pure: enrolled devices silent past their own heartbeat_interval_sec. */
export function evaluateDeviceSilence({ devices, nowMs = Date.now() }) {
  const silent = [];
  for (const d of devices ?? []) {
    if (!d || d.last_heartbeat_at == null) continue;
    const last = new Date(d.last_heartbeat_at).getTime();
    if (!Number.isFinite(last)) continue;
    const interval = Math.max(1, Number(d.heartbeat_interval_sec) || 300);
    const silentFor = Math.max(0, Math.floor((nowMs - last) / 1000));
    if (silentFor <= interval) continue;
    silent.push({
      device_id: d.device_id ?? null,
      host_id: d.host_id ?? null,
      hostname: d.hostname ?? null,
      last_heartbeat_at: new Date(last).toISOString(),
      expected_interval_sec: interval,
      silent_for_seconds: silentFor,
    });
  }
  silent.sort((a, b) => b.silent_for_seconds - a.silent_for_seconds);
  const listed = silent.slice(0, MAX_SILENT_DEVICES);
  const n = silent.length;
  if (n === 0) {
    return {
      alert: false,
      silentDevices: 0,
      devices: [],
      message: 'No enrolled device has gone silent past its expected heartbeat interval.',
    };
  }
  return {
    alert: true,
    silentDevices: n,
    devices: listed,
    message: `${n} enrolled device(s) stopped reporting past their expected interval.`,
  };
}

/** Pure: server-side DLQ (rejected_events) summary for operators. */
export function evaluateRejections({ total, byReason, recent }) {
  const totalN = num(total);
  const reasons = (byReason ?? []).map((r) => ({
    error: String(r.error ?? 'unspecified'),
    count: num(r.count),
  }));
  const recentRows = (recent ?? []).map((r) => ({
    received_at: r.received_at instanceof Date
      ? r.received_at.toISOString()
      : (r.received_at ?? null),
    error: String(r.error ?? 'unspecified'),
  }));
  return {
    total: totalN,
    byReason: reasons,
    recent: recentRows,
    message: totalN === 0
      ? 'No rejected events in the server DLQ.'
      : `${totalN} rejected event(s) in the server DLQ across ${reasons.length} reason(s).`,
  };
}

/**
 * Pure (AIM-439): collector-side drop health from heartbeat counters.
 *
 * Server DLQ (`rejected_events`) only sees what reached ingest. Client-side
 * loss — schema skew, full spool drain after 4xx — lives in each device's
 * last_counters and was previously invisible to the platform. This evaluator
 * turns those counters into a first-class signal.
 *
 * `devices` rows: { device_id, host_id, hostname, last_counters,
 * heartbeat_interval_sec? }. Uses projectDropHealth for field projection.
 */
export function evaluateCollectorDrops({ devices, nowMs = Date.now(), recentSec } = {}) {
  const dropping = [];
  let lifetimeRejected = 0;
  let lifetimeBatches = 0;
  let devicesWithLifetimeDrops = 0;
  for (const d of devices ?? []) {
    if (!d) continue;
    const drops = projectDropHealth(d.last_counters, nowMs, recentSec != null ? { recentSec } : {});
    lifetimeRejected += drops.events_rejected;
    lifetimeBatches += drops.batches_fully_rejected;
    if (drops.events_rejected > 0 || drops.batches_fully_rejected > 0) {
      devicesWithLifetimeDrops += 1;
    }
    if (!drops.drop_active) continue;
    dropping.push({
      device_id: d.device_id ?? null,
      host_id: d.host_id ?? null,
      hostname: d.hostname ?? null,
      events_rejected: drops.events_rejected,
      events_spooled: drops.events_spooled,
      batches_fully_rejected: drops.batches_fully_rejected,
      last_rejection_at: drops.last_rejection_at,
      rejected_ratio: drops.rejected_ratio,
    });
  }
  dropping.sort((a, b) => (b.events_rejected - a.events_rejected)
    || (b.batches_fully_rejected - a.batches_fully_rejected));
  const listed = dropping.slice(0, MAX_DROPPING_DEVICES);
  const n = dropping.length;
  if (n === 0) {
    return {
      alert: false,
      droppingDevices: 0,
      devicesWithLifetimeDrops,
      lifetimeRejectedEvents: lifetimeRejected,
      lifetimeBatchesFullyRejected: lifetimeBatches,
      devices: [],
      message: devicesWithLifetimeDrops === 0
        ? 'No collector has reported rejected or fully-rejected batches.'
        : `${devicesWithLifetimeDrops} device(s) have lifetime drop counters, but none are actively dropping within the recent window.`,
    };
  }
  return {
    alert: true,
    droppingDevices: n,
    devicesWithLifetimeDrops,
    lifetimeRejectedEvents: lifetimeRejected,
    lifetimeBatchesFullyRejected: lifetimeBatches,
    devices: listed,
    message: `${n} enrolled device(s) actively dropping events (client-side rejection within the recent window).`,
  };
}

const PROBE_TIMEOUT_MS = 2000;
const HOST_RE = /^[a-z0-9][a-z0-9.-]*(:[0-9]{1,5})?$/i;
const DEFAULT_GATEWAY_HOST = 'localhost:8443';

// SLOs — env-tunable, documented on each tile. Defaults are pilot-conservative.
const DEFAULT_THROUGHPUT_MIN_PER_HOUR = 1; // any live fleet should move
const DEFAULT_DLQ_WARN = 1;
const DEFAULT_DLQ_HARD = 50;
const DEFAULT_CNAPP_STALE_HOURS = 48;
// AIM-645 path-to-10: ≥99% enrolled endpoints reporting healthy collectors.
// Env: SYSTEM_STATUS_DEVICE_HEALTHY_MIN_PCT (align with COLLECTOR_COVERAGE_SLO_TARGET_PCT).
const DEFAULT_DEVICE_HEALTHY_MIN_PCT = DEFAULT_COVERAGE_SLO_TARGET_PCT;
// AIM-297: PR CI runner queue / health SLOs for the D2 status screen.
const DEFAULT_CI_RUNNER_QUEUE_WARN = 3;
const DEFAULT_CI_RUNNER_QUEUE_HARD = 10;
const DEFAULT_CI_RUNNER_STALE_SEC = 300;

const SEVERITY_ID = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
};

const STATE_RANK = {
  broken: 3,
  degraded: 2,
  never_configured: 1,
  ok: 0,
};

const num = (v) => (v == null ? 0 : Number(v));

function envInt(name, fallback) {
  const raw = Number(process.env[name]);
  return Number.isFinite(raw) && raw >= 0 ? Math.floor(raw) : fallback;
}

function gatewayHost() {
  const raw = process.env.AIM_GATEWAY_HOST;
  return raw && HOST_RE.test(raw) ? raw : DEFAULT_GATEWAY_HOST;
}

function configuredServices() {
  const raw = process.env.AIM_STACK_SERVICES;
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return null;
    return parsed.filter(
      (s) => s && typeof s.name === 'string' && typeof s.url === 'string',
    );
  } catch {
    return null;
  }
}

async function probe({ name, url, ui }, fetchImpl = fetch) {
  const started = Date.now();
  try {
    const res = await fetchImpl(url, {
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      redirect: 'manual',
    });
    const entry = {
      name,
      ui: ui ?? null,
      status: res.ok ? 'ok' : 'down',
      latencyMs: Date.now() - started,
    };
    if (!res.ok) entry.detail = `HTTP ${res.status}`;
    return entry;
  } catch (err) {
    const detail = err.name === 'TimeoutError'
      ? `timeout after ${PROBE_TIMEOUT_MS}ms`
      : (err.cause?.code ?? err.code ?? 'unreachable');
    return {
      name,
      ui: ui ?? null,
      status: 'down',
      latencyMs: Date.now() - started,
      detail,
    };
  }
}

function tileBase({ id, pillar, title, state, slo, value, message, breach }) {
  const s = state ?? 'never_configured';
  return {
    id,
    pillar,
    title,
    state: s,
    // Explicit: green only when state is ok. Everything else is a breach of
    // "looks healthy", including never_configured (which is not green).
    breach: breach ?? (s !== 'ok'),
    slo,
    value,
    message,
  };
}

/** Worst state across tiles — never collapses never_configured into ok. */
export function overallState(tiles) {
  let worst = 'ok';
  let rank = 0;
  for (const t of tiles ?? []) {
    const r = STATE_RANK[t.state] ?? 0;
    if (r > rank) {
      rank = r;
      worst = t.state;
    }
  }
  return worst;
}

// ---- pure tile evaluators -----------------------------------------------

export function tileIngestLag(liveness, { thresholdSeconds } = {}) {
  const thresh = thresholdSeconds ?? liveness?.thresholdSeconds ?? idleThresholdSeconds();
  const slo = {
    text: `Ingest accepts ≥1 event within ${thresh}s while collectors have reported in`,
    thresholdSeconds: thresh,
  };
  if (!liveness) {
    return tileBase({
      id: 'ingest_lag',
      pillar: 'aim',
      title: 'Ingest lag',
      state: 'broken',
      slo,
      value: null,
      message: 'Pipeline liveness unavailable',
    });
  }
  const value = {
    status: liveness.status,
    idleSeconds: liveness.idleSeconds,
    lastEventAt: liveness.lastEventAt,
    reportingDevices: liveness.reportingDevices,
    enrolledDevices: liveness.enrolledDevices,
  };
  if (liveness.status === 'no_collectors') {
    return tileBase({
      id: 'ingest_lag',
      pillar: 'aim',
      title: 'Ingest lag',
      state: 'never_configured',
      slo,
      value,
      message: liveness.message,
    });
  }
  if (liveness.status === 'pending_collectors') {
    return tileBase({
      id: 'ingest_lag',
      pillar: 'aim',
      title: 'Ingest lag',
      state: 'never_configured',
      slo,
      value,
      message: liveness.message,
    });
  }
  if (liveness.status === 'idle' || liveness.idle) {
    return tileBase({
      id: 'ingest_lag',
      pillar: 'aim',
      title: 'Ingest lag',
      state: 'broken',
      slo,
      value,
      message: liveness.message,
    });
  }
  return tileBase({
    id: 'ingest_lag',
    pillar: 'aim',
    title: 'Ingest lag',
    state: 'ok',
    slo,
    value,
    message: liveness.message,
  });
}

export function tileThroughput({ eventsLastHour, eventsLast15m }) {
  const minPerHour = envInt('SYSTEM_STATUS_THROUGHPUT_MIN_PER_HOUR', DEFAULT_THROUGHPUT_MIN_PER_HOUR);
  const slo = {
    text: `≥${minPerHour} event(s) accepted in the trailing hour when collectors are expected`,
    minEventsPerHour: minPerHour,
  };
  const hour = num(eventsLastHour);
  const m15 = num(eventsLast15m);
  const value = { eventsLastHour: hour, eventsLast15m: m15 };
  if (hour === 0 && m15 === 0) {
    // Quiet can be never_configured (no fleet) or broken (fleet idle) — the
    // ingest_lag tile owns that distinction. Throughput alone is degraded so
    // the screen never paints a quiet pipeline green.
    return tileBase({
      id: 'event_throughput',
      pillar: 'aim',
      title: 'Event throughput',
      state: 'degraded',
      slo,
      value,
      message: 'No events accepted in the last hour',
    });
  }
  if (hour < minPerHour) {
    return tileBase({
      id: 'event_throughput',
      pillar: 'aim',
      title: 'Event throughput',
      state: 'degraded',
      slo,
      value,
      message: `${hour} event(s)/h below SLO of ${minPerHour}/h`,
    });
  }
  return tileBase({
    id: 'event_throughput',
    pillar: 'aim',
    title: 'Event throughput',
    state: 'ok',
    slo,
    value,
    message: `${hour} event(s) in the last hour (${m15} in last 15m)`,
  });
}

export function tileDlq(rejections) {
  const warn = envInt('SYSTEM_STATUS_DLQ_WARN', DEFAULT_DLQ_WARN);
  const hard = envInt('SYSTEM_STATUS_DLQ_HARD', DEFAULT_DLQ_HARD);
  const slo = {
    text: `Server DLQ depth ≤${warn} (warn), hard breach >${hard}`,
    warn,
    hard,
  };
  if (!rejections) {
    return tileBase({
      id: 'dlq_depth',
      pillar: 'aim',
      title: 'DLQ depth',
      state: 'broken',
      slo,
      value: null,
      message: 'DLQ query unavailable',
    });
  }
  const total = num(rejections.total);
  const value = {
    total,
    byReason: rejections.byReason ?? [],
  };
  if (total > hard) {
    return tileBase({
      id: 'dlq_depth',
      pillar: 'aim',
      title: 'DLQ depth',
      state: 'broken',
      slo,
      value,
      message: `DLQ depth ${total} exceeds hard SLO ${hard}`,
    });
  }
  if (total >= warn) {
    return tileBase({
      id: 'dlq_depth',
      pillar: 'aim',
      title: 'DLQ depth',
      state: 'degraded',
      slo,
      value,
      message: `DLQ holds ${total} rejected event(s) (warn ≥${warn})`,
    });
  }
  return tileBase({
    id: 'dlq_depth',
    pillar: 'aim',
    title: 'DLQ depth',
    state: 'ok',
    slo,
    value,
    message: rejections.message || 'No rejected events in the server DLQ',
  });
}

/**
 * AIM-439 tile: collector-side event loss. Distinct from server DLQ —
 * batches the collector discarded after a schema/auth rejection never create
 * a rejected_events row, so dlq_depth can be green while the fleet bleeds.
 */
export function tileCollectorDrops(drops) {
  const recentSec = envInt('COLLECTOR_DROP_RECENT_SEC', 900);
  const slo = {
    text: `Zero devices actively dropping events (client rejection within ${recentSec}s)`,
    recentSec,
  };
  if (!drops) {
    return tileBase({
      id: 'collector_drops',
      pillar: 'aim',
      title: 'Collector event loss',
      state: 'broken',
      slo,
      value: null,
      message: 'Collector drop health unavailable',
    });
  }
  const value = {
    droppingDevices: num(drops.droppingDevices),
    devicesWithLifetimeDrops: num(drops.devicesWithLifetimeDrops),
    lifetimeRejectedEvents: num(drops.lifetimeRejectedEvents),
    lifetimeBatchesFullyRejected: num(drops.lifetimeBatchesFullyRejected),
    devices: drops.devices ?? [],
  };
  if (drops.alert || value.droppingDevices > 0) {
    return tileBase({
      id: 'collector_drops',
      pillar: 'aim',
      title: 'Collector event loss',
      state: 'broken',
      slo,
      value,
      message: drops.message
        || `${value.droppingDevices} device(s) actively dropping events`,
    });
  }
  if (value.devicesWithLifetimeDrops > 0) {
    return tileBase({
      id: 'collector_drops',
      pillar: 'aim',
      title: 'Collector event loss',
      state: 'degraded',
      slo,
      value,
      message: drops.message
        || `${value.devicesWithLifetimeDrops} device(s) have historical drop counters (not currently active)`,
    });
  }
  return tileBase({
    id: 'collector_drops',
    pillar: 'aim',
    title: 'Collector event loss',
    state: 'ok',
    slo,
    value,
    message: drops.message || 'No collector-side event loss reported',
  });
}

export function tileDeviceLiveness(liveness, silence, coverageSlo = null) {
  // Prefer explicit SYSTEM_STATUS_DEVICE_HEALTHY_MIN_PCT; else AIM-645 fleet SLO.
  const envOverride = process.env.SYSTEM_STATUS_DEVICE_HEALTHY_MIN_PCT;
  const minHealthyPct = envOverride != null && envOverride !== ''
    ? envInt('SYSTEM_STATUS_DEVICE_HEALTHY_MIN_PCT', DEFAULT_DEVICE_HEALTHY_MIN_PCT)
    : (coverageSlo?.targetPct ?? coverageSloTargetPct());
  const slo = {
    text: `≥${minHealthyPct}% of enrolled endpoints healthy (version + last_event_at + no active errors; AIM-645)`,
    minHealthyPct,
    windowSeconds: coverageSlo?.windowSeconds ?? null,
  };
  if (!liveness) {
    return tileBase({
      id: 'device_liveness',
      pillar: 'aim',
      title: 'Device liveness',
      state: 'broken',
      slo,
      value: null,
      message: 'Device liveness unavailable',
    });
  }
  const enrolled = num(liveness.enrolledDevices);
  const healthy = num(
    coverageSlo?.sloHealthy != null ? coverageSlo.sloHealthy : liveness.healthyDevices,
  );
  const reporting = num(liveness.reportingDevices);
  const silent = num(silence?.silentDevices);
  const inScope = coverageSlo?.inScope != null ? num(coverageSlo.inScope) : enrolled;
  const value = {
    enrolled,
    healthy,
    reporting,
    stale: num(liveness.staleDevices),
    silent,
    silentDevices: silence?.devices ?? [],
    inScope,
    graceExcluded: coverageSlo?.graceExcluded ?? 0,
    coverageSloStatus: coverageSlo?.status ?? null,
  };
  if (enrolled === 0) {
    return tileBase({
      id: 'device_liveness',
      pillar: 'aim',
      title: 'Device liveness',
      state: 'never_configured',
      slo,
      value,
      message: 'No collectors enrolled — fleet coverage is undefined',
    });
  }
  if (reporting === 0 && (coverageSlo?.status === 'pending_grace' || inScope === 0)) {
    return tileBase({
      id: 'device_liveness',
      pillar: 'aim',
      title: 'Device liveness',
      state: 'never_configured',
      slo,
      value,
      message: coverageSlo?.message
        || 'Enrolled devices have never heartbeated (still in grace window)',
    });
  }
  if (reporting === 0) {
    return tileBase({
      id: 'device_liveness',
      pillar: 'aim',
      title: 'Device liveness',
      state: 'never_configured',
      slo,
      value,
      message: 'Enrolled devices have never heartbeated',
    });
  }
  // Prefer the AIM-645 evaluator when present; otherwise fall back to
  // healthy/enrolled point-in-time share (legacy pipeline counts).
  let pct;
  if (coverageSlo && coverageSlo.healthyPct != null) {
    pct = coverageSlo.healthyPct;
  } else {
    const denom = enrolled > 0 ? enrolled : 0;
    if (denom === 0) pct = 0;
    else if (healthy === denom) pct = 100;
    else pct = Math.min(Math.round((healthy / denom) * 1000) / 10, 99.9);
  }
  // Full fleet dark → broken. Partial coverage below SLO → degraded (alertable).
  if (pct === 0 || (silent > 0 && healthy === 0)) {
    return tileBase({
      id: 'device_liveness',
      pillar: 'aim',
      title: 'Device liveness',
      state: 'broken',
      slo,
      value: { ...value, healthyPct: pct },
      message: silence?.message
        || coverageSlo?.message
        || `${silent} device(s) silent; 0% coverage`,
    });
  }
  if (pct < minHealthyPct || coverageSlo?.alert) {
    return tileBase({
      id: 'device_liveness',
      pillar: 'aim',
      title: 'Device liveness',
      state: 'degraded',
      slo,
      value: { ...value, healthyPct: pct },
      message: coverageSlo?.message
        || `${pct}% of enrolled devices healthy (SLO ≥${minHealthyPct}%)`
          + (silent > 0 ? `; ${silent} silent past interval` : ''),
    });
  }
  return tileBase({
    id: 'device_liveness',
    pillar: 'aim',
    title: 'Device liveness',
    state: 'ok',
    slo,
    value: { ...value, healthyPct: pct },
    message: coverageSlo?.message
      || `${healthy}/${inScope || enrolled} enrolled devices healthy (${pct}%)`,
  });
}

export function tileAttribution(attribution) {
  const target = attribution?.targetPct ?? 5;
  const slo = {
    text: `Unattributed event share ≤${target}% over the trailing window (identity coverage)`,
    targetPct: target,
    windowSeconds: attribution?.windowSeconds ?? null,
  };
  if (!attribution) {
    return tileBase({
      id: 'attribution_coverage',
      pillar: 'aim',
      title: 'Identity coverage',
      state: 'broken',
      slo,
      value: null,
      message: 'Attribution metrics unavailable',
    });
  }
  const value = {
    status: attribution.status,
    unattributedPct: attribution.unattributedPct,
    events: attribution.events,
    attributedEvents: attribution.attributedEvents,
    unattributedEvents: attribution.unattributedEvents,
    serviceAttributedEvents: attribution.serviceAttributedEvents,
    // AIM-452: every coverage claim carries when it was last verified e2e.
    lastVerifiedAt: attribution.lastVerifiedAt ?? null,
  };
  if (attribution.status === 'no_events') {
    return tileBase({
      id: 'attribution_coverage',
      pillar: 'aim',
      title: 'Identity coverage',
      state: 'never_configured',
      slo,
      value,
      message: attribution.message,
    });
  }
  if (attribution.status === 'none_attributed') {
    return tileBase({
      id: 'attribution_coverage',
      pillar: 'aim',
      title: 'Identity coverage',
      state: 'broken',
      slo,
      value,
      message: attribution.message,
    });
  }
  if (attribution.status === 'degraded') {
    return tileBase({
      id: 'attribution_coverage',
      pillar: 'aim',
      title: 'Identity coverage',
      state: 'degraded',
      slo,
      value,
      message: attribution.message,
    });
  }
  return tileBase({
    id: 'attribution_coverage',
    pillar: 'aim',
    title: 'Identity coverage',
    state: 'ok',
    slo,
    value,
    message: attribution.message,
  });
}

export function tileServiceProbe(name, pillar, title, probeResult, { required = true } = {}) {
  const slo = {
    text: `${title} responds 2xx on its health endpoint within ${PROBE_TIMEOUT_MS}ms`,
    probeTimeoutMs: PROBE_TIMEOUT_MS,
  };
  if (!probeResult) {
    return tileBase({
      id: `service_${name}`,
      pillar,
      title,
      state: required ? 'never_configured' : 'never_configured',
      slo,
      value: null,
      message: required
        ? `${title} probe not configured (AIM_STACK_SERVICES / env)`
        : `${title} not configured`,
    });
  }
  const value = {
    status: probeResult.status,
    latencyMs: probeResult.latencyMs,
    detail: probeResult.detail ?? null,
    ui: probeResult.ui ?? null,
  };
  if (probeResult.status === 'ok') {
    return tileBase({
      id: `service_${name}`,
      pillar,
      title,
      state: 'ok',
      slo,
      value,
      message: `${title} healthy (${probeResult.latencyMs}ms)`,
    });
  }
  return tileBase({
    id: `service_${name}`,
    pillar,
    title,
    state: 'broken',
    slo,
    value,
    message: `${title} down: ${probeResult.detail ?? probeResult.status}`,
  });
}

/**
 * CNAPP coverage + scan freshness (A3 / AIM-278 contract).
 * `coverage` is GET /accounts/coverage shape; `posture` is optional
 * /accounts/posture with per-account last_scan ages.
 */
export function tileCnappCoverage({ configured, coverage, posture, error, staleHours } = {}) {
  const stale = staleHours ?? envInt('SYSTEM_STATUS_CNAPP_STALE_HOURS', DEFAULT_CNAPP_STALE_HOURS);
  const slo = {
    text: `Dark (known-unscanned) accounts = 0; every enabled account last_scan ≤${stale}h`,
    staleHours: stale,
    darkAccountsMax: 0,
  };
  if (!configured) {
    return tileBase({
      id: 'cnapp_coverage',
      pillar: 'cnapp',
      title: 'CNAPP coverage',
      state: 'never_configured',
      slo,
      value: null,
      message: 'CNAPP coverage API not configured (set AIM_CNAPP_BASE_URL [+ AIM_CNAPP_API_KEY])',
    });
  }
  if (error) {
    return tileBase({
      id: 'cnapp_coverage',
      pillar: 'cnapp',
      title: 'CNAPP coverage',
      state: 'broken',
      slo,
      value: { error: String(error).slice(0, 200) },
      message: `CNAPP coverage fetch failed: ${String(error).slice(0, 160)}`,
    });
  }
  const known = num(coverage?.known ?? coverage?.counts?.known);
  const scanned = num(coverage?.scanned ?? coverage?.counts?.scanned);
  const dark = num(coverage?.dark ?? coverage?.counts?.dark);
  const byProvider = coverage?.by_provider ?? coverage?.byProvider ?? null;
  const staleAccounts = [];
  const providers = new Map();
  for (const a of posture?.accounts ?? []) {
    const p = a.provider || 'unknown';
    if (!providers.has(p)) providers.set(p, { provider: p, accounts: 0, stale: 0, neverScanned: 0, freshest: null, oldest: null });
    const row = providers.get(p);
    row.accounts += 1;
    const last = a.last_scan || a.lastScan || a.inventory_last || null;
    if (!last) {
      row.neverScanned += 1;
      staleAccounts.push({ id: a.id ?? a.cloud_account_id, provider: p, lastScan: null });
      continue;
    }
    const ts = new Date(last).getTime();
    if (!Number.isFinite(ts)) continue;
    const ageH = (Date.now() - ts) / 3_600_000;
    if (row.freshest == null || ts > new Date(row.freshest).getTime()) row.freshest = new Date(ts).toISOString();
    if (row.oldest == null || ts < new Date(row.oldest).getTime()) row.oldest = new Date(ts).toISOString();
    if (ageH > stale) {
      row.stale += 1;
      staleAccounts.push({ id: a.id ?? a.cloud_account_id, provider: p, lastScan: new Date(ts).toISOString(), ageHours: Math.round(ageH * 10) / 10 });
    }
  }
  const value = {
    known,
    scanned,
    dark,
    byProvider,
    scanFreshness: [...providers.values()],
    staleAccounts: staleAccounts.slice(0, 20),
  };
  if (known === 0 && scanned === 0) {
    return tileBase({
      id: 'cnapp_coverage',
      pillar: 'cnapp',
      title: 'CNAPP coverage',
      state: 'never_configured',
      slo,
      value,
      message: 'No cloud accounts discovered or enrolled in CNAPP',
    });
  }
  if (dark > 0) {
    return tileBase({
      id: 'cnapp_coverage',
      pillar: 'cnapp',
      title: 'CNAPP coverage',
      state: 'degraded',
      slo,
      value,
      message: `${dark} dark (known-unscanned) account(s) — coverage gap from discovery (A3)`,
    });
  }
  if (staleAccounts.length > 0) {
    return tileBase({
      id: 'cnapp_coverage',
      pillar: 'cnapp',
      title: 'CNAPP coverage',
      state: 'degraded',
      slo,
      value,
      message: `${staleAccounts.length} account(s) past ${stale}h scan-freshness SLO`,
    });
  }
  return tileBase({
    id: 'cnapp_coverage',
    pillar: 'cnapp',
    title: 'CNAPP coverage',
    state: 'ok',
    slo,
    value,
    message: `${scanned}/${known || scanned} account(s) scanned; no dark accounts; scan freshness within ${stale}h`,
  });
}

export function tileGuardrail({ probeResult, rulesLoaded, lastFindingAt } = {}) {
  const slo = {
    text: 'Guardrail process healthy and policy rules loaded (>0)',
  };
  if (!probeResult && rulesLoaded == null) {
    return tileBase({
      id: 'guardrail_health',
      pillar: 'aim',
      title: 'Guardrail health',
      state: 'never_configured',
      slo,
      value: null,
      message: 'Guardrail probe not configured and no local rule stats',
    });
  }
  const value = {
    probe: probeResult
      ? { status: probeResult.status, latencyMs: probeResult.latencyMs, detail: probeResult.detail ?? null }
      : null,
    rulesLoaded: rulesLoaded == null ? null : num(rulesLoaded),
    lastFindingAt: lastFindingAt ?? null,
  };
  if (probeResult && probeResult.status !== 'ok') {
    return tileBase({
      id: 'guardrail_health',
      pillar: 'aim',
      title: 'Guardrail health',
      state: 'broken',
      slo,
      value,
      message: `Guardrail down: ${probeResult.detail ?? probeResult.status}`,
    });
  }
  if (rulesLoaded != null && num(rulesLoaded) === 0) {
    return tileBase({
      id: 'guardrail_health',
      pillar: 'aim',
      title: 'Guardrail health',
      state: 'broken',
      slo,
      value,
      message: 'Guardrail reports zero loaded rules — policy not applied',
    });
  }
  if (probeResult?.status === 'ok' || (rulesLoaded != null && num(rulesLoaded) > 0)) {
    return tileBase({
      id: 'guardrail_health',
      pillar: 'aim',
      title: 'Guardrail health',
      state: 'ok',
      slo,
      value,
      message: rulesLoaded != null
        ? `Guardrail healthy with ${num(rulesLoaded)} rule(s) loaded`
        : 'Guardrail health endpoint ok',
    });
  }
  return tileBase({
    id: 'guardrail_health',
    pillar: 'aim',
    title: 'Guardrail health',
    state: 'degraded',
    slo,
    value,
    message: 'Guardrail state incomplete',
  });
}

/**
 * AIM-297: self-hosted PR security runner health + queue depth.
 *
 * Input shape (from file, URL, or live GitHub Actions API snapshot):
 *   {
 *     generatedAt?: string,
 *     runners: [{ name, status, busy, labels?, queuedJobs?, isolation? }],
 *     queuedJobs?: number,   // total queued workflow jobs across watched repos
 *     source?: string
 *   }
 *
 * States:
 *   never_configured — no status source (install path not wired)
 *   broken           — no online runner, or status stale beyond SLO
 *   degraded         — online but queue above warn / all busy with work waiting
 *   ok               — ≥1 online runner, queue within SLO
 */
export function tileCiRunner(snapshot, {
  queueWarn = envInt('SYSTEM_STATUS_CI_QUEUE_WARN', DEFAULT_CI_RUNNER_QUEUE_WARN),
  queueHard = envInt('SYSTEM_STATUS_CI_QUEUE_HARD', DEFAULT_CI_RUNNER_QUEUE_HARD),
  staleSec = envInt('SYSTEM_STATUS_CI_RUNNER_STALE_SEC', DEFAULT_CI_RUNNER_STALE_SEC),
  nowMs = Date.now(),
} = {}) {
  const slo = {
    text: `≥1 self-hosted PR runner online; queue depth ≤${queueWarn} (hard ${queueHard}); status ≤${staleSec}s old`,
    queueWarn,
    queueHard,
    staleSec,
  };
  if (!snapshot || snapshot.configured === false) {
    return tileBase({
      id: 'ci_runner',
      pillar: 'cicd',
      title: 'PR CI runner',
      state: 'never_configured',
      slo,
      value: null,
      message: 'CI runner status not configured (set AIM_CI_RUNNER_STATUS_FILE, AIM_CI_RUNNER_STATUS_URL, or AIM_CI_RUNNER_REPOS + GITHUB_TOKEN)',
    });
  }
  if (snapshot.error) {
    return tileBase({
      id: 'ci_runner',
      pillar: 'cicd',
      title: 'PR CI runner',
      state: 'broken',
      slo,
      value: { error: String(snapshot.error).slice(0, 200) },
      message: `CI runner status fetch failed: ${String(snapshot.error).slice(0, 160)}`,
    });
  }
  const runners = Array.isArray(snapshot.runners) ? snapshot.runners : [];
  const online = runners.filter((r) => String(r.status || '').toLowerCase() === 'online');
  const busy = online.filter((r) => r.busy === true || r.busy === 'true');
  const queued = num(
    snapshot.queuedJobs
      ?? snapshot.queued_jobs
      ?? runners.reduce((n, r) => n + num(r.queuedJobs ?? r.queued_jobs), 0),
  );
  const generatedAt = snapshot.generatedAt ?? snapshot.generated_at ?? null;
  let ageSec = null;
  if (generatedAt) {
    const t = new Date(generatedAt).getTime();
    if (Number.isFinite(t)) ageSec = Math.max(0, Math.floor((nowMs - t) / 1000));
  }
  const value = {
    online: online.length,
    total: runners.length,
    busy: busy.length,
    queuedJobs: queued,
    ageSec,
    source: snapshot.source ?? null,
    runners: runners.map((r) => ({
      name: r.name ?? null,
      status: r.status ?? null,
      busy: Boolean(r.busy),
      labels: r.labels ?? null,
      isolation: r.isolation ?? null,
    })),
  };
  if (ageSec != null && ageSec > staleSec) {
    return tileBase({
      id: 'ci_runner',
      pillar: 'cicd',
      title: 'PR CI runner',
      state: 'broken',
      slo,
      value,
      message: `CI runner status is stale (${ageSec}s > ${staleSec}s SLO) — health reporter may be down`,
    });
  }
  if (online.length === 0) {
    return tileBase({
      id: 'ci_runner',
      pillar: 'cicd',
      title: 'PR CI runner',
      state: 'broken',
      slo,
      value,
      message: runners.length === 0
        ? 'No self-hosted PR runners registered'
        : `All ${runners.length} registered runner(s) offline`,
    });
  }
  if (queued >= queueHard) {
    return tileBase({
      id: 'ci_runner',
      pillar: 'cicd',
      title: 'PR CI runner',
      state: 'broken',
      slo,
      value,
      message: `PR CI queue depth ${queued} exceeds hard SLO ${queueHard} (${online.length} online, ${busy.length} busy)`,
    });
  }
  if (queued >= queueWarn || (busy.length === online.length && queued > 0)) {
    return tileBase({
      id: 'ci_runner',
      pillar: 'cicd',
      title: 'PR CI runner',
      state: 'degraded',
      slo,
      value,
      message: `PR CI queue depth ${queued} (warn ≥${queueWarn}); ${online.length} online, ${busy.length} busy`,
    });
  }
  return tileBase({
    id: 'ci_runner',
    pillar: 'cicd',
    title: 'PR CI runner',
    state: 'ok',
    slo,
    value,
    message: `${online.length} self-hosted PR runner(s) online; queue depth ${queued}`,
  });
}

export function tileSentinel({ probeResult, healthBody } = {}) {
  const slo = {
    text: 'Sentinel process healthy; at least one notification channel configured when bus is live',
  };
  if (!probeResult) {
    return tileBase({
      id: 'sentinel_alerting',
      pillar: 'aim',
      title: 'Sentinel / alerting',
      state: 'never_configured',
      slo,
      value: null,
      message: 'Sentinel probe not configured',
    });
  }
  const channels = healthBody?.channels ?? null;
  const undelivered = healthBody?.undelivered ?? null;
  const busStatus = healthBody?.status ?? null;
  const value = {
    probe: { status: probeResult.status, latencyMs: probeResult.latencyMs, detail: probeResult.detail ?? null },
    channels,
    undelivered,
    busStatus,
  };
  if (probeResult.status !== 'ok') {
    return tileBase({
      id: 'sentinel_alerting',
      pillar: 'aim',
      title: 'Sentinel / alerting',
      state: 'broken',
      slo,
      value,
      message: `Sentinel down: ${probeResult.detail ?? probeResult.status}`,
    });
  }
  if (Array.isArray(channels) && channels.length === 0) {
    return tileBase({
      id: 'sentinel_alerting',
      pillar: 'aim',
      title: 'Sentinel / alerting',
      state: 'degraded',
      slo,
      value,
      message: 'Sentinel up but no notification channels configured — pages go nowhere',
    });
  }
  if (busStatus === 'degraded') {
    return tileBase({
      id: 'sentinel_alerting',
      pillar: 'aim',
      title: 'Sentinel / alerting',
      state: 'degraded',
      slo,
      value,
      message: 'Sentinel reports degraded status (bus or LLM path)',
    });
  }
  return tileBase({
    id: 'sentinel_alerting',
    pillar: 'aim',
    title: 'Sentinel / alerting',
    state: 'ok',
    slo,
    value,
    message: Array.isArray(channels)
      ? `Sentinel healthy; channels: ${channels.join(', ') || '(none)'}`
      : 'Sentinel health endpoint ok',
  });
}

// ---- alert candidates (same contract Sentinel already consumes) ---------

function stableAlertId(dedupeHex) {
  const hexed = dedupeHex.slice(0, 32).padEnd(32, '0');
  const variant = '89ab'[parseInt(hexed[16], 16) % 4];
  return `${hexed.slice(0, 8)}-${hexed.slice(8, 12)}-4${hexed.slice(13, 16)}-${variant}${hexed.slice(17, 20)}-${hexed.slice(20, 32)}`;
}

function dedupeHex(parts) {
  return createHash('sha256').update(parts.join('|')).digest('hex');
}

/**
 * Map breach tiles → security.alert/v1 payloads. Only broken/degraded tiles
 * that are NOT never_configured produce alerts — "not configured" is an
 * install gap, not an incident to page on.
 */
export function alertCandidatesFromTiles(tiles, { now = new Date() } = {}) {
  const stamp = now instanceof Date ? now.toISOString().replace(/\.\d{3}Z$/, 'Z') : String(now);
  const out = [];
  for (const t of tiles ?? []) {
    if (t.state === 'ok' || t.state === 'never_configured') continue;
    if (!t.breach) continue;
    const severity = t.state === 'broken' ? 'high' : 'medium';
    // AIM-452: unattributed rate is a first-class finding_type so Sentinel /
    // the inbox can route it without parsing free-text tile titles. Other
    // tiles keep the generic system_* leaf.
    const isAttribution = t.id === 'attribution_coverage';
    const isEnforce = t.id === 'enforce_coverage';
    // AIM-645: first-class finding_type for collector coverage SLO breaches.
    const isCoverageSlo = t.id === 'device_liveness';
    const findingType = isAttribution
      ? 'ai_usage.unattributed_rate'
      : isEnforce
        ? 'ai_usage.enforce_coverage_below_slo'
        : isCoverageSlo
          ? 'ai_usage.collector_coverage_slo'
          : `ai_usage.system_${t.id}`.replace(/[^a-z0-9_.]/g, '_').slice(0, 80);
    // finding_type must be namespace.leaf
    const ft = findingType.includes('.') ? findingType : `ai_usage.${findingType}`;
    const dedupe = dedupeHex(['system-status', t.id, t.state]);
    const pct = t.value?.unattributedPct;
    const target = t.slo?.targetPct;
    const coverPct = t.value?.coveragePct;
    const coverSlo = t.slo?.minCoveragePct;
    const healthyPct = t.value?.healthyPct;
    const minHealthy = t.slo?.minHealthyPct;
    const title = isAttribution && pct != null
      ? (t.state === 'broken'
        ? `Unattributed usage: ${pct}% of events have no identity`
        : `Unattributed usage: ${pct}% exceeds ${target ?? 5}% target`).slice(0, 200)
      : isEnforce && coverPct != null
        ? `Fleet enforce coverage: ${coverPct}% below pilot SLO ${coverSlo ?? 90}%`.slice(0, 200)
        : isCoverageSlo && healthyPct != null
          ? `Collector coverage: ${healthyPct}% of enrolled endpoints healthy (SLO ≥${minHealthy ?? 99}%)`.slice(0, 200)
          : `${t.title}: ${t.state}`.slice(0, 200);
    const labels = {
      tile: t.id.slice(0, 128),
      state: t.state.slice(0, 128),
      pillar: String(t.pillar || 'aim').slice(0, 128),
    };
    if (isAttribution && pct != null) {
      labels.unattributed_pct = String(pct).slice(0, 128);
      if (target != null) labels.target_pct = String(target).slice(0, 128);
    }
    if (isEnforce && coverPct != null) {
      labels.coverage_pct = String(coverPct).slice(0, 128);
      if (coverSlo != null) labels.slo_pct = String(coverSlo).slice(0, 128);
      if (t.value?.failOpenHosts != null) {
        labels.fail_open = String(t.value.failOpenHosts).slice(0, 128);
      }
    }
    if (isCoverageSlo && healthyPct != null) {
      labels.healthy_pct = String(healthyPct).slice(0, 128);
      if (minHealthy != null) labels.target_pct = String(minHealthy).slice(0, 128);
    }
    out.push({
      schema_version: '1.1',
      alert_id: stableAlertId(dedupe),
      dedupe_key: dedupe,
      pillar: 'ai_usage',
      producer: { name: 'aim-system-status', version: '1.0.0' },
      finding_type: ft.slice(0, 80),
      title,
      severity,
      severity_id: SEVERITY_ID[severity],
      status: 'new',
      observed_at: stamp,
      first_seen_at: stamp,
      last_seen_at: stamp,
      resource: {
        kind: 'host',
        ref: `aim:system-status/${t.id}`,
        display: t.title.slice(0, 120),
        provider: null,
        account_ref: null,
        region: null,
      },
      subject_ref: null,
      evidence: {
        source_uri: isEnforce
          ? 'aim:/fleet?panel=enforce-coverage'
          : `aim:/system/status?tile=${encodeURIComponent(t.id)}`,
        detail_count: 1,
        summary: String(t.message || t.title).slice(0, 240),
      },
      labels,
      remediation_hint: (
        isAttribution
          ? 'Open #/overview attribution panel and #/status Identity coverage. Check identity-sync directory coverage and device_mappings; a high unattributed rate is a coverage gap, not an ingest outage.'
          : isEnforce
            ? 'Open #/fleet enforce coverage panel. Fail-open hosts need enforcement.json delivered (AIM-440 install path / aim doctor --fix). Zero blocks without posture is coverage-absent, not clean.'
            : isCoverageSlo
              ? 'Open #/fleet. SLO-healthy requires collector_version, last_event_at (heartbeat within 1× interval), and drop_active=false. Run aim doctor on silent hosts.'
              : (t.state === 'broken'
                ? 'Open #/status, confirm the tile, then check the named service with aim doctor / stack status.'
                : 'Open #/status. Degraded means the signal works but is outside SLO — fix coverage before it hard-fails.')
      ).slice(0, 500),
      // Non-contract helper for the alerter / UI (stripped before XADD).
      _tileId: t.id,
    });
  }
  return out;
}

/** Strip internal fields before publishing. */
export function toPublishableAlert(candidate) {
  const { _tileId, ...alert } = candidate;
  return alert;
}

// ---- assembly -----------------------------------------------------------

export function assembleStatus({
  liveness,
  rejections,
  collectorDrops = null,
  coverageSlo = null,
  throughput,
  probes = {},
  sentinelHealth = null,
  cnapp = {},
  guardrailRules = null,
  lastFindingAt = null,
  ciRunner = null,
  enforceCoverage = null,
  now = new Date(),
} = {}) {
  const silence = liveness?.deviceSilence ?? null;
  const attribution = liveness?.attribution ?? null;
  // Prefer explicit collectorDrops; fall back to liveness.collectorDrops.
  // Missing signal defaults to an empty evaluation (ok), not broken — tests
  // and partial assembleStatus callers should not invent a red tile.
  const drops = collectorDrops
    ?? liveness?.collectorDrops
    ?? evaluateCollectorDrops({ devices: [] });
  // AIM-645: prefer caller-provided coverageSlo; else derive from liveness.coverageSlo.
  const slo = coverageSlo ?? liveness?.coverageSlo ?? null;

  const minEnforcePct = envInt('ENFORCE_COVERAGE_MIN_PCT', DEFAULT_MIN_COVERAGE_PCT);
  const tiles = [
    tileIngestLag(liveness),
    tileThroughput(throughput ?? { eventsLastHour: 0, eventsLast15m: 0 }),
    tileDlq(rejections),
    tileCollectorDrops(drops),
    tileDeviceLiveness(liveness, silence, slo),
    tileAttribution(attribution),
    // AIM-781: fleet enforce install-path coverage (pilot SLO).
    tileEnforceCoverage(enforceCoverage, { minCoveragePct: minEnforcePct }),
    tileCnappCoverage(cnapp),
    tileServiceProbe('gatehouse', 'aim', 'Gatehouse (PR gate)', probes.gatehouse),
    tileGuardrail({
      probeResult: probes.guardrail,
      rulesLoaded: guardrailRules,
      lastFindingAt,
    }),
    tileSentinel({ probeResult: probes.sentinel, healthBody: sentinelHealth }),
    tileCiRunner(ciRunner, { nowMs: now instanceof Date ? now.getTime() : Date.now() }),
  ];

  // Include any other configured stack services not already represented.
  for (const [name, result] of Object.entries(probes)) {
    if (['gatehouse', 'guardrail', 'sentinel', 'cnapp', 'ingest'].includes(name)) continue;
    tiles.push(tileServiceProbe(name, 'stack', name, result));
  }
  // Ingest probe is covered by lag/throughput tiles; still surface process health.
  if (probes.ingest) {
    tiles.splice(1, 0, tileServiceProbe('ingest', 'aim', 'Ingest process', probes.ingest));
  }
  if (probes.cnapp) {
    tiles.push(tileServiceProbe('cnapp', 'cnapp', 'CNAPP process', probes.cnapp));
  }

  const alertCandidates = alertCandidatesFromTiles(tiles, { now });
  const overall = overallState(tiles);
  const generatedAt = now instanceof Date ? now.toISOString() : String(now);
  return {
    overall,
    generatedAt,
    // AIM-452: same stamp as tile coverage claims so UI can render
    // "last verified" next to every figure without inventing a time.
    lastVerifiedAt: generatedAt,
    gatewayHost: gatewayHost(),
    tiles,
    // Same signals that would page via Sentinel — UI can show "would alert".
    alertCandidates: alertCandidates.map((a) => ({
      tileId: a._tileId,
      findingType: a.finding_type,
      severity: a.severity,
      title: a.title,
      dedupeKey: a.dedupe_key,
      alertId: a.alert_id,
    })),
    // Full payloads for the background alerter (not required by the UI).
    _alerts: alertCandidates,
  };
}

// ---- data gathering -----------------------------------------------------

/**
 * Load self-hosted PR runner status for the D2 health tile (AIM-297).
 *
 * Priority:
 *   1. AIM_CI_RUNNER_STATUS_FILE — JSON written by deploy/runner/health-report.sh
 *   2. AIM_CI_RUNNER_STATUS_URL  — HTTP JSON (same shape)
 *   3. AIM_CI_RUNNER_REPOS + GITHUB_TOKEN|GH_TOKEN — live GitHub Actions API
 *   4. never_configured
 */
export async function loadCiRunnerStatus({
  fetchImpl = fetch,
  readFile,
  now = new Date(),
} = {}) {
  const filePath = process.env.AIM_CI_RUNNER_STATUS_FILE;
  const url = process.env.AIM_CI_RUNNER_STATUS_URL;
  const reposRaw = process.env.AIM_CI_RUNNER_REPOS;
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.AIM_CI_GITHUB_TOKEN;

  if (filePath) {
    try {
      const fs = readFile
        ? { readFile }
        : await import('node:fs/promises');
      const raw = await (readFile ?? fs.readFile)(filePath, 'utf8');
      const parsed = JSON.parse(raw);
      return { configured: true, source: 'file', ...normalizeCiRunnerSnapshot(parsed, now) };
    } catch (err) {
      return { configured: true, source: 'file', error: err.message || 'status file unreadable' };
    }
  }

  if (url) {
    try {
      const res = await fetchImpl(url, { signal: AbortSignal.timeout(PROBE_TIMEOUT_MS * 2) });
      if (!res.ok) return { configured: true, source: 'url', error: `HTTP ${res.status}` };
      const parsed = await res.json();
      return { configured: true, source: 'url', ...normalizeCiRunnerSnapshot(parsed, now) };
    } catch (err) {
      return { configured: true, source: 'url', error: err.message || 'status url unreachable' };
    }
  }

  if (reposRaw && token) {
    const repos = reposRaw.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
    if (repos.length === 0) return { configured: false };
    try {
      const runners = [];
      let queuedJobs = 0;
      for (const repo of repos) {
        const headers = {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
          'User-Agent': 'aim-system-status',
        };
        const [runnerRes, queuedRes] = await Promise.all([
          fetchImpl(`https://api.github.com/repos/${repo}/actions/runners?per_page=100`, {
            headers,
            signal: AbortSignal.timeout(PROBE_TIMEOUT_MS * 2),
          }),
          fetchImpl(`https://api.github.com/repos/${repo}/actions/runs?status=queued&per_page=100`, {
            headers,
            signal: AbortSignal.timeout(PROBE_TIMEOUT_MS * 2),
          }),
        ]);
        if (!runnerRes.ok) {
          return {
            configured: true,
            source: 'github_api',
            error: `runners ${repo}: HTTP ${runnerRes.status}`,
          };
        }
        const body = await runnerRes.json();
        for (const r of body.runners ?? []) {
          const labels = (r.labels ?? []).map((l) => l.name ?? l);
          // Prefer PR-security labels; still report aim-ops / lw-local.
          runners.push({
            name: r.name,
            status: r.status,
            busy: r.busy,
            labels,
            isolation: labels.includes('aim-ci') ? 'hard' : (labels.includes('aim-ops') || labels.includes('lw-local') ? 'soft' : 'unknown'),
            repo,
          });
        }
        if (queuedRes.ok) {
          const q = await queuedRes.json();
          queuedJobs += num(q.total_count ?? (q.workflow_runs ?? []).length);
        }
      }
      return {
        configured: true,
        source: 'github_api',
        generatedAt: now instanceof Date ? now.toISOString() : String(now),
        runners,
        queuedJobs,
      };
    } catch (err) {
      return { configured: true, source: 'github_api', error: err.message || 'github api failed' };
    }
  }

  return { configured: false };
}

function normalizeCiRunnerSnapshot(parsed, now) {
  if (!parsed || typeof parsed !== 'object') {
    return { error: 'status payload is not an object' };
  }
  const runners = Array.isArray(parsed.runners) ? parsed.runners : [];
  return {
    generatedAt: parsed.generatedAt ?? parsed.generated_at
      ?? (now instanceof Date ? now.toISOString() : String(now)),
    runners,
    queuedJobs: num(parsed.queuedJobs ?? parsed.queued_jobs),
  };
}

async function fetchCnappCoverage(fetchImpl = fetch) {
  const base = process.env.AIM_CNAPP_BASE_URL?.replace(/\/$/, '');
  if (!base) return { configured: false };
  const headers = {};
  if (process.env.AIM_CNAPP_API_KEY) headers['X-API-Key'] = process.env.AIM_CNAPP_API_KEY;
  try {
    const [covRes, postRes] = await Promise.all([
      fetchImpl(`${base}/accounts/coverage`, {
        headers,
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS * 2),
      }),
      fetchImpl(`${base}/accounts/posture`, {
        headers,
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS * 2),
      }),
    ]);
    if (!covRes.ok) {
      return { configured: true, error: `coverage HTTP ${covRes.status}` };
    }
    const coverage = await covRes.json();
    let posture = null;
    if (postRes.ok) {
      posture = await postRes.json();
    }
    return { configured: true, coverage, posture };
  } catch (err) {
    return { configured: true, error: err.message || 'cnapp unreachable' };
  }
}

async function gatherStatus(db, { fetchImpl = fetch } = {}) {
  const thresholdSeconds = idleThresholdSeconds();
  const windowSeconds = attributionWindowSeconds();

  const [ingest, devices, attribution, silentRows, dropRows, throughput, rejectionsTotal, rejectionsByReason, findingsMeta] = await Promise.all([
    db.query(
      `SELECT max(received_at) AS last_received,
              EXTRACT(EPOCH FROM (now() - max(received_at))) AS idle_seconds
         FROM events`,
    ),
    db.query(
      `SELECT count(*) FILTER (WHERE revoked_at IS NULL) AS enrolled,
              count(*) FILTER (WHERE revoked_at IS NULL
                               AND last_heartbeat_at >= now() - interval '15 minutes') AS healthy,
              count(*) FILTER (WHERE revoked_at IS NULL
                               AND last_heartbeat_at IS NOT NULL) AS ever_seen,
              count(*) FILTER (WHERE revoked_at IS NULL
                               AND last_heartbeat_at IS NULL
                               AND enrolled_at < now() - interval '24 hours') AS stale
         FROM devices`,
    ),
    db.query(
      `SELECT count(*) AS total,
              count(user_pseudonym) AS attributed,
              count(*) FILTER (WHERE user_pseudonym IS NOT NULL
                               AND principal_kind = 'service') AS service_attributed
         FROM events
        WHERE received_at >= now() - ($1 || ' seconds')::interval`,
      [windowSeconds],
    ),
    db.query(
      `SELECT device_id, host_id, hostname, last_heartbeat_at, heartbeat_interval_sec
         FROM devices
        WHERE revoked_at IS NULL
          AND last_heartbeat_at IS NOT NULL
        ORDER BY last_heartbeat_at ASC`,
    ),
    // AIM-439 + AIM-645: full counter rows for drop detection and coverage SLO.
    db.query(
      `SELECT device_id, host_id, hostname, collector_version, enrolled_at,
              last_heartbeat_at, last_counters, heartbeat_interval_sec
         FROM devices
        WHERE revoked_at IS NULL`,
    ),
    db.query(
      `SELECT
         count(*) FILTER (WHERE received_at >= now() - interval '1 hour') AS hour,
         count(*) FILTER (WHERE received_at >= now() - interval '15 minutes') AS m15
         FROM events`,
    ),
    db.query(`SELECT count(*)::int AS total FROM rejected_events`),
    db.query(
      `SELECT error, count(*)::int AS count
         FROM rejected_events
        GROUP BY error
        ORDER BY count DESC
        LIMIT 20`,
    ),
    db.query(
      `SELECT count(*)::int AS n, max(detected_at) AS last_finding
         FROM findings`,
    ),
  ]);

  const ing = ingest.rows[0] ?? {};
  const dev = devices.rows[0] ?? {};
  const att = attribution.rows[0] ?? {};
  const lastReceived = ing.last_received;
  const verifiedAt = new Date().toISOString();
  const liveness = {
    ...evaluateLiveness({
      lastReceivedAt: lastReceived instanceof Date ? lastReceived.toISOString() : lastReceived ?? null,
      idleSeconds: ing.idle_seconds == null ? null : Number(ing.idle_seconds),
      enrolled: dev.enrolled,
      healthy: dev.healthy,
      everSeen: dev.ever_seen,
      stale: dev.stale,
      thresholdSeconds,
    }),
    attribution: {
      ...evaluateAttribution({
        total: att.total,
        attributed: att.attributed,
        service: att.service_attributed,
        windowSeconds,
      }),
      lastVerifiedAt: verifiedAt,
    },
    deviceSilence: evaluateDeviceSilence({ devices: silentRows.rows ?? [] }),
  };

  const rejections = evaluateRejections({
    total: rejectionsTotal.rows[0]?.total,
    byReason: rejectionsByReason.rows,
    recent: [],
  });

  const collectorDrops = evaluateCollectorDrops({
    devices: dropRows.rows ?? [],
  });

  // AIM-645: same SLO definition as GET /api/fleet (version + last_event_at + errors).
  const nowMs = Date.now();
  const coverageDevices = (dropRows.rows ?? []).map((r) => {
    const intervalSec = Number(r.heartbeat_interval_sec) || 300;
    const lastHb = r.last_heartbeat_at ? new Date(r.last_heartbeat_at) : null;
    let health = 'never_seen';
    if (lastHb) {
      const ageSec = (nowMs - lastHb.getTime()) / 1000;
      if (ageSec <= intervalSec) health = 'healthy';
      else if (ageSec <= intervalSec * 3) health = 'stale';
      else health = 'dead';
    }
    const drops = projectDropHealth(r.last_counters, nowMs);
    const sloDev = evaluateDeviceSloHealth({
      collector_version: r.collector_version,
      last_heartbeat_at: lastHb,
      heartbeat_interval_sec: intervalSec,
      drops,
      health,
      nowMs,
    });
    return {
      collector_version: r.collector_version ?? null,
      enrolled_at: r.enrolled_at instanceof Date
        ? r.enrolled_at.toISOString()
        : (r.enrolled_at ?? null),
      last_heartbeat_at: lastHb ? lastHb.toISOString() : null,
      heartbeat_interval_sec: intervalSec,
      health,
      drop_active: drops.drop_active,
      sloHealthy: sloDev.sloHealthy,
      unhealthyReasons: sloDev.unhealthyReasons,
    };
  });
  const coverageSlo = evaluateCollectorCoverageSlo(coverageDevices, {
    targetPct: coverageSloTargetPct(),
    nowMs,
  });

  const thr = throughput.rows[0] ?? {};
  const services = configuredServices() ?? [];
  // Always attempt well-known optional probes via env overrides.
  const extras = [];
  if (process.env.AIM_CNAPP_HEALTH_URL) {
    extras.push({ name: 'cnapp', url: process.env.AIM_CNAPP_HEALTH_URL });
  } else if (!services.some((s) => s.name === 'cnapp')) {
    // Best-effort default on the unified-stack edge network.
    extras.push({ name: 'cnapp', url: 'http://cnapp-api:8000/health' });
  }
  if (process.env.AIM_GUARDRAIL_HEALTH_URL) {
    extras.push({ name: 'guardrail', url: process.env.AIM_GUARDRAIL_HEALTH_URL });
  } else if (!services.some((s) => s.name === 'guardrail')) {
    extras.push({ name: 'guardrail', url: 'http://guardrail:8090/healthz' });
  }

  const toProbe = [...services, ...extras];
  const probed = await Promise.all(toProbe.map((s) => probe(s, fetchImpl)));
  const probes = Object.fromEntries(probed.map((p) => [p.name, p]));

  // Sentinel health body carries channel config — fetch JSON when probe is ok.
  let sentinelHealth = null;
  if (probes.sentinel?.status === 'ok') {
    const svc = toProbe.find((s) => s.name === 'sentinel');
    if (svc?.url) {
      try {
        const res = await fetchImpl(svc.url, { signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) });
        if (res.ok) sentinelHealth = await res.json();
      } catch {
        // tile still has probe status
      }
    }
  }

  const [cnapp, ciRunner, enforceCoverage] = await Promise.all([
    fetchCnappCoverage(fetchImpl),
    loadCiRunnerStatus({ fetchImpl }),
    // AIM-781: pilot enforce install-path SLO. Failures must not break the
    // rest of system status — tile becomes never_configured/broken via null.
    loadEnforceCoverageSummary(db).catch(() => null),
  ]);
  const lastFinding = findingsMeta.rows[0]?.last_finding;
  // rulesLoaded: we do not re-parse YAML here; presence of findings or a live
  // guardrail probe is the signal. Optional AIM_GUARDRAIL_RULES_COUNT override
  // for tests.
  let guardrailRules = process.env.AIM_GUARDRAIL_RULES_COUNT != null
    ? Number(process.env.AIM_GUARDRAIL_RULES_COUNT)
    : null;
  if (guardrailRules == null && probes.guardrail?.status === 'ok') {
    guardrailRules = 1; // process up ⇒ policy path exists; count unknown
  }

  return assembleStatus({
    liveness,
    rejections,
    collectorDrops,
    coverageSlo,
    throughput: {
      eventsLastHour: thr.hour,
      eventsLast15m: thr.m15,
    },
    probes,
    sentinelHealth,
    cnapp,
    guardrailRules,
    lastFindingAt: lastFinding instanceof Date ? lastFinding.toISOString() : lastFinding ?? null,
    ciRunner,
    enforceCoverage,
  });
}

// ---- routes -------------------------------------------------------------

export async function systemStatusRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const fetchImpl = opts?.fetchImpl ?? fetch;
  // Operator view — same gate as pipeline liveness (auditor+).
  const anyRole = requireRoles('admin', 'analyst', 'auditor', 'viewer');

  fastify.get('/api/system/status', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const status = await gatherStatus(db, { fetchImpl });
    // Strip internal alert payloads from the wire response.
    const { _alerts, ...publicStatus } = status;
    return publicStatus;
  });
}

// ---- background alerter (not on the request path) -----------------------

/**
 * Periodically re-evaluates system status and XADDs breach alerts onto the
 * existing alert bus. Same path Sentinel already consumes. Opt-in via
 * SYSTEM_STATUS_ALERTS=1 (and ALERT_BUS_URL).
 *
 * Deliberately NOT invoked from GET /api/system/status — alertbus.js forbids
 * XADD on the request path so a dashboard refresh cannot mutate the stream.
 */
export function startSystemStatusAlerter({
  db = { query },
  fetchImpl = fetch,
  publish,
  intervalMs,
  log = console,
} = {}) {
  if (process.env.SYSTEM_STATUS_ALERTS !== '1' && process.env.SYSTEM_STATUS_ALERTS !== 'true') {
    return { stop() {}, enabled: false };
  }
  if (typeof publish !== 'function') {
    log.warn?.('SYSTEM_STATUS_ALERTS set but no publish function — alerter idle');
    return { stop() {}, enabled: false };
  }
  const ms = intervalMs
    ?? (envInt('SYSTEM_STATUS_ALERT_INTERVAL_SEC', 300) * 1000);
  const seen = new Map(); // dedupe_key -> last published ms
  const TTL = 6 * 60 * 60 * 1000; // re-emit standing breaches every 6h

  let timer = null;
  let running = false;

  async function tick() {
    if (running) return;
    running = true;
    try {
      const status = await gatherStatus(db, { fetchImpl });
      const now = Date.now();
      for (const raw of status._alerts ?? []) {
        const alert = toPublishableAlert(raw);
        const last = seen.get(alert.dedupe_key) ?? 0;
        if (now - last < TTL) continue;
        await publish(alert);
        seen.set(alert.dedupe_key, now);
      }
      // Drop resolved keys so a re-breach pages again.
      const live = new Set((status._alerts ?? []).map((a) => a.dedupe_key));
      for (const k of seen.keys()) {
        if (!live.has(k)) seen.delete(k);
      }
    } catch (err) {
      log.error?.({ err }, 'system-status alerter tick failed');
    } finally {
      running = false;
    }
  }

  timer = setInterval(tick, ms);
  // First pass after a short delay so boot is not blocked on probes.
  const boot = setTimeout(tick, Math.min(ms, 15_000));
  return {
    enabled: true,
    stop() {
      clearInterval(timer);
      clearTimeout(boot);
    },
    // test seam
    _tick: tick,
    _seen: seen,
  };
}

/**
 * Build a Redis XADD publisher for security.alert/v1. Injectable createClient
 * for tests. Validates nothing here — callers should prefer
 * toPublishableAlert(alertCandidatesFromTiles(...)) which already builds
 * contract-shaped payloads; Sentinel's consumer profile is the backstop.
 */
export function createAlertBusPublisher({
  url = process.env.ALERT_BUS_URL,
  stream = process.env.ALERT_BUS_STREAM ?? 'secstack:alerts:v1',
  createClient,
  log = console,
} = {}) {
  if (!url) return null;
  let clientPromise = null;
  async function client() {
    if (!clientPromise) {
      const { createClient: create } = createClient
        ? { createClient }
        : await import('redis');
      const c = create({ url });
      c.on('error', (err) => log.error?.({ err }, 'system-status alert bus redis error'));
      clientPromise = c.connect().then(() => c);
    }
    return clientPromise;
  }
  return async function publish(alert) {
    const c = await client();
    await c.xAdd(stream, '*', { alert: JSON.stringify(alert) }, {
      TRIM: { strategy: 'MAXLEN', strategyModifier: '~', threshold: 50_000 },
    });
    return alert.alert_id;
  };
}

export default systemStatusRoutes;

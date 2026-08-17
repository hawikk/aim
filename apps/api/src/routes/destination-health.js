// Destination health / failed delivery SLO (AIM-704).
//
// Ops answer: "are webhook / email / Slack (and other) alert destinations
// actually receiving findings — and is our success rate inside the SLO?"
//
// Source of truth: finding_deliveries (one row per finding per destination,
// status delivered|failed). Written by guardrail notifiers after each batch.
//
// SLO (env-tunable):
//   DESTINATION_HEALTH_WINDOW_HOURS   default 24
//   DESTINATION_HEALTH_SUCCESS_PCT    default 99   (success rate ≥ this)
//   DESTINATION_HEALTH_MIN_SAMPLES    default 5    (below this, no rate breach)
//   DESTINATION_HEALTH_FAIL_HARD      default 3    (absolute failed count
//                                                  → broken even if rate ok)
// Alerts (opt-in bus publisher):
//   DESTINATION_HEALTH_ALERTS=1
//   DESTINATION_HEALTH_ALERT_INTERVAL_SEC=300
//
// Gate: analyst+ (same privacy tier as /api/findings — delivery rows carry
// finding refs and transport error text, never prompt content).

import { createHash } from 'node:crypto';
import { query } from '../db.js';
import { requireRoles } from '../auth.js';

export const DEFAULT_WINDOW_HOURS = 24;
export const DEFAULT_SUCCESS_PCT = 99;
export const DEFAULT_MIN_SAMPLES = 5;
export const DEFAULT_FAIL_HARD = 3;

/** Primary SOC destinations called out by AIM-704 acceptance. */
export const PRIMARY_DESTINATIONS = Object.freeze(['webhook', 'email', 'slack']);

/**
 * Full set we always surface as tiles (primary first). Extra destinations
 * that appear in finding_deliveries (sentinel, bus, google_chat, …) are
 * appended so Ops never loses visibility on configured SIEM paths.
 */
export const KNOWN_DESTINATIONS = Object.freeze([
  'webhook',
  'email',
  'slack',
  'google_chat',
  'sentinel',
  'bus',
  'splunk_hec',
  'syslog_cef',
]);

const SEVERITY_ID = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
};

function envInt(name, def, env = process.env) {
  const raw = env[name];
  if (raw == null || raw === '') return def;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : def;
}

function envFloat(name, def, env = process.env) {
  const raw = env[name];
  if (raw == null || raw === '') return def;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 && n <= 100 ? n : def;
}

export function resolveWindowHours(env = process.env) {
  return envInt('DESTINATION_HEALTH_WINDOW_HOURS', DEFAULT_WINDOW_HOURS, env);
}

export function resolveSuccessPct(env = process.env) {
  return envFloat('DESTINATION_HEALTH_SUCCESS_PCT', DEFAULT_SUCCESS_PCT, env);
}

export function resolveMinSamples(env = process.env) {
  return envInt('DESTINATION_HEALTH_MIN_SAMPLES', DEFAULT_MIN_SAMPLES, env);
}

export function resolveFailHard(env = process.env) {
  return envInt('DESTINATION_HEALTH_FAIL_HARD', DEFAULT_FAIL_HARD, env);
}

/**
 * Pure: classify one destination's delivery posture over the window.
 *
 * States:
 *   never_configured — zero delivery attempts in the window
 *   ok               — success rate ≥ SLO, no failures (or only idle)
 *   degraded         — failures present or success rate under SLO (min samples)
 *   broken           — absolute failed ≥ failHard, or rate < successPct-5
 */
export function classifyDestination({
  destination,
  delivered = 0,
  failed = 0,
  lastFailureAt = null,
  lastSuccessAt = null,
  lastError = null,
  allTimeTotal = null,
} = {}, {
  successPct = DEFAULT_SUCCESS_PCT,
  minSamples = DEFAULT_MIN_SAMPLES,
  failHard = DEFAULT_FAIL_HARD,
} = {}) {
  const d = Math.max(0, Number(delivered) || 0);
  const f = Math.max(0, Number(failed) || 0);
  const total = d + f;
  const rate = total > 0 ? (d / total) * 100 : null;
  const name = String(destination || 'unknown');
  const isPrimary = PRIMARY_DESTINATIONS.includes(name);

  if (total === 0) {
    const ever = allTimeTotal == null ? 0 : Number(allTimeTotal) || 0;
    return {
      destination: name,
      primary: isPrimary,
      delivered: 0,
      failed: 0,
      total: 0,
      successRatePct: null,
      lastFailureAt: toIso(lastFailureAt),
      lastSuccessAt: toIso(lastSuccessAt),
      lastError: null,
      state: 'never_configured',
      breach: false,
      message: ever > 0
        ? `No deliveries in the window (has ${ever} all-time).`
        : 'No deliveries recorded — destination not used or not configured.',
    };
  }

  const rateOk = rate != null && rate >= successPct;
  const hardFail = f >= failHard;
  const softBreach = total >= minSamples && !rateOk;
  const severeRate = total >= minSamples && rate != null && rate < Math.max(0, successPct - 5);

  let state = 'ok';
  let breach = false;
  let message = `${d}/${total} delivered (${fmtPct(rate)}); ${f} failed.`;

  if (hardFail || severeRate) {
    state = 'broken';
    breach = true;
    if (hardFail && severeRate) {
      message = `${f} failed deliveries and success rate ${fmtPct(rate)} below ${successPct}% SLO.`;
    } else if (hardFail) {
      message = `${f} failed deliveries in window (hard threshold ${failHard}).`;
    } else {
      message = `Success rate ${fmtPct(rate)} is well below ${successPct}% SLO (${d}/${total}).`;
    }
  } else if (softBreach || f > 0) {
    // Any failure surfaces as degraded so Ops sees it (acceptance: failed
    // deliveries alert ops). Soft rate breach also degraded.
    state = 'degraded';
    breach = true;
    if (softBreach) {
      message = `Success rate ${fmtPct(rate)} below ${successPct}% SLO (${d}/${total}, min samples ${minSamples}).`;
    } else {
      message = `${f} failed delivery(ies) in window; rate ${fmtPct(rate)} still ≥ ${successPct}% or under min samples.`;
    }
  }

  return {
    destination: name,
    primary: isPrimary,
    delivered: d,
    failed: f,
    total,
    successRatePct: rate == null ? null : round1(rate),
    lastFailureAt: toIso(lastFailureAt),
    lastSuccessAt: toIso(lastSuccessAt),
    lastError: lastError == null ? null : String(lastError).slice(0, 500),
    state,
    breach,
    message,
  };
}

/**
 * Pure: roll up destination rows into overall posture + tiles + alert candidates.
 */
export function assembleDestinationHealth({
  rows = [],
  nowMs = Date.now(),
  windowHours = DEFAULT_WINDOW_HOURS,
  successPct = DEFAULT_SUCCESS_PCT,
  minSamples = DEFAULT_MIN_SAMPLES,
  failHard = DEFAULT_FAIL_HARD,
} = {}) {
  const byName = new Map();
  for (const r of rows) {
    if (!r || r.destination == null) continue;
    byName.set(String(r.destination), r);
  }

  const names = [...KNOWN_DESTINATIONS];
  for (const n of byName.keys()) {
    if (!names.includes(n)) names.push(n);
  }

  const destinations = names.map((name) => {
    const r = byName.get(name) || {};
    return classifyDestination({
      destination: name,
      delivered: r.delivered ?? 0,
      failed: r.failed ?? 0,
      lastFailureAt: r.lastFailureAt ?? r.last_failure_at ?? null,
      lastSuccessAt: r.lastSuccessAt ?? r.last_success_at ?? null,
      lastError: r.lastError ?? r.last_error ?? null,
      allTimeTotal: r.allTimeTotal ?? r.all_time_total ?? null,
    }, { successPct, minSamples, failHard });
  });

  const measured = destinations.filter((d) => d.total > 0);
  const primary = destinations.filter((d) => d.primary);
  const primaryMeasured = primary.filter((d) => d.total > 0);

  let delivered = 0;
  let failed = 0;
  let broken = 0;
  let degraded = 0;
  let never = 0;
  for (const d of destinations) {
    delivered += d.delivered;
    failed += d.failed;
    if (d.state === 'broken') broken += 1;
    else if (d.state === 'degraded') degraded += 1;
    else if (d.state === 'never_configured') never += 1;
  }
  const total = delivered + failed;
  const overallRate = total > 0 ? round1((delivered / total) * 100) : null;

  let overall = 'ok';
  let overallMessage = '';
  if (measured.length === 0) {
    overall = 'never_configured';
    overallMessage = 'No alert deliveries in the window — destinations may be off or idle.';
  } else if (broken > 0) {
    overall = 'broken';
    const bad = destinations.filter((d) => d.state === 'broken').map((d) => d.destination);
    overallMessage = `Broken destination(s): ${bad.join(', ')}.`;
  } else if (degraded > 0 || destinations.some((d) => d.breach)) {
    overall = 'degraded';
    const bad = destinations.filter((d) => d.breach).map((d) => d.destination);
    overallMessage = `Degraded / failing destination(s): ${bad.join(', ')}.`;
  } else {
    overall = 'ok';
    overallMessage = primaryMeasured.length
      ? `Primary destinations healthy; fleet success rate ${fmtPct(overallRate)} over ${windowHours}h.`
      : `Measured destinations healthy; success rate ${fmtPct(overallRate)} over ${windowHours}h.`;
  }

  const slo = {
    text: `delivery success rate ≥ ${successPct}% over ${windowHours}h (min ${minSamples} samples; hard fail ≥ ${failHard})`,
    windowHours,
    successPct,
    minSamples,
    failHard,
  };

  const summary = {
    windowHours,
    destinations: destinations.length,
    measured: measured.length,
    primaryMeasured: primaryMeasured.length,
    delivered,
    failed,
    total,
    successRatePct: overallRate,
    broken,
    degraded,
    neverConfigured: never,
  };

  const tiles = [
    tileOverall({ overall, overallMessage, slo, summary }),
    ...primary.map((d) => tileDestination(d, slo)),
    ...destinations
      .filter((d) => !d.primary && (d.total > 0 || d.state === 'broken' || d.state === 'degraded'))
      .map((d) => tileDestination(d, slo)),
  ];

  const alertCandidates = buildAlertCandidates({
    overall,
    destinations,
    slo,
    summary,
    nowMs,
  });

  const failing = destinations
    .filter((d) => d.failed > 0)
    .sort((a, b) => b.failed - a.failed || String(a.destination).localeCompare(b.destination));

  return {
    overall,
    message: overallMessage,
    slo,
    summary,
    tiles,
    destinations,
    failing,
    alertCandidates,
    generatedAt: new Date(nowMs).toISOString(),
    lastVerifiedAt: new Date(nowMs).toISOString(),
  };
}

function tileOverall({ overall, overallMessage, slo, summary }) {
  return {
    id: 'destination_health_overall',
    pillar: 'aim',
    title: 'Destination health',
    state: overall,
    slo,
    value: {
      delivered: summary.delivered,
      failed: summary.failed,
      total: summary.total,
      successRatePct: summary.successRatePct,
      measured: summary.measured,
      broken: summary.broken,
    },
    message: overallMessage,
    breach: overall !== 'ok' && overall !== 'never_configured',
  };
}

function tileDestination(d, slo) {
  return {
    id: `destination_${d.destination}`,
    pillar: 'aim',
    title: displayName(d.destination),
    state: d.state,
    slo: {
      text: `${d.destination} success ≥ ${slo.successPct}% / ${slo.windowHours}h`,
      windowHours: slo.windowHours,
      successPct: slo.successPct,
      destination: d.destination,
    },
    value: {
      destination: d.destination,
      delivered: d.delivered,
      failed: d.failed,
      total: d.total,
      successRatePct: d.successRatePct,
      lastFailureAt: d.lastFailureAt,
      lastSuccessAt: d.lastSuccessAt,
    },
    message: d.message,
    breach: d.breach,
  };
}

/** Build security.alert/v1 candidates for failed / SLO-breaching destinations. */
export function buildAlertCandidates({ overall, destinations, slo, summary, nowMs }) {
  if (overall === 'ok' || overall === 'never_configured') return [];
  const stamp = new Date(nowMs).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const out = [];

  const breaching = destinations
    .filter((d) => d.breach && d.total > 0)
    .sort((a, b) => {
      if (a.primary !== b.primary) return a.primary ? -1 : 1;
      const rank = { broken: 0, degraded: 1, ok: 2, never_configured: 3 };
      const ra = rank[a.state] ?? 9;
      const rb = rank[b.state] ?? 9;
      if (ra !== rb) return ra - rb;
      return b.failed - a.failed;
    });

  for (const d of breaching) {
    const severity = d.state === 'broken' ? 'high' : 'medium';
    const dedupe = dedupeHex([
      'destination-health',
      d.destination,
      d.state,
      String(slo.successPct),
      String(slo.windowHours),
    ]);
    const title = d.state === 'broken'
      ? `Alert destination ${d.destination} failing (${d.failed} failed / ${d.total} in ${slo.windowHours}h)`
      : `Alert destination ${d.destination} degraded (success ${fmtPct(d.successRatePct)} < ${slo.successPct}%)`;

    out.push({
      schema_version: '1.1',
      alert_id: stableAlertId(dedupe),
      dedupe_key: dedupe,
      pillar: 'ai_usage',
      producer: { name: 'aim-destination-health', version: '1.0.0' },
      finding_type: d.state === 'broken'
        ? 'ai_usage.destination_delivery_failed'
        : 'ai_usage.destination_delivery_slo_breach',
      title: title.slice(0, 200),
      severity,
      severity_id: SEVERITY_ID[severity],
      status: 'new',
      observed_at: stamp,
      first_seen_at: stamp,
      last_seen_at: stamp,
      resource: {
        kind: 'host',
        ref: `aim:destination-health/${d.destination}`,
        display: displayName(d.destination),
        provider: null,
        account_ref: null,
        region: null,
      },
      subject_ref: null,
      evidence: {
        source_uri: 'aim:/destination-health',
        detail_count: d.failed || 1,
        summary: (
          d.lastError
            ? `${d.message} Last error: ${d.lastError}`
            : d.message
        ).slice(0, 240),
      },
      labels: {
        tile: `destination_${d.destination}`,
        destination: String(d.destination).slice(0, 128),
        state: String(d.state).slice(0, 128),
        failed: String(d.failed).slice(0, 128),
        delivered: String(d.delivered).slice(0, 128),
        success_pct: String(d.successRatePct ?? '').slice(0, 128),
        slo_success_pct: String(slo.successPct).slice(0, 128),
        window_hours: String(slo.windowHours).slice(0, 128),
        primary: d.primary ? '1' : '0',
      },
      remediation_hint: (
        `Open #/destination-health. Check ${d.destination} credentials/URL, receiver health, and guardrail.alert.error logs. ` +
        'finding_deliveries holds the audit trail (status=failed). Re-drive is a manual runbook action in v1.'
      ).slice(0, 500),
      tileId: `destination_${d.destination}`,
      findingType: d.state === 'broken'
        ? 'ai_usage.destination_delivery_failed'
        : 'ai_usage.destination_delivery_slo_breach',
    });
  }

  if (summary.failed >= slo.failHard && breaching.length >= 2) {
    const band = summary.failed <= 5 ? '3-5' : summary.failed <= 20 ? '6-20' : summary.failed <= 50 ? '21-50' : '51+';
    const fleetDedupe = dedupeHex(['destination-health', 'fleet', band, String(slo.windowHours)]);
    out.push({
      schema_version: '1.1',
      alert_id: stableAlertId(fleetDedupe),
      dedupe_key: fleetDedupe,
      pillar: 'ai_usage',
      producer: { name: 'aim-destination-health', version: '1.0.0' },
      finding_type: 'ai_usage.destination_delivery_fleet_failed',
      title: `${summary.failed} failed alert deliveries across ${breaching.length} destinations (${slo.windowHours}h)`.slice(0, 200),
      severity: 'high',
      severity_id: SEVERITY_ID.high,
      status: 'new',
      observed_at: stamp,
      first_seen_at: stamp,
      last_seen_at: stamp,
      resource: {
        kind: 'host',
        ref: 'aim:destination-health/fleet',
        display: 'Alert destination fleet',
        provider: null,
        account_ref: null,
        region: null,
      },
      subject_ref: null,
      evidence: {
        source_uri: 'aim:/destination-health',
        detail_count: summary.failed,
        summary: (
          `Fleet success ${fmtPct(summary.successRatePct)}; failing: ${breaching.map((d) => d.destination).join(', ')}`
        ).slice(0, 240),
      },
      labels: {
        tile: 'destination_health_overall',
        state: overall,
        failed: String(summary.failed).slice(0, 128),
        window_hours: String(slo.windowHours).slice(0, 128),
        breach_band: band,
      },
      remediation_hint: (
        'Open #/destination-health. Multiple sinks are failing — check shared egress, DNS, or guardrail poller health before per-destination secrets.'
      ).slice(0, 500),
      tileId: 'destination_health_overall',
      findingType: 'ai_usage.destination_delivery_fleet_failed',
    });
  }

  return out;
}

function displayName(dest) {
  const map = {
    webhook: 'Webhook',
    email: 'Email',
    slack: 'Slack',
    google_chat: 'Google Chat',
    sentinel: 'Microsoft Sentinel',
    bus: 'Alert bus',
    splunk_hec: 'Splunk HEC',
    syslog_cef: 'Syslog CEF',
  };
  return map[dest] || dest;
}

function toIso(v) {
  if (v == null) return null;
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v.toISOString();
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function round1(n) {
  return Math.round(n * 10) / 10;
}

function fmtPct(n) {
  if (n == null || !Number.isFinite(n)) return '—';
  return `${round1(n)}%`;
}

function stableAlertId(dedupeHexVal) {
  const hexed = dedupeHexVal.slice(0, 32).padEnd(32, '0');
  const variant = '89ab'[parseInt(hexed[16], 16) % 4];
  return `${hexed.slice(0, 8)}-${hexed.slice(8, 12)}-4${hexed.slice(13, 16)}-${variant}${hexed.slice(17, 20)}-${hexed.slice(20, 32)}`;
}

function dedupeHex(parts) {
  return createHash('sha256').update(parts.join('|')).digest('hex');
}

/** Load window aggregates from finding_deliveries. */
export async function loadDestinationDeliveryRows(db = { query }, {
  windowHours = DEFAULT_WINDOW_HOURS,
} = {}) {
  const hours = Math.max(1, Math.floor(windowHours));
  const { rows } = await db.query(
    `WITH windowed AS (
       SELECT
         destination,
         COUNT(*) FILTER (WHERE status = 'delivered')::int AS delivered,
         COUNT(*) FILTER (WHERE status = 'failed')::int AS failed,
         MAX(recorded_at) FILTER (WHERE status = 'failed') AS last_failure_at,
         MAX(COALESCE(delivered_at, recorded_at)) FILTER (WHERE status = 'delivered') AS last_success_at
       FROM finding_deliveries
       WHERE recorded_at >= NOW() - make_interval(hours => $1::int)
       GROUP BY destination
     ),
     errors AS (
       SELECT DISTINCT ON (destination)
         destination,
         error AS last_error
       FROM finding_deliveries
       WHERE status = 'failed'
         AND recorded_at >= NOW() - make_interval(hours => $1::int)
       ORDER BY destination, recorded_at DESC
     ),
     all_time AS (
       SELECT destination, COUNT(*)::int AS all_time_total
       FROM finding_deliveries
       GROUP BY destination
     )
     SELECT
       COALESCE(w.destination, a.destination) AS destination,
       COALESCE(w.delivered, 0) AS delivered,
       COALESCE(w.failed, 0) AS failed,
       w.last_failure_at,
       w.last_success_at,
       e.last_error,
       COALESCE(a.all_time_total, 0) AS all_time_total
     FROM all_time a
     FULL OUTER JOIN windowed w ON w.destination = a.destination
     LEFT JOIN errors e ON e.destination = COALESCE(w.destination, a.destination)`,
    [hours],
  );

  return rows.map((r) => ({
    destination: r.destination,
    delivered: Number(r.delivered) || 0,
    failed: Number(r.failed) || 0,
    lastFailureAt: r.last_failure_at ?? null,
    lastSuccessAt: r.last_success_at ?? null,
    lastError: r.last_error ?? null,
    allTimeTotal: Number(r.all_time_total) || 0,
  }));
}

export async function destinationHealthRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const userLevel = requireRoles('analyst', 'admin');

  fastify.get('/api/destination-health', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;

    const windowHours = resolveWindowHours();
    const successPct = resolveSuccessPct();
    const minSamples = resolveMinSamples();
    const failHard = resolveFailHard();
    const nowMs = Date.now();

    let rows = [];
    try {
      rows = await loadDestinationDeliveryRows(db, { windowHours });
    } catch {
      rows = [];
    }

    return assembleDestinationHealth({
      rows,
      nowMs,
      windowHours,
      successPct,
      minSamples,
      failHard,
    });
  });
}

/**
 * Background publisher: standing destination delivery failures → alert bus.
 * Opt-in via DESTINATION_HEALTH_ALERTS=1. Never XADDs on the request path.
 */
export function startDestinationHealthAlerter({
  db = { query },
  publish,
  intervalMs,
  log = console,
} = {}) {
  if (
    process.env.DESTINATION_HEALTH_ALERTS !== '1' &&
    process.env.DESTINATION_HEALTH_ALERTS !== 'true'
  ) {
    return { stop() {}, enabled: false };
  }
  if (typeof publish !== 'function') {
    log.warn?.('DESTINATION_HEALTH_ALERTS set but no publish function — alerter idle');
    return { stop() {}, enabled: false };
  }

  const ms = intervalMs ?? (envInt('DESTINATION_HEALTH_ALERT_INTERVAL_SEC', 300) * 1000);
  const seen = new Map();
  const TTL = 6 * 60 * 60 * 1000;

  let timer = null;
  let running = false;

  async function tick() {
    if (running) return;
    running = true;
    try {
      const windowHours = resolveWindowHours();
      const successPct = resolveSuccessPct();
      const minSamples = resolveMinSamples();
      const failHard = resolveFailHard();
      const rows = await loadDestinationDeliveryRows(db, { windowHours });
      const body = assembleDestinationHealth({
        rows,
        nowMs: Date.now(),
        windowHours,
        successPct,
        minSamples,
        failHard,
      });
      const now = Date.now();
      const live = new Set();
      for (const alert of body.alertCandidates ?? []) {
        live.add(alert.dedupe_key);
        const last = seen.get(alert.dedupe_key) ?? 0;
        if (now - last < TTL) continue;
        const { tileId: _t, findingType: _f, ...wire } = alert;
        await publish(wire);
        seen.set(alert.dedupe_key, now);
        log.info?.(
          {
            destination: alert.labels?.destination,
            finding_type: alert.finding_type,
            dedupe: alert.dedupe_key,
          },
          'destination health breach alert published',
        );
      }
      for (const k of seen.keys()) {
        if (!live.has(k)) seen.delete(k);
      }
    } catch (err) {
      log.error?.({ err }, 'destination health alerter tick failed');
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

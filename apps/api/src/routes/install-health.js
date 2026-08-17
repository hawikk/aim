// Install health / time-to-first-evidence SLO (AIM-746).
//
// Ops answer: "after a collector enrolls, how long until we have evidence it
// is working — and are any enrollments past the SLO with nothing back?"
//
// Evidence kinds (honest with the schema we have today):
//   heartbeat  devices.last_heartbeat_at — first server-side proof the
//              collector is alive and talking to ingest. Enrollment → first
//              heartbeat is seconds in practice (docs/fleet-enrollment-reaping.md).
//   event      fleet-level only: MIN(events.received_at) vs MIN(devices.enrolled_at).
//              Events are keyed by host_ref (HMAC), not device_id, so per-device
//              first-event latency is not joinable without a device stamp on
//              events (ingest follow-up). The fleet tile still answers
//              "enroll → first usage event on this install".
//
// SLO (env-tunable): INSTALL_HEALTH_SLO_SEC, default 300 (5 minutes).
// Lookback for the recent-enrollment table: INSTALL_HEALTH_LOOKBACK_DAYS, default 7.
//
// Gate: analyst+ (same as /api/fleet) — device hostnames are operator data.

import { createHash } from 'node:crypto';
import { query } from '../db.js';
import { requireRoles } from '../auth.js';

export const DEFAULT_SLO_SEC = 300;
export const DEFAULT_LOOKBACK_DAYS = 7;

const SEVERITY_ID = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };

const toIso = (v) => {
  if (v == null) return null;
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v.toISOString();
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
};

const toMs = (v) => {
  if (v == null) return null;
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v.getTime();
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.getTime();
};

/** Pure env accessors so unit tests can pass a fake env object. */
export function resolveSloSec(env = process.env) {
  const raw = env.INSTALL_HEALTH_SLO_SEC;
  if (raw == null || raw === '') return DEFAULT_SLO_SEC;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_SLO_SEC;
}

export function resolveLookbackDays(env = process.env) {
  const raw = env.INSTALL_HEALTH_LOOKBACK_DAYS;
  if (raw == null || raw === '') return DEFAULT_LOOKBACK_DAYS;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_LOOKBACK_DAYS;
}

/**
 * Classify one device's enroll → first-evidence posture.
 *
 * Pure: no I/O. `nowMs` injectable for tests.
 *
 * States:
 *   pending   — enrolled, no heartbeat yet, still inside the SLO window
 *   met       — has a heartbeat; latency upper-bound is last_heartbeat − enrolled
 *               (true first-HB ≤ this; for a brand-new device they are equal)
 *   breached  — enrolled past SLO with no heartbeat yet (the pageable case)
 */
export function classifyDevice({ enrolledAt, lastHeartbeatAt, deviceId, hostId, hostname, os, ring }, {
  nowMs = Date.now(),
  sloSec = DEFAULT_SLO_SEC,
} = {}) {
  const enrolledMs = toMs(enrolledAt);
  if (enrolledMs == null) {
    return {
      device_id: deviceId ?? null,
      host_id: hostId ?? null,
      hostname: hostname ?? null,
      os: os ?? null,
      ring: ring ?? null,
      enrolled_at: null,
      first_evidence_at: null,
      evidence_kind: null,
      latency_seconds: null,
      age_seconds: null,
      state: 'pending',
      breach: false,
    };
  }
  const ageSec = Math.max(0, Math.floor((nowMs - enrolledMs) / 1000));
  const hbMs = toMs(lastHeartbeatAt);

  if (hbMs == null) {
    const breached = ageSec >= sloSec;
    return {
      device_id: deviceId ?? null,
      host_id: hostId ?? null,
      hostname: hostname ?? null,
      os: os ?? null,
      ring: ring ?? null,
      enrolled_at: toIso(enrolledAt),
      first_evidence_at: null,
      evidence_kind: null,
      latency_seconds: null,
      age_seconds: ageSec,
      state: breached ? 'breached' : 'pending',
      breach: breached,
    };
  }

  // Upper bound on first-evidence latency. Heartbeat proves evidence existed
  // by last_heartbeat_at; first_heartbeat_at is not stored, so latency is
  // "≤ last_hb − enroll". For devices that enrolled recently this is tight.
  const latencySec = Math.max(0, Math.floor((hbMs - enrolledMs) / 1000));
  return {
    device_id: deviceId ?? null,
    host_id: hostId ?? null,
    hostname: hostname ?? null,
    os: os ?? null,
    ring: ring ?? null,
    enrolled_at: toIso(enrolledAt),
    first_evidence_at: toIso(lastHeartbeatAt),
    evidence_kind: 'heartbeat',
    latency_seconds: latencySec,
    age_seconds: ageSec,
    state: 'met',
    breach: false,
  };
}

/**
 * Fleet-level enroll → first usage event.
 * Returns nulls when either side is missing.
 */
export function fleetFirstEventLatency({ firstEnrolledAt, firstEventAt }) {
  const enrollMs = toMs(firstEnrolledAt);
  const eventMs = toMs(firstEventAt);
  if (enrollMs == null || eventMs == null) {
    return {
      first_enrolled_at: toIso(firstEnrolledAt),
      first_event_at: toIso(firstEventAt),
      latency_seconds: null,
    };
  }
  return {
    first_enrolled_at: toIso(firstEnrolledAt),
    first_event_at: toIso(firstEventAt),
    // Negative is possible when legacy INGEST_TOKENS posted events before
    // any device enrolled — surface the raw gap rather than clamp.
    latency_seconds: Math.floor((eventMs - enrollMs) / 1000),
  };
}

/**
 * Rollup + overall state from classified devices + fleet event latency.
 *
 * overall:
 *   never_configured — zero enrolled devices
 *   broken           — any device breached (no evidence past SLO), or fleet
 *                      has enrollments past SLO with zero usage events ever
 *   degraded         — no device breaches, but p95 heartbeat latency > SLO,
 *                      or fleet first-event latency > SLO
 *   ok               — everyone met / still pending inside window
 */
export function assembleInstallHealth({
  devices = [],
  firstEnrolledAt = null,
  firstEventAt = null,
  nowMs = Date.now(),
  sloSec = DEFAULT_SLO_SEC,
  lookbackDays = DEFAULT_LOOKBACK_DAYS,
} = {}) {
  const classified = devices.map((d) => classifyDevice(d, { nowMs, sloSec }));
  const fleet = fleetFirstEventLatency({ firstEnrolledAt, firstEventAt });

  let pending = 0;
  let met = 0;
  let breached = 0;
  const latencies = [];
  for (const d of classified) {
    if (d.state === 'pending') pending += 1;
    else if (d.state === 'met') {
      met += 1;
      if (d.latency_seconds != null) latencies.push(d.latency_seconds);
    } else if (d.state === 'breached') breached += 1;
  }
  latencies.sort((a, b) => a - b);
  const p50 = percentile(latencies, 0.5);
  const p95 = percentile(latencies, 0.95);

  const lookbackMs = lookbackDays * 86_400_000;
  const recent = classified
    .filter((d) => {
      const ms = toMs(d.enrolled_at);
      return ms != null && (nowMs - ms) <= lookbackMs;
    })
    // Worst first: breached → pending → met, then newest enroll.
    .sort((a, b) => {
      const rank = { breached: 0, pending: 1, met: 2 };
      const ra = rank[a.state] ?? 9;
      const rb = rank[b.state] ?? 9;
      if (ra !== rb) return ra - rb;
      return (toMs(b.enrolled_at) ?? 0) - (toMs(a.enrolled_at) ?? 0);
    });

  const enrolled = classified.length;
  const hasEvents = firstEventAt != null;
  const oldestEnrollAgeSec = firstEnrolledAt != null
    ? Math.max(0, Math.floor((nowMs - toMs(firstEnrolledAt)) / 1000))
    : null;

  let overall = 'ok';
  let overallMessage = '';
  if (enrolled === 0) {
    overall = 'never_configured';
    overallMessage = 'No collectors enrolled — first-evidence SLO is undefined until a device joins.';
  } else if (breached > 0) {
    overall = 'broken';
    overallMessage = `${breached} device(s) past the ${formatDuration(sloSec)} enroll→first-evidence SLO with no heartbeat.`;
  } else if (!hasEvents && oldestEnrollAgeSec != null && oldestEnrollAgeSec >= sloSec) {
    // Devices heartbeating is not enough for the *usage* half of the SLO:
    // if the install has ever enrolled and never produced a usage event past
    // the SLO window, Ops still has a broken pipeline (AIM-215 no-events).
    overall = 'broken';
    overallMessage = `Collectors enrolled but no usage events have ever arrived (fleet past ${formatDuration(sloSec)} SLO).`;
  } else if (
    (p95 != null && p95 > sloSec) ||
    (fleet.latency_seconds != null && fleet.latency_seconds > sloSec)
  ) {
    overall = 'degraded';
    const bits = [];
    if (p95 != null && p95 > sloSec) bits.push(`p95 heartbeat evidence ${formatDuration(p95)}`);
    if (fleet.latency_seconds != null && fleet.latency_seconds > sloSec) {
      bits.push(`fleet first event ${formatDuration(fleet.latency_seconds)}`);
    }
    overallMessage = `${bits.join('; ')} exceeds ${formatDuration(sloSec)} SLO.`;
  } else if (pending > 0) {
    overall = 'ok';
    overallMessage = `${pending} recent enrollment(s) still inside the ${formatDuration(sloSec)} window; ${met} met.`;
  } else {
    overall = 'ok';
    overallMessage = hasEvents
      ? `${met}/${enrolled} devices have first-evidence within the measured window.`
      : `${met}/${enrolled} devices heartbeating; waiting for first usage event.`;
  }

  const slo = {
    text: `enroll → first evidence ≤ ${formatDuration(sloSec)}`,
    targetSeconds: sloSec,
    // heartbeat is the per-device evidence we can measure today; event is fleet-level.
    evidenceKinds: ['heartbeat', 'event'],
  };

  const summary = {
    enrolled,
    pending,
    met,
    breached,
    p50Seconds: p50,
    p95Seconds: p95,
    lookbackDays,
    fleetFirstEvent: fleet,
  };

  const tiles = [
    tileOverall({ overall, overallMessage, slo, summary }),
    tileDeviceEvidence({ overall, slo, summary, breached, pending, met }),
    tileFleetFirstEvent({ slo, fleet, hasEvents, enrolled, oldestEnrollAgeSec }),
  ];

  const alertCandidates = buildAlertCandidates({
    overall,
    summary,
    slo,
    breachedDevices: classified.filter((d) => d.breach),
    nowMs,
  });

  return {
    overall,
    message: overallMessage,
    slo,
    summary,
    tiles,
    devices: recent,
    // Full set available for export consumers; UI uses `devices` (lookback).
    allDevices: classified,
    alertCandidates,
    generatedAt: new Date(nowMs).toISOString(),
    lastVerifiedAt: new Date(nowMs).toISOString(),
  };
}

function tileOverall({ overall, overallMessage, slo, summary }) {
  return {
    id: 'install_health_overall',
    pillar: 'aim',
    title: 'Install health',
    state: overall,
    slo,
    value: {
      enrolled: summary.enrolled,
      breached: summary.breached,
      pending: summary.pending,
      met: summary.met,
      p50Seconds: summary.p50Seconds,
      p95Seconds: summary.p95Seconds,
    },
    message: overallMessage,
    breach: overall !== 'ok' && overall !== 'never_configured',
  };
}

function tileDeviceEvidence({ overall: _overall, slo, summary, breached, pending, met }) {
  let state = 'ok';
  let message = `${met} device(s) with heartbeat evidence; ${pending} pending; ${breached} breached.`;
  if (summary.enrolled === 0) {
    state = 'never_configured';
    message = 'No enrolled devices to measure.';
  } else if (breached > 0) {
    state = 'broken';
    message = `${breached} device(s) enrolled with no heartbeat past the SLO.`;
  } else if (summary.p95Seconds != null && summary.p95Seconds > slo.targetSeconds) {
    state = 'degraded';
    message = `p95 enroll→heartbeat ${formatDuration(summary.p95Seconds)} exceeds ${formatDuration(slo.targetSeconds)}.`;
  }
  return {
    id: 'device_first_evidence',
    pillar: 'aim',
    title: 'Device first evidence',
    state,
    slo: {
      text: `enroll → first heartbeat ≤ ${formatDuration(slo.targetSeconds)}`,
      targetSeconds: slo.targetSeconds,
      evidenceKind: 'heartbeat',
    },
    value: {
      met, pending, breached,
      p50Seconds: summary.p50Seconds,
      p95Seconds: summary.p95Seconds,
    },
    message,
    breach: state !== 'ok' && state !== 'never_configured',
  };
}

function tileFleetFirstEvent({ slo, fleet, hasEvents, enrolled, oldestEnrollAgeSec }) {
  const target = slo.targetSeconds;
  let state = 'ok';
  let message = 'Fleet first usage event within SLO of first enroll.';
  if (enrolled === 0) {
    state = 'never_configured';
    message = 'No enrollments — fleet first-event latency is undefined.';
  } else if (!hasEvents) {
    if (oldestEnrollAgeSec != null && oldestEnrollAgeSec >= target) {
      state = 'broken';
      message = `No usage events have arrived since first enroll (${formatDuration(oldestEnrollAgeSec)} ago).`;
    } else {
      // Still inside the SLO window — not green-by-default silence: message
      // says waiting; breach stays false so we do not page mid-window.
      state = 'ok';
      message = 'Waiting for the first usage event on this install (still inside SLO window).';
    }
  } else if (fleet.latency_seconds != null && fleet.latency_seconds > target) {
    state = 'degraded';
    message = `First usage event arrived ${formatDuration(fleet.latency_seconds)} after first enroll (SLO ${formatDuration(target)}).`;
  } else if (fleet.latency_seconds != null && fleet.latency_seconds < 0) {
    state = 'ok';
    message = 'Usage events existed before the first device enrollment (legacy ingest tokens).';
  } else if (fleet.latency_seconds != null) {
    message = `First usage event ${formatDuration(fleet.latency_seconds)} after first enroll.`;
  }
  return {
    id: 'fleet_first_event',
    pillar: 'aim',
    title: 'Fleet first usage event',
    state,
    slo: {
      text: `first enroll → first usage event ≤ ${formatDuration(target)}`,
      targetSeconds: target,
      evidenceKind: 'event',
    },
    value: {
      firstEnrolledAt: fleet.first_enrolled_at,
      firstEventAt: fleet.first_event_at,
      latencySeconds: fleet.latency_seconds,
    },
    message,
    breach: state !== 'ok' && state !== 'never_configured',
  };
}

function buildAlertCandidates({ overall, summary, slo, breachedDevices, nowMs }) {
  if (overall === 'ok' || overall === 'never_configured') return [];
  const stamp = new Date(nowMs).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const out = [];

  if (summary.breached > 0) {
    const dedupe = dedupeHex(['install-health', 'device-breach', String(slo.targetSeconds)]);
    const sample = breachedDevices.slice(0, 5).map((d) => d.hostname || d.device_id).filter(Boolean);
    out.push({
      schema_version: '1.1',
      alert_id: stableAlertId(dedupe),
      dedupe_key: dedupe,
      pillar: 'ai_usage',
      producer: { name: 'aim-install-health', version: '1.0.0' },
      finding_type: 'ai_usage.install_first_evidence_breach',
      title: `${summary.breached} device(s) past enroll→first-evidence SLO (${formatDuration(slo.targetSeconds)})`.slice(0, 200),
      severity: 'high',
      severity_id: SEVERITY_ID.high,
      status: 'new',
      observed_at: stamp,
      first_seen_at: stamp,
      last_seen_at: stamp,
      resource: {
        kind: 'host',
        ref: 'aim:install-health/device_first_evidence',
        display: 'Device first evidence',
        provider: null,
        account_ref: null,
        region: null,
      },
      subject_ref: null,
      evidence: {
        source_uri: 'aim:/install-health',
        detail_count: summary.breached,
        summary: sample.length
          ? `Breached hosts (sample): ${sample.join(', ')}`.slice(0, 240)
          : `${summary.breached} enrolled device(s) with no heartbeat past SLO.`.slice(0, 240),
      },
      labels: {
        tile: 'device_first_evidence',
        state: 'broken',
        breached: String(summary.breached).slice(0, 128),
        slo_seconds: String(slo.targetSeconds).slice(0, 128),
      },
      remediation_hint: 'Open #/install-health. On each breached host run `aim doctor` and confirm the device can reach the ingest URL. Re-run `aim join` if enrollment never completed.'.slice(0, 500),
      // UI helpers (same shape as system-status candidates after projection).
      tileId: 'device_first_evidence',
      findingType: 'ai_usage.install_first_evidence_breach',
    });
  }

  const fleetLat = summary.fleetFirstEvent?.latency_seconds;
  if (
    summary.breached === 0 &&
    (
      (fleetLat != null && fleetLat > slo.targetSeconds) ||
      (summary.fleetFirstEvent?.first_event_at == null && summary.enrolled > 0 && overall === 'broken')
    )
  ) {
    const dedupe = dedupeHex(['install-health', 'fleet-first-event', String(slo.targetSeconds)]);
    const title = summary.fleetFirstEvent?.first_event_at == null
      ? 'No usage events after enroll — fleet first-evidence SLO breached'
      : `Fleet first usage event ${formatDuration(fleetLat)} after first enroll`;
    out.push({
      schema_version: '1.1',
      alert_id: stableAlertId(dedupe),
      dedupe_key: dedupe,
      pillar: 'ai_usage',
      producer: { name: 'aim-install-health', version: '1.0.0' },
      finding_type: 'ai_usage.install_fleet_first_event_breach',
      title: title.slice(0, 200),
      severity: overall === 'broken' ? 'high' : 'medium',
      severity_id: overall === 'broken' ? SEVERITY_ID.high : SEVERITY_ID.medium,
      status: 'new',
      observed_at: stamp,
      first_seen_at: stamp,
      last_seen_at: stamp,
      resource: {
        kind: 'host',
        ref: 'aim:install-health/fleet_first_event',
        display: 'Fleet first usage event',
        provider: null,
        account_ref: null,
        region: null,
      },
      subject_ref: null,
      evidence: {
        source_uri: 'aim:/install-health',
        detail_count: 1,
        summary: title.slice(0, 240),
      },
      labels: {
        tile: 'fleet_first_event',
        state: overall === 'broken' ? 'broken' : 'degraded',
        slo_seconds: String(slo.targetSeconds).slice(0, 128),
      },
      remediation_hint: 'Open #/install-health and #/status. Confirm collectors emit events (not only heartbeats) and that ingest is accepting batches.'.slice(0, 500),
      tileId: 'fleet_first_event',
      findingType: 'ai_usage.install_fleet_first_event_breach',
    });
  }

  if (
    summary.breached === 0 &&
    summary.p95Seconds != null &&
    summary.p95Seconds > slo.targetSeconds &&
    out.length === 0
  ) {
    const dedupe = dedupeHex(['install-health', 'p95-degraded', String(slo.targetSeconds)]);
    out.push({
      schema_version: '1.1',
      alert_id: stableAlertId(dedupe),
      dedupe_key: dedupe,
      pillar: 'ai_usage',
      producer: { name: 'aim-install-health', version: '1.0.0' },
      finding_type: 'ai_usage.install_first_evidence_degraded',
      title: `p95 enroll→first-evidence ${formatDuration(summary.p95Seconds)} exceeds ${formatDuration(slo.targetSeconds)} SLO`.slice(0, 200),
      severity: 'medium',
      severity_id: SEVERITY_ID.medium,
      status: 'new',
      observed_at: stamp,
      first_seen_at: stamp,
      last_seen_at: stamp,
      resource: {
        kind: 'host',
        ref: 'aim:install-health/device_first_evidence',
        display: 'Device first evidence',
        provider: null,
        account_ref: null,
        region: null,
      },
      subject_ref: null,
      evidence: {
        source_uri: 'aim:/install-health',
        detail_count: 1,
        summary: `p95=${summary.p95Seconds}s p50=${summary.p50Seconds ?? '—'}s slo=${slo.targetSeconds}s`.slice(0, 240),
      },
      labels: {
        tile: 'device_first_evidence',
        state: 'degraded',
        p95_seconds: String(summary.p95Seconds).slice(0, 128),
        slo_seconds: String(slo.targetSeconds).slice(0, 128),
      },
      remediation_hint: 'Open #/install-health. Investigate slow-to-evidence hosts — spool backlog, offline laptops, or blocked egress.'.slice(0, 500),
      tileId: 'device_first_evidence',
      findingType: 'ai_usage.install_first_evidence_degraded',
    });
  }

  return out;
}

function percentile(sorted, p) {
  if (!sorted.length) return null;
  if (sorted.length === 1) return sorted[0];
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil(p * sorted.length) - 1));
  return sorted[idx];
}

export function formatDuration(sec) {
  const n = Math.max(0, Math.floor(Number(sec) || 0));
  if (n < 60) return `${n}s`;
  if (n < 3600) {
    const m = Math.floor(n / 60);
    const s = n % 60;
    return s ? `${m}m ${s}s` : `${m}m`;
  }
  const h = Math.floor(n / 3600);
  const m = Math.floor((n % 3600) / 60);
  return m ? `${h}h ${m}m` : `${h}h`;
}

function stableAlertId(dedupeHexVal) {
  const hexed = dedupeHexVal.slice(0, 32).padEnd(32, '0');
  const variant = '89ab'[parseInt(hexed[16], 16) % 4];
  return `${hexed.slice(0, 8)}-${hexed.slice(8, 12)}-4${hexed.slice(13, 16)}-${variant}${hexed.slice(17, 20)}-${hexed.slice(20, 32)}`;
}

function dedupeHex(parts) {
  return createHash('sha256').update(parts.join('|')).digest('hex');
}

// opts.db injectable for tests.
export async function installHealthRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const userLevel = requireRoles('analyst', 'admin');

  fastify.get('/api/install-health', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;

    const sloSec = resolveSloSec();
    const lookbackDays = resolveLookbackDays();
    const nowMs = Date.now();

    let deviceRows = [];
    try {
      const { rows } = await db.query(
        `SELECT device_id, host_id, hostname, os, ring,
                enrolled_at, last_heartbeat_at
           FROM devices
          WHERE revoked_at IS NULL
          ORDER BY enrolled_at DESC`,
      );
      deviceRows = rows;
    } catch {
      // Ingest tables not migrated yet — treat as empty fleet.
      deviceRows = [];
    }

    let firstEventAt = null;
    try {
      const ev = await db.query('SELECT MIN(received_at) AS first_event_at FROM events');
      firstEventAt = ev.rows[0]?.first_event_at ?? null;
    } catch {
      firstEventAt = null;
    }

    let firstEnrolledAt = null;
    if (deviceRows.length) {
      // rows ordered DESC; find min in JS so we don't need a second query.
      let minMs = Infinity;
      let minVal = null;
      for (const r of deviceRows) {
        const ms = toMs(r.enrolled_at);
        if (ms != null && ms < minMs) {
          minMs = ms;
          minVal = r.enrolled_at;
        }
      }
      firstEnrolledAt = minVal;
    }

    const devices = deviceRows.map((r) => ({
      deviceId: String(r.device_id),
      hostId: r.host_id != null ? String(r.host_id) : null,
      hostname: r.hostname ?? null,
      os: r.os ?? null,
      ring: r.ring ?? null,
      enrolledAt: r.enrolled_at,
      lastHeartbeatAt: r.last_heartbeat_at,
    }));

    const body = assembleInstallHealth({
      devices,
      firstEnrolledAt,
      firstEventAt,
      nowMs,
      sloSec,
      lookbackDays,
    });
    // Drop allDevices from the wire payload — lookback table is enough for the UI
    // and keeps response size bounded on large fleets.
    const { allDevices: _all, ...wire } = body;
    return wire;
  });
}

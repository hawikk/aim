// Pipeline liveness + attribution health + coverage gaps.
//
// A monitoring product that silently stops monitoring is a governance failure:
// if collectors are enrolled but ingest has accepted no events for a while,
// someone must SEE that without shelling into Postgres. Same argument applies
// to attribution — a pipeline that accepts events it can attribute to nobody
// answers "what happened" but not "who did it", which is the whole pitch. Both
// signals are aggregate operational metadata and both live behind this route.
//
// Idle alert condition (documented, env-tunable):
//   ingest has accepted no event for > PIPELINE_IDLE_THRESHOLD_SECONDS
//   (default 7200 = 2h) AND at least one non-revoked device has EVER
//   heartbeated.
// The "ever heartbeated" gate is. It used to be mere enrollment, which
// let a device that never once reported in hold the guard open — an enrollment
// row created by an e2e run is not evidence that telemetry is expected. A
// device that heartbeated once and then died still counts (that IS evidence),
// so a dead collector keeps alerting. A brand-new stack with zero collectors
// reports `no_collectors`; enrolled-but-never-seen reports
// `pending_collectors`; both are informational, never `idle`.
//
// Idle is measured on events.received_at (server-side accept time), NOT the
// client ts: it answers "is the PIPELINE accepting data", independent of any
// backdated or clock-skewed event timestamp.
//
// Attribution: share of events in a trailing window stored
// with user_pseudonym NULL. docs/identity-mapping-design.md §3 sets the target
// at <5% unresolved; anything above that is directory/mapping coverage debt
// and must be visible rather than silent (unresolved events are stored, not
// dropped, precisely so they can be counted). makes the rate a
// first-class, alertable metric: Overview trend + by-tool/by-host splits,
// last-verified stamp, and an alert-bus candidate when the threshold is
// breached (status "degraded" alone is not enough).
//
// Device-silent coverage gap (AC4 /): an enrolled device that
// has heartbeated at least once and then goes quiet for longer than its own
// `heartbeat_interval_sec` is a first-class gap. Aggregate pipeline "ok" can
// hide a single laptop that stopped reporting — silence looks exactly like
// compliance. See evaluateDeviceSilence().
//
// All figures are counts and timestamps — no user-level rows, no plaintext
// identity — so this is open to every dashboard role, the same gate as
// /api/overview.
import { query } from '../db.js';
import { requireRoles } from '../auth.js';

const DEFAULT_IDLE_THRESHOLD_SECONDS = 2 * 60 * 60; // 2h

// Heartbeat freshness used only for the informational healthy_devices count;
// it does NOT gate the idle alert (event flow is the signal that matters, and
// gating on *fresh* heartbeats would silence the alert exactly when every
// collector dies at once).
const HEALTHY_HEARTBEAT_SECONDS = 15 * 60;

// Grace period before an enrolled device that has never heartbeated is called
// stale. Enrollment → first heartbeat is seconds in practice; a day is a
// generous allowance for a laptop enrolled just before a weekend. Past it the
// enrollment never completed and is a reaping candidate (see the ADR).
const STALE_ENROLLMENT_SECONDS = 24 * 60 * 60; // 24h

// Trailing window for the attribution rate, and the coverage target it is
// judged against (docs/identity-mapping-design.md §3: <5% unresolved).
const DEFAULT_ATTRIBUTION_WINDOW_SECONDS = 24 * 60 * 60; // 24h
/** Default unattributed-rate target (docs/identity-mapping-design.md §3). */
export const ATTRIBUTION_TARGET_PCT = 5;

// Cap silent devices / breakdown rows returned in one response.
const MAX_SILENT_DEVICES = 50;
const MAX_BREAKDOWN_ROWS = 25;
const DEFAULT_TREND_DAYS = 14;

export function idleThresholdSeconds(env = process.env) {
  const raw = Number(env.PIPELINE_IDLE_THRESHOLD_SECONDS);
  return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : DEFAULT_IDLE_THRESHOLD_SECONDS;
}

export function attributionWindowSeconds(env = process.env) {
  const raw = Number(env.PIPELINE_ATTRIBUTION_WINDOW_SECONDS);
  return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : DEFAULT_ATTRIBUTION_WINDOW_SECONDS;
}

export function attributionTargetPct(env = process.env) {
  const raw = Number(env.PIPELINE_ATTRIBUTION_TARGET_PCT);
  return Number.isFinite(raw) && raw >= 0 && raw <= 100 ? raw : ATTRIBUTION_TARGET_PCT;
}

const num = (v) => (v == null ? 0 : Number(v));

// Human duration in the largest sensible unit (used only in the message text).
function humanizeSeconds(s) {
  const n = Math.max(0, Math.floor(s));
  if (n < 90) return `${n} sec`;
  if (n < 5400) return `${Math.round(n / 60)} min`;
  return `${(n / 3600).toFixed(1)} h`;
}

/** ISO stamp for "last verified end-to-end" claims (AC3). */
export function nowVerifiedAt(now = new Date()) {
  return now instanceof Date ? now.toISOString() : new Date(now).toISOString();
}

// Pure decision so it is unit-testable without a DB. Inputs are already-parsed
// numbers/ISO strings from the aggregate queries.
export function evaluateLiveness({
  lastReceivedAt, idleSeconds, enrolled, healthy, everSeen, stale, thresholdSeconds,
}) {
  const enrolledN = num(enrolled);
  const everSeenN = num(everSeen);
  const base = {
    lastEventAt: lastReceivedAt ?? null,
    idleSeconds: idleSeconds == null ? null : Math.max(0, Math.floor(idleSeconds)),
    thresholdSeconds,
    enrolledDevices: enrolledN,
    healthyDevices: num(healthy),
    // Non-revoked devices that have heartbeated at least once — the population
    // whose silence actually means something.
    reportingDevices: everSeenN,
    // Enrolled, never heartbeated, past the grace period.
    staleDevices: num(stale),
  };
  if (enrolledN === 0) {
    return {
      ...base,
      status: 'no_collectors',
      idle: false,
      message: 'No collectors enrolled — no telemetry is expected. Enroll a device with `aim join`.',
    };
  }
  // Recent events settle it: the pipeline is demonstrably accepting data,
  // whatever the device bookkeeping says.
  const overThreshold = base.idleSeconds == null || base.idleSeconds > thresholdSeconds;
  if (!overThreshold) {
    return {
      ...base,
      status: 'ok',
      idle: false,
      message: `Ingest healthy: last event ${humanizeSeconds(base.idleSeconds)} ago, ` +
        `${everSeenN} of ${enrolledN} enrolled collector(s) have reported in.`,
    };
  }
  // Quiet, and no device has ever reported in: nothing was ever collecting, so
  // "the pipeline stalled" is the wrong diagnosis. Say what is actually true.
  if (everSeenN === 0) {
    const staleNote = base.staleDevices > 0
      ? ` ${base.staleDevices} are past the ${humanizeSeconds(STALE_ENROLLMENT_SECONDS)} grace period and should be reaped.`
      : '';
    return {
      ...base,
      status: 'pending_collectors',
      idle: false,
      message: `${enrolledN} enrolled device(s) have never heartbeated — enrollment ` +
        `never completed, so idle alerting is suppressed until one reports in.${staleNote} ` +
        'Check the collector with `aim doctor`.',
    };
  }
  const since = base.idleSeconds == null
    ? 'no events have ever been accepted'
    : `no events accepted for ${humanizeSeconds(base.idleSeconds)}`;
  return {
    ...base,
    status: 'idle',
    idle: true,
    message: `Ingest idle: ${since} while ${everSeenN} collector(s) have reported in ` +
      `(threshold ${humanizeSeconds(thresholdSeconds)}). Check collector health with \`aim doctor\`.`,
  };
}

// Pure decision for the attribution rate. `total`/`attributed` are counts over
// the trailing window; unattributedPct is null when the window is empty (no
// data is neither 0% nor 100% — claiming either would be a lie).
//
// `service` is the machine-principal share of `attributed`: declared
// agent hosts and CI runners. It is real attribution — we know exactly what
// produced those events — but it is NOT per-engineer coverage, and folding the
// two together would let a single enrolled agent host read as a fully
// attributed fleet while the directory still holds no engineers. Counted and
// reported separately for that reason.
export function evaluateAttribution({ total, attributed, service, windowSeconds, targetPct }) {
  const totalN = num(total);
  const attributedN = Math.min(num(attributed), totalN);
  const serviceN = Math.min(num(service), attributedN);
  const unattributed = totalN - attributedN;
  const target = targetPct == null ? ATTRIBUTION_TARGET_PCT : Number(targetPct);
  const base = {
    windowSeconds,
    events: totalN,
    attributedEvents: attributedN,
    serviceAttributedEvents: serviceN,
    humanAttributedEvents: attributedN - serviceN,
    unattributedEvents: unattributed,
    targetPct: target,
  };
  // Machine share of ALL events in the window — the qualifier on every
  // "attributed" figure below.
  const machineNote = serviceN > 0 && totalN > 0
    ? ` ${Math.max(Math.round((serviceN / totalN) * 1000) / 10, 0.1)}% is machine activity ` +
      '(declared agent/CI hosts), not per-engineer coverage.'
    : '';
  if (totalN === 0) {
    return {
      ...base,
      unattributedPct: null,
      status: 'no_events',
      message: `No events in the last ${humanizeSeconds(windowSeconds)} — attribution rate is undefined.`,
    };
  }
  // One decimal, with a floor: a security metric must not let the last
  // unattributed event disappear into a rounding rule (1 in 10k rounds to
  // 0.0%, which reads as "fully attributed"). Invariant the callers rely on:
  // unattributedPct === 0 if and only if unattributedEvents === 0. The floor
  // overstates a sub-0.1% residue, which is the safe direction to err.
  const exact = Math.round((unattributed / totalN) * 1000) / 10;
  const pct = unattributed > 0 ? Math.max(exact, 0.1) : 0;
  const window = humanizeSeconds(windowSeconds);
  if (unattributed === totalN) {
    return {
      ...base,
      unattributedPct: pct,
      status: 'none_attributed',
      message: `No usage is attributable: all ${totalN} events in the last ${window} have no ` +
        'identity. Ingest sees activity but cannot say whose — check identity-sync directory ' +
        'coverage and device_mappings.',
    };
  }
  if (pct > target) {
    return {
      ...base,
      unattributedPct: pct,
      status: 'degraded',
      message: `${pct}% of events in the last ${window} are unattributed (${unattributed} of ` +
        `${totalN}), above the ${target}% target. Identity coverage gap, not an ingest fault.` +
        machineNote,
    };
  }
  return {
    ...base,
    unattributedPct: pct,
    status: 'ok',
    message: `${pct}% of events in the last ${window} are unattributed ` +
      `(target ≤${target}%).` + machineNote,
  };
}

/**
 * Unattributed-rate alert candidate (AC2).
 *
 * Status "degraded" on a dashboard tile is not enough for a monitoring
 * product — blindness must page someone. This pure helper builds the same
 * security.alert/v1-shaped fields the system-status alerter publishes when
 * the rate exceeds the target. Callers publish; this only decides.
 *
 * Returns null when the rate is ok / undefined (no_events).
 */
export function unattributedRateAlertCandidate(attribution, { now = new Date() } = {}) {
  if (!attribution) return null;
  if (attribution.status !== 'degraded' && attribution.status !== 'none_attributed') {
    return null;
  }
  const stamp = now instanceof Date
    ? now.toISOString().replace(/\.\d{3}Z$/, 'Z')
    : String(now).replace(/\.\d{3}Z$/, 'Z');
  const pct = attribution.unattributedPct;
  const severity = attribution.status === 'none_attributed' ? 'high' : 'medium';
  const severityId = severity === 'high' ? 4 : 3;
  const title = attribution.status === 'none_attributed'
    ? `Unattributed usage: 100% of ${attribution.events} events have no identity`
    : `Unattributed usage: ${pct}% exceeds ${attribution.targetPct}% target`;
  return {
    fires: true,
    findingType: 'ai_usage.unattributed_rate',
    severity,
    severityId,
    title: title.slice(0, 200),
    message: String(attribution.message || title).slice(0, 500),
    observedAt: stamp,
    // Labels for bus publishers / UI — not full contract payload (that is
    // assembled by system-status alertCandidatesFromTiles).
    labels: {
      tile: 'attribution_coverage',
      status: attribution.status,
      unattributed_pct: pct == null ? '' : String(pct),
      target_pct: String(attribution.targetPct ?? ATTRIBUTION_TARGET_PCT),
    },
  };
}

/**
 * Device-silent coverage gap (AC4).
 *
 * Inputs are already-fetched device rows (non-revoked, ever-heartbeated). A
 * device is silent when age(last_heartbeat_at) > its own heartbeat_interval_sec
 * — silence longer than the interval the device itself promised. Never-seen
 * enrollments are excluded: they have a different diagnosis
 * (pending_collectors / reaping), not "stopped reporting".
 *
 * Pure so it is unit-testable without a DB. `nowMs` is injectable for tests.
 */
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
  // Loudest first so the operator sees the longest-dark device at the top.
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
  const worst = listed[0];
  return {
    alert: true,
    silentDevices: n,
    devices: listed,
    message: `${n} enrolled device(s) stopped reporting for longer than their expected ` +
      `interval (worst: ${humanizeSeconds(worst.silent_for_seconds)} silent, expected ` +
      `${humanizeSeconds(worst.expected_interval_sec)}). Silence looks like compliance — ` +
      'check the endpoint with `aim doctor`.',
  };
}

/**
 * Pure rate helper used by Overview / breakdowns.
 * Same floor rule as evaluateAttribution: nonzero unattributed never rounds
 * to 0%. Returns null unattributedPct when total is 0.
 */
export function attributionRate(total, attributed) {
  const totalN = num(total);
  const attributedN = Math.min(num(attributed), totalN);
  const unattributed = totalN - attributedN;
  if (totalN === 0) {
    return {
      events: 0,
      attributedEvents: 0,
      unattributedEvents: 0,
      unattributedPct: null,
      attributedPct: null,
    };
  }
  const exact = Math.round((unattributed / totalN) * 1000) / 10;
  const unattributedPct = unattributed > 0 ? Math.max(exact, 0.1) : 0;
  // Mirror the floor on the complement so attributed + unattributed never
  // round past 100 when a residue exists.
  const attributedPct = unattributed === 0
    ? 100
    : Math.min(Math.round((attributedN / totalN) * 1000) / 10, 99.9);
  return {
    events: totalN,
    attributedEvents: attributedN,
    unattributedEvents: unattributed,
    unattributedPct,
    attributedPct,
  };
}

/** Pure: map a group-by row into a breakdown entry with unattributed %. */
export function attributionBreakdownRow({ key, total, attributed }) {
  const rate = attributionRate(total, attributed);
  return {
    key: key == null || key === '' ? '(unknown)' : String(key),
    ...rate,
  };
}

/** Pure: daily trend points from SQL rows. */
export function attributionTrendPoints(rows) {
  return (rows ?? []).map((r) => {
    const day = r.day instanceof Date
      ? r.day.toISOString().slice(0, 10)
      : String(r.day).slice(0, 10);
    return {
      day,
      ...attributionRate(r.total, r.attributed),
    };
  });
}

// ---------------------------------------------------------------------------
// — live attribution health (Epic A gate shape)
//
// Gate SQL (docs + re-measure) uses event `ts` and treats
// an event as OK when:
//   user_pseudonym IS NOT NULL OR principal_kind = 'service'
// That is deliberately broader than the unattributed-rate tile (which is
// per-engineer coverage): service principals count as attributed for the
// vertical gate. Multi-window 1h / 24h / 7d so washout vs live regressions
// are visible without shelling into Postgres.
// ---------------------------------------------------------------------------

/** Epic A trailing-7d gate: ≥95% of events carry identity or service principal. */
export const EPIC_A_GATE_PCT = 95;

/** Warn when no OK-attributed event has landed for this many seconds. */
export const ATTRIBUTED_STALE_SECONDS = 15 * 60;

/** Fixed windows surfaced on the Attribution health panel (label → seconds). */
export const ATTRIBUTION_HEALTH_WINDOWS = Object.freeze({
  '1h': 60 * 60,
  '24h': 24 * 60 * 60,
  '7d': 7 * 24 * 60 * 60,
});

/**
 * Pure: pct_ok for one window from raw counts.
 * Two-decimal rounding matches re-measure tables (`round(..., 2)`).
 * Empty window → pctOk null (not 0 — silence is not failure).
 */
export function pctOkFromCounts({ n, ok, service } = {}) {
  const total = num(n);
  const okN = Math.min(num(ok), total);
  const serviceN = Math.min(num(service), okN);
  if (total === 0) {
    return {
      n: 0,
      ok: 0,
      unbound: 0,
      service: 0,
      human: 0,
      pctOk: null,
    };
  }
  const unbound = total - okN;
  // Two decimals, no floor — gate re-measure tables use plain round(..., 2).
  const pctOk = Math.round((okN / total) * 10000) / 100;
  return {
    n: total,
    ok: okN,
    unbound,
    service: serviceN,
    human: Math.max(0, okN - serviceN),
    pctOk,
  };
}

/**
 * Pure: assemble the multi-window health payload operators see on Overview/Fleet.
 *
 * @param {object} input
 * @param {Record<string,{n:number,ok:number,service?:number}>} input.windowCounts
 * @param {string|Date|null} [input.lastAttributedAt]
 * @param {number|null} [input.lastAttributedAgeSeconds]
 * @param {{unbound?:number,serviceOnly?:number,distinct?:number}} [input.hosts]
 * @param {Array<{hour?:string|Date,bucket?:string|Date,n:number,ok:number}>} [input.trendRows]
 * @param {number} [input.gateThresholdPct]
 * @param {number} [input.staleThresholdSeconds]
 * @param {Date|string} [input.now]
 */
export function evaluateAttributionHealth({
  windowCounts = {},
  lastAttributedAt = null,
  lastAttributedAgeSeconds = null,
  hosts = {},
  trendRows = [],
  gateThresholdPct = EPIC_A_GATE_PCT,
  staleThresholdSeconds = ATTRIBUTED_STALE_SECONDS,
  now = new Date(),
} = {}) {
  const windows = {};
  for (const key of Object.keys(ATTRIBUTION_HEALTH_WINDOWS)) {
    const raw = windowCounts[key] || {};
    const w = pctOkFromCounts(raw);
    windows[key] = {
      ...w,
      windowSeconds: ATTRIBUTION_HEALTH_WINDOWS[key],
      // Gate threshold applies to every window for RAG; only 7d is the AC.
      gateThresholdPct,
      met: w.pctOk != null && w.pctOk >= gateThresholdPct,
    };
  }
  const gate = windows['7d'];
  const lastIso = lastAttributedAt instanceof Date
    ? lastAttributedAt.toISOString()
    : (lastAttributedAt ? String(lastAttributedAt) : null);
  let age = lastAttributedAgeSeconds == null
    ? null
    : Math.max(0, Math.floor(Number(lastAttributedAgeSeconds)));
  if (age == null && lastIso) {
    const t = new Date(lastIso).getTime();
    if (Number.isFinite(t)) {
      const nowMs = now instanceof Date ? now.getTime() : new Date(now).getTime();
      age = Math.max(0, Math.floor((nowMs - t) / 1000));
    }
  }
  const stale = age != null && age > staleThresholdSeconds;
  const trend = (trendRows ?? []).map((r) => {
    const bucket = r.hour ?? r.bucket ?? r.day;
    const label = bucket instanceof Date
      ? bucket.toISOString()
      : (bucket == null ? null : String(bucket));
    const point = pctOkFromCounts({ n: r.n ?? r.total, ok: r.ok ?? r.attributed, service: r.service });
    return { hour: label, ...point };
  });
  return {
    lastVerifiedAt: nowVerifiedAt(now instanceof Date ? now : new Date(now)),
    gate: {
      window: '7d',
      thresholdPct: gateThresholdPct,
      pctOk: gate?.pctOk ?? null,
      n: gate?.n ?? 0,
      met: Boolean(gate?.met),
      // Status for the overall tile: no_events / met / breached.
      status: gate?.pctOk == null ? 'no_events' : (gate.met ? 'met' : 'breached'),
    },
    windows,
    lastAttributedAt: lastIso,
    lastAttributedAgeSeconds: age,
    stale,
    staleThresholdSeconds,
    hosts: {
      unbound: num(hosts.unbound),
      serviceOnly: num(hosts.serviceOnly),
      distinct: num(hosts.distinct),
      // Deep-link target for the device/host list ranked by unbound share.
      unboundHref: '#/overview',
    },
    trend24h: trend,
  };
}

// opts.db is injectable for tests; defaults to the real pg pool.
export async function pipelineRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const anyRole = requireRoles('admin', 'analyst', 'auditor', 'viewer');

  fastify.get('/api/pipeline/liveness', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const thresholdSeconds = idleThresholdSeconds();
    const windowSeconds = attributionWindowSeconds();
    const targetPct = attributionTargetPct();
    const verifiedAt = nowVerifiedAt();

    const [ingest, devices, attribution, silentRows] = await Promise.all([
      // received_at drives idleness; server-side clock via now() avoids skew.
      db.query(
        `SELECT max(received_at) AS last_received,
                EXTRACT(EPOCH FROM (now() - max(received_at))) AS idle_seconds
           FROM events`
      ),
      db.query(
        `SELECT count(*) FILTER (WHERE revoked_at IS NULL) AS enrolled,
                count(*) FILTER (WHERE revoked_at IS NULL
                                 AND last_heartbeat_at >= now() - ($1 || ' seconds')::interval) AS healthy,
                count(*) FILTER (WHERE revoked_at IS NULL
                                 AND last_heartbeat_at IS NOT NULL) AS ever_seen,
                count(*) FILTER (WHERE revoked_at IS NULL
                                 AND last_heartbeat_at IS NULL
                                 AND enrolled_at < now() - ($2 || ' seconds')::interval) AS stale
           FROM devices`,
        [HEALTHY_HEARTBEAT_SECONDS, STALE_ENROLLMENT_SECONDS]
      ),
      // count(user_pseudonym) counts non-NULLs — the attributed share.
      db.query(
        `SELECT count(*) AS total,
                count(user_pseudonym) AS attributed,
                count(*) FILTER (WHERE user_pseudonym IS NOT NULL
                                 AND principal_kind = 'service') AS service_attributed
           FROM events
          WHERE received_at >= now() - ($1 || ' seconds')::interval`,
        [windowSeconds]
      ),
      // Per-device silence: ever-heartbeated, non-revoked devices.
      db.query(
        `SELECT device_id, host_id, hostname, last_heartbeat_at, heartbeat_interval_sec
           FROM devices
          WHERE revoked_at IS NULL
            AND last_heartbeat_at IS NOT NULL
          ORDER BY last_heartbeat_at ASC`
      ),
    ]);

    const ing = ingest.rows[0] ?? {};
    const dev = devices.rows[0] ?? {};
    const att = attribution.rows[0] ?? {};
    const lastReceived = ing.last_received;
    const attributionEval = evaluateAttribution({
      total: att.total,
      attributed: att.attributed,
      service: att.service_attributed,
      windowSeconds,
      targetPct,
    });
    const deviceSilence = evaluateDeviceSilence({ devices: silentRows.rows ?? [] });
    return {
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
        ...attributionEval,
        lastVerifiedAt: verifiedAt,
      },
      deviceSilence,
      lastVerifiedAt: verifiedAt,
      alertCandidate: unattributedRateAlertCandidate(attributionEval),
    };
  });

  /**
   * first-class attribution metric for Overview.
   * Current rate + daily trend + by-tool / by-host splits + last-verified
   * stamp + alert candidate when the unattributed rate exceeds the target.
   */
  fastify.get('/api/pipeline/attribution', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const windowSeconds = attributionWindowSeconds();
    const targetPct = attributionTargetPct();
    const verifiedAt = nowVerifiedAt();
    const daysRaw = Number(req.query?.days);
    const days = Number.isFinite(daysRaw) && daysRaw > 0 && daysRaw <= 90
      ? Math.floor(daysRaw)
      : DEFAULT_TREND_DAYS;

    const [current, trend, byTool, byHost] = await Promise.all([
      db.query(
        `SELECT count(*) AS total,
                count(user_pseudonym) AS attributed,
                count(*) FILTER (WHERE user_pseudonym IS NOT NULL
                                 AND principal_kind = 'service') AS service_attributed
           FROM events
          WHERE received_at >= now() - ($1 || ' seconds')::interval`,
        [windowSeconds]
      ),
      db.query(
        `SELECT date_trunc('day', received_at)::date AS day,
                count(*) AS total,
                count(user_pseudonym) AS attributed
           FROM events
          WHERE received_at >= (current_date - ($1::int - 1))
          GROUP BY 1
          ORDER BY 1 ASC`,
        [days]
      ),
      db.query(
        `SELECT tool AS key,
                count(*) AS total,
                count(user_pseudonym) AS attributed
           FROM events
          WHERE received_at >= now() - ($1 || ' seconds')::interval
          GROUP BY tool
          ORDER BY count(*) FILTER (WHERE user_pseudonym IS NULL) DESC, count(*) DESC
          LIMIT $2`,
        [windowSeconds, MAX_BREAKDOWN_ROWS]
      ),
      // host_ref is a salted HMAC pseudonym — never a hostname or IP.
      db.query(
        `SELECT host_ref AS key,
                count(*) AS total,
                count(user_pseudonym) AS attributed
           FROM events
          WHERE received_at >= now() - ($1 || ' seconds')::interval
          GROUP BY host_ref
          ORDER BY count(*) FILTER (WHERE user_pseudonym IS NULL) DESC, count(*) DESC
          LIMIT $2`,
        [windowSeconds, MAX_BREAKDOWN_ROWS]
      ),
    ]);

    const cur = current.rows[0] ?? {};
    const currentEval = evaluateAttribution({
      total: cur.total,
      attributed: cur.attributed,
      service: cur.service_attributed,
      windowSeconds,
      targetPct,
    });
    return {
      lastVerifiedAt: verifiedAt,
      windowSeconds,
      targetPct,
      current: currentEval,
      trend: attributionTrendPoints(trend.rows),
      byTool: (byTool.rows ?? []).map((r) => attributionBreakdownRow(r)),
      byHost: (byHost.rows ?? []).map((r) => attributionBreakdownRow(r)),
      alertCandidate: unattributedRateAlertCandidate(currentEval),
    };
  });

  /**
   * multi-window Epic A attribution health for Overview / Fleet.
   *
   * Matches the re-measure queries on:
   *   pct_ok = share of events where
   *     user_pseudonym IS NOT NULL OR principal_kind = 'service'
   * over trailing 1h / 24h / 7d on event `ts` (not received_at).
   * Plus last-attributed age, unbound / service-only host counts, optional
   * hourly 24h series. Aggregate metadata only — no user rows.
   */
  fastify.get('/api/pipeline/attribution-health', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const verifiedAt = nowVerifiedAt();
    // One 7d scan for the three window cards + a host rollup + optional
    // hourly series for the sparkline. All pure aggregates.
    const okPred = `(user_pseudonym IS NOT NULL OR principal_kind = 'service')`;
    const unboundPred = `(user_pseudonym IS NULL AND COALESCE(principal_kind, '') <> 'service')`;

    const [windowRow, lastRow, hostRow, trendRows] = await Promise.all([
      db.query(
        `SELECT
            count(*) FILTER (WHERE ts > now() - interval '1 hour') AS n_1h,
            count(*) FILTER (WHERE ts > now() - interval '1 hour'
                             AND ${okPred}) AS ok_1h,
            count(*) FILTER (WHERE ts > now() - interval '1 hour'
                             AND principal_kind = 'service') AS service_1h,
            count(*) FILTER (WHERE ts > now() - interval '24 hours') AS n_24h,
            count(*) FILTER (WHERE ts > now() - interval '24 hours'
                             AND ${okPred}) AS ok_24h,
            count(*) FILTER (WHERE ts > now() - interval '24 hours'
                             AND principal_kind = 'service') AS service_24h,
            count(*) AS n_7d,
            count(*) FILTER (WHERE ${okPred}) AS ok_7d,
            count(*) FILTER (WHERE principal_kind = 'service') AS service_7d
           FROM events
          WHERE ts > now() - interval '7 days'`
      ),
      db.query(
        `SELECT max(ts) FILTER (WHERE ${okPred}) AS last_attributed,
                EXTRACT(EPOCH FROM (now() - max(ts) FILTER (WHERE ${okPred}))) AS age_seconds
           FROM events`
      ),
      // Host identity posture over the 7d gate window.
      // unbound: any unbound event in window.
      // service_only: all events in window are service principals (no human, no unbound).
      db.query(
        `SELECT
            count(*) FILTER (WHERE unbound_n > 0) AS unbound_hosts,
            count(*) FILTER (WHERE service_n > 0 AND human_n = 0 AND unbound_n = 0) AS service_only_hosts,
            count(*) AS distinct_hosts
           FROM (
             SELECT host_ref,
                    count(*) FILTER (WHERE principal_kind = 'service') AS service_n,
                    count(*) FILTER (WHERE user_pseudonym IS NOT NULL
                                          AND COALESCE(principal_kind, '') <> 'service') AS human_n,
                    count(*) FILTER (WHERE ${unboundPred}) AS unbound_n
               FROM events
              WHERE ts > now() - interval '7 days'
              GROUP BY host_ref
           ) host_roll`
      ),
      db.query(
        `SELECT date_trunc('hour', ts) AS hour,
                count(*) AS n,
                count(*) FILTER (WHERE ${okPred}) AS ok
           FROM events
          WHERE ts > now() - interval '24 hours'
          GROUP BY 1
          ORDER BY 1 ASC`
      ),
    ]);

    const w = windowRow.rows[0] ?? {};
    const last = lastRow.rows[0] ?? {};
    const h = hostRow.rows[0] ?? {};
    const lastAttributed = last.last_attributed instanceof Date
      ? last.last_attributed.toISOString()
      : (last.last_attributed ?? null);

    const health = evaluateAttributionHealth({
      windowCounts: {
        '1h': { n: w.n_1h, ok: w.ok_1h, service: w.service_1h },
        '24h': { n: w.n_24h, ok: w.ok_24h, service: w.service_24h },
        '7d': { n: w.n_7d, ok: w.ok_7d, service: w.service_7d },
      },
      lastAttributedAt: lastAttributed,
      lastAttributedAgeSeconds: last.age_seconds == null ? null : Number(last.age_seconds),
      hosts: {
        unbound: h.unbound_hosts,
        serviceOnly: h.service_only_hosts,
        distinct: h.distinct_hosts,
      },
      trendRows: trendRows.rows ?? [],
      now: new Date(verifiedAt),
    });
    // Prefer the request-scoped verified stamp so the stamp matches siblings.
    health.lastVerifiedAt = verifiedAt;
    return health;
  });
}

#!/usr/bin/env node
/**
 * Ingest scale proof: 700-engineer burst load test.
 *
 * Converts the *asserted* ingest scale posture (idempotent ingest, DLQ+replay,
 * batch caps) into *measured* evidence. Runs against a deployed ingest service
 * and the local compose Postgres. Truthful measurement with stated hardware
 * caveats — not a production benchmark.
 *
 * PHASES (run in order, single process):
 *   A. model     — derive target event rates from a stated 700-engineer mix.
 *   B. sustained — hold the modelled peak offered load; measure p50/p95/p99
 *                  ingest latency and error rate at realistic load (SLO check).
 *   C. ceiling   — closed-loop concurrency ramp; find the max sustainable
 *                  throughput before the latency SLO or errors break.
 *   D. overload  — push past the ceiling to observe backpressure, then a
 *                  retry-storm replay of every sent event to verify idempotency
 *                  under duplicate delivery (zero double-store).
 *
 * The event-mix MODEL is stated here as named constants, not hand-waved:
 *   ENGINEERS ................ fleet size we are proving for
 *   SESSIONS_PER_ENG_PER_DAY . AI-tool coding sessions per engineer per workday
 *   EVENTS_PER_SESSION ....... usage events emitted per session (turns +
 *                              tool-call events; one collector event each)
 *   ACTIVE_HOURS ............. hours/day the fleet is actually generating load
 *   DIURNAL_BURST ............ peak-hour offered load / flat daily average
 *   CORRELATED_BURST ......... short correlated spike / peak-hour average
 *                              (CI fan-out, standups ending, save storms)
 *   BATCH .................... events per collector flush (collectors batch)
 *
 * Usage:
 *   INGEST_TOKEN=... node scripts/ingest-loadtest.mjs
 * Env:
 *   INGEST_URL (default http://127.0.0.1:8080), INGEST_TOKEN (required),
 *   PGDB (aim), OUT (JSON artifact path),
 *   SLO_P99_MS (500) latency SLO used to define the throughput ceiling,
 *   PHASES=A,B,C,D  subset to run (default all),
 *   FAST=1          shorter durations for a smoke run.
 */
import { randomUUID, createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFileSync } from "node:fs";

const execFileP = promisify(execFile);

// ---- config -------------------------------------------------------------
const BASE = (process.env.INGEST_URL ?? "http://127.0.0.1:8080").replace(/\/+$/, "");
const TOKEN = process.env.INGEST_TOKEN;
const PGDB = process.env.PGDB ?? "aim";
const SLO_P99_MS = Number(process.env.SLO_P99_MS ?? 500);
const OUT = process.env.OUT ?? null;
const FAST = process.env.FAST === "1";
const PHASES = (process.env.PHASES ?? "A,B,C,D").split(",").map((s) => s.trim().toUpperCase());

if (!TOKEN) {
  console.error("INGEST_TOKEN is required");
  process.exit(2);
}

// ---- event-mix model ----------------------------------------------------
const MODEL = {
  ENGINEERS: 700,
  SESSIONS_PER_ENG_PER_DAY: 8,
  EVENTS_PER_SESSION: 40,
  ACTIVE_HOURS: 8,
  DIURNAL_BURST: 4, // peak hour vs flat daily average
  CORRELATED_BURST: 3, // short correlated spike vs peak-hour average
  BATCH: 50, // events per collector flush
};

function deriveModel(m) {
  const eventsPerDay = m.ENGINEERS * m.SESSIONS_PER_ENG_PER_DAY * m.EVENTS_PER_SESSION;
  const flatDayAvgEps = eventsPerDay / (24 * 3600);
  const workdayAvgEps = eventsPerDay / (m.ACTIVE_HOURS * 3600);
  const peakHourEps = workdayAvgEps * m.DIURNAL_BURST;
  const correlatedBurstEps = peakHourEps * m.CORRELATED_BURST;
  return {
    ...m,
    eventsPerDay,
    eventsPerMonth: eventsPerDay * 30,
    flatDayAvgEps: round(flatDayAvgEps, 2),
    workdayAvgEps: round(workdayAvgEps, 2),
    peakHourEps: round(peakHourEps, 2),
    correlatedBurstEps: round(correlatedBurstEps, 2),
  };
}

// ---- helpers ------------------------------------------------------------
const hex64 = (s) => createHash("sha256").update(s).digest("hex");
const round = (n, d = 2) => Math.round(n * 10 ** d) / 10 ** d;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function makeEvent(overrides = {}) {
  const eng = Math.floor(Math.random() * MODEL.ENGINEERS);
  return {
    schema_version: "1.0",
    event_id: randomUUID(),
    ts: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    host_ref: hex64(`host-${eng}`),
    user_ref: hex64(`user-${eng}`),
    tool: "claude_code",
    // Sentinel so synthetic load events are cleanly deletable after the run
    // (DELETE FROM events WHERE tool_raw='aim118-loadtest') and never pollute
    // the pilot dashboard. tool_raw is low-sensitivity free metadata (<=64).
    tool_raw: "aim118-loadtest",
    tool_version: "1.0.0",
    model: "claude-opus-4",
    provider: "anthropic",
    session_id: randomUUID(),
    tokens_in: 400 + Math.floor(Math.random() * 800),
    tokens_out: 80 + Math.floor(Math.random() * 400),
    repo_ref: hex64(`repo-${eng % 120}`),
    match_flags: [],
    source: "endpoint",
    ...overrides,
  };
}

/** POST a batch; returns { status, ms, ackAccepted, ackDuplicates, retryAfter, err }. */
async function postEvents(events, ids = null) {
  const t0 = performance.now();
  try {
    const res = await fetch(`${BASE}/v1/events`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({ events }),
    });
    const ms = performance.now() - t0;
    let body = null;
    try {
      body = await res.json();
    } catch {
      /* non-JSON */
    }
    // Only accepted (2xx) ids are recorded for the idempotency replay: a shed
    // (429) batch was never stored, so replaying it is a fresh insert, not a
    // duplicate. This keeps the idempotency invariant valid under load-shedding
    // as well as the original queue-and-hold behaviour.
    if (ids && res.ok) for (const e of events) ids.push(e.event_id);
    return {
      status: res.status,
      ms,
      ackAccepted: body?.accepted ?? 0,
      ackDuplicates: body?.duplicates ?? 0,
      retryAfter: res.headers.get("retry-after"),
    };
  } catch (err) {
    return { status: 0, ms: performance.now() - t0, ackAccepted: 0, ackDuplicates: 0, err: String(err) };
  }
}

/** Scrape a single numeric metric from /metrics (null if absent/unreachable). */
async function scrapeMetric(name) {
  try {
    const res = await fetch(`${BASE}/metrics`);
    const text = await res.text();
    const line = text.split("\n").find((l) => l.startsWith(`${name} `));
    return line ? Number(line.slice(name.length + 1)) : null;
  } catch {
    return null;
  }
}

function percentile(sorted, p) {
  if (sorted.length === 0) return null;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return round(sorted[idx], 1);
}

function summarizeLatency(latencies) {
  const s = [...latencies].sort((a, b) => a - b);
  return {
    count: s.length,
    p50: percentile(s, 50),
    p95: percentile(s, 95),
    p99: percentile(s, 99),
    max: s.length ? round(s[s.length - 1], 1) : null,
    mean: s.length ? round(s.reduce((a, b) => a + b, 0) / s.length, 1) : null,
  };
}

async function dbCount(sql) {
  const { stdout } = await execFileP("docker", [
    "compose", "exec", "-T", "postgres", "psql", "-U", "aim", "-d", PGDB, "-tAc", sql,
  ]);
  return Number(stdout.trim());
}

/** Sample Postgres activity — non-fatal if psql is unreachable. */
async function pgSnapshot() {
  try {
    const active = await dbCount(
      "SELECT count(*) FROM pg_stat_activity WHERE datname='" + PGDB + "' AND state='active';",
    );
    const total = await dbCount(
      "SELECT count(*) FROM pg_stat_activity WHERE datname='" + PGDB + "';",
    );
    const relBytes = await dbCount("SELECT pg_total_relation_size('events');");
    return { activeConns: active, totalConns: total, eventsTableBytes: relBytes };
  } catch (err) {
    return { error: String(err) };
  }
}

// ---- open-loop rate-paced run (Phase B: latency at a target offered eps) --
async function runOpenLoop({ targetEps, durationS, batch, maxInflight = 256 }) {
  const batchesPerSec = targetEps / batch;
  const intervalMs = 1000 / batchesPerSec;
  const latencies = [];
  const statuses = new Map();
  const sentIds = [];
  let dispatched = 0;
  const inflight = new Set();
  const t0 = performance.now();
  let tick = 0;

  while ((performance.now() - t0) / 1000 < durationS) {
    const due = t0 + tick * intervalMs;
    const now = performance.now();
    if (now < due) await sleep(due - now);
    if (inflight.size >= maxInflight) {
      // Offered load exceeds service capacity — record and keep going.
      statuses.set("dropped_inflight", (statuses.get("dropped_inflight") ?? 0) + 1);
    } else {
      const events = Array.from({ length: batch }, () => makeEvent());
      const p = postEvents(events, sentIds).then((r) => {
        latencies.push(r.ms);
        statuses.set(r.status, (statuses.get(r.status) ?? 0) + 1);
        inflight.delete(p);
      });
      inflight.add(p);
      dispatched += batch;
    }
    tick += 1;
  }
  await Promise.all(inflight);
  const elapsedS = (performance.now() - t0) / 1000;
  return {
    targetEps,
    achievedEps: round(dispatched / elapsedS, 1),
    durationS: round(elapsedS, 1),
    batch,
    dispatchedEvents: dispatched,
    latencyMs: summarizeLatency(latencies),
    statuses: Object.fromEntries(statuses),
    sentIds,
  };
}

// ---- closed-loop run (Phase C/D: N workers send back-to-back) ------------
async function runClosedLoop({ concurrency, durationS, batch, collectIds = null, samplePg = false }) {
  const latencies = [];
  const statuses = new Map();
  const retryAfterSeen = new Set();
  let dispatched = 0;
  let ackAccepted = 0;
  let ackDuplicates = 0;
  const t0 = performance.now();

  // Concurrent Postgres sampler — captures PEAK active/total connections while
  // load is actually in flight (a post-run snapshot always reads ~idle).
  let pgPeak = { activeConns: 0, totalConns: 0 };
  let sampling = samplePg;
  const sampler = (async () => {
    while (sampling && (performance.now() - t0) / 1000 < durationS) {
      const s = await pgSnapshot();
      if (typeof s.activeConns === "number")
        pgPeak.activeConns = Math.max(pgPeak.activeConns, s.activeConns);
      if (typeof s.totalConns === "number")
        pgPeak.totalConns = Math.max(pgPeak.totalConns, s.totalConns);
      await sleep(500);
    }
  })();

  async function worker() {
    while ((performance.now() - t0) / 1000 < durationS) {
      const events = Array.from({ length: batch }, () => makeEvent());
      const r = await postEvents(events, collectIds);
      latencies.push(r.ms);
      statuses.set(r.status, (statuses.get(r.status) ?? 0) + 1);
      if (r.retryAfter != null) retryAfterSeen.add(r.retryAfter);
      dispatched += batch;
      ackAccepted += r.ackAccepted;
      ackDuplicates += r.ackDuplicates;
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));
  sampling = false;
  await sampler;
  const elapsedS = (performance.now() - t0) / 1000;
  return {
    concurrency,
    achievedEps: round(dispatched / elapsedS, 1),
    durationS: round(elapsedS, 1),
    batch,
    dispatchedEvents: dispatched,
    ackAccepted,
    ackDuplicates,
    pgPeak: samplePg ? pgPeak : null,
    latencyMs: summarizeLatency(latencies),
    statuses: Object.fromEntries(statuses),
    retryAfterSeen: [...retryAfterSeen],
    errorRate: round(
      1 - (statuses.get(200) ?? 0) / Math.max(1, [...statuses.values()].reduce((a, b) => a + b, 0)),
      4,
    ),
  };
}

// ---- main ---------------------------------------------------------------
const report = { startedAt: new Date().toISOString(), base: BASE, phases: {} };

const model = deriveModel(MODEL);
report.model = model;
console.log("\n=== ingest scale proof ===");
console.log(`target: ${BASE}   SLO p99 <= ${SLO_P99_MS}ms   batch=${MODEL.BATCH}`);
console.log("\n[A] event-mix model (700 engineers):");
console.log(`    events/day ............ ${model.eventsPerDay.toLocaleString()}`);
console.log(`    events/month .......... ${model.eventsPerMonth.toLocaleString()}`);
console.log(`    flat 24h avg .......... ${model.flatDayAvgEps} eps`);
console.log(`    workday avg (${MODEL.ACTIVE_HOURS}h) ..... ${model.workdayAvgEps} eps`);
console.log(`    peak hour (x${MODEL.DIURNAL_BURST}) ........ ${model.peakHourEps} eps`);
console.log(`    correlated burst (x${MODEL.CORRELATED_BURST}) .. ${model.correlatedBurstEps} eps`);

report.pgBefore = await pgSnapshot();
report.eventsBefore = await dbCount("SELECT count(*) FROM events;").catch(() => null);

// Phase B — sustained at modelled correlated-burst load (the honest peak).
if (PHASES.includes("B")) {
  const durationS = FAST ? 15 : 60;
  const targetEps = Math.ceil(model.correlatedBurstEps);
  console.log(`\n[B] sustained @ modelled correlated-burst load: ${targetEps} eps for ${durationS}s`);
  const res = await runOpenLoop({ targetEps, durationS, batch: MODEL.BATCH });
  const pg = await pgSnapshot();
  delete res.sentIds; // large; not needed in artifact
  res.pgDuringTail = pg;
  res.meetsSLO = res.latencyMs.p99 !== null && res.latencyMs.p99 <= SLO_P99_MS && !res.statuses["0"];
  report.phases.B_sustained = res;
  console.log(
    `    achieved ${res.achievedEps} eps  p50=${res.latencyMs.p50}ms p95=${res.latencyMs.p95}ms p99=${res.latencyMs.p99}ms  statuses=${JSON.stringify(res.statuses)}  SLO=${res.meetsSLO ? "PASS" : "FAIL"}`,
  );
}

// Phase C — closed-loop concurrency ramp to find the throughput ceiling.
if (PHASES.includes("C")) {
  const durationS = FAST ? 6 : 12;
  const levels = FAST ? [2, 8, 32] : [1, 2, 4, 8, 16, 32, 64];
  console.log(`\n[C] throughput ceiling — closed-loop ramp (${durationS}s/level):`);
  const ramp = [];
  let ceiling = null;
  for (const concurrency of levels) {
    const res = await runClosedLoop({ concurrency, durationS, batch: MODEL.BATCH, samplePg: true });
    res.pgActiveConns = res.pgPeak?.activeConns ?? null;
    ramp.push(res);
    const ok = res.errorRate === 0 && res.latencyMs.p99 <= SLO_P99_MS;
    if (ok) ceiling = res;
    console.log(
      `    c=${String(concurrency).padStart(2)}  ${String(res.achievedEps).padStart(7)} eps  p99=${String(res.latencyMs.p99).padStart(6)}ms  errRate=${res.errorRate}  pgActivePeak=${res.pgActiveConns}  ${ok ? "within-SLO" : "OVER-SLO"}`,
    );
  }
  report.phases.C_ceiling = {
    slaP99Ms: SLO_P99_MS,
    ramp,
    ceilingEps: ceiling ? ceiling.achievedEps : null,
    ceilingConcurrency: ceiling ? ceiling.concurrency : null,
    maxObservedEps: Math.max(...ramp.map((r) => r.achievedEps)),
    headroomVsCorrelatedBurst: ceiling
      ? round(ceiling.achievedEps / model.correlatedBurstEps, 1)
      : null,
  };
  console.log(
    `    => sustainable ceiling (within SLO): ${report.phases.C_ceiling.ceilingEps} eps  |  max observed: ${report.phases.C_ceiling.maxObservedEps} eps`,
  );
}

// Phase D — overload backpressure + retry-storm idempotency.
if (PHASES.includes("D")) {
  const durationS = FAST ? 8 : 15;
  const overloadConcurrency = FAST ? 48 : 96;
  console.log(`\n[D] overload + retry storm (idempotency under duplicate delivery):`);
  const storedBefore = await dbCount("SELECT count(*) FROM events;");
  const rejectedBefore = await dbCount("SELECT count(*) FROM rejected_events;").catch(() => 0);

  // D1: deliberate overload — offered load above the ceiling. Observe how the
  // service degrades: latency, and whether it sheds with 5xx or holds.
  const collectIds = [];
  console.log(`    D1 overload: concurrency=${overloadConcurrency} for ${durationS}s (above ceiling)`);
  // Snapshot admission-control counters around the overload so we can attribute
  // any shedding to this phase. Null when admission is off / metrics
  // unreachable — the harness still runs against an un-instrumented service.
  const admissionMode = await scrapeMetric("ingest_admission_max_inflight");
  const shedBefore = (await scrapeMetric("ingest_admission_shed_total")) ?? 0;
  const shadowBefore = (await scrapeMetric("ingest_admission_shadow_sheddable_total")) ?? 0;
  const overload = await runClosedLoop({
    concurrency: overloadConcurrency,
    durationS,
    batch: MODEL.BATCH,
    collectIds,
    samplePg: true,
  });
  const pgOverload = overload.pgPeak ?? {};
  const shedAfter = (await scrapeMetric("ingest_admission_shed_total")) ?? 0;
  const shadowAfter = (await scrapeMetric("ingest_admission_shadow_sheddable_total")) ?? 0;
  const inflightHighWater = await scrapeMetric("ingest_admission_inflight_high_water");
  console.log(
    `       achieved ${overload.achievedEps} eps  p99=${overload.latencyMs.p99}ms  max=${overload.latencyMs.max}ms  statuses=${JSON.stringify(overload.statuses)}  pgActivePeak=${pgOverload.activeConns}`,
  );
  const shed429 = overload.statuses["429"] ?? 0;
  console.log(
    `       admission: maxInflight=${admissionMode}  429s=${shed429}  retryAfter=${JSON.stringify(overload.retryAfterSeen)}  shed_total(+)=${shedAfter - shedBefore}  shadow_sheddable(+)=${shadowAfter - shadowBefore}  inflightHighWater=${inflightHighWater}`,
  );

  // Settle, then measure how many distinct ids from the overload actually landed.
  await sleep(1500);
  const storedAfterOverload = await dbCount("SELECT count(*) FROM events;");
  const distinctSent = new Set(collectIds).size;

  // D2: retry storm — re-POST every id sent during overload (duplicate
  // delivery). Idempotency requires: acks report duplicates, DB does NOT grow.
  console.log(`    D2 retry storm: replaying ${collectIds.length} events (${distinctSent} distinct)`);
  let replayAccepted = 0;
  let replayDuplicates = 0;
  let replayErrors = 0;
  const uniqueIds = [...new Set(collectIds)];
  const BATCH = MODEL.BATCH;
  // Concurrency-8 replay of the exact same ids.
  let cursor = 0;
  async function replayWorker() {
    while (true) {
      const start = cursor;
      cursor += BATCH;
      if (start >= uniqueIds.length) break;
      const ids = uniqueIds.slice(start, start + BATCH);
      const events = ids.map((id) => makeEvent({ event_id: id }));
      const r = await postEvents(events);
      if (r.status === 200) {
        replayAccepted += r.ackAccepted;
        replayDuplicates += r.ackDuplicates;
      } else {
        replayErrors += 1;
      }
    }
  }
  await Promise.all(Array.from({ length: 8 }, replayWorker));
  await sleep(1000);

  const storedAfterReplay = await dbCount("SELECT count(*) FROM events;");
  const distinctInDb = await dbCount("SELECT count(DISTINCT event_id) FROM events;");
  const rejectedAfter = await dbCount("SELECT count(*) FROM rejected_events;").catch(() => 0);

  const idempotencyHeld = storedAfterReplay === storedAfterOverload && replayAccepted === 0;
  const zeroDoubleStore = storedAfterReplay === distinctInDb;

  report.phases.D_overload = {
    overload: { ...overload, pgSnapshot: pgOverload },
    backpressure: {
      // A shed-load service returns 5xx/429; a queue-and-hold service returns
      // 200 with rising latency. Record which behaviour we actually observed.
      non200: Object.entries(overload.statuses)
        .filter(([k]) => k !== "200")
        .reduce((a, [, v]) => a + v, 0),
      shed429: shed429,
      retryAfterSeen: overload.retryAfterSeen,
      p99Ms: overload.latencyMs.p99,
      maxMs: overload.latencyMs.max,
      observedMode:
        shed429 > 0
          ? "shed (429 Retry-After returned; admission control engaged)"
          : Object.keys(overload.statuses).every((s) => s === "200")
            ? "queue-and-hold (200 with elevated latency; no load shedding)"
            : "mixed / shed (non-200 responses observed)",
      admission: {
        // Null maxInflight = admission disabled or /metrics unreachable.
        maxInflight: admissionMode,
        inflightHighWater,
        shedTotalDelta: shedAfter - shedBefore,
        shadowSheddableDelta: shadowAfter - shadowBefore,
      },
    },
    idempotency: {
      eventsSentDuringOverload: collectIds.length,
      distinctSent,
      storedBefore,
      storedAfterOverload,
      storedAfterReplay,
      distinctInDb,
      replayAccepted,
      replayDuplicates,
      replayErrors,
      idempotencyHeld,
      zeroDoubleStore,
    },
    dlq: {
      rejectedBefore,
      rejectedAfter,
      note: "no invalid events injected in overload; rejected_events (DLQ) unchanged is expected",
    },
  };
  console.log(
    `       stored: before=${storedBefore} afterOverload=${storedAfterOverload} afterReplay=${storedAfterReplay}  distinctInDb=${distinctInDb}`,
  );
  console.log(
    `       replay: accepted=${replayAccepted} duplicates=${replayDuplicates} errors=${replayErrors}`,
  );
  console.log(
    `       idempotency held (no double-store on replay): ${idempotencyHeld ? "PASS" : "FAIL"}  |  stored==distinct: ${zeroDoubleStore ? "PASS" : "FAIL"}`,
  );
}

report.pgAfter = await pgSnapshot();
report.eventsAfter = await dbCount("SELECT count(*) FROM events;").catch(() => null);
report.finishedAt = new Date().toISOString();

if (OUT) {
  writeFileSync(OUT, JSON.stringify(report, null, 2));
  console.log(`\nartifact written: ${OUT}`);
} else {
  console.log("\n(no OUT set; JSON artifact not written)");
}
console.log("done.");

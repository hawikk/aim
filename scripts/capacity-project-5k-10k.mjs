#!/usr/bin/env node
/**
 * Capacity projection model: 700 → 5k → 10k endpoints.
 *
 * Spreadsheet-grade, deterministic model. No live load is driven.
 * Combines two intensity tracks with explicit measured vs extrapolated labels:
 *
 * dogfood — per-device rates (security-team pilot intensity)
 * coding — upper-bound active-coding intensity
 *
 * Single-node ingest SLO ceiling (~775 eps p99≤500ms) is a MEASURED number
 * on a co-located single-host rig (conservative). Replica counts
 * and IOPS are EXTRAPOLATED from that knee + stated write-amplification
 * assumptions — not re-measured at 5k/10k.
 *
 * Usage:
 *   node scripts/capacity-project-5k-10k.mjs
 *   node scripts/capacity-project-5k-10k.mjs --json
 *   ENDPOINTS=5000,10000 node scripts/capacity-project-5k-10k.mjs
 *   node scripts/capacity-project-5k-10k.mjs --csv
 *
 * Optional OUT=/path/to.json writes the full projection object.
 */

import { writeFileSync } from "node:fs";

// ---- measured / stated inputs ------------------------------------------

/** dogfood model (docs/aim-323-fleet-scale-proof.md §2, results JSON). */
const DOGFOOD = {
  label: "dogfood",
  provenance: "measured model at 700 devices; rates linear-extrapolated beyond 700",
  eventsPerDevicePerDay: 6.833,
  activeHours: 8,
  /** Harness burst multiplier vs workday average (not diurnal×correlated). */
  burstMult: 10,
  /** Measured during drill: pg_total_relation_size delta / rows. */
  pgBytesPerEvent: 1195,
  /** Measured MinIO /data byte delta / synthetic events (~27.7k). */
  minioBytesPerEvent: 973,
};

/**
 * coding-intensity upper bound
 * (docs/aim-118-ingest-scale-proof-2026-07-23.md §2).
 */
const CODING = {
  label: "coding intensity (upper bound)",
  provenance:
    "stated model (sessions×events), peak sustained on single-node at 700-scale; rates linear-extrapolated",
  sessionsPerDevicePerDay: 8,
  eventsPerSession: 40,
  activeHours: 8,
  diurnalBurst: 4, // peak-hour vs workday average
  correlatedBurst: 3, // short spike vs peak-hour
  /** Measured during loadtest: ~1,332 B/event heap+indexes+TOAST. */
  pgBytesPerEvent: 1332,
  /**
   * No MinIO measurement; reuse archive byte/event as
   * EXTRAPOLATED lower-bound (coding events may be larger).
   */
  minioBytesPerEvent: 973,
};

/** Phase C — within-SLO ceiling on co-located single-host rig. */
const NODE = {
  sloCeilingEps: 775,
  maxThroughputEps: 2345,
  /** Default admission cap (tuned). Per-process. */
  maxInflight: 64,
  admissionMode: "enforce",
  retryAfterS: 1,
  /**
   * Target utilisation of the measured SLO ceiling when sizing replicas.
   * 0.5 = run at ≤50% of measured knee so co-location / noisy-neighbour
   * variance and HA loss of one replica still fit.
   */
  targetUtilisation: 0.5,
  provenance:
    "MEASURED on 16 vCPU / 15 GiB WSL2 host with loadgen+ingest+PG co-located. Absolute numbers are conservative vs split production topology.",
};

/**
 * Postgres IOPS model — EXTRAPOLATED, not measured.
 * Budget 8 provisioned IOPS per event at peak for heap+index+WAL on gp3-class.
 * observed PG was not the bottleneck up to ~775 eps (active conns ≤13).
 */
const PG_IOPS_PER_EVENT = 8;

/** Retention assumptions for storage growth (policy-proposed, not enforced). */
const RETENTION = {
  eventsMonths: 12,
  rawArchiveDays: 90, // docs/deployment/raw-batch-archival.md proposal
};

// ---- math --------------------------------------------------------------

const round = (n, d = 2) => {
  const f = 10 ** d;
  return Math.round(n * f) / f;
};

function parseEndpoints() {
  const arg = process.argv.find((a) => a.startsWith("--endpoints="));
  const raw = arg?.split("=")[1] ?? process.env.ENDPOINTS ?? "700,5000,10000";
  return raw
    .split(",")
    .map((s) => Number(s.trim()))
    .filter((n) => Number.isFinite(n) && n > 0);
}

function dogfoodRates(devices) {
  const eventsPerDay = devices * DOGFOOD.eventsPerDevicePerDay;
  const workdayAvgEps = eventsPerDay / (DOGFOOD.activeHours * 3600);
  const burstEps = workdayAvgEps * DOGFOOD.burstMult;
  const flatDayAvgEps = eventsPerDay / 86400;
  return {
    track: "dogfood",
    devices,
    eventsPerDevicePerDay: DOGFOOD.eventsPerDevicePerDay,
    eventsPerDay: round(eventsPerDay, 1),
    eventsPerMonth: round(eventsPerDay * 30, 0),
    flatDayAvgEps: round(flatDayAvgEps, 4),
    workdayAvgEps: round(workdayAvgEps, 4),
    burstEps: round(burstEps, 3),
    burstDefinition: `workday_avg × ${DOGFOOD.burstMult} (harness)`,
    pgBytesPerEvent: DOGFOOD.pgBytesPerEvent,
    minioBytesPerEvent: DOGFOOD.minioBytesPerEvent,
  };
}

function codingRates(devices) {
  const eventsPerDevicePerDay =
    CODING.sessionsPerDevicePerDay * CODING.eventsPerSession;
  const eventsPerDay = devices * eventsPerDevicePerDay;
  const workdayAvgEps = eventsPerDay / (CODING.activeHours * 3600);
  const peakHourEps = workdayAvgEps * CODING.diurnalBurst;
  const correlatedBurstEps = peakHourEps * CODING.correlatedBurst;
  const flatDayAvgEps = eventsPerDay / 86400;
  return {
    track: "coding",
    devices,
    eventsPerDevicePerDay,
    eventsPerDay: round(eventsPerDay, 0),
    eventsPerMonth: round(eventsPerDay * 30, 0),
    flatDayAvgEps: round(flatDayAvgEps, 3),
    workdayAvgEps: round(workdayAvgEps, 3),
    peakHourEps: round(peakHourEps, 2),
    burstEps: round(correlatedBurstEps, 2),
    burstDefinition: `workday_avg × ${CODING.diurnalBurst} × ${CODING.correlatedBurst} (honest peak)`,
    pgBytesPerEvent: CODING.pgBytesPerEvent,
    minioBytesPerEvent: CODING.minioBytesPerEvent,
  };
}

function storage(rates) {
  const pgBytesDay = rates.eventsPerDay * rates.pgBytesPerEvent;
  const minioBytesDay = rates.eventsPerDay * rates.minioBytesPerEvent;
  const pgBytesYear = pgBytesDay * 365;
  const pgBytesRetained = pgBytesDay * (RETENTION.eventsMonths * 30);
  const minioBytesRetained = minioBytesDay * RETENTION.rawArchiveDays;
  return {
    pgGrowthGbPerDay: round(pgBytesDay / 1e9, 4),
    pgGrowthGbPerMonth: round((pgBytesDay * 30) / 1e9, 3),
    pgResidentGbAtRetention: round(pgBytesRetained / 1e9, 2),
    pgAnnualGrowthGb: round(pgBytesYear / 1e9, 2),
    minioGrowthGbPerDay: round(minioBytesDay / 1e9, 4),
    minioGrowthGbPerMonth: round((minioBytesDay * 30) / 1e9, 3),
    minioResidentGbAtRetention: round(minioBytesRetained / 1e9, 2),
    retention: { ...RETENTION },
  };
}

function iops(burstEps) {
  const peak = burstEps * PG_IOPS_PER_EVENT;
  return {
    model: `peak_eps × ${PG_IOPS_PER_EVENT} IOPS/event (EXTRAPOLATED; not measured)`,
    peakProvisionedIops: round(peak, 0),
    note: "Postgres was not the bottleneck up to ~775 eps on the test host. Provisioned IOPS is a planning budget, not a measured requirement.",
  };
}

function replicas(burstEps) {
  const minForSlo = Math.max(1, Math.ceil(burstEps / NODE.sloCeilingEps));
  const recommended = Math.max(
    minForSlo,
    Math.ceil(burstEps / (NODE.sloCeilingEps * NODE.targetUtilisation)),
  );
  // HA floor: never recommend a single ingest node once coding intensity
  // burst exceeds 25% of one node's SLO ceiling (still cheap; buys failover).
  const haFloor =
    burstEps > NODE.sloCeilingEps * 0.25 ? Math.max(recommended, 2) : recommended;
  return {
    measuredSloCeilingEps: NODE.sloCeilingEps,
    targetUtilisation: NODE.targetUtilisation,
    minReplicasForSlo: minForSlo,
    recommendedIngestReplicas: haFloor,
    headroomAtRecommended: round(
      (haFloor * NODE.sloCeilingEps) / Math.max(burstEps, 1e-9),
      2,
    ),
    admission: {
      mode: NODE.admissionMode,
      maxInflightPerReplica: NODE.maxInflight,
      retryAfterS: NODE.retryAfterS,
      multiNodeNote:
        "Admission is per-process (residual). Fleet-wide cap ≈ replicas × maxInflight under a LB.",
    },
  };
}

function topology(track, rates, rep) {
  const burst = rates.burstEps;
  const codingLike = track === "coding";
  const devices = rates.devices;

  let postgres;
  let objectStore;
  let notes = [];

  if (!codingLike || burst < 50) {
    postgres = {
      tier: "single primary (compose / small managed)",
      vcpu: 2,
      memoryGb: 8,
      multiAz: false,
      reason: "dogfood or low coding peak; PG not load-bound at 700 measured",
    };
    objectStore = {
      tier: "single MinIO or small S3 bucket",
      reason: "archive growth modest at dogfood rates",
    };
  } else if (burst < NODE.sloCeilingEps * 0.7) {
    postgres = {
      tier: "dedicated managed primary",
      vcpu: 4,
      memoryGb: 16,
      multiAz: devices >= 5000,
      provisionedIopsHint: iops(burst).peakProvisionedIops,
      reason: "coding peak consumes double-digit % of node; buy headroom + optional multi-AZ",
    };
    objectStore = {
      tier: "S3 / MinIO with lifecycle (90d raw)",
      reason: "GB/day archive at coding intensity",
    };
  } else {
    postgres = {
      tier: "external multi-AZ managed Postgres",
      vcpu: devices >= 10000 ? 8 : 4,
      memoryGb: devices >= 10000 ? 32 : 16,
      multiAz: true,
      provisionedIopsHint: iops(burst).peakProvisionedIops,
      reason:
        "coding peak approaches or exceeds single-node ingest SLO knee; DB becomes shared critical path — multi-AZ for RPO/RTO",
    };
    objectStore = {
      tier: "S3 multi-AZ or MinIO distributed",
      reason: "archive + fail-open path must survive AZ loss",
    };
    notes.push(
      "Move Postgres off the app host; do not co-locate loadgen/ingest/DB as rig.",
    );
  }

  if (rep.recommendedIngestReplicas >= 2) {
    notes.push("Put ingest behind an L4/L7 load balancer; sticky sessions not required.");
  }

  return {
    ingestReplicas: rep.recommendedIngestReplicas,
    ingestSize: "2 vCPU / 4 GB per replica (cost baseline class)",
    postgres,
    objectStore,
    admission: rep.admission,
    notes,
  };
}

function projectTier(devices) {
  const dog = dogfoodRates(devices);
  const code = codingRates(devices);
  const dogRep = replicas(dog.burstEps);
  const codeRep = replicas(code.burstEps);
  return {
    devices,
    dogfood: {
      ...dog,
      storage: storage(dog),
      iops: iops(dog.burstEps),
      scale: dogRep,
      topology: topology("dogfood", dog, dogRep),
      confidence: "rates EXTRAPOLATED linearly 700-device dogfood model; node ceiling MEASURED",
    },
    coding: {
      ...code,
      storage: storage(code),
      iops: iops(code.burstEps),
      scale: codeRep,
      topology: topology("coding", code, codeRep),
      confidence:
        "rates EXTRAPOLATED linearly stated coding mix; 700-scale peak MEASURED at 93 eps; 5k/10k peaks not load-tested",
    },
  };
}

function scalingTriggers() {
  return [
    {
      signal: "ingest p99 > 400 ms for 15m (approaching 500 ms SLO)",
      action: "Add 1 ingest replica; verify LB health; re-check admission high-water",
      owner: "platform",
    },
    {
      signal: `sustained offered load > ${round(NODE.sloCeilingEps * NODE.targetUtilisation, 0)} eps per ingest replica`,
      action: "Add replicas so each stays ≤50% of measured 775 eps SLO ceiling",
      owner: "platform",
    },
    {
      signal: "ingest_admission_shed_total rising under normal business load (not a drill)",
      action:
        "Do NOT raise maxInflight blindly — scale out replicas. Cap is a collapse guard (§6)",
      owner: "platform",
    },
    {
      signal: "Postgres CPU > 70% or commit latency p95 > 50 ms for 15m",
      action: "Scale DB instance class; enable/verify multi-AZ if not already",
      owner: "platform",
    },
    {
      signal: "Postgres provisioned IOPS saturation (queue depth / wait events)",
      action: `Raise gp3/io2 IOPS toward peak_eps × ${PG_IOPS_PER_EVENT} budget; review index bloat`,
      owner: "platform",
    },
    {
      signal: "events table resident size > 70% of allocated volume",
      action: "Expand volume; confirm retention job; consider partition by month",
      owner: "platform",
    },
    {
      signal: "MinIO/S3 growth > 80% of bucket/PVC quota",
      action: "Enforce 90d raw lifecycle; expand quota; cold-tier transition",
      owner: "platform",
    },
    {
      signal: "Single Postgres primary is sole copy (any fleet ≥5k coding intensity)",
      action: "Move to external multi-AZ managed Postgres; prove restore drill",
      owner: "platform + security",
    },
    {
      signal: "Multi-AZ required by policy (RPO≈0) regardless of load",
      action: "External multi-AZ DB + multi-AZ object store; document RPO/RTO",
      owner: "security policy",
    },
  ];
}

// ---- output ------------------------------------------------------------

function buildReport(endpoints) {
  return {
    title: "Capacity plan projection — 5k–10k endpoints",
    generatedAt: new Date().toISOString(),
    honesty: {
      measured: [
        "Dogfood per-device rates at 700 devices (6.833 events/device/day)",
        "PG bytes/event ≈ 1,195 B; MinIO ≈ 973 B/event",
        "Coding mix constants and 700-engineer peak 93.3 eps sustained p99=161ms",
        "Single-node SLO ceiling ≈ 775 eps; max throughput ≈ 2,345 eps (latency-degraded)",
        "PG bytes/event ≈ 1,332 B",
        "Admission enforce maxInflight=64, zero silent loss under shed",
      ],
      extrapolated: [
        "Linear scale of dogfood and coding rates from 700 → 5k/10k (no 5k/10k load test)",
        "Replica counts from ceil(burst / (775 × utilisation))",
        `Postgres IOPS budget = peak_eps × ${PG_IOPS_PER_EVENT} (not measured)`,
        "Topology class recommendations (multi-AZ thresholds)",
        "Coding-track MinIO bytes/event reuses dogfood measurement",
      ],
      caveats: [
        NODE.provenance,
        "Admission is per-process; multi-node global admission is a residual",
        "Cost figures in source docs exclude API/web tier, egress, backups",
      ],
    },
    inputs: { DOGFOOD, CODING, NODE, PG_IOPS_PER_EVENT, RETENTION },
    formulas: {
      dogfood_events_per_day: "devices × 6.833",
      dogfood_workday_eps: "events_per_day / (8 × 3600)",
      dogfood_burst_eps: "workday_eps × 10",
      coding_events_per_day: "devices × 8 × 40",
      coding_workday_eps: "events_per_day / (8 × 3600)",
      coding_honest_peak_eps: "workday_eps × 4 × 3",
      min_replicas: "max(1, ceil(burst_eps / 775))",
      recommended_replicas:
        "max(min_replicas, ceil(burst_eps / (775 × 0.5)), ha_floor)",
      pg_growth_bytes_day: "events_per_day × pg_bytes_per_event",
      minio_growth_bytes_day: "events_per_day × minio_bytes_per_event",
      peak_iops_budget: `burst_eps × ${PG_IOPS_PER_EVENT}`,
    },
    tiers: endpoints.map(projectTier),
    scalingTriggers: scalingTriggers(),
  };
}

function printHuman(report) {
  console.log(`# ${report.title}`);
  console.log(`generated: ${report.generatedAt}`);
  console.log("");
  console.log("## Honesty");
  console.log("MEASURED:");
  for (const m of report.honesty.measured) console.log(`  - ${m}`);
  console.log("EXTRAPOLATED:");
  for (const m of report.honesty.extrapolated) console.log(`  - ${m}`);
  console.log("");

  for (const tier of report.tiers) {
    console.log(`## ${tier.devices.toLocaleString()} endpoints`);
    for (const track of ["dogfood", "coding"]) {
      const t = tier[track];
      console.log(`### ${track}`);
      console.log(
        `  events/day ........ ${t.eventsPerDay.toLocaleString()}  (${t.eventsPerDevicePerDay}/device)`,
      );
      console.log(`  workday avg eps ... ${t.workdayAvgEps}`);
      console.log(`  burst eps ......... ${t.burstEps}  [${t.burstDefinition}]`);
      console.log(
        `  PG growth ......... ${t.storage.pgGrowthGbPerDay} GB/day · ${t.storage.pgResidentGbAtRetention} GB @ ${t.storage.retention.eventsMonths}mo`,
      );
      console.log(
        `  MinIO growth ...... ${t.storage.minioGrowthGbPerDay} GB/day · ${t.storage.minioResidentGbAtRetention} GB @ ${t.storage.retention.rawArchiveDays}d`,
      );
      console.log(
        `  peak IOPS budget .. ${t.iops.peakProvisionedIops}  (${t.iops.model})`,
      );
      console.log(
        `  ingest replicas ... min=${t.scale.minReplicasForSlo} recommended=${t.scale.recommendedIngestReplicas} (headroom×${t.scale.headroomAtRecommended})`,
      );
      console.log(
        `  admission ......... ${t.scale.admission.mode} maxInflight=${t.scale.admission.maxInflightPerReplica}/replica`,
      );
      console.log(`  postgres .......... ${t.topology.postgres.tier}`);
      console.log(`  object store ...... ${t.topology.objectStore.tier}`);
      console.log(`  confidence ........ ${t.confidence}`);
      console.log("");
    }
  }

  console.log("## Scaling triggers");
  for (const tr of report.scalingTriggers) {
    console.log(`- WHEN ${tr.signal}`);
    console.log(`  THEN ${tr.action}  (owner: ${tr.owner})`);
  }
}

function printCsv(report) {
  const headers = [
    "devices",
    "track",
    "events_per_day",
    "workday_eps",
    "burst_eps",
    "pg_gb_day",
    "pg_gb_retained",
    "minio_gb_day",
    "minio_gb_retained",
    "peak_iops_budget",
    "min_replicas",
    "recommended_replicas",
    "postgres_tier",
  ];
  console.log(headers.join(","));
  for (const tier of report.tiers) {
    for (const track of ["dogfood", "coding"]) {
      const t = tier[track];
      console.log(
        [
          tier.devices,
          track,
          t.eventsPerDay,
          t.workdayAvgEps,
          t.burstEps,
          t.storage.pgGrowthGbPerDay,
          t.storage.pgResidentGbAtRetention,
          t.storage.minioGrowthGbPerDay,
          t.storage.minioResidentGbAtRetention,
          t.iops.peakProvisionedIops,
          t.scale.minReplicasForSlo,
          t.scale.recommendedIngestReplicas,
          JSON.stringify(t.topology.postgres.tier),
        ].join(","),
      );
    }
  }
}

const endpoints = parseEndpoints();
const report = buildReport(endpoints);
const wantJson = process.argv.includes("--json");
const wantCsv = process.argv.includes("--csv");

if (wantCsv) printCsv(report);
else if (wantJson) console.log(JSON.stringify(report, null, 2));
else printHuman(report);

if (process.env.OUT) {
  writeFileSync(process.env.OUT, JSON.stringify(report, null, 2));
  console.error(`wrote ${process.env.OUT}`);
}

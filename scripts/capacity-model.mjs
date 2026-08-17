#!/usr/bin/env node
/**
 * capacity projection for 5k–10k endpoints.
 * Dogfood rates; upper-bound note.
 *
 * Usage:
 *   node scripts/capacity-model.mjs
 *   node scripts/capacity-model.mjs --devices 700,5000,10000 --burst 10
 */
const args = process.argv.slice(2);
function flag(name, def) {
  const i = args.indexOf(name);
  if (i === -1) return def;
  return args[i + 1] ?? def;
}

const EVENTS_PER_DEVICE_DAY = 6.833; // measured model
const HEARTBEAT_S = 300;
const WORKDAY_S = 8 * 3600;
const devices = String(flag("--devices", "700,5000,10000"))
  .split(",")
  .map((s) => parseInt(s.trim(), 10))
  .filter((n) => Number.isFinite(n) && n > 0);
const burst = parseFloat(flag("--burst", "10"));

function row(n) {
  const eventsDay = n * EVENTS_PER_DEVICE_DAY;
  const epsAvg = eventsDay / WORKDAY_S;
  const epsBurst = epsAvg * burst;
  const hbps = n / HEARTBEAT_S;
  return {
    devices: n,
    eventsPerDay: Math.round(eventsDay),
    eventsPerMonth: Math.round(eventsDay * 30),
    workdayAvgEps: Number(epsAvg.toFixed(3)),
    burstEps: Number(epsBurst.toFixed(3)),
    heartbeatsPerSec: Number(hbps.toFixed(3)),
    label: n <= 700 ? "pilot-measured-base" : "extrapolated-from-dogfood",
  };
}

const table = devices.map(row);
const out = {
  kind: "aim-635-capacity-model",
  source: {
    eventsPerDeviceDay: EVENTS_PER_DEVICE_DAY,
    heartbeatSeconds: HEARTBEAT_S,
    workdaySeconds: WORKDAY_S,
    burstMultiplier: burst,
    measuredAtDevices: 700,
    measuredRef: "docs/aim-323-fleet-scale-proof.md",
  },
  tiers: table,
  topologyHints: {
    700: { ingestReplicas: 2, apiReplicas: 2, postgres: "lab-or-small-managed", admissionMaxInflight: 64 },
    5000: { ingestReplicas: 3, apiReplicas: 3, postgres: "external-multi-az", admissionMaxInflight: 128 },
    10000: { ingestReplicas: 4, apiReplicas: 3, postgres: "external-multi-az+pooler", admissionMaxInflight: 256 },
  },
  notes: [
    "Dogfood rates are conservative (security pilot intensity).",
    "Upper-bound coding intensity can be 10–100× higher — load-test before 10k cutover.",
    "This script does not authorize cloud spend.",
  ],
};

console.log(JSON.stringify(out, null, 2));

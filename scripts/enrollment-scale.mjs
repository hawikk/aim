#!/usr/bin/env node
/**
 * synthetic enrollment scale toward ~700 endpoints.
 *
 * Posts N enrollments against a live ingest (/v1/enroll), measures latency
 * and success rate, then optionally cleans up by revoking via SQL when
 * CLEANUP=1 and a postgres container is reachable.
 *
 * Usage:
 *   ENROLL_TOKEN=dev-enroll-token-change-me node scripts/enrollment-scale.mjs
 *
 * Env:
 *   INGEST_URL      default http://127.0.0.1:8080
 *   ENROLL_TOKEN    required (legacy ENROLL_TOKENS env or minted token)
 *   N               default 700 (use N=50 for a quick smoke)
 *   CONCURRENCY     default 25
 *   RING            default ring0
 *   HOSTNAME_PREFIX default aim600-scale
 *   CLEANUP         set 1 to DELETE devices with hostname prefix after run
 *   PG_CONTAINER    optional; auto-detected when CLEANUP=1 (prefers aim-local)
 *   OUT             optional path to write JSON summary (also printed to stdout)
 */
import { randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { writeFileSync } from "node:fs";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

const BASE = process.env.INGEST_URL ?? "http://127.0.0.1:8080";
const TOKEN = process.env.ENROLL_TOKEN;
const N = Number(process.env.N ?? 700);
const CONCURRENCY = Number(process.env.CONCURRENCY ?? 25);
const RING = process.env.RING ?? "ring0";
const PREFIX = process.env.HOSTNAME_PREFIX ?? "aim600-scale";
const CLEANUP = process.env.CLEANUP === "1";
const OUT = process.env.OUT;

if (!TOKEN) {
  console.error("ENROLL_TOKEN is required");
  process.exit(2);
}
if (!Number.isFinite(N) || N < 1) {
  console.error("N must be a positive number");
  process.exit(2);
}

const results = {
  ok: 0,
  already: 0,
  fail: 0,
  statuses: {},
  latenciesMs: [],
};

function percentile(sorted, p) {
  if (sorted.length === 0) return null;
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[idx];
}

async function enrollOne(i) {
  const hostId = randomUUID();
  const body = {
    host_id: hostId,
    hostname: `${PREFIX}-${String(i).padStart(4, "0")}`,
    os: "linux-scale-sim",
    ring: RING,
    collector_version: "0.0.0-aim553",
  };
  const t0 = performance.now();
  let res;
  try {
    res = await fetch(`${BASE}/v1/enroll`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${TOKEN}`,
      },
      body: JSON.stringify(body),
    });
  } catch (err) {
    results.fail += 1;
    results.statuses["network_error"] = (results.statuses["network_error"] ?? 0) + 1;
    results.latenciesMs.push(performance.now() - t0);
    return { ok: false, err: String(err) };
  }
  const ms = performance.now() - t0;
  results.latenciesMs.push(ms);
  results.statuses[String(res.status)] = (results.statuses[String(res.status)] ?? 0) + 1;
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* ignore */
  }
  if (res.status === 201) {
    results.ok += 1;
    return { ok: true, ms, device_id: json?.device_id };
  }
  if (res.status === 200 && json?.already_enrolled) {
    results.already += 1;
    return { ok: true, already: true, ms };
  }
  results.fail += 1;
  return { ok: false, status: res.status, body: json };
}

async function mapPool(items, limit, fn) {
  let idx = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (idx < items.length) {
      const i = idx++;
      await fn(items[i], i);
    }
  });
  await Promise.all(workers);
}

console.log("== enrollment scale ==");
console.log(
  JSON.stringify(
    { base: BASE, N, concurrency: CONCURRENCY, ring: RING, prefix: PREFIX },
    null,
    0,
  ),
);

// Preflight
const health = await fetch(`${BASE}/healthz`).catch((e) => ({ ok: false, status: 0, err: e }));
if (!health.ok) {
  console.error(`FAIL: ingest healthz not ok at ${BASE}/healthz`);
  process.exit(1);
}

const wall0 = performance.now();
const indexes = Array.from({ length: N }, (_, i) => i + 1);
await mapPool(indexes, CONCURRENCY, async (i) => {
  await enrollOne(i);
});
const wallMs = performance.now() - wall0;

const sorted = [...results.latenciesMs].sort((a, b) => a - b);
const summary = {
  N,
  ok: results.ok,
  already: results.already,
  fail: results.fail,
  successRate: (results.ok + results.already) / N,
  statuses: results.statuses,
  wallSeconds: +(wallMs / 1000).toFixed(3),
  enrollPerSec: +((N / wallMs) * 1000).toFixed(2),
  latencyMs: {
    p50: percentile(sorted, 50)?.toFixed?.(1) ?? null,
    p95: percentile(sorted, 95)?.toFixed?.(1) ?? null,
    p99: percentile(sorted, 99)?.toFixed?.(1) ?? null,
    max: sorted.length ? sorted[sorted.length - 1].toFixed(1) : null,
  },
};

console.log(JSON.stringify(summary, null, 2));

if (OUT) {
  try {
    writeFileSync(OUT, JSON.stringify(summary, null, 2) + "\n");
    console.log(`wrote ${OUT}`);
  } catch (err) {
    console.warn("OUT write failed:", err?.message || err);
  }
}

if (CLEANUP) {
  let pg = process.env.PG_CONTAINER;
  if (!pg) {
    try {
      const { stdout } = await execFileP("docker", ["ps", "--format", "{{.Names}}"]);
      const names = stdout
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);
      // Prefer stable local stack over throwaway drill containers (aim599drill-*, etc.).
      pg =
        names.find((n) => /^aim-local-postgres/.test(n)) ||
        names.find((n) => /postgres/.test(n) && /aim-local/.test(n)) ||
        names.find((n) => /postgres/.test(n) && /^stack-aim-/.test(n)) ||
        names.find((n) => /postgres/.test(n) && /aim/.test(n) && !/drill/.test(n)) ||
        names.find((n) => /postgres/.test(n) && /aim/.test(n)) ||
        names.find((n) => /postgres/.test(n));
    } catch {
      pg = null;
    }
  }
  if (!pg) {
    console.warn("CLEANUP=1 but no postgres container found — skipped");
  } else {
    // PREFIX is controlled by this process (env), not raw SQL input from callers.
    const sql = `DELETE FROM devices WHERE hostname LIKE '${PREFIX.replace(/'/g, "")}-%';`;
    try {
      const { stdout } = await execFileP("docker", [
        "exec",
        pg,
        "psql",
        "-U",
        "aim",
        "-d",
        "aim",
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        sql,
      ]);
      console.log(`cleanup via ${pg}:`, stdout.trim());
    } catch (err) {
      console.warn("cleanup failed:", err?.stderr || err);
    }
  }
}

const pass = results.fail === 0 && results.ok + results.already === N;
if (!pass) {
  console.error("RESULT: FAIL");
  process.exit(1);
}
console.log("RESULT: PASS");
process.exit(0);

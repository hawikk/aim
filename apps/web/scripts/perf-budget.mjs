#!/usr/bin/env node
/**
 * performance budget measurement under synthetic 700-seat load.
 *
 * Measures:
 *  1. Gzip transfer sizes for critical path + eager index.html modules
 *  2. tableHtml render times at 700 and 5_000 rows (users / fleet / findings)
 *  3. Synthetic API payload sizes for those row sets
 *  4. Optional Playwright navigation timing against a scale fixture server
 *
 * Usage:
 *   cd apps/web && npm run perf:budget
 *   npm run perf:budget -- --out ../../docs/aim-709-perf-measurement.json
 *   npm run perf:budget -- --no-browser
 *
 * Exit 1 if any 700-seat hard budget fails. 5k overruns are reported as
 * path-to-5k gaps (exit still 1 only when 700-seat gates fail, unless --strict-5k).
 */
import { readFileSync, existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, extname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createServer } from 'node:http';
import { gzipSync } from 'node:zlib';
import { performance } from 'node:perf_hooks';

const here = dirname(fileURLToPath(import.meta.url));
const PUBLIC = join(here, '..', 'public');
const REPO_DOCS = join(here, '..', '..', '..', 'docs');
const DEFAULT_OUT = join(REPO_DOCS, 'aim-709-perf-measurement.json');

/** Hard budgets (700-seat). Sizes in bytes gzip; times in ms. */
export const BUDGETS_700 = {
  criticalShellGzip: 80 * 1024,
  vendorChartGzip: 75 * 1024,
  criticalPathTotalGzip: 155 * 1024,
  eagerModuleTaxGzip: 100 * 1024,
  usersTableRenderMs: 100,
  fleetTableRenderMs: 120,
  findingsTableRenderMs: 80,
  usersPayloadBytes: 350 * 1024,
  fleetPayloadBytes: 500 * 1024,
  findingsPayloadBytes: 250 * 1024,
  navDomContentLoadedMs: 2500,
  navLoadMs: 3500,
};

/** Path-to-5k: reported, not hard-fail unless --strict-5k. */
export const BUDGETS_5K = {
  usersTableRenderMs: 150,
  fleetTableRenderMs: 150,
  usersPayloadBytes: 350 * 1024,
  fleetPayloadBytes: 500 * 1024,
};

const CRITICAL_SHELL = [
  'index.html',
  'styles.css',
  'app.js',
  'lib/api.js',
  'lib/dom.js',
  'lib/format.js',
  'lib/components.js',
  'lib/runtime.js',
  'lib/router.js',
  'lib/ui.js',
  'lib/severity.js',
  'lib/charts.js',
  'views/overview.js',
];

const VENDOR_CHART = 'vendor/chart.umd.js';
const TEAMS = ['Engineering', 'Platform', 'Security', 'Data', 'Mobile', 'Infra', 'Design', 'Product'];
const OS = ['darwin', 'linux', 'windows'];
const SEV = ['critical', 'high', 'medium', 'low'];

function parseArgs(argv) {
  const out = { out: DEFAULT_OUT, browser: true, strict5k: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out') out.out = resolve(argv[++i]);
    else if (a === '--no-browser') out.browser = false;
    else if (a === '--strict-5k') out.strict5k = true;
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node scripts/perf-budget.mjs [--out PATH] [--no-browser] [--strict-5k]');
      process.exit(0);
    }
  }
  return out;
}

function gzipSize(buf) {
  return gzipSync(buf, { level: 9 }).length;
}

function fileGzip(rel) {
  const p = join(PUBLIC, rel);
  if (!existsSync(p)) return { path: rel, raw: 0, gzip: 0, missing: true };
  const buf = readFileSync(p);
  return { path: rel, raw: buf.length, gzip: gzipSize(buf), missing: false };
}

function eagerModulesFromIndex() {
  const html = readFileSync(join(PUBLIC, 'index.html'), 'utf8');
  const mods = [];
  const re = /<script\s+type="module"\s+src="([^"]+)"/g;
  let m;
  while ((m = re.exec(html))) mods.push(m[1].replace(/^\//, ''));
  return mods;
}

function measureAssets() {
  const shell = CRITICAL_SHELL.map(fileGzip);
  const chart = fileGzip(VENDOR_CHART);
  const shellGzip = shell.reduce((s, f) => s + f.gzip, 0);
  const criticalTotal = shellGzip + chart.gzip;
  const eager = eagerModulesFromIndex().map(fileGzip);
  const taxFiles = eager.filter((f) => f.path !== 'app.js');
  const taxGzip = taxFiles.reduce((s, f) => s + f.gzip, 0);
  return {
    shell,
    chart,
    shellGzip,
    criticalPathTotalGzip: criticalTotal,
    eagerModules: eager,
    eagerModuleTaxGzip: taxGzip,
  };
}

function day(offsetHours) {
  return new Date(Date.now() - offsetHours * 3600_000).toISOString();
}

function hex(n, i) {
  return i.toString(16).padStart(n, '0').slice(-n);
}

/** Synthetic /api/users payload at N seats. */
export function synthUsers(n) {
  const users = [];
  for (let i = 0; i < n; i++) {
    users.push({
      pseudonym: `u_${hex(16, i + 0x1000)}`,
      team: TEAMS[i % TEAMS.length],
      teamFromEvents: TEAMS[i % TEAMS.length],
      teamOverride: null,
      sessions: 10 + (i % 200),
      tools: 1 + (i % 6),
      tokens: 50_000 + i * 1200,
      costUsd: Number((2.5 + (i % 40) * 0.37).toFixed(2)),
      lastActive: day(i % 72),
      flagHits: i % 11 === 0 ? (i % 5) + 1 : 0,
    });
  }
  return {
    rangeDays: 30,
    note: 'Synthetic 700-seat fixture; pseudonymous only.',
    users,
  };
}

/** Synthetic /api/fleet payload at N devices. */
export function synthFleet(n) {
  const devices = [];
  const healthCycle = ['healthy', 'healthy', 'healthy', 'stale', 'dead', 'never_seen', 'healthy'];
  for (let i = 0; i < n; i++) {
    const health = healthCycle[i % healthCycle.length];
    const silent = health === 'stale' || health === 'dead';
    devices.push({
      device_id: `d_${hex(16, i + 0x2000)}`,
      host_id: `h_${hex(16, i + 0x3000)}`,
      hostname: health === 'never_seen' ? null : `eng-laptop-${String(i).padStart(4, '0')}`,
      os: OS[i % OS.length],
      ring: i % 20 === 0 ? 'canary' : 'broad',
      collector_version: '0.9.3',
      enrolled_at: day(24 * 30),
      last_heartbeat_at: health === 'never_seen' ? null : day(health === 'healthy' ? 0.1 : 6),
      heartbeat_interval_sec: 300,
      health,
      silent,
      coverageGap: health !== 'healthy',
      events_rejected: silent ? 10 + (i % 50) : 0,
      events_spooled: silent ? i % 20 : 0,
      batches_fully_rejected: silent && i % 7 === 0 ? 1 : 0,
      last_rejection_at: silent ? day(2) : null,
      rejected_ratio: silent ? 0.02 : 0,
      drop_active: silent && i % 5 === 0,
    });
  }
  const summary = {
    deployed: n,
    healthy: 0,
    stale: 0,
    dead: 0,
    never_seen: 0,
    silent: 0,
    coverageGaps: 0,
    dropping: 0,
    lastVerifiedAt: new Date().toISOString(),
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

/** Synthetic findings page (API max 200). */
export function synthFindings(n) {
  const findings = [];
  for (let i = 0; i < n; i++) {
    findings.push({
      findingId: `f-${1000 + i}`,
      ts: day(i % 48),
      detectedAt: day(i % 48),
      ruleId: i % 3 === 0 ? 'secret-in-prompt' : 'unapproved-tool',
      severity: SEV[i % SEV.length],
      title: `Synthetic finding ${i}`,
      subject: { user_ref: `u_${hex(16, i)}`, host_ref: `h_${hex(16, i)}` },
      evidence: { summary: `synthetic evidence line ${i}` },
      policyHash: 'polhash_synthetic_aim709',
      decision: 'observe',
      eventId: `e-f-${i}`,
      status: i % 2 === 0 ? 'new' : 'acknowledged',
      triageNote: null,
      triagedBy: null,
      triagedAt: null,
    });
  }
  return { total: n, limit: n, offset: 0, findings };
}

async function loadTableHtml() {
  const mod = await import(pathToFileURL(join(PUBLIC, 'lib/components.js')).href);
  return mod.tableHtml;
}

const USER_COLS = [
  { key: 'pseudonym', label: 'Pseudonym', render: (r) => r.pseudonym },
  { key: 'team', label: 'Team', render: (r) => r.team ?? '' },
  { key: 'tools', label: 'Tools', num: true },
  { key: 'sessions', label: 'Sessions', num: true, render: (r) => String(r.sessions) },
  { key: 'tokens', label: 'Tokens', num: true, render: (r) => String(r.tokens) },
  { key: 'costUsd', label: 'Est. cost', num: true, render: (r) => String(r.costUsd) },
  { key: 'flagHits', label: 'Flags', num: true, render: (r) => String(r.flagHits) },
  { key: 'lastActive', label: 'Last active', render: (r) => r.lastActive },
];

const FLEET_COLS = [
  { key: 'host_id', label: 'Host', render: (r) => r.host_id },
  { key: 'hostname', label: 'Device', render: (r) => r.hostname ?? '—' },
  { key: 'health', label: 'Health', render: (r) => r.health },
  { key: 'events_rejected', label: 'Ingest health', render: (r) => String(r.events_rejected) },
  { key: 'last_heartbeat_at', label: 'Last heartbeat', render: (r) => r.last_heartbeat_at ?? 'never' },
  { key: 'collector_version', label: 'Collector', render: (r) => r.collector_version ?? '—' },
  { key: 'os', label: 'OS', render: (r) => r.os ?? '—' },
];

const FINDING_COLS = [
  { key: 'severity', label: 'Severity', render: (r) => r.severity },
  { key: 'title', label: 'Title', render: (r) => r.title },
  { key: 'ruleId', label: 'Rule', render: (r) => r.ruleId },
  { key: 'status', label: 'Status', render: (r) => r.status },
  { key: 'detectedAt', label: 'Detected', render: (r) => r.detectedAt },
];

function timeRender(tableHtml, cols, rows, caption, iterations = 3) {
  tableHtml(cols, rows.slice(0, Math.min(10, rows.length)), { caption });
  const times = [];
  let htmlBytes = 0;
  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    const html = tableHtml(cols, rows, { caption });
    const t1 = performance.now();
    times.push(t1 - t0);
    htmlBytes = html.length;
  }
  times.sort((a, b) => a - b);
  return {
    medianMs: Number(times[Math.floor(times.length / 2)].toFixed(2)),
    minMs: Number(times[0].toFixed(2)),
    maxMs: Number(times[times.length - 1].toFixed(2)),
    htmlBytes,
    rows: rows.length,
  };
}

function measureRenders(tableHtml) {
  const u700 = synthUsers(700);
  const u5k = synthUsers(5000);
  const f700 = synthFleet(700);
  const f5k = synthFleet(5000);
  const find200 = synthFindings(200);

  return {
    users700: timeRender(tableHtml, USER_COLS, u700.users, 'Users 700'),
    users5k: timeRender(tableHtml, USER_COLS, u5k.users, 'Users 5k'),
    fleet700: timeRender(tableHtml, FLEET_COLS, f700.devices, 'Fleet 700'),
    fleet5k: timeRender(tableHtml, FLEET_COLS, f5k.devices, 'Fleet 5k'),
    findings200: timeRender(tableHtml, FINDING_COLS, find200.findings, 'Findings 200'),
    payload: {
      users700Bytes: Buffer.byteLength(JSON.stringify(u700)),
      users5kBytes: Buffer.byteLength(JSON.stringify(u5k)),
      fleet700Bytes: Buffer.byteLength(JSON.stringify(f700)),
      fleet5kBytes: Buffer.byteLength(JSON.stringify(f5k)),
      findings200Bytes: Buffer.byteLength(JSON.stringify(find200)),
    },
    notes: {
      apiUsersHardLimit: 500,
      apiUsersHardLimitNote:
        'Production GET /api/users uses LIMIT 500 with no total — a 700-seat pilot can hide 200 active users.',
      apiFleetUnbounded: true,
    },
  };
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
};

async function startScaleFixtureServer(usersPayload, fleetPayload) {
  const { populatedRoutes, ME_ADMIN } = await import(
    pathToFileURL(join(here, '..', 'test/helpers/fixtures.js')).href
  );
  const routes = {
    ...populatedRoutes(ME_ADMIN),
    '/api/users': usersPayload,
    '/api/fleet': fleetPayload,
  };

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname.startsWith('/api/')) {
      let body = routes[url.pathname];
      if (body === undefined) {
        for (const [pattern, handler] of Object.entries(routes)) {
          if (pattern.endsWith('/*') && url.pathname.startsWith(pattern.slice(0, -1))) {
            body = handler;
            break;
          }
        }
      }
      if (body === undefined) {
        res.writeHead(404, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: 'no fixture', path: url.pathname }));
      }
      const data = typeof body === 'function'
        ? body({ searchParams: url.searchParams, method: req.method })
        : body;
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(data));
    }
    const rel = url.pathname === '/' ? '/index.html' : url.pathname;
    const file = join(PUBLIC, rel);
    try {
      const buf = await readFile(file);
      res.writeHead(200, { 'content-type': MIME[extname(file)] ?? 'application/octet-stream' });
      return res.end(buf);
    } catch {
      res.writeHead(404);
      return res.end('not found');
    }
  });

  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return {
    origin: `http://127.0.0.1:${port}`,
    close: () => new Promise((r) => server.close(r)),
  };
}

async function measureBrowser(usersPayload, fleetPayload) {
  let chromium;
  try {
    ({ chromium } = await import('playwright'));
  } catch {
    return { skipped: true, reason: 'playwright not installed' };
  }

  const server = await startScaleFixtureServer(usersPayload, fleetPayload);
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch (err) {
    await server.close().catch(() => {});
    return { skipped: true, reason: `chromium launch failed: ${err?.message || err}` };
  }

  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const views = ['overview', 'fleet', 'users'];
    const results = {};
    for (const view of views) {
      const hash = view === 'overview' ? '#/' : `#/${view}`;
      const t0 = performance.now();
      await page.goto(`${server.origin}/${hash}`, { waitUntil: 'networkidle', timeout: 30_000 });
      await page.waitForTimeout(200);
      const timing = await page.evaluate(() => {
        const nav = performance.getEntriesByType('navigation')[0];
        const paints = Object.fromEntries(
          performance.getEntriesByType('paint').map((p) => [p.name, p.startTime]),
        );
        return {
          domContentLoaded: nav?.domContentLoadedEventEnd ?? null,
          load: nav?.loadEventEnd ?? null,
          responseEnd: nav?.responseEnd ?? null,
          transferSize: nav?.transferSize ?? null,
          fcp: paints['first-contentful-paint'] ?? null,
        };
      });
      const wallMs = performance.now() - t0;
      const rowCount = await page.evaluate(() => {
        const tables = [...document.querySelectorAll('table tbody')];
        return tables.map((tb) => tb.querySelectorAll('tr').length);
      });
      results[view] = {
        wallMs: Number(wallMs.toFixed(1)),
        ...timing,
        tableRowCounts: rowCount,
      };
    }
    return { skipped: false, origin: server.origin, views: results };
  } catch (err) {
    return { skipped: true, reason: String(err?.message || err) };
  } finally {
    await browser.close().catch(() => {});
    await server.close().catch(() => {});
  }
}

function check(name, actual, budget, unit = '') {
  const pass = actual <= budget;
  return {
    name,
    actual,
    budget,
    unit,
    pass,
    overBy: pass ? 0 : Number((actual - budget).toFixed(2)),
  };
}

function evaluate(assets, renders, browser, opts) {
  const checks700 = [
    check('critical_shell_gzip', assets.shellGzip, BUDGETS_700.criticalShellGzip, 'B'),
    check('vendor_chart_gzip', assets.chart.gzip, BUDGETS_700.vendorChartGzip, 'B'),
    check('critical_path_total_gzip', assets.criticalPathTotalGzip, BUDGETS_700.criticalPathTotalGzip, 'B'),
    check('eager_module_tax_gzip', assets.eagerModuleTaxGzip, BUDGETS_700.eagerModuleTaxGzip, 'B'),
    check('users_table_700_ms', renders.users700.medianMs, BUDGETS_700.usersTableRenderMs, 'ms'),
    check('fleet_table_700_ms', renders.fleet700.medianMs, BUDGETS_700.fleetTableRenderMs, 'ms'),
    check('findings_table_200_ms', renders.findings200.medianMs, BUDGETS_700.findingsTableRenderMs, 'ms'),
    check('users_payload_700_B', renders.payload.users700Bytes, BUDGETS_700.usersPayloadBytes, 'B'),
    check('fleet_payload_700_B', renders.payload.fleet700Bytes, BUDGETS_700.fleetPayloadBytes, 'B'),
    check('findings_payload_200_B', renders.payload.findings200Bytes, BUDGETS_700.findingsPayloadBytes, 'B'),
  ];

  if (browser && !browser.skipped) {
    for (const [view, t] of Object.entries(browser.views || {})) {
      if (t.domContentLoaded != null) {
        checks700.push(
          check(`nav_${view}_dcl_ms`, t.domContentLoaded, BUDGETS_700.navDomContentLoadedMs, 'ms'),
        );
      }
      if (t.load != null) {
        checks700.push(check(`nav_${view}_load_ms`, t.load, BUDGETS_700.navLoadMs, 'ms'));
      }
    }
  }

  const checks5k = [
    check('users_table_5k_ms', renders.users5k.medianMs, BUDGETS_5K.usersTableRenderMs, 'ms'),
    check('fleet_table_5k_ms', renders.fleet5k.medianMs, BUDGETS_5K.fleetTableRenderMs, 'ms'),
    check('users_payload_5k_B', renders.payload.users5kBytes, BUDGETS_5K.usersPayloadBytes, 'B'),
    check('fleet_payload_5k_B', renders.payload.fleet5kBytes, BUDGETS_5K.fleetPayloadBytes, 'B'),
  ];

  const fail700 = checks700.filter((c) => !c.pass);
  const fail5k = checks5k.filter((c) => !c.pass);

  return {
    checks700,
    checks5k,
    fail700,
    fail5k,
    pass700: fail700.length === 0,
    pass5k: fail5k.length === 0,
    exitCode: fail700.length > 0 || (opts.strict5k && fail5k.length > 0) ? 1 : 0,
  };
}

function printReport(evalResult, assets, renders, browser) {
  const line = (c) => {
    const mark = c.pass ? 'PASS' : 'FAIL';
    const a = c.unit === 'B' ? `${(c.actual / 1024).toFixed(1)} KB` : `${c.actual}${c.unit}`;
    const b = c.unit === 'B' ? `${(c.budget / 1024).toFixed(1)} KB` : `${c.budget}${c.unit}`;
    return `  [${mark}] ${c.name}: ${a} (budget ${b})`;
  };
  console.log('\n=== performance budget (700 seats) ===');
  console.log(`Critical shell gzip: ${(assets.shellGzip / 1024).toFixed(1)} KB`);
  console.log(`Chart vendor gzip:   ${(assets.chart.gzip / 1024).toFixed(1)} KB`);
  console.log(`Critical path total: ${(assets.criticalPathTotalGzip / 1024).toFixed(1)} KB`);
  console.log(`Eager module tax:    ${(assets.eagerModuleTaxGzip / 1024).toFixed(1)} KB`);
  console.log(`Users table 700:     ${renders.users700.medianMs} ms (${renders.users700.htmlBytes} HTML bytes)`);
  console.log(`Fleet table 700:     ${renders.fleet700.medianMs} ms`);
  console.log(`Users table 5k:      ${renders.users5k.medianMs} ms`);
  console.log(`Fleet table 5k:      ${renders.fleet5k.medianMs} ms`);
  console.log('\n700-seat gates:');
  for (const c of evalResult.checks700) console.log(line(c));
  console.log('\n5k path (informational unless --strict-5k):');
  for (const c of evalResult.checks5k) console.log(line(c));
  if (browser?.skipped) {
    console.log(`\nBrowser timing: skipped (${browser.reason})`);
  } else if (browser) {
    console.log('\nBrowser navigation (fixture server + 700-seat users/fleet):');
    console.log(JSON.stringify(browser.views, null, 2));
  }
  console.log(`\nResult: 700-seat ${evalResult.pass700 ? 'PASS' : 'FAIL'} | 5k path ${evalResult.pass5k ? 'PASS' : 'GAPS'}`);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const assets = measureAssets();
  const tableHtml = await loadTableHtml();
  const renders = measureRenders(tableHtml);

  let browser = { skipped: true, reason: '--no-browser' };
  if (opts.browser) {
    browser = await measureBrowser(synthUsers(700), synthFleet(700));
  }

  const evalResult = evaluate(assets, renders, browser, opts);
  printReport(evalResult, assets, renders, browser);

  const report = {
    measuredAt: new Date().toISOString(),
    scaleModel: { pilotSeats: 700, pathTo: 5000 },
    budgets: { '700': BUDGETS_700, '5k': BUDGETS_5K },
    assets,
    renders,
    browser,
    evaluation: {
      pass700: evalResult.pass700,
      pass5k: evalResult.pass5k,
      fail700: evalResult.fail700,
      fail5k: evalResult.fail5k,
      checks700: evalResult.checks700,
      checks5k: evalResult.checks5k,
    },
    knownServerLimits: renders.notes,
    doc: 'docs/frontend-performance-budget.md',
  };

  await mkdir(dirname(opts.out), { recursive: true });
  await writeFile(opts.out, JSON.stringify(report, null, 2) + '\n');
  console.log(`\nWrote ${opts.out}`);
  process.exit(evalResult.exitCode);
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main().catch((err) => {
    console.error(err);
    process.exit(2);
  });
}

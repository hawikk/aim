#!/usr/bin/env node
/**
 * Operator CLI policy simulation (dry-run against historical findings).
 * Equivalent surface to `aim policy simulate`.
 *
 * Usage:
 *   node scripts/aim-policy-simulate.mjs --days 7
 *   node scripts/aim-policy-simulate.mjs --days 14 --pack-id pack-abc123
 *   node scripts/aim-policy-simulate.mjs --days 7 --disable-rule anomalous-volume-hourly
 *   node scripts/aim-policy-simulate.mjs --offline --findings-json f.json --enforcement-dispositions-json e.json
 *
 * Env: AIM_API_URL, AIM_API_TOKEN, AIM_SESSION_COOKIE
 */
import { readFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const apiSrc = join(here, '..', 'apps', 'api', 'src');

function usage(code = 2) {
  console.error(`Usage: aim policy simulate [options]
       node scripts/aim-policy-simulate.mjs [options]

Options:
  --days N                 lookback window (default 7, max 90)
  --pack-id ID             candidate signed policy pack from registry
  --pack-file PATH         candidate pack envelope JSON (not promoted)
  --enforcement-file PATH  candidate endpoint enforcement.json
  --disable-rule ID        drop a guardrail rule from the candidate (repeatable)
  --severity ID=LEVEL      override severity on the candidate (repeatable)
  --json                   print full report JSON (default: text summary)
  --api-url URL            override AIM_API_URL
  --token TOKEN            override AIM_API_TOKEN
  --cookie COOKIE          session cookie (alternative to bearer token)
  --offline                pure local projection from fixture files (no API)
  --findings-json PATH     offline: [{rule_id,severity,n}, ...]
  --enforcement-dispositions-json PATH  offline: [{rule_id,action,n}, ...]
  -h, --help               this help
`);
  process.exit(code);
}

function argValue(args, name) {
  const i = args.indexOf(name);
  if (i < 0) return null;
  return args[i + 1] ?? null;
}

function allValues(args, name) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === name && args[i + 1]) out.push(args[++i]);
  }
  return out;
}

const args = process.argv.slice(2);
if (args.includes('-h') || args.includes('--help')) usage(0);

const days = argValue(args, '--days') ?? '7';
const packId = argValue(args, '--pack-id');
const packFile = argValue(args, '--pack-file');
const enforcementFile = argValue(args, '--enforcement-file');
const disableRules = allValues(args, '--disable-rule');
const severityArgs = allValues(args, '--severity');
const wantJson = args.includes('--json');
const offline = args.includes('--offline');
const findingsJson = argValue(args, '--findings-json');
const enfDispJson = argValue(args, '--enforcement-dispositions-json');
const apiUrl = (argValue(args, '--api-url') || process.env.AIM_API_URL || '').replace(/\/$/, '');
const token = argValue(args, '--token') || process.env.AIM_API_TOKEN || '';
const cookie = argValue(args, '--cookie') || process.env.AIM_SESSION_COOKIE || '';

const severityOverrides = {};
for (const s of severityArgs) {
  const [id, level] = s.split('=');
  if (!id || !level) {
    console.error(`bad --severity ${s} (want ruleId=severity)`);
    process.exit(2);
  }
  severityOverrides[id] = level;
}

async function runOffline() {
  const {
    projectEnforcementCounts,
    sumEnforcementBaseline,
    projectFindingCounts,
    sumFindingBaseline,
    rulesFromPackFiles,
    applyRuleDeltas,
    buildSimulationReport,
    formatSimulationSummary,
    parseSimDays,
  } = await import(join(apiSrc, 'policy-simulate.js'));

  const findingRows = findingsJson
    ? JSON.parse(readFileSync(resolve(findingsJson), 'utf8'))
    : [];
  const enfRows = enfDispJson
    ? JSON.parse(readFileSync(resolve(enfDispJson), 'utf8'))
    : [];

  let candidateRules = new Map();
  let policyHash = null;
  let source = 'offline';
  let resolvedPackId = null;

  if (packFile) {
    const pack = JSON.parse(readFileSync(resolve(packFile), 'utf8'));
    const parsed = rulesFromPackFiles(pack.payload?.files ?? []);
    candidateRules = parsed.rules;
    policyHash = pack.payload?.policyHash ?? parsed.policyHash;
    source = 'pack-file';
    resolvedPackId = pack.packId ?? null;
  } else {
    for (const r of findingRows) {
      const id = r.rule_id ?? r.ruleId;
      if (id) candidateRules.set(id, { id, severity: r.severity || 'medium' });
    }
    source = 'historical-identity';
  }
  candidateRules = applyRuleDeltas(candidateRules, {
    disableRules: disableRules.length ? disableRules : undefined,
    severityOverrides: Object.keys(severityOverrides).length ? severityOverrides : undefined,
  });

  let enfBundle = null;
  if (enforcementFile) {
    enfBundle = JSON.parse(readFileSync(resolve(enforcementFile), 'utf8'));
  }

  const d = parseSimDays(days);
  const to = new Date();
  const from = new Date(to.getTime() - d * 86400_000);
  const baselineAlerts = sumFindingBaseline(findingRows);
  const candidateAlerts = projectFindingCounts(findingRows, candidateRules);
  const baselineBlocks = sumEnforcementBaseline(enfRows);
  const candidateBlocks = enfBundle
    ? projectEnforcementCounts(enfRows, enfBundle)
    : {
      byRule: baselineBlocks.byRule.map((r) => ({
        ruleId: r.ruleId,
        enforced: false,
        baseline: { ...r },
        candidate: {
          blocked: r.blocked || 0,
          would_block: r.would_block || 0,
          confirmed: r.confirmed || 0,
          redacted: r.redacted || 0,
          total: r.total || 0,
        },
      })),
      totals: { ...baselineBlocks.totals },
    };

  const report = buildSimulationReport({
    days: d,
    from: from.toISOString(),
    to: to.toISOString(),
    baselineBlocks,
    candidateBlocks,
    baselineAlerts,
    candidateAlerts,
    candidateMeta: {
      source,
      packId: resolvedPackId,
      policyHash,
      enforcementMode: enfBundle?.mode ?? null,
      enforcementPolicyHash: enfBundle?.policy_hash ?? null,
      ruleCount: candidateRules.size,
      notes: ['offline mode — no API / DB'],
    },
  });
  report.textSummary = formatSimulationSummary(report);
  return report;
}

async function runRemote() {
  if (!apiUrl) {
    console.error('AIM_API_URL (or --api-url) is required unless --offline');
    process.exit(2);
  }
  if (!token && !cookie) {
    console.error('AIM_API_TOKEN / --token or AIM_SESSION_COOKIE / --cookie required');
    process.exit(2);
  }

  const body = { days: Number(days) || 7 };
  if (packId) body.packId = packId;
  if (packFile) body.pack = JSON.parse(readFileSync(resolve(packFile), 'utf8'));
  if (enforcementFile) {
    body.enforcement = JSON.parse(readFileSync(resolve(enforcementFile), 'utf8'));
  }
  if (disableRules.length) body.disableRules = disableRules;
  if (Object.keys(severityOverrides).length) body.severityOverrides = severityOverrides;

  const headers = {
    'content-type': 'application/json',
    accept: 'application/json',
  };
  if (token) headers.authorization = `Bearer ${token}`;
  if (cookie) headers.cookie = cookie;

  const res = await fetch(`${apiUrl}/api/policy/simulate`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let report;
  try {
    report = JSON.parse(text);
  } catch {
    console.error(`API ${res.status}: ${text.slice(0, 400)}`);
    process.exit(1);
  }
  if (!res.ok) {
    console.error(`API ${res.status}: ${JSON.stringify(report)}`);
    process.exit(1);
  }
  return report;
}

const report = offline ? await runOffline() : await runRemote();
if (wantJson) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(report.textSummary || JSON.stringify(report.delta?.summary, null, 2));
}
process.exit(0);

// Policy simulation API (AIM-686).
//
//   POST /api/policy/simulate
//     Body (all optional except at least one candidate source OR empty body
//     for "live enforcement vs itself" identity check):
//       {
//         days?: number,                 // default 7, max 90
//         packId?: string,               // registry pack → candidate guardrail rules
//         pack?: object,                 // full signed envelope (not stored)
//         enforcement?: object,          // candidate endpoint enforcement.json
//         useLiveEnforcement?: boolean,  // default true when enforcement omitted
//         disableRules?: string[],
//         enableOnlyRules?: string[],
//         severityOverrides?: { [ruleId]: severity }
//       }
//
//   Dry-run only: reads findings + enforcement events, never mutates policy
//   or writes findings. Admin only (same gate as pack promote).
//
//   GET /api/policy/simulate?days=N&packId=...
//     Same report via query params (packId / days / useLiveEnforcement only;
//     complex deltas require POST).

import { query } from '../db.js';
import { requireRoles } from '../auth.js';
import { audit } from '../audit.js';
import { loadPolicy, policyPath } from '../guardrail-policy.js';
import { loadEnforcementPolicy } from '../enforcement-policy.js';
import { loadPack, packDir, recomputePolicyHash } from '../policy-pack.js';
import {
  parseSimDays,
  rulesFromPackFiles,
  candidateRulesFromLive,
  applyRuleDeltas,
  projectEnforcementCounts,
  sumEnforcementBaseline,
  projectFindingCounts,
  sumFindingBaseline,
  buildSimulationReport,
  formatSimulationSummary,
} from '../policy-simulate.js';

async function loadFindingRows(fromIso) {
  const { rows } = await query(
    `SELECT rule_id, severity, COUNT(*)::int AS n
       FROM findings
      WHERE detected_at >= $1
      GROUP BY 1, 2`,
    [fromIso],
  );
  return rows;
}

async function loadEnforcementRows(fromIso) {
  const { rows } = await query(
    `SELECT payload->'enforcement'->>'rule_id' AS rule_id,
            payload->'enforcement'->>'action' AS action,
            COUNT(*)::int AS n
       FROM events
      WHERE ts >= $1
        AND payload ? 'enforcement'
      GROUP BY 1, 2`,
    [fromIso],
  );
  return rows;
}

function resolveCandidateRules({ pack, packId, dir, livePolicy, deltas }) {
  const notes = [];
  let source = 'live';
  let resolvedPackId = null;
  let policyHash = livePolicy?.contentHash ?? null;
  let rules;
  let parseErrors = [];

  if (packId || pack) {
    let envelope = pack;
    if (packId && !pack) {
      envelope = loadPack(dir, packId);
      if (!envelope) {
        return { error: { code: 404, body: { error: 'not_found', detail: `no pack ${packId} in registry` } } };
      }
    }
    const files = envelope?.payload?.files;
    if (!Array.isArray(files) || files.length === 0) {
      return { error: { code: 400, body: { error: 'bad_request', detail: 'pack has no files' } } };
    }
    const parsed = rulesFromPackFiles(files);
    rules = parsed.rules;
    parseErrors = parsed.parseErrors;
    try {
      policyHash = envelope.payload?.policyHash || recomputePolicyHash(files);
    } catch {
      policyHash = parsed.policyHash;
    }
    source = packId ? 'packId' : 'pack';
    resolvedPackId = envelope.packId || packId || null;
    notes.push(`Candidate guardrail rules loaded from pack (${rules.size} rules).`);
  } else {
    rules = candidateRulesFromLive(livePolicy, {});
    notes.push(`Candidate guardrail rules defaulted to live policy at ${policyPath()} (${rules.size} rules).`);
  }

  const before = rules.size;
  rules = applyRuleDeltas(rules, deltas);
  if (deltas.disableRules?.length || deltas.enableOnlyRules || deltas.severityOverrides) {
    notes.push(
      `Applied rule deltas (disable=${(deltas.disableRules || []).length}, `
      + `enableOnly=${deltas.enableOnlyRules ? deltas.enableOnlyRules.length : '—'}, `
      + `severityOverrides=${Object.keys(deltas.severityOverrides || {}).length}); `
      + `rules ${before} → ${rules.size}.`,
    );
    if (source === 'live') source = 'live+deltas';
    else source = `${source}+deltas`;
  }

  return {
    rules,
    source,
    packId: resolvedPackId,
    policyHash,
    notes,
    parseErrors,
  };
}

function resolveCandidateEnforcement({ bodyEnforcement, useLiveEnforcement }) {
  if (bodyEnforcement && typeof bodyEnforcement === 'object' && !Array.isArray(bodyEnforcement)) {
    return {
      bundle: bodyEnforcement,
      source: 'body',
      mode: bodyEnforcement.mode ?? null,
      policyHash: bodyEnforcement.policy_hash ?? bodyEnforcement.policyHash ?? null,
      notes: ['Candidate enforcement bundle supplied in request body.'],
    };
  }
  if (useLiveEnforcement === false) {
    return {
      bundle: null,
      source: 'none',
      mode: null,
      policyHash: null,
      notes: ['No candidate enforcement bundle — block projection uses baseline totals only (no remapping).'],
    };
  }
  const live = loadEnforcementPolicy();
  if (!live.loaded || !live.policy) {
    return {
      bundle: null,
      source: 'live_missing',
      mode: null,
      policyHash: null,
      notes: [`Live enforcement policy not loaded (${live.error || 'unknown'}); block projection is identity on baseline.`],
    };
  }
  return {
    bundle: live.policy,
    source: 'live',
    mode: live.policy.mode ?? null,
    policyHash: live.policy.policy_hash ?? null,
    notes: [`Candidate enforcement defaulted to live bundle at ${live.path}.`],
  };
}

function windowBounds(days) {
  const to = new Date();
  const from = new Date(to.getTime() - days * 86400_000);
  return {
    from: from.toISOString(),
    to: to.toISOString(),
    fromIso: from.toISOString(),
  };
}

export async function runPolicySimulate(input = {}, opts = {}) {
  const days = parseSimDays(input.days);
  const { from, to, fromIso } = windowBounds(days);
  const dir = opts.packDir ?? packDir();

  let livePolicy = null;
  try {
    livePolicy = opts.livePolicy ?? loadPolicy(opts.policyPath ?? policyPath());
  } catch (err) {
    livePolicy = { rules: [], contentHash: null, error: err.message };
  }

  const deltas = {
    disableRules: Array.isArray(input.disableRules) ? input.disableRules : undefined,
    enableOnlyRules: Array.isArray(input.enableOnlyRules) ? input.enableOnlyRules : undefined,
    severityOverrides:
      input.severityOverrides && typeof input.severityOverrides === 'object'
        ? input.severityOverrides
        : undefined,
  };

  const candRules = resolveCandidateRules({
    pack: input.pack,
    packId: input.packId,
    dir,
    livePolicy,
    deltas,
  });
  if (candRules.error) return candRules;

  const candEnf = resolveCandidateEnforcement({
    bodyEnforcement: input.enforcement,
    useLiveEnforcement: input.useLiveEnforcement,
  });

  const [findingRows, enfRows] = await Promise.all([
    (opts.loadFindings ?? loadFindingRows)(fromIso),
    (opts.loadEnforcement ?? loadEnforcementRows)(fromIso),
  ]);

  const baselineAlerts = sumFindingBaseline(findingRows);
  const candidateAlerts = projectFindingCounts(findingRows, candRules.rules);

  const baselineBlocks = sumEnforcementBaseline(enfRows);
  let candidateBlocks;
  if (candEnf.bundle) {
    candidateBlocks = projectEnforcementCounts(enfRows, candEnf.bundle);
  } else {
    candidateBlocks = {
      byRule: (baselineBlocks.byRule || []).map((r) => ({
        ruleId: r.ruleId,
        enforced: false,
        baseline: {
          blocked: r.blocked || 0,
          would_block: r.would_block || 0,
          confirmed: r.confirmed || 0,
          redacted: r.redacted || 0,
          total: r.total || 0,
        },
        candidate: {
          blocked: r.blocked || 0,
          would_block: r.would_block || 0,
          confirmed: r.confirmed || 0,
          redacted: r.redacted || 0,
          total: r.total || 0,
        },
      })),
      totals: { ...baselineBlocks.totals },
      enforceMap: {},
    };
  }

  const report = buildSimulationReport({
    days,
    from,
    to,
    baselineBlocks,
    candidateBlocks,
    baselineAlerts,
    candidateAlerts,
    candidateMeta: {
      source: candRules.source,
      packId: candRules.packId,
      policyHash: candRules.policyHash,
      enforcementMode: candEnf.mode,
      enforcementPolicyHash: candEnf.policyHash,
      ruleCount: candRules.rules.size,
      notes: [...candRules.notes, ...candEnf.notes],
    },
    notes: [
      ...(candRules.parseErrors || []).map((e) => `pack parse: ${e}`),
      livePolicy?.error ? `live policy load warning: ${livePolicy.error}` : null,
    ].filter(Boolean),
  });

  report.textSummary = formatSimulationSummary(report);
  return { report };
}

export async function policySimulateRoutes(fastify, opts = {}) {
  const adminOnly = requireRoles('admin');
  const dir = opts.packDir ?? packDir();

  async function handle(req, reply, input) {
    if (!adminOnly(req, reply)) return reply;
    let result;
    try {
      result = await runPolicySimulate(input, {
        packDir: dir,
        policyPath: opts.policyPath,
        livePolicy: opts.livePolicy,
        loadFindings: opts.loadFindings,
        loadEnforcement: opts.loadEnforcement,
      });
    } catch (err) {
      req.log?.error?.({ err }, 'policy.simulate failed');
      return reply.code(500).send({ error: 'simulate_failed', detail: err.message });
    }
    if (result.error) {
      return reply.code(result.error.code).send(result.error.body);
    }

    const actor = req.identity?.email ?? 'unknown';
    audit(actor, 'policy.simulate', 'policy/simulate', {
      days: result.report.window.days,
      packId: result.report.candidate.packId,
      policyHash: result.report.candidate.policyHash,
      delta: result.report.delta.summary,
      dryRun: true,
    });

    return result.report;
  }

  fastify.post('/api/policy/simulate', async (req, reply) => {
    const body = req.body ?? {};
    return handle(req, reply, {
      days: body.days,
      packId: body.packId,
      pack: body.pack,
      enforcement: body.enforcement,
      useLiveEnforcement: body.useLiveEnforcement,
      disableRules: body.disableRules,
      enableOnlyRules: body.enableOnlyRules,
      severityOverrides: body.severityOverrides,
    });
  });

  fastify.get('/api/policy/simulate', async (req, reply) => {
    const q = req.query ?? {};
    const useLive = q.useLiveEnforcement === '0' || q.useLiveEnforcement === 'false'
      ? false
      : undefined;
    return handle(req, reply, {
      days: q.days,
      packId: q.packId,
      useLiveEnforcement: useLive,
    });
  });
}

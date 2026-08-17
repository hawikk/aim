// AIM-687: canary policy rollout + automatic rollback on FP spike.
//
// Progressive deploy of a signed policy pack (AIM-688) with a cohort ladder
// (AIM-793 semantics: percent of hosts). A periodic / manual tick evaluates
// the detector session FP rate (AIM-672). If the rate breaches the canary
// SLO with enough session volume, the controller restores the baseline pack
// and freezes further expansion.
//
// Pure decision logic lives above I/O so unit tests need no Postgres.
// Persistence: <POLICY_PACK_DIR>/canary.json next to the pack registry.
//
// Status:
//   idle        — no active canary
//   running     — canary pack is active; cohort ladder in progress
//   completed   — ladder reached 100% (or final step) without FP breach
//   rolled_back — auto/manual rollback restored baseline pack

import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
} from 'node:fs';
import { join } from 'node:path';
import { packDir as defaultPackDir } from './policy-pack.js';
import { evaluateSessionFpRate, sessionFpSloPct } from './fp-rate.js';

export const CANARY_SCHEMA = 'aim.policy-canary/v1';
export const CANARY_STATE_FILE = 'canary.json';

/** Default progressive ladder — percent of fleet under the canary pack. */
export const DEFAULT_LADDER = Object.freeze([5, 25, 50, 100]);

/** Minimum sessions in the measurement window before FP can trigger rollback. */
export const DEFAULT_MIN_SESSIONS = 20;

/** Default max session FP rate (%) for canary bake (inherits detector SLO). */
export function defaultCanaryFpSloPct() {
  return sessionFpSloPct();
}

function ensureDir(dir) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

function atomicWriteJson(file, obj) {
  const tmp = `${file}.tmp-${process.pid}`;
  writeFileSync(tmp, `${JSON.stringify(obj, null, 2)}\n`, 'utf8');
  renameSync(tmp, file);
}

function iso(v) {
  if (v == null) return new Date().toISOString();
  if (v instanceof Date) return v.toISOString();
  const d = new Date(v);
  return Number.isFinite(d.getTime()) ? d.toISOString() : String(v);
}

function num(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

/**
 * Validate and clamp a ladder of cohort percents.
 * @param {unknown} input
 * @returns {number[]}
 */
export function normalizeLadder(input) {
  const raw = Array.isArray(input) && input.length > 0
    ? input
    : [...DEFAULT_LADDER];
  const out = [];
  let prev = -1;
  for (const step of raw) {
    const p = Math.round(num(step, NaN));
    if (!Number.isFinite(p) || p < 0 || p > 100) {
      throw new Error(`invalid ladder step: ${step} (need integer 0..100)`);
    }
    if (p <= prev) {
      throw new Error(`ladder must be strictly increasing; got ${p} after ${prev}`);
    }
    out.push(p);
    prev = p;
  }
  return out;
}

/**
 * Create a fresh running canary state.
 *
 * @param {{
 *   targetPackId: string,
 *   targetPolicyHash: string,
 *   baselinePackId: string|null,
 *   baselinePolicyHash: string|null,
 *   ladder?: number[],
 *   fpSloPct?: number,
 *   minSessions?: number,
 *   actor?: string,
 *   now?: Date|string,
 *   note?: string,
 * }} opts
 */
export function createCanaryState(opts) {
  if (!opts?.targetPackId) throw new Error('targetPackId is required');
  if (!opts?.targetPolicyHash) throw new Error('targetPolicyHash is required');

  const ladder = normalizeLadder(opts.ladder);
  const fpSloPct = Math.min(
    100,
    Math.max(0, num(opts.fpSloPct, defaultCanaryFpSloPct())),
  );
  const minSessions = Math.max(1, Math.floor(num(opts.minSessions, DEFAULT_MIN_SESSIONS)));
  const now = iso(opts.now);
  const actor = opts.actor || 'unknown';

  return {
    schema: CANARY_SCHEMA,
    status: 'running',
    targetPackId: String(opts.targetPackId),
    targetPolicyHash: String(opts.targetPolicyHash),
    baselinePackId: opts.baselinePackId != null ? String(opts.baselinePackId) : null,
    baselinePolicyHash: opts.baselinePolicyHash != null
      ? String(opts.baselinePolicyHash)
      : null,
    ladder,
    stepIndex: 0,
    cohortPercent: ladder[0],
    fpSloPct,
    minSessions,
    startedAt: now,
    startedBy: actor,
    updatedAt: now,
    completedAt: null,
    rolledBackAt: null,
    lastDecision: {
      action: 'start',
      reason: 'canary_started',
      at: now,
      cohortPercent: ladder[0],
      fp: null,
    },
    history: [
      {
        action: 'start',
        reason: opts.note || 'canary_started',
        at: now,
        actor,
        cohortPercent: ladder[0],
        stepIndex: 0,
        packId: String(opts.targetPackId),
      },
    ],
  };
}

/**
 * Pure: decide the next canary action from state + FP evaluation.
 *
 * Rollback triggers (all required for auto-rollback):
 *   - canary status is `running`
 *   - sessions >= minSessions (avoid zero-volume noise)
 *   - FP evaluation is `broken` (session FP rate > canary SLO)
 *
 * Expand when under SLO with enough sessions and not at final step.
 * Complete when under SLO at final step (100% / last ladder rung).
 *
 * @param {object|null} state
 * @param {object|null} fpEvaluation  result of evaluateSessionFpRate
 * @param {{ now?: Date|string }} [opts]
 * @returns {{
 *   action: 'idle'|'hold'|'expand'|'complete'|'rollback',
 *   reason: string,
 *   nextState: object|null,
 *   shouldRollback: boolean,
 *   shouldExpand: boolean,
 * }}
 */
export function evaluateCanaryTick(state, fpEvaluation, { now = new Date() } = {}) {
  const at = iso(now);

  if (!state || state.status === 'idle' || !state.status) {
    return {
      action: 'idle',
      reason: 'no_active_canary',
      nextState: state ?? null,
      shouldRollback: false,
      shouldExpand: false,
    };
  }

  if (state.status === 'rolled_back' || state.status === 'completed') {
    return {
      action: 'hold',
      reason: `canary_${state.status}`,
      nextState: state,
      shouldRollback: false,
      shouldExpand: false,
    };
  }

  // Running canary — evaluate FP.
  const sessions = Math.max(0, Math.floor(num(fpEvaluation?.sessions)));
  const minSessions = Math.max(1, Math.floor(num(state.minSessions, DEFAULT_MIN_SESSIONS)));
  const maxPct = num(state.fpSloPct, defaultCanaryFpSloPct());

  // Re-evaluate with the canary's own SLO so callers can pass raw counts
  // or a prebuilt evaluation sealed under a different SLO.
  let eval_ = fpEvaluation;
  if (fpEvaluation && typeof fpEvaluation === 'object') {
    if (
      fpEvaluation.sessions != null
      && (fpEvaluation.fpSessions != null || fpEvaluation.sessionFpRate != null)
    ) {
      const fpSessions = fpEvaluation.fpSessions != null
        ? fpEvaluation.fpSessions
        : Math.round(num(fpEvaluation.sessionFpRate) * num(fpEvaluation.sessions));
      eval_ = evaluateSessionFpRate(
        {
          sessions: fpEvaluation.sessions,
          fpSessions,
          findings: fpEvaluation.findings?.byRule
            ? Object.values(fpEvaluation.findings.byRule).flatMap((r) => [
              { ruleId: r.ruleId, status: 'false_positive', count: r.false_positive || 0 },
              { ruleId: r.ruleId, status: 'resolved', count: r.resolved || 0 },
              { ruleId: r.ruleId, status: 'new', count: r.new || 0 },
              { ruleId: r.ruleId, status: 'acknowledged', count: r.acknowledged || 0 },
            ])
            : undefined,
          period: fpEvaluation.period,
        },
        { maxSessionFpPct: maxPct, now },
      );
    }
  }

  const fpSummary = eval_
    ? {
      sessions: eval_.sessions,
      fpSessions: eval_.fpSessions,
      sessionFpRatePct: eval_.sessionFpRatePct,
      state: eval_.state,
      maxSessionFpPct: maxPct,
    }
    : null;

  // Insufficient volume: hold (never auto-expand or auto-rollback).
  if (!eval_ || sessions < minSessions) {
    const next = appendDecision(state, {
      action: 'hold',
      reason: 'insufficient_sessions',
      at,
      cohortPercent: state.cohortPercent,
      fp: fpSummary,
    });
    return {
      action: 'hold',
      reason: 'insufficient_sessions',
      nextState: next,
      shouldRollback: false,
      shouldExpand: false,
    };
  }

  // FP spike → automatic rollback.
  if (eval_.state === 'broken' || eval_.breach === true) {
    const next = applyRollback(state, {
      reason: 'fp_spike',
      actor: 'system:canary-controller',
      now: at,
      fp: fpSummary,
    });
    return {
      action: 'rollback',
      reason: 'fp_spike',
      nextState: next,
      shouldRollback: true,
      shouldExpand: false,
    };
  }

  // Under SLO — expand or complete.
  const ladder = normalizeLadder(state.ladder);
  const stepIndex = Math.max(0, Math.min(ladder.length - 1, Math.floor(num(state.stepIndex))));
  const atFinal = stepIndex >= ladder.length - 1;

  if (atFinal) {
    const next = applyComplete(state, {
      reason: 'ladder_complete',
      actor: 'system:canary-controller',
      now: at,
      fp: fpSummary,
    });
    return {
      action: 'complete',
      reason: 'ladder_complete',
      nextState: next,
      shouldRollback: false,
      shouldExpand: false,
    };
  }

  const next = applyExpand(state, {
    reason: 'fp_under_slo',
    actor: 'system:canary-controller',
    now: at,
    fp: fpSummary,
  });
  return {
    action: 'expand',
    reason: 'fp_under_slo',
    nextState: next,
    shouldRollback: false,
    shouldExpand: true,
  };
}

function appendDecision(state, decision) {
  return {
    ...state,
    updatedAt: decision.at,
    lastDecision: {
      action: decision.action,
      reason: decision.reason,
      at: decision.at,
      cohortPercent: decision.cohortPercent ?? state.cohortPercent,
      fp: decision.fp ?? null,
    },
  };
}

/**
 * Advance one ladder step. No-op if not running or already at final step
 * (caller should use applyComplete for terminal).
 */
export function applyExpand(state, {
  reason = 'expand',
  actor = 'unknown',
  now = new Date(),
  fp = null,
} = {}) {
  if (!state || state.status !== 'running') {
    throw new Error(`cannot expand canary in status=${state?.status ?? 'null'}`);
  }
  const ladder = normalizeLadder(state.ladder);
  const stepIndex = Math.max(0, Math.floor(num(state.stepIndex)));
  if (stepIndex >= ladder.length - 1) {
    return applyComplete(state, { reason: 'ladder_complete', actor, now, fp });
  }
  const nextIndex = stepIndex + 1;
  const at = iso(now);
  const history = [
    ...(state.history || []),
    {
      action: 'expand',
      reason,
      at,
      actor,
      fromStepIndex: stepIndex,
      toStepIndex: nextIndex,
      fromPercent: ladder[stepIndex],
      toPercent: ladder[nextIndex],
      fp,
    },
  ];
  return {
    ...state,
    stepIndex: nextIndex,
    cohortPercent: ladder[nextIndex],
    updatedAt: at,
    lastDecision: {
      action: 'expand',
      reason,
      at,
      cohortPercent: ladder[nextIndex],
      fp,
    },
    history,
  };
}

/**
 * Mark canary complete (final rung held under SLO).
 */
export function applyComplete(state, {
  reason = 'ladder_complete',
  actor = 'unknown',
  now = new Date(),
  fp = null,
} = {}) {
  if (!state || state.status !== 'running') {
    throw new Error(`cannot complete canary in status=${state?.status ?? 'null'}`);
  }
  const ladder = normalizeLadder(state.ladder);
  const at = iso(now);
  const finalIdx = ladder.length - 1;
  const history = [
    ...(state.history || []),
    {
      action: 'complete',
      reason,
      at,
      actor,
      cohortPercent: ladder[finalIdx],
      stepIndex: finalIdx,
      packId: state.targetPackId,
      fp,
    },
  ];
  return {
    ...state,
    status: 'completed',
    stepIndex: finalIdx,
    cohortPercent: ladder[finalIdx],
    updatedAt: at,
    completedAt: at,
    lastDecision: {
      action: 'complete',
      reason,
      at,
      cohortPercent: ladder[finalIdx],
      fp,
    },
    history,
  };
}

/**
 * Rollback canary: freeze status and point operators at baseline pack.
 * Does not itself rewrite active.json — the route / apply layer does that.
 */
export function applyRollback(state, {
  reason = 'fp_spike',
  actor = 'system:canary-controller',
  now = new Date(),
  fp = null,
} = {}) {
  if (!state) throw new Error('no canary state to roll back');
  if (state.status === 'rolled_back') {
    return state; // idempotent
  }
  if (state.status === 'idle') {
    throw new Error('cannot rollback idle canary');
  }
  const at = iso(now);
  const history = [
    ...(state.history || []),
    {
      action: 'rollback',
      reason,
      at,
      actor,
      fromPackId: state.targetPackId,
      toPackId: state.baselinePackId,
      fromPercent: state.cohortPercent,
      toPercent: 0,
      fp,
    },
  ];
  return {
    ...state,
    status: 'rolled_back',
    cohortPercent: 0,
    updatedAt: at,
    rolledBackAt: at,
    lastDecision: {
      action: 'rollback',
      reason,
      at,
      cohortPercent: 0,
      fp,
    },
    history,
  };
}

/** Clear to idle (operator dismiss after complete/rollback). */
export function clearCanaryState(state, { actor = 'unknown', now = new Date() } = {}) {
  const at = iso(now);
  return {
    schema: CANARY_SCHEMA,
    status: 'idle',
    targetPackId: null,
    targetPolicyHash: null,
    baselinePackId: state?.baselinePackId ?? null,
    baselinePolicyHash: state?.baselinePolicyHash ?? null,
    ladder: DEFAULT_LADDER.slice(),
    stepIndex: 0,
    cohortPercent: 0,
    fpSloPct: defaultCanaryFpSloPct(),
    minSessions: DEFAULT_MIN_SESSIONS,
    startedAt: null,
    startedBy: null,
    updatedAt: at,
    completedAt: null,
    rolledBackAt: null,
    lastDecision: {
      action: 'clear',
      reason: 'operator_clear',
      at,
      cohortPercent: 0,
      fp: null,
    },
    history: [
      ...(state?.history || []).slice(-20),
      { action: 'clear', reason: 'operator_clear', at, actor },
    ],
  };
}

// ── Persistence ──────────────────────────────────────────────────────────

export function canaryStatePath(dir = defaultPackDir()) {
  return join(dir, CANARY_STATE_FILE);
}

export function readCanaryState(dir = defaultPackDir()) {
  const path = canaryStatePath(dir);
  if (!existsSync(path)) {
    return {
      schema: CANARY_SCHEMA,
      status: 'idle',
      targetPackId: null,
      targetPolicyHash: null,
      baselinePackId: null,
      baselinePolicyHash: null,
      ladder: DEFAULT_LADDER.slice(),
      stepIndex: 0,
      cohortPercent: 0,
      fpSloPct: defaultCanaryFpSloPct(),
      minSessions: DEFAULT_MIN_SESSIONS,
      startedAt: null,
      startedBy: null,
      updatedAt: null,
      completedAt: null,
      rolledBackAt: null,
      lastDecision: null,
      history: [],
    };
  }
  try {
    const raw = JSON.parse(readFileSync(path, 'utf8'));
    if (!raw || typeof raw !== 'object') throw new Error('invalid canary state shape');
    return raw;
  } catch (err) {
    throw new Error(`failed to read canary state: ${err.message}`);
  }
}

export function writeCanaryState(dir, state) {
  if (!state || typeof state !== 'object') {
    throw new Error('canary state must be an object');
  }
  ensureDir(dir);
  atomicWriteJson(canaryStatePath(dir), state);
  return state;
}

/**
 * Public summary for API responses (no internal noise).
 */
export function publicCanaryView(state) {
  if (!state) return null;
  return {
    schema: state.schema ?? CANARY_SCHEMA,
    status: state.status ?? 'idle',
    targetPackId: state.targetPackId ?? null,
    targetPolicyHash: state.targetPolicyHash ?? null,
    baselinePackId: state.baselinePackId ?? null,
    baselinePolicyHash: state.baselinePolicyHash ?? null,
    ladder: Array.isArray(state.ladder) ? state.ladder : DEFAULT_LADDER.slice(),
    stepIndex: state.stepIndex ?? 0,
    cohortPercent: state.cohortPercent ?? 0,
    fpSloPct: state.fpSloPct ?? defaultCanaryFpSloPct(),
    minSessions: state.minSessions ?? DEFAULT_MIN_SESSIONS,
    startedAt: state.startedAt ?? null,
    startedBy: state.startedBy ?? null,
    updatedAt: state.updatedAt ?? null,
    completedAt: state.completedAt ?? null,
    rolledBackAt: state.rolledBackAt ?? null,
    lastDecision: state.lastDecision ?? null,
    history: Array.isArray(state.history) ? state.history.slice(-50) : [],
  };
}

/**
 * Build a rollback alert payload for the security.alert bus (optional).
 */
export function canaryRollbackAlert(state, fpEvaluation, { now = new Date() } = {}) {
  if (!state || state.status !== 'rolled_back') return null;
  const stamp = iso(now);
  const pct = fpEvaluation?.sessionFpRatePct ?? state.lastDecision?.fp?.sessionFpRatePct ?? '?';
  const max = state.fpSloPct ?? defaultCanaryFpSloPct();
  return {
    schema_version: '1.1',
    alert_id: null,
    dedupe_key: `policy-canary-rollback:${state.targetPackId}:${state.rolledBackAt ?? stamp}`,
    pillar: 'ai_usage',
    producer: { name: 'aim-policy-canary', version: '1.0.0' },
    finding_type: 'ai_usage.policy_canary_rollback',
    title: `Policy canary rolled back: FP ${pct}% > ${max}% SLO`.slice(0, 200),
    severity: 'high',
    severity_id: 4,
    status: 'new',
    observed_at: stamp,
    first_seen_at: stamp,
    last_seen_at: stamp,
    resource: {
      kind: 'host',
      ref: 'aim:security/policy-canary',
      display: 'Policy canary controller',
      provider: null,
      account_ref: null,
      region: null,
    },
    subject_ref: null,
    evidence: {
      source_uri: 'aim:/policy/canary',
      detail_count: 1,
      summary: (
        `Rolled back pack ${state.targetPackId} → baseline ${state.baselinePackId}; `
        + `reason=${state.lastDecision?.reason ?? 'fp_spike'}`
      ).slice(0, 240),
    },
    labels: {
      target_pack_id: String(state.targetPackId ?? '').slice(0, 128),
      baseline_pack_id: String(state.baselinePackId ?? '').slice(0, 128),
      reason: String(state.lastDecision?.reason ?? 'fp_spike').slice(0, 128),
      session_fp_rate_pct: String(pct).slice(0, 128),
      slo_max_pct: String(max).slice(0, 128),
    },
    remediation_hint: (
      'Inspect GET /api/policy/canary and GET /api/security/fp-rate. '
      + 'Baseline pack was restored as active. Tune the canary pack before re-start.'
    ).slice(0, 500),
  };
}

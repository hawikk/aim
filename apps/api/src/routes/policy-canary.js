// — canary policy rollout + auto-rollback on FP spike.
//
//   GET  /api/policy/canary           — current canary state + active pack
//   GET  /api/policy/canary/ladder    — default progressive ladder
//   POST /api/policy/canary/start     — promote target pack, start ladder
//   POST /api/policy/canary/tick      — evaluate FP; expand or auto-rollback
//   POST /api/policy/canary/expand    — manual expand one ladder step
//   POST /api/policy/canary/rollback  — force rollback to baseline pack
//   POST /api/policy/canary/clear     — dismiss completed/rolled_back state
//
// Admin only. Mutations audit policy.canary.* with actor + pack hashes.

import { requireRoles } from '../auth.js';
import { audit } from '../audit.js';
import {
  packDir,
  packMode,
  loadPublicKeyFromEnv,
  loadPack,
  readActive,
  writeActivePointer,
  verifyPack,
} from '../policy-pack.js';
import {
  DEFAULT_LADDER,
  DEFAULT_MIN_SESSIONS,
  defaultCanaryFpSloPct,
  createCanaryState,
  evaluateCanaryTick,
  applyExpand,
  applyRollback,
  applyComplete,
  clearCanaryState,
  readCanaryState,
  writeCanaryState,
  publicCanaryView,
  canaryRollbackAlert,
  normalizeLadder,
} from '../policy-canary.js';
import {
  evaluateSessionFpRate,
  loadSessionFpRate,
} from '../fp-rate.js';

export async function policyCanaryRoutes(fastify, opts = {}) {
  const dir = opts.packDir ?? packDir();
  const env = opts.env ?? process.env;
  const adminOnly = requireRoles('admin');
  // Optional injected FP loader for tests (skip Postgres).
  const loadFp = opts.loadSessionFpRate ?? loadSessionFpRate;

  function mode() {
    return opts.mode ?? packMode(env);
  }

  function pubkey() {
    return opts.publicKey ?? loadPublicKeyFromEnv(env);
  }

  function promotePack(pack, actor) {
    const m = mode();
    const pub = pubkey();
    let verification;

    if (m === 'enforce') {
      if (!pub) {
        const err = new Error('POLICY_PACK_PUBLIC_KEY is required to promote packs in enforce mode');
        err.code = 'promote_unavailable';
        err.statusCode = 503;
        throw err;
      }
      verification = verifyPack(pack, pub, {
        expectedKeyId: env.POLICY_PACK_KEY_ID || null,
      });
      if (!verification.ok) {
        const err = new Error(verification.reason || 'verification_failed');
        err.code = 'verification_failed';
        err.statusCode = 400;
        err.verification = verification;
        throw err;
      }
    } else if (pub) {
      verification = verifyPack(pack, pub, {
        expectedKeyId: env.POLICY_PACK_KEY_ID || null,
      });
      if (!verification.ok) {
        const err = new Error(verification.reason || 'verification_failed');
        err.code = 'verification_failed';
        err.statusCode = 400;
        err.verification = verification;
        throw err;
      }
    } else {
      verification = { ok: false, reason: 'unsigned_observe', checks: [] };
    }

    const pointer = writeActivePointer(dir, {
      pack,
      actor,
      verified: verification.ok === true,
      mode: m,
    });
    return { pointer, verification, mode: m };
  }

  async function resolveFp(req) {
    const body = req.body ?? {};
    // Inline metrics for dry-run / tests — never requires Postgres.
    if (body.sessions != null || body.fp != null) {
      const sessions = Number(body.sessions ?? body.fp?.sessions ?? 0);
      const fpSessions = Number(body.fpSessions ?? body.fp?.fpSessions ?? 0);
      const maxPct = Number(
        body.fpSloPct
        ?? readCanaryState(dir).fpSloPct
        ?? defaultCanaryFpSloPct(),
      );
      return evaluateSessionFpRate(
        {
          sessions,
          fpSessions,
          findings: body.findings,
          period: body.period,
        },
        { maxSessionFpPct: maxPct, now: new Date() },
      );
    }
    try {
      return await loadFp();
    } catch (err) {
      req.log?.warn?.({ err }, 'policy canary: FP load failed; treating as insufficient data');
      return evaluateSessionFpRate(
        { sessions: 0, fpSessions: 0 },
        { maxSessionFpPct: defaultCanaryFpSloPct() },
      );
    }
  }

  fastify.get('/api/policy/canary/ladder', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    return {
      defaultLadder: [...DEFAULT_LADDER],
      defaultFpSloPct: defaultCanaryFpSloPct(),
      defaultMinSessions: DEFAULT_MIN_SESSIONS,
      notes: [
        'Ladder steps are cohort percents: hosts under the canary pack.',
        'Expand/rollback is a policy_hash bump via the active pack pointer.',
        'Auto-rollback fires when session FP rate exceeds canary FP SLO with enough sessions.',
      ],
    };
  });

  fastify.get('/api/policy/canary', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const state = readCanaryState(dir);
    const active = readActive(dir);
    return {
      canary: publicCanaryView(state),
      active: active
        ? {
          packId: active.packId,
          policyHash: active.policyHash,
          promotedBy: active.promotedBy,
          promotedAt: active.promotedAt,
          verified: active.verified,
        }
        : null,
      mode: mode(),
    };
  });

  // Start: promote target pack as active, record baseline, begin ladder at step 0.
  fastify.post('/api/policy/canary/start', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const body = req.body ?? {};
    const packId = body.packId;
    if (!packId) {
      return reply.code(400).send({ error: 'bad_request', detail: 'packId is required' });
    }

    const existing = readCanaryState(dir);
    if (existing.status === 'running') {
      return reply.code(409).send({
        error: 'canary_already_running',
        detail: `canary already running for pack ${existing.targetPackId}`,
        canary: publicCanaryView(existing),
      });
    }

    const pack = loadPack(dir, packId);
    if (!pack) {
      return reply.code(404).send({ error: 'not_found', detail: `no pack ${packId} in registry` });
    }

    let ladder;
    try {
      ladder = body.ladder != null ? normalizeLadder(body.ladder) : [...DEFAULT_LADDER];
    } catch (err) {
      return reply.code(400).send({ error: 'bad_request', detail: err.message });
    }

    const actor = req.identity?.email ?? 'unknown';
    const previous = readActive(dir);

    let promoted;
    try {
      promoted = promotePack(pack, actor);
    } catch (err) {
      return reply.code(err.statusCode || 500).send({
        error: err.code || 'promote_failed',
        detail: err.message,
        verification: err.verification,
      });
    }

    const state = createCanaryState({
      targetPackId: pack.packId,
      targetPolicyHash: pack.payload.policyHash,
      baselinePackId: previous?.packId ?? null,
      baselinePolicyHash: previous?.policyHash ?? null,
      ladder,
      fpSloPct: body.fpSloPct,
      minSessions: body.minSessions,
      actor,
      note: body.note || 'canary_started',
    });
    writeCanaryState(dir, state);

    const auditRec = audit(actor, 'policy.canary.start', `policy/canary/${pack.packId}`, {
      targetPackId: pack.packId,
      targetPolicyHash: pack.payload.policyHash,
      baselinePackId: previous?.packId ?? null,
      baselinePolicyHash: previous?.policyHash ?? null,
      ladder,
      cohortPercent: state.cohortPercent,
      fpSloPct: state.fpSloPct,
      minSessions: state.minSessions,
    });

    return {
      started: true,
      canary: publicCanaryView(state),
      active: promoted.pointer,
      verification: promoted.verification,
      audit: auditRec
        ? { seq: auditRec.seq, seal: auditRec.seal, action: 'policy.canary.start' }
        : null,
    };
  });

  // Tick: evaluate FP → hold | expand | complete | auto-rollback.
  fastify.post('/api/policy/canary/tick', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const state = readCanaryState(dir);
    if (state.status !== 'running') {
      return {
        action: state.status === 'idle' ? 'idle' : 'hold',
        reason: state.status === 'idle' ? 'no_active_canary' : `canary_${state.status}`,
        canary: publicCanaryView(state),
        fp: null,
        rolledBack: false,
        expanded: false,
      };
    }

    const fp = await resolveFp(req);
    const decision = evaluateCanaryTick(state, fp, { now: new Date() });
    const actor = req.identity?.email ?? 'system:canary-controller';

    let nextState = decision.nextState;
    let rolledBack = false;
    let expanded = false;
    let completed = false;
    let active = readActive(dir);
    let promoteAudit = null;

    if (decision.shouldRollback) {
      // Restore baseline pack if we still have it.
      const baselineId = state.baselinePackId;
      if (baselineId) {
        const baseline = loadPack(dir, baselineId);
        if (baseline) {
          try {
            const promoted = promotePack(baseline, actor);
            active = promoted.pointer;
            promoteAudit = audit(actor, 'policy.canary.rollback', `policy/canary/${state.targetPackId}`, {
              reason: decision.reason,
              fromPackId: state.targetPackId,
              fromPolicyHash: state.targetPolicyHash,
              toPackId: baseline.packId,
              toPolicyHash: baseline.payload.policyHash,
              fp: {
                sessions: fp.sessions,
                fpSessions: fp.fpSessions,
                sessionFpRatePct: fp.sessionFpRatePct,
                state: fp.state,
              },
              cohortPercent: 0,
            });
          } catch (err) {
            req.log?.error?.(err, 'policy canary rollback promote failed');
            return reply.code(err.statusCode || 500).send({
              error: 'rollback_promote_failed',
              detail: err.message,
              verification: err.verification,
              canary: publicCanaryView(state),
              fp,
            });
          }
        } else {
          // No baseline pack on disk — still mark rolled_back; operator must re-promote.
          nextState = applyRollback(state, {
            reason: 'fp_spike_baseline_missing',
            actor,
            fp: {
              sessions: fp.sessions,
              fpSessions: fp.fpSessions,
              sessionFpRatePct: fp.sessionFpRatePct,
              state: fp.state,
            },
          });
          audit(actor, 'policy.canary.rollback', `policy/canary/${state.targetPackId}`, {
            reason: 'fp_spike_baseline_missing',
            fromPackId: state.targetPackId,
            toPackId: null,
            warning: 'baseline pack not in registry; active pointer unchanged',
            fp: {
              sessions: fp.sessions,
              fpSessions: fp.fpSessions,
              sessionFpRatePct: fp.sessionFpRatePct,
            },
          });
        }
      } else {
        // No baseline — still freeze canary; leave active as-is.
        audit(actor, 'policy.canary.rollback', `policy/canary/${state.targetPackId}`, {
          reason: decision.reason,
          fromPackId: state.targetPackId,
          toPackId: null,
          warning: 'no baseline pack recorded; active pointer unchanged',
          fp: {
            sessions: fp.sessions,
            fpSessions: fp.fpSessions,
            sessionFpRatePct: fp.sessionFpRatePct,
          },
        });
      }
      rolledBack = true;
    } else if (decision.action === 'expand') {
      expanded = true;
      audit(actor, 'policy.canary.expand', `policy/canary/${state.targetPackId}`, {
        reason: decision.reason,
        fromPercent: state.cohortPercent,
        toPercent: nextState.cohortPercent,
        stepIndex: nextState.stepIndex,
        fp: {
          sessions: fp.sessions,
          fpSessions: fp.fpSessions,
          sessionFpRatePct: fp.sessionFpRatePct,
          state: fp.state,
        },
      });
    } else if (decision.action === 'complete') {
      completed = true;
      audit(actor, 'policy.canary.complete', `policy/canary/${state.targetPackId}`, {
        reason: decision.reason,
        packId: state.targetPackId,
        policyHash: state.targetPolicyHash,
        cohortPercent: nextState.cohortPercent,
        fp: {
          sessions: fp.sessions,
          fpSessions: fp.fpSessions,
          sessionFpRatePct: fp.sessionFpRatePct,
          state: fp.state,
        },
      });
    }

    writeCanaryState(dir, nextState);

    const rollbackAlert = rolledBack
      ? canaryRollbackAlert(nextState, fp)
      : null;

    return {
      action: decision.action,
      reason: decision.reason,
      canary: publicCanaryView(nextState),
      fp: {
        sessions: fp.sessions,
        fpSessions: fp.fpSessions,
        sessionFpRatePct: fp.sessionFpRatePct,
        state: fp.state,
        message: fp.message,
        slo: fp.slo,
      },
      active: active
        ? {
          packId: active.packId,
          policyHash: active.policyHash,
          promotedBy: active.promotedBy,
          promotedAt: active.promotedAt,
        }
        : null,
      rolledBack,
      expanded,
      completed,
      rollbackAlert,
      audit: promoteAudit
        ? { seq: promoteAudit.seq, seal: promoteAudit.seal, action: 'policy.canary.rollback' }
        : null,
    };
  });

  // Manual expand one step (still requires running canary).
  fastify.post('/api/policy/canary/expand', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const state = readCanaryState(dir);
    if (state.status !== 'running') {
      return reply.code(409).send({
        error: 'canary_not_running',
        detail: `status=${state.status}`,
        canary: publicCanaryView(state),
      });
    }
    const actor = req.identity?.email ?? 'unknown';
    let next;
    try {
      const ladder = normalizeLadder(state.ladder);
      if (state.stepIndex >= ladder.length - 1) {
        next = applyComplete(state, {
          reason: req.body?.reason || 'manual_complete',
          actor,
        });
      } else {
        next = applyExpand(state, {
          reason: req.body?.reason || 'manual_expand',
          actor,
        });
      }
    } catch (err) {
      return reply.code(400).send({ error: 'expand_failed', detail: err.message });
    }
    writeCanaryState(dir, next);
    const action = next.status === 'completed' ? 'policy.canary.complete' : 'policy.canary.expand';
    const rec = audit(actor, action, `policy/canary/${state.targetPackId}`, {
      reason: req.body?.reason || 'manual',
      fromPercent: state.cohortPercent,
      toPercent: next.cohortPercent,
      stepIndex: next.stepIndex,
      status: next.status,
    });
    return {
      expanded: next.status === 'running',
      completed: next.status === 'completed',
      canary: publicCanaryView(next),
      audit: rec ? { seq: rec.seq, seal: rec.seal, action } : null,
    };
  });

  // Force rollback to baseline (operator kill-switch).
  fastify.post('/api/policy/canary/rollback', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const state = readCanaryState(dir);
    if (state.status !== 'running' && state.status !== 'completed') {
      return reply.code(409).send({
        error: 'canary_not_rollbackable',
        detail: `status=${state.status}`,
        canary: publicCanaryView(state),
      });
    }
    const actor = req.identity?.email ?? 'unknown';
    const reason = req.body?.reason || 'manual_rollback';
    let next = applyRollback(state, { reason, actor });
    let active = readActive(dir);

    if (state.baselinePackId) {
      const baseline = loadPack(dir, state.baselinePackId);
      if (baseline) {
        try {
          const promoted = promotePack(baseline, actor);
          active = promoted.pointer;
        } catch (err) {
          return reply.code(err.statusCode || 500).send({
            error: 'rollback_promote_failed',
            detail: err.message,
            verification: err.verification,
          });
        }
      }
    }

    writeCanaryState(dir, next);
    const rec = audit(actor, 'policy.canary.rollback', `policy/canary/${state.targetPackId}`, {
      reason,
      fromPackId: state.targetPackId,
      fromPolicyHash: state.targetPolicyHash,
      toPackId: state.baselinePackId,
      toPolicyHash: state.baselinePolicyHash,
      manual: true,
    });

    return {
      rolledBack: true,
      canary: publicCanaryView(next),
      active: active
        ? {
          packId: active.packId,
          policyHash: active.policyHash,
          promotedBy: active.promotedBy,
          promotedAt: active.promotedAt,
        }
        : null,
      audit: rec ? { seq: rec.seq, seal: rec.seal, action: 'policy.canary.rollback' } : null,
    };
  });

  // Dismiss terminal canary state.
  fastify.post('/api/policy/canary/clear', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const state = readCanaryState(dir);
    if (state.status === 'running') {
      return reply.code(409).send({
        error: 'canary_running',
        detail: 'rollback or complete before clear',
        canary: publicCanaryView(state),
      });
    }
    const actor = req.identity?.email ?? 'unknown';
    const next = clearCanaryState(state, { actor });
    writeCanaryState(dir, next);
    audit(actor, 'policy.canary.clear', 'policy/canary', {
      previousStatus: state.status,
      previousPackId: state.targetPackId,
    });
    return { cleared: true, canary: publicCanaryView(next) };
  });
}

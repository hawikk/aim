// team cost budgets + model/provider allowlist APIs.
// Tables: team_budgets, model_provider_allowlist (migration 019).
// Cost figures are estimates — every response carries estimateNote.
import { query } from '../db.js';
import { requireRoles } from '../auth.js';
import { COST_SQL } from '../pricing.js';

export const ESTIMATE_NOTE =
  'cost_estimate_usd / public list-price fallback; error bars apply — not invoiced spend. See docs/cost-attribution-accuracy.md';

function periodBounds(period, now = new Date()) {
  if (period === 'rolling_30d') {
    const to = now;
    const from = new Date(to.getTime() - 30 * 86400_000);
    return { from, to };
  }
  const from = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const to = now;
  return { from, to };
}

export async function modelCostRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const anyRole = requireRoles('security-admin', 'analyst', 'auditor');
  const adminOnly = requireRoles('security-admin');

  // ---- budgets -----------------------------------------------------------

  fastify.get('/api/governance/budgets', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    try {
      const { rows } = await db.query(
        `SELECT team, period, token_budget, cost_budget_usd, warn_pct, critical_pct,
                enabled, note, updated_at, updated_by
           FROM team_budgets ORDER BY team`,
      );
      return { estimateNote: ESTIMATE_NOTE, budgets: rows };
    } catch (err) {
      if (String(err?.message || err).includes('team_budgets')) {
        return {
          estimateNote: ESTIMATE_NOTE,
          budgets: [],
          note: 'team_budgets table missing — apply migration 019',
        };
      }
      throw err;
    }
  });

  fastify.put('/api/governance/budgets/:team', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const team = req.params.team;
    const b = req.body ?? {};
    if (b.token_budget == null && b.cost_budget_usd == null) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'token_budget or cost_budget_usd required',
      });
    }
    const actor = req.identity?.email ?? 'unknown';
    const { rows } = await db.query(
      `INSERT INTO team_budgets
         (team, period, token_budget, cost_budget_usd, warn_pct, critical_pct, enabled, note, updated_by)
       VALUES ($1, COALESCE($2,'calendar_month'), $3, $4, COALESCE($5,80), COALESCE($6,100), COALESCE($7,true), $8, $9)
       ON CONFLICT (team) DO UPDATE SET
         period = EXCLUDED.period,
         token_budget = EXCLUDED.token_budget,
         cost_budget_usd = EXCLUDED.cost_budget_usd,
         warn_pct = EXCLUDED.warn_pct,
         critical_pct = EXCLUDED.critical_pct,
         enabled = EXCLUDED.enabled,
         note = EXCLUDED.note,
         updated_at = now(),
         updated_by = EXCLUDED.updated_by
       RETURNING *`,
      [
        team,
        b.period ?? 'calendar_month',
        b.token_budget ?? null,
        b.cost_budget_usd ?? null,
        b.warn_pct ?? 80,
        b.critical_pct ?? 100,
        b.enabled ?? true,
        b.note ?? null,
        actor,
      ],
    );
    return { ...rows[0], estimateNote: ESTIMATE_NOTE };
  });

  // Utilization vs budgets for the current period.
  fastify.get('/api/governance/budgets/utilization', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    let budgets;
    try {
      ({ rows: budgets } = await db.query(
        `SELECT team, period, token_budget, cost_budget_usd, warn_pct, critical_pct, enabled
           FROM team_budgets WHERE enabled = true ORDER BY team`,
      ));
    } catch (err) {
      if (String(err?.message || err).includes('team_budgets')) {
        return {
          estimateNote: ESTIMATE_NOTE,
          utilization: [],
          note: 'team_budgets table missing — apply migration 019',
        };
      }
      throw err;
    }

    const out = [];
    for (const b of budgets) {
      const { from, to } = periodBounds(b.period);
      const { rows } = await db.query(
        `SELECT
           COALESCE(SUM(COALESCE(tokens_in,0) + COALESCE(tokens_out,0)), 0) AS tokens,
           COALESCE(SUM(${COST_SQL}), 0) AS cost
         FROM events
         WHERE team = $1 AND ts >= $2 AND ts < $3 AND tool <> 'genai_app'`,
        [b.team, from.toISOString(), to.toISOString()],
      );
      const tokens = Number(rows[0]?.tokens ?? 0);
      const cost = Number(rows[0]?.cost ?? 0);
      const tokenPct =
        b.token_budget != null && Number(b.token_budget) > 0
          ? (tokens / Number(b.token_budget)) * 100
          : null;
      const costPct =
        b.cost_budget_usd != null && Number(b.cost_budget_usd) > 0
          ? (cost / Number(b.cost_budget_usd)) * 100
          : null;
      const warn = Number(b.warn_pct ?? 80);
      const crit = Number(b.critical_pct ?? 100);
      out.push({
        team: b.team,
        period: b.period,
        periodFrom: from.toISOString(),
        periodTo: to.toISOString(),
        tokensUsed: tokens,
        tokenBudget: b.token_budget != null ? Number(b.token_budget) : null,
        tokenPct,
        tokenWarn: tokenPct != null && tokenPct >= warn,
        tokenCritical: tokenPct != null && tokenPct >= crit,
        costUsdUsed: cost,
        costBudgetUsd: b.cost_budget_usd != null ? Number(b.cost_budget_usd) : null,
        costPct,
        costWarn: costPct != null && costPct >= warn,
        costCritical: costPct != null && costPct >= crit,
      });
    }
    return { estimateNote: ESTIMATE_NOTE, utilization: out };
  });

  // ---- model/provider allowlist ------------------------------------------

  fastify.get('/api/governance/model-allowlist', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    try {
      const { rows } = await db.query(
        `SELECT id, scope_type, scope_id, provider, model, mode, enabled, note, created_at, updated_at
           FROM model_provider_allowlist
          ORDER BY scope_type, scope_id NULLS FIRST, provider, model`,
      );
      return {
        entries: rows,
        note: 'Empty allowlist for a scope = unrestricted (fail-open). mode=observe|enforce (observe→enforce rollout).',
      };
    } catch (err) {
      if (String(err?.message || err).includes('model_provider_allowlist')) {
        return {
          entries: [],
          note: 'model_provider_allowlist table missing — apply migration 019',
        };
      }
      throw err;
    }
  });

  fastify.post('/api/governance/model-allowlist', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const b = req.body ?? {};
    if (!b.scope_type || !['global', 'team'].includes(b.scope_type)) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'scope_type global|team required',
      });
    }
    if (b.provider == null && b.model == null) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'provider or model required',
      });
    }
    if (b.scope_type === 'team' && !b.scope_id) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'scope_id required for team scope',
      });
    }
    if (b.mode && !['observe', 'enforce'].includes(b.mode)) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'mode must be observe or enforce',
      });
    }
    const { rows } = await db.query(
      `INSERT INTO model_provider_allowlist
         (scope_type, scope_id, provider, model, mode, enabled, note)
       VALUES ($1, $2, $3, $4, COALESCE($5,'observe'), COALESCE($6,true), $7)
       RETURNING *`,
      [
        b.scope_type,
        b.scope_type === 'global' ? null : b.scope_id,
        b.provider ?? null,
        b.model ?? null,
        b.mode ?? 'observe',
        b.enabled ?? true,
        b.note ?? null,
      ],
    );
    return reply.code(201).send(rows[0]);
  });

  fastify.delete('/api/governance/model-allowlist/:id', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) {
      return reply.code(400).send({ error: 'bad_request', detail: 'numeric id required' });
    }
    const { rowCount } = await db.query(
      `DELETE FROM model_provider_allowlist WHERE id = $1`,
      [id],
    );
    if (!rowCount) return reply.code(404).send({ error: 'not_found' });
    return reply.code(204).send();
  });
}

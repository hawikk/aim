// Application-LLM telemetry read API (AIM-105 / AIM-574 / AIM-737, schema v1.3).
// Per-app view for first-party services instrumented with OTel GenAI semantic
// conventions and ingested via the OTLP receiver (source='otel', tool='genai_app'):
//   - model inventory per app (which models/providers each service calls)
//   - token metering + cost estimate per app and per model
//   - fleet-wide model distribution (list view, no drill-down required)
//   - error/latency operational signals (span status + duration)
//   - CSV export for apps and for model rollup (exportable AC)
//
// This is APM-class service telemetry: there is deliberately NO employee
// dimension here (user_ref/team are null on otel events), so no per-user
// privacy gate applies. service_name is company infrastructure, cleartext by
// design (same class as mcp_server — see packages/schema/FIELDS.md).
import { query } from '../db.js';
import { COST_SQL } from '../pricing.js';
import { requireRoles } from '../auth.js';
import { checkFormat, sendCsv, wantsCsv } from '../csv.js';

function parseDays(q, def = 30, max = 365) {
  const d = Number(q?.days ?? def);
  if (!Number.isFinite(d) || d < 1) return def;
  return Math.min(Math.floor(d), max);
}

const num = (v) => Number(v ?? 0);

const APPS_CSV_COLS = [
  { key: 'service', label: 'service' },
  { key: 'providers', label: 'providers' },
  { key: 'requests', label: 'requests' },
  { key: 'tokensInput', label: 'tokens_input' },
  { key: 'tokensOutput', label: 'tokens_output' },
  { key: 'costUsd', label: 'cost_usd' },
  { key: 'errorRate', label: 'error_rate' },
  { key: 'avgDurationMs', label: 'avg_duration_ms' },
  { key: 'p95DurationMs', label: 'p95_duration_ms' },
  { key: 'firstSeen', label: 'first_seen' },
  { key: 'lastSeen', label: 'last_seen' },
];

// AIM-737: model distribution export (fleet-wide OTel sources).
const MODELS_CSV_COLS = [
  { key: 'model', label: 'model' },
  { key: 'provider', label: 'provider' },
  { key: 'services', label: 'services' },
  { key: 'requests', label: 'requests' },
  { key: 'tokensInput', label: 'tokens_input' },
  { key: 'tokensOutput', label: 'tokens_output' },
  { key: 'tokens', label: 'tokens' },
  { key: 'costUsd', label: 'cost_usd' },
  { key: 'errors', label: 'errors' },
];

// opts.db is injectable for tests; defaults to the real pg pool.
export async function appsRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const anyRole = requireRoles('admin', 'analyst', 'auditor', 'viewer');

  // ---- per-app rollup: services, volume, tokens, cost, error/latency ----
  // AIM-737: ?breakdown=models&format=csv exports the fleet model rollup.
  fastify.get('/api/apps/llm', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const days = parseDays(req.query);
    const breakdown = String(req.query?.breakdown ?? '').toLowerCase();
    if (breakdown && breakdown !== 'models' && breakdown !== 'apps') {
      return reply.code(400).send({
        error: 'bad_request',
        detail: "breakdown must be 'models', 'apps', or omitted",
      });
    }
    const range = `e.ts >= now() - ($1 || ' days')::interval`;

    const summary = await db.query(
      `SELECT
         e.service_name AS service,
         COUNT(*) AS requests,
         COUNT(DISTINCT e.provider) FILTER (WHERE e.provider IS NOT NULL) AS providers,
         COALESCE(SUM(e.tokens_in), 0)  AS tokens_input,
         COALESCE(SUM(e.tokens_out), 0) AS tokens_output,
         COALESCE(SUM(${COST_SQL}), 0)  AS cost,
         COUNT(*) FILTER (WHERE e.status = 'error') AS errors,
         AVG(e.duration_ms) AS avg_duration_ms,
         percentile_cont(0.95) WITHIN GROUP (ORDER BY e.duration_ms) AS p95_duration_ms,
         MIN(e.ts) AS first_seen,
         MAX(e.ts) AS last_seen
       FROM events e
       WHERE e.source = 'otel' AND e.tool = 'genai_app' AND ${range}
       GROUP BY e.service_name
       ORDER BY cost DESC`,
      [days],
    );

    // Model inventory per service (which models each app actually calls).
    // AIM-574: tokens_in / tokens_out split so analysts can answer "how many
    // tokens" without aggregating client-side; `tokens` kept as the sum for
    // existing consumers (detail charts, fixtures).
    // AIM-737: cost_usd on every model row so estimated cost is first-class.
    const models = await db.query(
      `SELECT
         e.service_name AS service,
         COALESCE(e.model, '(unspecified)') AS model,
         MIN(e.provider) AS provider,
         COUNT(*) AS requests,
         COALESCE(SUM(e.tokens_in), 0) AS tokens_input,
         COALESCE(SUM(e.tokens_out), 0) AS tokens_output,
         COALESCE(SUM(e.tokens_in + e.tokens_out), 0) AS tokens,
         COALESCE(SUM(${COST_SQL}), 0) AS cost,
         COUNT(*) FILTER (WHERE e.status = 'error') AS errors
       FROM events e
       WHERE e.source = 'otel' AND e.tool = 'genai_app' AND ${range}
       GROUP BY e.service_name, 2
       ORDER BY e.service_name, tokens DESC, requests DESC`,
      [days],
    );

    // Fleet-wide model distribution across all OTel apps (AIM-574 list view).
    // One row per model — answers "which models / tokens / cost" without drill-down.
    const modelRollup = await db.query(
      `SELECT
         COALESCE(e.model, '(unspecified)') AS model,
         MIN(e.provider) AS provider,
         COUNT(DISTINCT e.service_name) AS services,
         COUNT(*) AS requests,
         COALESCE(SUM(e.tokens_in), 0) AS tokens_input,
         COALESCE(SUM(e.tokens_out), 0) AS tokens_output,
         COALESCE(SUM(e.tokens_in + e.tokens_out), 0) AS tokens,
         COALESCE(SUM(${COST_SQL}), 0) AS cost,
         COUNT(*) FILTER (WHERE e.status = 'error') AS errors
       FROM events e
       WHERE e.source = 'otel' AND e.tool = 'genai_app' AND ${range}
       GROUP BY 1
       ORDER BY tokens DESC, requests DESC`,
      [days],
    );


    const trend = await db.query(
      `SELECT
         e.service_name AS service,
         date_trunc('day', e.ts)::date AS day,
         COUNT(*) AS requests,
         COALESCE(SUM(e.tokens_in + e.tokens_out), 0) AS tokens,
         COUNT(*) FILTER (WHERE e.status = 'error') AS errors
       FROM events e
       WHERE e.source = 'otel' AND e.tool = 'genai_app' AND ${range}
       GROUP BY e.service_name, 2
       ORDER BY e.service_name, 2`,
      [days],
    );

    const modelsByService = new Map();
    for (const m of models.rows) {
      if (!modelsByService.has(m.service)) modelsByService.set(m.service, []);
      modelsByService.get(m.service).push({
        model: m.model,
        provider: m.provider,
        requests: num(m.requests),
        tokensInput: num(m.tokens_input),
        tokensOutput: num(m.tokens_output),
        tokens: num(m.tokens),
        costUsd: num(m.cost),
        errors: num(m.errors),
      });
    }
    const trendByService = new Map();
    for (const t of trend.rows) {
      if (!trendByService.has(t.service)) trendByService.set(t.service, []);
      trendByService.get(t.service).push({
        day: t.day,
        requests: num(t.requests),
        tokens: num(t.tokens),
        errors: num(t.errors),
      });
    }

    const providers = await db.query(
      `SELECT DISTINCT e.provider FROM events e
       WHERE e.source = 'otel' AND e.tool = 'genai_app' AND e.provider IS NOT NULL AND ${range}
       ORDER BY 1`,
      [days],
    );

    const rows = summary.rows.map((s) => ({
      service: s.service,
      providers: num(s.providers),
      requests: num(s.requests),
      tokensInput: num(s.tokens_input),
      tokensOutput: num(s.tokens_output),
      costUsd: num(s.cost),
      errors: num(s.errors),
      errorRate: num(s.requests) > 0 ? num(s.errors) / num(s.requests) : 0,
      avgDurationMs: s.avg_duration_ms === null ? null : Math.round(num(s.avg_duration_ms)),
      p95DurationMs: s.p95_duration_ms === null ? null : Math.round(num(s.p95_duration_ms)),
      firstSeen: s.first_seen,
      lastSeen: s.last_seen,
      models: modelsByService.get(s.service) ?? [],
      trend: trendByService.get(s.service) ?? [],
    }));

    const modelsFleet = modelRollup.rows.map((m) => ({
      model: m.model,
      provider: m.provider,
      services: num(m.services),
      requests: num(m.requests),
      tokensInput: num(m.tokens_input),
      tokensOutput: num(m.tokens_output),
      tokens: num(m.tokens),
      costUsd: num(m.cost),
      errors: num(m.errors),
    }));

    if (wantsCsv(req)) {
      if (breakdown === 'models') {
        return sendCsv(reply, `apps-llm-models-${days}d.csv`, MODELS_CSV_COLS, modelsFleet);
      }
      return sendCsv(reply, 'apps-llm.csv', APPS_CSV_COLS, rows);
    }
    return {
      rangeDays: days,
      services: rows.length,
      providersSeen: providers.rows.map((r) => r.provider),
      // AIM-574 / AIM-737: fleet-wide model distribution (metadata only).
      // AIM-574: fleet-wide model distribution (metadata only — model/provider/tokens).
      models: modelsFleet,
      apps: rows,
    };
  });
}

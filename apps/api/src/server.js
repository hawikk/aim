import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  authPlugin, mePayload, serviceTokenLoadError, serviceTokenNames,
} from './auth.js';
import { dashboardRoutes } from './routes/dashboard.js';
import { findingsRoutes } from './routes/findings.js';
import { fleetRoutes } from './routes/fleet.js';
import { enforcementRoutes } from './routes/enforcement.js';
import { installHealthRoutes } from './routes/install-health.js';
import {
  destinationHealthRoutes,
  startDestinationHealthAlerter,
} from './routes/destination-health.js';
import { onboardingRoutes } from './routes/onboarding.js';
import { sessionRoutes } from './routes/sessions.js';
import { guardrailRoutes } from './routes/guardrail.js';
import { policyPackRoutes } from './routes/policy-packs.js';
import { policyCanaryRoutes } from './routes/policy-canary.js';
import { policySimulateRoutes } from './routes/policy-simulate.js';
import { aggregateRoutes } from './routes/aggregate.js';
import { complianceRoutes } from './routes/compliance.js';
import { governanceRoutes } from './routes/governance.js';
import { auditRoutes } from './routes/audit.js';
import { viewsRoutes } from './routes/views.js';
import { appsRoutes } from './routes/apps.js';
import { vendorAdminRoutes } from './routes/vendor-admin.js';
import { mcpRoutes } from './routes/mcp.js';
import { shadowAiRoutes } from './routes/shadow-ai.js';
import { coverageRoutes } from './routes/coverage.js';
import { enforcementCoverageRoutes } from './routes/enforcement-coverage.js';
import { activityRoutes } from './routes/activity.js';
import { pipelineRoutes } from './routes/pipeline.js';
import { alertsRoutes, setAlertBusClient } from './routes/alerts.js';
import { inboxRoutes } from './routes/inbox.js';
import { modelCostRoutes } from './routes/model-cost.js';
import { sanctionedRoutes } from './routes/sanctioned.js';
import { casesRoutes } from './routes/cases.js';
import { scimRoutes, isScimConfigured } from './routes/scim.js';
import { breakGlassAdminRoutes } from './routes/break-glass-admin.js';
import { accessReviewRoutes } from './routes/access-review.js';
import {
  systemStatusRoutes,
  startSystemStatusAlerter,
  createAlertBusPublisher,
} from './routes/system-status.js';
import { startFindingSlaAlerter } from './finding-sla.js';
import { fpRateRoutes } from './routes/fp-rate.js';
import {
  startFpRateAlerter,
  startFpRateSnapshotScheduler,
} from './fp-rate.js';
import { createBusClient, schemaLoadError } from './alertbus.js';
import { initAudit, audit } from './audit.js';
import { refreshSanctionedTools, SANCTIONED_TOOLS } from './sanctioned.js';
import { loadRevocationsFromDb } from './session-revocation.js';
import { loadScimDirectory } from './scim-store.js';
import { loadAccessReviewCampaigns } from './access-review-store.js';
import * as db from './db.js';

const here = dirname(fileURLToPath(import.meta.url));
const webRoot = join(here, '..', '..', 'web', 'public');

const fastify = Fastify({ logger: true });

// Service tokens (AIM-165). Unlike the bus, a broken token FILE is fatal:
// it was explicitly configured, and the failure mode of continuing is an API
// that boots clean and 401s every headless consumer — the sentinel goes quiet
// and nothing says why. Refuse to start instead.
const serviceTokenError = serviceTokenLoadError();
if (serviceTokenError) {
  fastify.log.error({ serviceTokenError }, 'AIM_SERVICE_TOKENS_FILE is set but unusable — refusing to start');
  process.exit(1);
}
if (serviceTokenNames().length) {
  fastify.log.info({ serviceTokens: serviceTokenNames() }, 'service tokens loaded');
}

// Apply auth hooks at root scope (register() would encapsulate them away from the routes).
await authPlugin(fastify);
await fastify.register(dashboardRoutes);
await fastify.register(findingsRoutes);
await fastify.register(fleetRoutes);
await fastify.register(enforcementRoutes);
await fastify.register(installHealthRoutes);
await fastify.register(destinationHealthRoutes);
await fastify.register(onboardingRoutes);
await fastify.register(sessionRoutes);
await fastify.register(guardrailRoutes);
await fastify.register(policyPackRoutes);
await fastify.register(policyCanaryRoutes);
await fastify.register(policySimulateRoutes);
await fastify.register(aggregateRoutes);
await fastify.register(complianceRoutes);
await fastify.register(accessReviewRoutes);
await fastify.register(governanceRoutes);
await fastify.register(auditRoutes);
await fastify.register(viewsRoutes);
await fastify.register(appsRoutes);
await fastify.register(vendorAdminRoutes);
await fastify.register(mcpRoutes);
await fastify.register(shadowAiRoutes);
await fastify.register(coverageRoutes);
// AIM-781 fleet coverage on /api/enforcement/fleet-coverage (path split after
// concurrent AIM-789/AIM-781 merges both claimed /api/enforcement/coverage).
await fastify.register(enforcementCoverageRoutes);
await fastify.register(activityRoutes);
await fastify.register(pipelineRoutes);
await fastify.register(systemStatusRoutes);
await fastify.register(fpRateRoutes);
await fastify.register(alertsRoutes);
await fastify.register(inboxRoutes);
await fastify.register(modelCostRoutes);
await fastify.register(sanctionedRoutes);
await fastify.register(casesRoutes);
await fastify.register(scimRoutes);
await fastify.register(breakGlassAdminRoutes);
initAudit(fastify);

// AIM-713: hydrate SCIM directory from Postgres when configured. Missing
// table / DB offline is non-fatal — routes still work in-memory after push.
if (isScimConfigured()) {
  try {
    const loaded = await loadScimDirectory(db);
    if (loaded.ok) {
      fastify.log.info(
        { users: loaded.users, groups: loaded.groups },
        'SCIM directory hydrated from store',
      );
    } else {
      fastify.log.warn(
        { err: loaded.error },
        'SCIM directory not hydrated at boot (empty memory until IdP push or migration)',
      );
    }
  } catch (err) {
    fastify.log.warn({ err: err.message }, 'SCIM directory hydrate failed — continuing with empty memory');
  }
} else {
  fastify.log.info('SCIM provisioning disabled (AIM_SCIM_BEARER_TOKEN unset)');
}

// AIM-484: load the persisted sanctioned-tool list into the in-process cache
// so activity-score and other sync consumers start on the live allow-list
// rather than the AIM-16 seed until the first request refresh.
try {
  await refreshSanctionedTools();
  fastify.log.info({ tools: [...SANCTIONED_TOOLS] }, 'sanctioned-tool list loaded from store');
} catch (err) {
  // Non-fatal: missing table falls back inside refreshSanctionedTools; a
  // real DB outage still lets the API boot and serve health while consumers
  // keep the seed until connectivity returns.
  fastify.log.warn({ err: err.message }, 'sanctioned-tool list not loaded at boot — using seed until first successful refresh');
}

// AIM-613: hydrate session-revoke watermarks so process restarts keep
// mid-TTL leaver denials (memory alone would re-admit until re-revoke).
try {
  const n = await loadRevocationsFromDb(db);
  if (n > 0) {
    fastify.log.info({ revocations: n }, 'session revocations loaded from store');
  }
} catch (err) {
  fastify.log.warn(
    { err: err.message },
    'session revocations not loaded at boot — table missing or DB down; in-memory revokes still apply after admin call',
  );
}

// AIM-718: hydrate access-review campaigns so attestations survive restart.
try {
  await loadAccessReviewCampaigns(db);
  fastify.log.info('access-review campaigns loaded from store (if any)');
} catch (err) {
  fastify.log.warn(
    { err: err.message },
    'access-review campaigns not loaded at boot — table missing or DB down; in-memory reviews still apply this process',
  );
}

// AIM-290: publish system-status breaches onto the existing alert bus so
// Sentinel pages the same signals the #/status screen shows. Opt-in
// (SYSTEM_STATUS_ALERTS=1); never runs XADD on the request path.
// AIM-442: same bus for critical finding-ack SLA breaches (FINDING_SLA_ALERTS=1).
// AIM-672: same bus for secret/PII detector session FP-rate SLO breaches
// (DETECTOR_FP_RATE_ALERTS=1).
// AIM-704: same bus for alert destination delivery failures / SLO breaches
// (DESTINATION_HEALTH_ALERTS=1).
if (process.env.ALERT_BUS_URL) {
  const publish = createAlertBusPublisher({ log: fastify.log });
  const alerter = startSystemStatusAlerter({ publish, log: fastify.log });
  if (alerter.enabled) {
    fastify.log.info('system-status alerter enabled (SYSTEM_STATUS_ALERTS)');
    fastify.addHook('onClose', async () => alerter.stop());
  }
  const slaAlerter = startFindingSlaAlerter({ publish, log: fastify.log });
  if (slaAlerter.enabled) {
    fastify.log.info('finding SLA alerter enabled (FINDING_SLA_ALERTS)');
    fastify.addHook('onClose', async () => slaAlerter.stop());
  }
  const fpAlerter = startFpRateAlerter({ publish, log: fastify.log });
  if (fpAlerter.enabled) {
    fastify.log.info('detector FP rate alerter enabled (DETECTOR_FP_RATE_ALERTS)');
    fastify.addHook('onClose', async () => fpAlerter.stop());
  }
  const destAlerter = startDestinationHealthAlerter({ publish, log: fastify.log });
  if (destAlerter.enabled) {
    fastify.log.info('destination health alerter enabled (DESTINATION_HEALTH_ALERTS)');
    fastify.addHook('onClose', async () => destAlerter.stop());
  }
}

// AIM-672: weekly FP-rate snapshot series (independent of the alert bus —
// history is retained even when ALERT_BUS_URL is unset).
{
  const snap = startFpRateSnapshotScheduler({ log: fastify.log });
  if (snap.enabled) {
    fastify.log.info('detector FP rate weekly snapshot scheduler enabled');
    fastify.addHook('onClose', async () => snap.stop());
  }
}

// Cross-pillar alert bus (AIM-158). Optional: a single-pillar or personal
// install sets no ALERT_BUS_URL, and /api/alerts then answers 503 "not
// configured" rather than pretending the inbox is empty.
if (process.env.ALERT_BUS_URL) {
  const busClient = createBusClient();
  setAlertBusClient(() => busClient);
  // Packaging check, not a health check: the reader validates every entry
  // against the contract file, so if that file is missing from the image
  // every alert would be dropped as invalid and the inbox would look quiet.
  // Better to say so at boot than to have an analyst discover it.
  const schemaError = schemaLoadError();
  if (schemaError) {
    fastify.log.error({ schemaError }, 'alert bus enabled but the contract schema is unreadable — /api/alerts will drop every entry');
  } else {
    fastify.log.info('alert bus reader enabled');
  }
}

// Immutable audit trail (AIM-27): record who accessed which dashboard/data view,
// including denied attempts (statusCode in detail). Metadata only — no payloads.
fastify.addHook('onResponse', async (req, reply) => {
  if (req.method !== 'GET' || !req.url.startsWith('/api/')) return;
  if (req.url === '/api/health' || req.url === '/api/me') return;
  const view = req.url.split('?')[0];
  audit(req.identity?.email ?? 'unauthenticated', 'dashboard.view', `dashboard${view}`, {
    statusCode: reply.statusCode,
    rangeDays: req.query?.days,
  });
});

fastify.get('/api/health', async () => ({ status: 'ok', service: 'aim-api', ts: new Date().toISOString() }));

fastify.get('/api/me', async (req) => mePayload(req));

// Static dashboard (no build step; Chart.js vendored into web/public/vendor)
await fastify.register(fastifyStatic, { root: webRoot, index: ['index.html'] });

const port = Number(process.env.PORT ?? 8080);
const host = process.env.HOST ?? '0.0.0.0';

try {
  await fastify.listen({ port, host });
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}

// Unified inbox: shell-side ack/snooze state + stack health.
//
// The inbox UI (apps/web/public/inbox.js) renders the cross-pillar alerts
// served by routes/alerts.js. Acknowledgement is SHELL state: it is
// stored by this API in alert_inbox_state (migration 017) and never written
// back into any pillar's own store (D1) — the shell reads the bus, it does
// not mutate the pillars. State is keyed on the contract's alert_id (a uuid4)
// and "open" is the absence of a row, so a re-delivered alert cannot
// resurrect as acked unless someone acked that exact alert_id.
//
// Same privacy gate as /api/alerts (analyst+): the state map reveals which
// alerts an analyst has seen, which is user-level metadata. Every mutation is
// recorded in the immutable audit trail, mirroring findings triage.
//
// GET /api/stack/health lives here too: it is the other half of the shell's
// chrome (health strip + pillar deep links) and shares the module's gate.
import { requireRoles } from '../auth.js';
import { audit } from '../audit.js';
import { query } from '../db.js';

// alert_id is a uuid4 in the contract (security-alert.schema.json); anything
// else is a client bug, answered 400 rather than a Postgres cast error.
const UUID4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

// Snooze is capped so "snoozed forever" cannot happen: an open-ended snooze
// is a silent drop wearing a UI badge. 30 days matches the retention note in
// migration 017.
const MAX_SNOOZE_MINUTES = 30 * 24 * 60;
// The state endpoint batch-fetches for one inbox page; the page is capped at
// MAX_LIMIT (500) by /api/alerts, so the id list is capped to match.
const MAX_STATE_IDS = 500;

const PROBE_TIMEOUT_MS = 2000;
const MAX_PROBE_DETAIL_CHARS = 160;
const DEFAULT_GATEWAY_HOST = 'localhost:8443';
// Operator-supplied, but it is rendered into URLs the UI builds — a value
// that is not host[:port] falls back to the default rather than breaking out.
const HOST_RE = /^[a-z0-9][a-z0-9.-]*(:[0-9]{1,5})?$/i;

/* ---------- the store ----------
 *
 * Injected by server.js implicitly (default: Postgres) and by tests with an
 * in-memory fake via setInboxStore(), the same seam setAlertBusClient()
 * provides for the bus read path — route tests must not need a database.
 * The store returns RAW rows; expiry semantics (an expired snooze reads as
 * open) live in visibleState() below so the fake cannot drift from the SQL. */
const pgStore = {
  async statesFor(ids) {
    const { rows } = await query(
      `SELECT alert_id::text AS alert_id, state, snooze_until, actor, updated_at
         FROM alert_inbox_state
        WHERE alert_id = ANY($1::uuid[])`,
      [ids],
    );
    return rows;
  },
  async upsert(id, state, snoozeUntil, actor) {
    await query(
      `INSERT INTO alert_inbox_state (alert_id, state, snooze_until, actor, updated_at)
       VALUES ($1, $2, $3, $4, now())
       ON CONFLICT (alert_id) DO UPDATE
         SET state = EXCLUDED.state,
             snooze_until = EXCLUDED.snooze_until,
             actor = EXCLUDED.actor,
             updated_at = now()`,
      [id, state, snoozeUntil, actor],
    );
  },
  async clear(id) {
    await query('DELETE FROM alert_inbox_state WHERE alert_id = $1', [id]);
  },
};

let storeFactory = () => pgStore;
/** Test seam; pass null to restore the Postgres store. */
export function setInboxStore(factory) {
  storeFactory = factory ?? (() => pgStore);
}

/* Expiry semantics, stated once: a snoozed row whose snooze_until is in the
 * past is OPEN, and open rows are EXCLUDED from the state map (rather than
 * returned marked expired) — the row stays in the table until unack or the
 * purge, but no reader can mistake it for a live snooze. */
function visibleState(row) {
  if (row.state === 'snoozed') {
    const until = row.snooze_until ? new Date(row.snooze_until) : null;
    if (!until || until.getTime() <= Date.now()) return null;
  }
  return {
    state: row.state,
    snooze_until: row.snooze_until ? new Date(row.snooze_until).toISOString() : null,
    actor: row.actor,
    updated_at: new Date(row.updated_at).toISOString(),
  };
}

// Body is {minutes: N} or {until: ISO}. Returns a Date or an error string.
function snoozeUntilFrom(body) {
  const hasMinutes = body.minutes !== undefined;
  const hasUntil = body.until !== undefined;
  if (hasMinutes === hasUntil) return 'exactly one of minutes or until is required';
  const now = Date.now();
  const cap = now + MAX_SNOOZE_MINUTES * 60_000;
  if (hasMinutes) {
    const minutes = Number(body.minutes);
    if (!Number.isFinite(minutes) || minutes < 1) return 'minutes must be a number >= 1';
    if (minutes > MAX_SNOOZE_MINUTES) return `snooze is capped at ${MAX_SNOOZE_MINUTES} minutes (30 days)`;
    return new Date(now + minutes * 60_000);
  }
  const until = new Date(body.until);
  if (Number.isNaN(until.getTime())) return 'until must be an ISO-8601 timestamp';
  if (until.getTime() <= now) return 'until must be in the future';
  if (until.getTime() > cap) return `snooze is capped at ${MAX_SNOOZE_MINUTES} minutes (30 days)`;
  return until;
}

/* ---------- stack health ---------- */

function gatewayHost() {
  const raw = process.env.AIM_GATEWAY_HOST;
  return raw && HOST_RE.test(raw) ? raw : DEFAULT_GATEWAY_HOST;
}

// AIM_STACK_SERVICES: JSON array of {name, url, ui?}. Unset or unparsable is
// a supported state (single-pillar install), answered with configured:false —
// never a 500: the health strip failing must not take the shell chrome down.
function configuredServices() {
  const raw = process.env.AIM_STACK_SERVICES;
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return null;
    return parsed.filter(
      (s) => s && typeof s.name === 'string' && typeof s.url === 'string',
    );
  } catch {
    return null;
  }
}

async function probe({ name, url, ui }) {
  const started = Date.now();
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      redirect: 'manual',
    });
    const entry = { name, ui: ui ?? null, status: res.ok ? 'ok' : 'down', latencyMs: Date.now() - started };
    if (!res.ok) {
      entry.detail = `HTTP ${res.status}`;
      return entry;
    }
    // A service that answers 200 may still report itself degraded (sentinel's
    // /healthz stays 200 so compose does not restart it — the body carries the
    // state). Without this, "no notification channel configured" rendered as a
    // green dot. Only the single token 'degraded' is adopted; any
    // other body is treated as ok.
    const degraded = await readDegradedDetail(res);
    if (degraded) {
      entry.status = 'degraded';
      if (degraded.detail) entry.detail = degraded.detail;
    }
    return entry;
  } catch (err) {
    // TimeoutError from the abort signal; otherwise the cause carries the
    // socket-level code (ECONNREFUSED et al.). Never the URL or a stack.
    const detail = err.name === 'TimeoutError' ? `timeout after ${PROBE_TIMEOUT_MS}ms` : (err.cause?.code ?? 'unreachable');
    return { name, ui: ui ?? null, status: 'down', latencyMs: Date.now() - started, detail };
  }
}

// Returns {detail} when the health body says status:"degraded", else null.
// A body that is not JSON, or JSON without that exact status, is just "ok".
async function readDegradedDetail(res) {
  try {
    const body = await res.json();
    if (!body || body.status !== 'degraded') return null;
    const detail = typeof body.detail === 'string' && body.detail
      ? body.detail.slice(0, MAX_PROBE_DETAIL_CHARS) : null;
    return { detail };
  } catch {
    return null;
  }
}

export async function inboxRoutes(fastify) {
  // Same gate as /api/alerts: the state map is inbox metadata at the same
  // privacy tier, and the health strip carries internal service topology.
  const userLevel = requireRoles('analyst', 'admin');

  fastify.get('/api/alerts/state', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const ids = String(req.query?.ids ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    if (ids.length === 0 || ids.length > MAX_STATE_IDS) {
      return reply.code(400).send({ error: 'bad_request', detail: `ids must be a comma list of 1..${MAX_STATE_IDS} alert_ids` });
    }
    if (ids.some((id) => !UUID4_RE.test(id))) {
      return reply.code(400).send({ error: 'bad_request', detail: 'every id must be a uuid4 alert_id' });
    }
    const rows = await storeFactory().statesFor(ids);
    const states = {};
    for (const row of rows) {
      const visible = visibleState(row);
      if (visible) states[row.alert_id] = visible;
    }
    return { states };
  });

  fastify.post('/api/alerts/:id/ack', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    if (!UUID4_RE.test(req.params.id)) {
      return reply.code(400).send({ error: 'bad_request', detail: 'alert id must be a uuid4' });
    }
    const actor = req.identity?.email ?? 'unknown';
    await storeFactory().upsert(req.params.id, 'acknowledged', null, actor);
    audit(actor, 'alert.ack', `alerts/${req.params.id}`, {});
    return { ok: true, state: 'acknowledged' };
  });

  fastify.post('/api/alerts/:id/snooze', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    if (!UUID4_RE.test(req.params.id)) {
      return reply.code(400).send({ error: 'bad_request', detail: 'alert id must be a uuid4' });
    }
    const until = snoozeUntilFrom(req.body ?? {});
    if (typeof until === 'string') {
      return reply.code(400).send({ error: 'bad_request', detail: until });
    }
    const actor = req.identity?.email ?? 'unknown';
    await storeFactory().upsert(req.params.id, 'snoozed', until, actor);
    audit(actor, 'alert.snooze', `alerts/${req.params.id}`, { snooze_until: until.toISOString() });
    return { ok: true, state: 'snoozed', snooze_until: until.toISOString() };
  });

  fastify.post('/api/alerts/:id/unack', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    if (!UUID4_RE.test(req.params.id)) {
      return reply.code(400).send({ error: 'bad_request', detail: 'alert id must be a uuid4' });
    }
    const actor = req.identity?.email ?? 'unknown';
    await storeFactory().clear(req.params.id);
    audit(actor, 'alert.unack', `alerts/${req.params.id}`, {});
    return { ok: true, state: 'open' };
  });

  fastify.get('/api/stack/health', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const host = gatewayHost();
    // The API itself is always present and healthy — it answered this request.
    // Its UI is this dashboard, served at the aim gateway subdomain.
    const self = { name: 'api', ui: `https://aim.${host}/`, status: 'ok', latencyMs: 0 };
    const services = configuredServices();
    if (!services) {
      return { configured: false, gatewayHost: host, services: [self] };
    }
    const probed = await Promise.all(services.map(probe));
    return { configured: true, gatewayHost: host, services: [self, ...probed] };
  });
}

export default inboxRoutes;

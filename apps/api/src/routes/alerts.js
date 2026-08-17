// Unified alert inbox read API (AIM-158).
//
// The replayable consumer surface for the inbox UI and the sentinel agent.
// Gated to analyst+ like /api/findings: alerts carry pseudonyms and rule
// evidence, and the same privacy bar applies to the cross-pillar view as to
// the AI-usage one.
//
// This is the only path from a browser to the bus (D3.1 §5) — the bus itself
// has no published port and the API holds the read-only `secbus_sub`
// credential. Reads never mutate the stream: no XACK, no XDEL, no trim.
import { requireRoles } from '../auth.js';
import {
  readRange, isValidCursor, severityRank, severityBand, MAX_LIMIT, STREAM_KEY,
} from '../alertbus.js';

// Injected by server.js at boot, and by tests with a fake. Null means this
// install has no bus configured, which is a supported state, not an error.
let clientFactory = null;
export function setAlertBusClient(factory) { clientFactory = factory; }

function client() {
  if (!clientFactory) return null;
  return clientFactory();
}

export async function alertsRoutes(fastify) {
  // Alerts carry user/host pseudonyms and rule evidence, so the same privacy
  // tier as /api/findings — analyst+. Applied inline rather than as a
  // preHandler to match the other routes.
  const userLevel = requireRoles('analyst', 'admin');

  // Cursor-based replay. `after` is the opaque cursor from a previous page;
  // omit it to start from the beginning of the retention window.
  fastify.get('/api/alerts', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const bus = client();
    if (!bus) {
      // The bus is optional: a personal/standalone install runs one pillar and
      // never sets ALERT_BUS_URL. Say so plainly rather than 500 or, worse,
      // return an empty page that reads as "no alerts" (§7.3).
      return reply.code(503).send({
        error: 'alert bus not configured',
        detail: 'ALERT_BUS_URL is unset; this install publishes no cross-pillar alerts.',
      });
    }

    const { after, limit, severity, pillar, order } = req.query ?? {};
    if (after && !isValidCursor(after)) {
      // A 400 here, not a 502: a client bug and a bus outage must not look the
      // same to whoever is reading the inbox.
      return reply.code(400).send({ error: 'invalid cursor' });
    }
    // Default newest-first so the first page is recent activity (AIM-476).
    // `order=oldest` keeps the completeness-scan path for tools that walk the
    // whole retention window.
    const direction = order === 'oldest' ? 'oldest' : 'newest';
    const want = Math.min(Math.max(Number(limit) || 50, 1), MAX_LIMIT);

    // Severity / pillar filters are applied as we fill the page, not after a
    // single raw page: with newest-first a stream dominated by one pillar would
    // otherwise answer `?pillar=ai_usage` with an empty first page while 728
    // matching alerts sit further back (AIM-476 class of silent empty inbox).
    const sevWanted = severity
      ? new Set(String(severity).split(',').map((s) => s.trim()).filter(Boolean))
      : null;
    // Matched on the band as well as the raw label (§7.4 rev 6 / AIM-179).
    const sevBands = sevWanted
      ? new Set([...sevWanted].map(severityBand).filter((b) => b !== undefined))
      : null;
    const pilWanted = pillar
      ? new Set(String(pillar).split(',').map((s) => s.trim()).filter(Boolean))
      : null;

    function matchesFilters(decoded) {
      const a = decoded.alert;
      if (sevWanted) {
        if (!(sevWanted.has(a.severity) || sevBands.has(severityRank(a)))) return false;
      }
      if (pilWanted && !pilWanted.has(a.pillar)) return false;
      return true;
    }

    const alerts = [];
    const dropped = {
      malformed: 0, invalid: 0, unsupportedVersion: 0,
      projectedFields: 0, legacyWire: 0, scanned: 0,
    };
    let cursor = after || '-';
    let exhausted = false;
    // Budget: walk past non-matching entries (e.g. long pr_security run when
    // filtering ai_usage) without unbounded stream scans. Deeper when filtered.
    const maxBatches = (sevWanted || pilWanted) ? 100 : 20;

    try {
      for (let batch = 0; batch < maxBatches && alerts.length < want && !exhausted; batch += 1) {
        const page = await readRange(bus, {
          after: cursor,
          limit: want,
          streamKey: STREAM_KEY,
          direction,
        });
        dropped.malformed += page.stats.malformed;
        dropped.invalid += page.stats.invalid;
        dropped.unsupportedVersion += page.stats.unsupportedVersion;
        dropped.projectedFields += page.stats.projectedFields;
        dropped.legacyWire += page.stats.legacyWire;
        dropped.scanned += page.stats.scanned;
        for (const decoded of page.alerts) {
          if (!matchesFilters(decoded)) continue;
          alerts.push(decoded);
          if (alerts.length >= want) break;
        }
        cursor = page.nextCursor;
        exhausted = page.exhausted;
        if (!page.alerts.length && page.exhausted) break;
        if (batch > 0 && page.stats.scanned === 0) break;
      }
    } catch (err) {
      req.log.error({ err }, 'alert bus read failed');
      // §7.3: absence of alerts is not absence of findings. A read failure
      // must never be presented as an empty, all-clear inbox.
      return reply.code(502).send({ error: 'alert bus unavailable' });
    }

    if (dropped.invalid || dropped.malformed || dropped.legacyWire) {
      req.log.warn({
        malformed: dropped.malformed,
        invalid: dropped.invalid,
        legacyWire: dropped.legacyWire,
        scanned: dropped.scanned,
      }, 'dropped or legacy-wire alerts on page');
    }

    return {
      alerts: alerts.map((a) => ({ cursor: a.cursor, ...a.alert })),
      nextCursor: cursor,
      exhausted,
      order: direction === 'newest' ? 'newest' : 'oldest',
      // Surfaced rather than hidden: a consumer silently dropping entries is
      // exactly the failure a security inbox may not have.
      dropped,
      limits: { maxLimit: MAX_LIMIT },
    };
  });
}

export default alertsRoutes;

// Audit trail read API + CSV export: lets auditors (and
// admins) query the immutable, hash-chained audit log without shell access
// to the host. Reads the JSONL path configured for the writer side
// (AUDIT_LOG_PATH); when the trail is not configured the endpoint answers an
// empty list rather than an error — "not configured" is a deployment fact,
// not a request failure.
//
// Gated to auditor + admin (the aggregate-only viewer tier is deliberately
// excluded: the audit trail names actors). Every read is itself recorded by
// the global dashboard.view audit hook in server.js.
//
// ?format=csv exports the same rows the JSON response carries, so
// an auditor can hand Legal the trail without jq. The seal column rides
// along so the export stays verifiable against the chain.
import { AuditLog } from '../../../../packages/audit/src/audit-log.ts';
import { requireRoles } from '../auth.js';
import { wantsCsv, checkFormat, sendCsv } from '../csv.js';

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;

const AUDIT_CSV_COLS = [
  { key: 'seq', label: 'seq' },
  { key: 'ts', label: 'ts' },
  { key: 'actor', label: 'actor' },
  { key: 'action', label: 'action' },
  { key: 'resource', label: 'resource' },
  { key: 'detail', label: 'detail' },
  { key: 'seal', label: 'seal' },
];

export async function auditRoutes(fastify) {
  const auditReader = requireRoles('auditor', 'admin');

  // GET /api/audit/events?action=&actor=&since=&until=&limit=&format=csv
  fastify.get('/api/audit/events', async (req, reply) => {
    if (!auditReader(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const path = process.env.AUDIT_LOG_PATH;
    const limit = Math.min(Math.max(Number(req.query?.limit) || DEFAULT_LIMIT, 1), MAX_LIMIT);
    let events = [];
    if (path) {
      try {
        events = AuditLog.query({
          path,
          action: req.query?.action || undefined,
          actor: req.query?.actor || undefined,
          since: req.query?.since || undefined,
          until: req.query?.until || undefined,
        });
      } catch (err) {
        req.log.warn(err, 'audit log read failed');
      }
    }
    const page = events.slice(-limit);
    if (wantsCsv(req)) {
      return sendCsv(reply, 'aim-audit-events.csv', AUDIT_CSV_COLS, page);
    }
    return { events: page };
  });
}

import { query } from '../db.js';
import { requireRoles } from '../auth.js';
import { loadVendorFeeds } from '../vendor-feeds.js';

function parseDays(q, def = 30, max = 365) {
  const d = Number(q?.days ?? def);
  if (!Number.isFinite(d) || d < 1) return def;
  return Math.min(Math.floor(d), max);
}

export async function vendorAdminRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const anyRole = requireRoles('admin', 'analyst', 'auditor', 'viewer');

  fastify.get('/api/vendor-admin/feeds', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const days = parseDays(req.query);
    return loadVendorFeeds(db, days);
  });
}

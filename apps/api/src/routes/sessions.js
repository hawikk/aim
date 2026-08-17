// Session admin routes (AIM-613 / AIM-714): force-deny live SSO sessions for a
// leaver before the HMAC cookie TTL expires.
//
// Callers:
//   * Human admin (SSO role `admin`) — operator leaver playbook
//   * Designated service tokens (AIM_SESSION_REVOKE_SERVICES) — automation from
//     identity-sync deprovision (AIM-714) or future SCIM deactivate
//
// Complements IdP group-removal deprovision (next login is already fail-closed).
// Deliberately keeps canRevokeSessions free of heavy OIDC deps so unit tests
// stay pure.
import { audit } from '../audit.js';
import {
  isValidEmail,
  normalizeEmail,
  persistRevocation,
  sessionRevocations,
} from '../session-revocation.js';
import * as defaultDb from '../db.js';

function splitCsv(value) {
  return String(value ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

function isAdminIdentity(identity) {
  const role = identity?.role;
  // Product alias security-admin → admin (same as auth.js ROLE_ALIASES).
  return role === 'admin' || role === 'security-admin';
}

/**
 * Admin humans, or a machine token whose `name` is listed in
 * AIM_SESSION_REVOKE_SERVICES (default empty — no service may revoke until
 * operators opt in). Service tokens still cannot hold the admin role.
 */
export function canRevokeSessions(req, {
  revokeServices = process.env.AIM_SESSION_REVOKE_SERVICES,
} = {}) {
  if (!req?.identity) return false;
  if (isAdminIdentity(req.identity)) return true;
  if (req.identity.mode !== 'service') return false;
  const allowed = new Set(splitCsv(revokeServices));
  const name = String(req.identity.name ?? '').trim().toLowerCase();
  return name.length > 0 && allowed.has(name);
}

/**
 * @param {import('fastify').FastifyInstance} fastify
 * @param {{ db?: typeof defaultDb, store?: typeof sessionRevocations, revokeServices?: string }} [opts]
 */
export async function sessionRoutes(fastify, opts = {}) {
  const db = opts.db ?? defaultDb;
  const store = opts.store ?? sessionRevocations;
  const revokeServices = opts.revokeServices ?? process.env.AIM_SESSION_REVOKE_SERVICES;

  // Force-deny every HMAC session issued at or before now for this email.
  // Idempotent: re-revoking advances the watermark.
  fastify.post('/api/admin/sessions/revoke', async (req, reply) => {
    if (!req.identity) {
      return reply.code(401).send({ error: 'unauthenticated' });
    }
    if (!canRevokeSessions(req, { revokeServices })) {
      audit(req.identity.email ?? 'unauthenticated', 'authz.deny', '/api/admin/sessions/revoke', {
        requiredRoles: ['admin', 'session_revoke_service'],
        role: req.identity.role ?? null,
        reason: 'session_revoke_forbidden',
      });
      return reply.code(403).send({
        error: 'forbidden',
        detail: 'requires role: admin or a service listed in AIM_SESSION_REVOKE_SERVICES',
      });
    }

    const rawEmail = req.body?.email;
    if (!isValidEmail(rawEmail)) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'body.email must be a non-empty email address',
      });
    }
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.slice(0, 500) : null;
    const actor = req.identity?.email ?? 'unknown';
    const entry = store.revoke(rawEmail, { reason, revokedBy: actor });

    let persisted = false;
    try {
      persisted = await persistRevocation(db, entry);
    } catch (err) {
      // Memory watermark still applies on this process. Log for operators;
      // do not 500 the leaver path when the table is not yet migrated.
      req.log?.warn?.(
        { err: err.message, email: entry.email },
        'session revoke memory-only (DB persist failed)',
      );
    }

    audit(actor, 'auth.session.revoke', `admin/sessions/revoke/${entry.email}`, {
      email: entry.email,
      revokedAtSec: entry.revokedAtSec,
      reason: entry.reason,
      persisted,
      via: req.identity.mode === 'service' ? 'service' : 'admin',
    });

    return {
      ok: true,
      email: entry.email,
      revokedAt: new Date(entry.revokedAtSec * 1000).toISOString(),
      revokedAtSec: entry.revokedAtSec,
      reason: entry.reason,
      revokedBy: entry.revokedBy,
      persisted,
    };
  });

  // Read the current watermark (admin or revoke-capable service). 404 when never revoked.
  fastify.get('/api/admin/sessions/revoke/:email', async (req, reply) => {
    if (!req.identity) {
      return reply.code(401).send({ error: 'unauthenticated' });
    }
    if (!canRevokeSessions(req, { revokeServices })) {
      return reply.code(403).send({
        error: 'forbidden',
        detail: 'requires role: admin or a service listed in AIM_SESSION_REVOKE_SERVICES',
      });
    }
    const email = normalizeEmail(req.params.email);
    if (!isValidEmail(email)) {
      return reply.code(400).send({ error: 'bad_request', detail: 'email path param invalid' });
    }
    const entry = store.get(email);
    if (!entry) {
      return reply.code(404).send({ error: 'not_found', detail: `no revoke watermark for ${email}` });
    }
    return {
      email: entry.email,
      revokedAt: new Date(entry.revokedAtSec * 1000).toISOString(),
      revokedAtSec: entry.revokedAtSec,
      reason: entry.reason,
      revokedBy: entry.revokedBy,
    };
  });
}

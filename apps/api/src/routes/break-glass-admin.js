// AIM-719 — Break-glass admin with dual control / hardware-key (WebAuthn).
//
// Emergency admin path that does NOT require flipping AIM_REQUIRE_SSO or
// AIM_AUTH_DEV. Fully audited via audit() + break_glass_admin_events.
//
// Gated by AIM_BREAK_GLASS_ADMIN=1 (default off).
//
// Surfaces:
//   Admin (role admin) under /api/admin/break-glass/*
//   Ceremony (open under /auth/break-glass/* — same open prefix as OIDC)
//
// Dual control: two distinct admin identities must approve a pending grant;
// second approval returns a one-time activationToken; principal activates.
// WebAuthn: pre-registered ES256 hardware key signs a server challenge →
// short-lived admin session (no dual control required — alternative path).

import { randomUUID } from 'node:crypto';
import { audit } from '../audit.js';
import { requireRoles, issueBreakGlassAdminSession } from '../auth.js';
import * as defaultDb from '../db.js';
import {
  applyDualApproval,
  challengeMessage,
  clampTtlMinutes,
  consumeChallenge,
  DEFAULT_TTL_MINUTES,
  hashToken,
  isBreakGlassAdminEnabled,
  issueChallenge,
  normalizeEmail,
  normalizePublicKeyJwk,
  publicCredential,
  publicGrant,
  publicPrincipal,
  safeEqualHex,
  verifyEs256Signature,
} from '../break-glass-admin.js';

function featureOff(reply) {
  return reply.code(503).send({
    error: 'break_glass_admin_disabled',
    detail: 'Set AIM_BREAK_GLASS_ADMIN=1 to enable the emergency admin path (AIM-719).',
  });
}

function requireFeature(reply) {
  if (!isBreakGlassAdminEnabled()) {
    featureOff(reply);
    return false;
  }
  return true;
}

function tableMissing(err) {
  const msg = String(err?.message ?? err ?? '');
  return (
    msg.includes('break_glass_admin_') ||
    msg.includes('does not exist') ||
    err?.code === '42P01'
  );
}

function missingMigration(reply) {
  return reply.code(503).send({
    error: 'migration_required',
    detail: 'break_glass_admin tables missing — apply migration 036_break_glass_admin.sql',
  });
}

async function appendEvent(db, { grantId = null, eventType, actor, detail = {} }) {
  try {
    await db.query(
      `INSERT INTO break_glass_admin_events (grant_id, event_type, actor, detail)
       VALUES ($1::uuid, $2, $3, $4::jsonb)`,
      [grantId, eventType, actor, JSON.stringify(detail)],
    );
  } catch (err) {
    // Events are best-effort when the table is present; never break the request
    // path on audit secondary write failures (primary audit() still fires).
    if (!tableMissing(err)) {
      console.error('break_glass_admin event append failed:', err.message);
    }
  }
}

function actorOf(req) {
  return req.identity?.email ?? 'unauthenticated';
}

/**
 * @param {import('fastify').FastifyInstance} fastify
 * @param {{ db?: typeof defaultDb }} [opts]
 */
export async function breakGlassAdminRoutes(fastify, opts = {}) {
  const db = opts.db ?? defaultDb;
  const adminOnly = requireRoles('admin');

  /* ---------- status ---------- */
  fastify.get('/api/admin/break-glass/status', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const enabled = isBreakGlassAdminEnabled();
    let principals = 0;
    let credentials = 0;
    let pendingGrants = 0;
    let store = 'ok';
    if (enabled) {
      try {
        const p = await db.query(
          `SELECT count(*)::int AS n FROM break_glass_admin_principals WHERE enabled = true AND disabled_at IS NULL`,
        );
        principals = p.rows[0]?.n ?? 0;
        const c = await db.query(
          `SELECT count(*)::int AS n FROM break_glass_admin_webauthn WHERE revoked_at IS NULL`,
        );
        credentials = c.rows[0]?.n ?? 0;
        const g = await db.query(
          `SELECT count(*)::int AS n FROM break_glass_admin_grants WHERE status = 'pending'`,
        );
        pendingGrants = g.rows[0]?.n ?? 0;
      } catch (err) {
        if (tableMissing(err)) store = 'migration_required';
        else throw err;
      }
    }
    return {
      enabled,
      store,
      principals,
      credentials,
      pendingGrants,
      acceptance: {
        dualControl: 'two distinct admin approvals + one-time activation token',
        webauthn: 'ES256 hardware-key challenge (WebAuthn-compatible)',
        audited: true,
      },
      note:
        'Emergency admin path (AIM-719). Prefer dual control when two admins are available; use WebAuthn when IdP is down.',
    };
  });

  /* ---------- principals ---------- */
  fastify.get('/api/admin/break-glass/principals', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    if (!requireFeature(reply)) return reply;
    try {
      const { rows } = await db.query(
        `SELECT * FROM break_glass_admin_principals ORDER BY created_at DESC`,
      );
      return { principals: rows.map(publicPrincipal) };
    } catch (err) {
      if (tableMissing(err)) return missingMigration(reply);
      throw err;
    }
  });

  fastify.post('/api/admin/break-glass/principals', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    if (!requireFeature(reply)) return reply;
    const email = normalizeEmail(req.body?.email);
    if (!email) {
      return reply.code(400).send({ error: 'bad_request', detail: 'valid email required' });
    }
    const displayName =
      typeof req.body?.displayName === 'string' && req.body.displayName.trim()
        ? req.body.displayName.trim().slice(0, 256)
        : null;
    const id = randomUUID();
    const actor = actorOf(req);
    try {
      const { rows } = await db.query(
        `INSERT INTO break_glass_admin_principals (id, email, display_name, created_by)
         VALUES ($1::uuid, $2, $3, $4)
         ON CONFLICT ((lower(email))) DO UPDATE
           SET enabled = true,
               disabled_at = NULL,
               disabled_by = NULL,
               display_name = COALESCE(EXCLUDED.display_name, break_glass_admin_principals.display_name),
               updated_at = now()
         RETURNING *`,
        [id, email, displayName, actor],
      );
      const row = rows[0];
      await appendEvent(db, {
        eventType: 'principal_added',
        actor,
        detail: { principalId: row.id, email },
      });
      audit(actor, 'break_glass.admin.principal.add', `break-glass/principals/${row.id}`, {
        email,
      });
      return reply.code(201).send({ principal: publicPrincipal(row) });
    } catch (err) {
      if (tableMissing(err)) return missingMigration(reply);
      // Unique index name may vary; surface conflict cleanly.
      if (err?.code === '23505') {
        return reply.code(409).send({ error: 'conflict', detail: 'principal already exists' });
      }
      throw err;
    }
  });

  fastify.delete('/api/admin/break-glass/principals/:id', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    if (!requireFeature(reply)) return reply;
    const actor = actorOf(req);
    try {
      const { rows } = await db.query(
        `UPDATE break_glass_admin_principals
         SET enabled = false, disabled_at = now(), disabled_by = $2, updated_at = now()
         WHERE id = $1::uuid AND enabled = true
         RETURNING *`,
        [req.params.id, actor],
      );
      if (!rows[0]) {
        return reply.code(404).send({ error: 'not_found' });
      }
      await appendEvent(db, {
        eventType: 'principal_disabled',
        actor,
        detail: { principalId: rows[0].id, email: rows[0].email },
      });
      audit(actor, 'break_glass.admin.principal.disable', `break-glass/principals/${rows[0].id}`, {
        email: rows[0].email,
      });
      return { principal: publicPrincipal(rows[0]) };
    } catch (err) {
      if (tableMissing(err)) return missingMigration(reply);
      throw err;
    }
  });

  /* ---------- WebAuthn credential registration (SSO healthy) ---------- */
  fastify.post('/api/admin/break-glass/webauthn/register', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    if (!requireFeature(reply)) return reply;
    const email = normalizeEmail(req.body?.email);
    const credentialId =
      typeof req.body?.credentialId === 'string' ? req.body.credentialId.trim() : '';
    if (!email || !credentialId || credentialId.length > 512) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'email and credentialId (≤512) required',
      });
    }
    let publicKeyJwk;
    try {
      publicKeyJwk = normalizePublicKeyJwk(req.body?.publicKeyJwk);
    } catch (err) {
      return reply.code(400).send({ error: 'bad_request', detail: err.message });
    }
    const nickname =
      typeof req.body?.nickname === 'string' && req.body.nickname.trim()
        ? req.body.nickname.trim().slice(0, 128)
        : null;
    const actor = actorOf(req);
    try {
      const p = await db.query(
        `SELECT * FROM break_glass_admin_principals
         WHERE lower(email) = $1 AND enabled = true AND disabled_at IS NULL`,
        [email],
      );
      if (!p.rows[0]) {
        return reply.code(404).send({
          error: 'not_found',
          detail: 'register the principal first (POST /api/admin/break-glass/principals)',
        });
      }
      const id = randomUUID();
      const { rows } = await db.query(
        `INSERT INTO break_glass_admin_webauthn
           (id, principal_id, credential_id, public_key_jwk, nickname, created_by)
         VALUES ($1::uuid, $2::uuid, $3, $4::jsonb, $5, $6)
         RETURNING *`,
        [id, p.rows[0].id, credentialId, JSON.stringify(publicKeyJwk), nickname, actor],
      );
      await appendEvent(db, {
        eventType: 'webauthn_registered',
        actor,
        detail: { credentialId, principalEmail: email, nickname },
      });
      audit(actor, 'break_glass.admin.webauthn.register', `break-glass/webauthn/${id}`, {
        email,
        credentialId,
      });
      return reply.code(201).send({ credential: publicCredential(rows[0]) });
    } catch (err) {
      if (tableMissing(err)) return missingMigration(reply);
      if (err?.code === '23505') {
        return reply.code(409).send({ error: 'conflict', detail: 'credentialId already registered' });
      }
      throw err;
    }
  });

  fastify.get('/api/admin/break-glass/webauthn/credentials', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    if (!requireFeature(reply)) return reply;
    const email = normalizeEmail(req.query?.email);
    try {
      let rows;
      if (email) {
        const r = await db.query(
          `SELECT w.* FROM break_glass_admin_webauthn w
           JOIN break_glass_admin_principals p ON p.id = w.principal_id
           WHERE lower(p.email) = $1 AND w.revoked_at IS NULL
           ORDER BY w.created_at DESC`,
          [email],
        );
        rows = r.rows;
      } else {
        const r = await db.query(
          `SELECT * FROM break_glass_admin_webauthn
           WHERE revoked_at IS NULL ORDER BY created_at DESC LIMIT 200`,
        );
        rows = r.rows;
      }
      return { credentials: rows.map(publicCredential) };
    } catch (err) {
      if (tableMissing(err)) return missingMigration(reply);
      throw err;
    }
  });

  fastify.delete('/api/admin/break-glass/webauthn/credentials/:id', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    if (!requireFeature(reply)) return reply;
    const actor = actorOf(req);
    try {
      const { rows } = await db.query(
        `UPDATE break_glass_admin_webauthn
         SET revoked_at = now(), revoked_by = $2
         WHERE id = $1::uuid AND revoked_at IS NULL
         RETURNING *`,
        [req.params.id, actor],
      );
      if (!rows[0]) return reply.code(404).send({ error: 'not_found' });
      await appendEvent(db, {
        eventType: 'webauthn_revoked',
        actor,
        detail: { credentialRowId: rows[0].id, credentialId: rows[0].credential_id },
      });
      audit(actor, 'break_glass.admin.webauthn.revoke', `break-glass/webauthn/${rows[0].id}`, {
        credentialId: rows[0].credential_id,
      });
      return { credential: publicCredential(rows[0]) };
    } catch (err) {
      if (tableMissing(err)) return missingMigration(reply);
      throw err;
    }
  });

  /* ---------- dual-control grant management ---------- */
  fastify.get('/api/admin/break-glass/grants', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    if (!requireFeature(reply)) return reply;
    const status = typeof req.query?.status === 'string' ? req.query.status : null;
    try {
      const params = [];
      let sql = `SELECT * FROM break_glass_admin_grants`;
      if (status) {
        params.push(status);
        sql += ` WHERE status = $1`;
      }
      sql += ` ORDER BY requested_at DESC LIMIT 200`;
      const { rows } = await db.query(sql, params);
      return {
        grants: rows.map((r) => publicGrant(r, { includeActivationHint: true })),
      };
    } catch (err) {
      if (tableMissing(err)) return missingMigration(reply);
      throw err;
    }
  });

  fastify.post('/api/admin/break-glass/grants/:id/approve', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    if (!requireFeature(reply)) return reply;
    const actor = actorOf(req);
    try {
      const { rows } = await db.query(
        `SELECT * FROM break_glass_admin_grants WHERE id = $1::uuid`,
        [req.params.id],
      );
      const grant = rows[0];
      if (!grant) return reply.code(404).send({ error: 'not_found' });
      const decision = applyDualApproval(grant, actor);
      if (!decision.ok) {
        const code = decision.reason === 'duplicate_approver' ? 409 : 400;
        return reply.code(code).send({ error: decision.reason });
      }
      if (decision.stage === 'first') {
        const p = decision.patch;
        const { rows: updated } = await db.query(
          `UPDATE break_glass_admin_grants
           SET first_approver = $2, first_approved_at = $3, updated_at = $3
           WHERE id = $1::uuid AND status = 'pending' AND first_approver IS NULL
           RETURNING *`,
          [grant.id, p.first_approver, p.first_approved_at],
        );
        if (!updated[0]) {
          return reply.code(409).send({ error: 'race', detail: 'grant already advanced' });
        }
        await appendEvent(db, {
          grantId: grant.id,
          eventType: 'grant_approved',
          actor,
          detail: { stage: 'first' },
        });
        audit(actor, 'break_glass.admin.grant.approve', `break-glass/grants/${grant.id}`, {
          stage: 'first',
          principalEmail: grant.principal_email,
        });
        return {
          grant: publicGrant(updated[0], { includeActivationHint: true }),
          stage: 'first',
          note: 'First dual-control approval recorded. A second distinct admin must approve.',
        };
      }
      // second
      const p = decision.patch;
      const { rows: updated } = await db.query(
        `UPDATE break_glass_admin_grants
         SET second_approver = $2,
             second_approved_at = $3,
             status = 'approved',
             activation_token_hash = $4,
             expires_at = $5,
             updated_at = $3
         WHERE id = $1::uuid AND status = 'pending' AND first_approver IS NOT NULL
           AND second_approver IS NULL
         RETURNING *`,
        [
          grant.id,
          p.second_approver,
          p.second_approved_at,
          p.activation_token_hash,
          p.expires_at,
        ],
      );
      if (!updated[0]) {
        return reply.code(409).send({ error: 'race', detail: 'grant already advanced' });
      }
      await appendEvent(db, {
        grantId: grant.id,
        eventType: 'grant_approved',
        actor,
        detail: { stage: 'second', expiresAt: p.expires_at },
      });
      audit(actor, 'break_glass.admin.grant.approve', `break-glass/grants/${grant.id}`, {
        stage: 'second',
        principalEmail: grant.principal_email,
        expiresAt: p.expires_at,
      });
      return {
        grant: publicGrant(updated[0], { includeActivationHint: true }),
        stage: 'second',
        // Returned once. Relay out-of-band to the principal for activate.
        activationToken: decision.activationToken,
        note:
          'Dual control complete. Relay activationToken to the principal out-of-band; they POST /auth/break-glass/activate.',
      };
    } catch (err) {
      if (tableMissing(err)) return missingMigration(reply);
      throw err;
    }
  });

  fastify.post('/api/admin/break-glass/grants/:id/revoke', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    if (!requireFeature(reply)) return reply;
    const actor = actorOf(req);
    const reason =
      typeof req.body?.reason === 'string' && req.body.reason.trim()
        ? req.body.reason.trim().slice(0, 2000)
        : 'revoked';
    try {
      const { rows } = await db.query(
        `UPDATE break_glass_admin_grants
         SET status = 'revoked',
             revoked_by = $2,
             revoked_at = now(),
             revoke_reason = $3,
             activation_token_hash = NULL,
             updated_at = now()
         WHERE id = $1::uuid AND status IN ('pending', 'approved', 'activated')
         RETURNING *`,
        [req.params.id, actor, reason],
      );
      if (!rows[0]) return reply.code(404).send({ error: 'not_found' });
      await appendEvent(db, {
        grantId: rows[0].id,
        eventType: 'grant_revoked',
        actor,
        detail: { reason },
      });
      audit(actor, 'break_glass.admin.grant.revoke', `break-glass/grants/${rows[0].id}`, {
        reason,
        principalEmail: rows[0].principal_email,
      });
      return { grant: publicGrant(rows[0]) };
    } catch (err) {
      if (tableMissing(err)) return missingMigration(reply);
      throw err;
    }
  });

  fastify.get('/api/admin/break-glass/audit-export', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    if (!requireFeature(reply)) return reply;
    const days = Math.min(365, Math.max(1, Number(req.query?.days) || 90));
    try {
      const since = new Date(Date.now() - days * 86400 * 1000);
      const grants = await db.query(
        `SELECT * FROM break_glass_admin_grants
         WHERE requested_at >= $1 ORDER BY requested_at DESC`,
        [since],
      );
      const events = await db.query(
        `SELECT * FROM break_glass_admin_events
         WHERE created_at >= $1 ORDER BY created_at DESC LIMIT 5000`,
        [since],
      );
      audit(actorOf(req), 'break_glass.admin.audit_export', 'break-glass/audit-export', {
        days,
        grants: grants.rows.length,
        events: events.rows.length,
      });
      return {
        exportedAt: new Date().toISOString(),
        days,
        grants: grants.rows.map((r) => publicGrant(r, { includeActivationHint: true })),
        events: events.rows.map((e) => ({
          id: e.id,
          grantId: e.grant_id,
          eventType: e.event_type,
          actor: e.actor,
          detail: e.detail,
          createdAt: e.created_at,
        })),
      };
    } catch (err) {
      if (tableMissing(err)) return missingMigration(reply);
      throw err;
    }
  });

  /* ---------- Public ceremony: dual-control request ---------- */
  fastify.post('/auth/break-glass/dual/request', async (req, reply) => {
    if (!requireFeature(reply)) return reply;
    const email = normalizeEmail(req.body?.email);
    const reason =
      typeof req.body?.reason === 'string' ? req.body.reason.trim() : '';
    if (!email || !reason || reason.length > 2000) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'email and reason (1..2000 chars) required',
      });
    }
    const ticketRef =
      typeof req.body?.ticketRef === 'string' && req.body.ticketRef.trim()
        ? req.body.ticketRef.trim().slice(0, 256)
        : null;
    const ttlMinutes = clampTtlMinutes(req.body?.ttlMinutes, DEFAULT_TTL_MINUTES);
    const requestedBy = req.identity?.email ?? email;
    try {
      const p = await db.query(
        `SELECT id FROM break_glass_admin_principals
         WHERE lower(email) = $1 AND enabled = true AND disabled_at IS NULL`,
        [email],
      );
      if (!p.rows[0]) {
        // Do not leak whether other emails exist; still fail closed.
        return reply.code(404).send({
          error: 'not_found',
          detail: 'principal is not registered for break-glass admin',
        });
      }
      const id = randomUUID();
      const { rows } = await db.query(
        `INSERT INTO break_glass_admin_grants
           (id, principal_email, method, status, reason, ticket_ref,
            requested_by, ttl_minutes)
         VALUES ($1::uuid, $2, 'dual_control', 'pending', $3, $4, $5, $6)
         RETURNING *`,
        [id, email, reason, ticketRef, requestedBy, ttlMinutes],
      );
      await appendEvent(db, {
        grantId: id,
        eventType: 'grant_requested',
        actor: requestedBy,
        detail: { method: 'dual_control', principalEmail: email, ticketRef },
      });
      audit(requestedBy, 'break_glass.admin.grant.request', `break-glass/grants/${id}`, {
        method: 'dual_control',
        principalEmail: email,
        ticketRef,
      });
      return reply.code(201).send({
        grant: publicGrant(rows[0]),
        note:
          'Dual-control grant pending. Two distinct admins must POST /api/admin/break-glass/grants/:id/approve.',
      });
    } catch (err) {
      if (tableMissing(err)) return missingMigration(reply);
      throw err;
    }
  });

  /* ---------- Public ceremony: activate dual-control grant ---------- */
  fastify.post('/auth/break-glass/activate', async (req, reply) => {
    if (!requireFeature(reply)) return reply;
    const grantId = typeof req.body?.grantId === 'string' ? req.body.grantId.trim() : '';
    const activationToken =
      typeof req.body?.activationToken === 'string' ? req.body.activationToken.trim() : '';
    if (!grantId || !activationToken) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'grantId and activationToken required',
      });
    }
    try {
      const { rows } = await db.query(
        `SELECT * FROM break_glass_admin_grants WHERE id = $1::uuid`,
        [grantId],
      );
      const grant = rows[0];
      if (!grant) return reply.code(404).send({ error: 'not_found' });
      if (grant.status !== 'approved') {
        return reply.code(409).send({
          error: 'not_activatable',
          detail: `grant status is ${grant.status}; need approved`,
        });
      }
      if (grant.expires_at && new Date(grant.expires_at) <= new Date()) {
        await db.query(
          `UPDATE break_glass_admin_grants
           SET status = 'expired', updated_at = now()
           WHERE id = $1::uuid AND status = 'approved'`,
          [grant.id],
        );
        return reply.code(410).send({ error: 'expired' });
      }
      if (
        !grant.activation_token_hash ||
        !safeEqualHex(grant.activation_token_hash, hashToken(activationToken))
      ) {
        audit('unauthenticated', 'break_glass.admin.activate_denied', `break-glass/grants/${grantId}`, {
          reason: 'bad_token',
        });
        return reply.code(401).send({ error: 'invalid_activation_token' });
      }
      const now = new Date();
      const { rows: updated } = await db.query(
        `UPDATE break_glass_admin_grants
         SET status = 'activated',
             activated_at = $2,
             activated_by = $3,
             activation_token_hash = NULL,
             updated_at = $2
         WHERE id = $1::uuid AND status = 'approved'
         RETURNING *`,
        [grant.id, now, grant.principal_email],
      );
      if (!updated[0]) {
        return reply.code(409).send({ error: 'race' });
      }
      const ttlSeconds = clampTtlMinutes(grant.ttl_minutes) * 60;
      const session = issueBreakGlassAdminSession(reply, {
        email: grant.principal_email,
        name: `Break-glass ${grant.principal_email}`,
        ttlSeconds,
        grantId: grant.id,
        method: 'dual_control',
      });
      await appendEvent(db, {
        grantId: grant.id,
        eventType: 'grant_activated',
        actor: grant.principal_email,
        detail: { method: 'dual_control', ttlSeconds },
      });
      audit(grant.principal_email, 'break_glass.admin.activate', `break-glass/grants/${grant.id}`, {
        method: 'dual_control',
        ttlSeconds,
      });
      return {
        ok: true,
        method: 'dual_control',
        session: { email: session.email, role: session.role, mode: session.mode, exp: session.exp },
        grant: publicGrant(updated[0]),
      };
    } catch (err) {
      if (tableMissing(err)) return missingMigration(reply);
      throw err;
    }
  });

  /* ---------- Public ceremony: WebAuthn options + verify ---------- */
  fastify.post('/auth/break-glass/webauthn/options', async (req, reply) => {
    if (!requireFeature(reply)) return reply;
    const email = normalizeEmail(req.body?.email);
    if (!email) {
      return reply.code(400).send({ error: 'bad_request', detail: 'email required' });
    }
    try {
      const p = await db.query(
        `SELECT id FROM break_glass_admin_principals
         WHERE lower(email) = $1 AND enabled = true AND disabled_at IS NULL`,
        [email],
      );
      if (!p.rows[0]) {
        return reply.code(404).send({ error: 'not_found', detail: 'principal not registered' });
      }
      const creds = await db.query(
        `SELECT credential_id FROM break_glass_admin_webauthn
         WHERE principal_id = $1::uuid AND revoked_at IS NULL`,
        [p.rows[0].id],
      );
      if (!creds.rows.length) {
        return reply.code(404).send({
          error: 'no_credentials',
          detail: 'no hardware keys registered for this principal',
        });
      }
      const issued = issueChallenge(email);
      return {
        email,
        challengeId: issued.challengeId,
        challenge: issued.challenge,
        expiresInSeconds: issued.expiresInSeconds,
        allowCredentials: creds.rows.map((r) => r.credential_id),
        rpId: process.env.AIM_WEBAUTHN_RP_ID || undefined,
        userVerification: 'required',
        note:
          'Sign SHA-256("AIM-BG-ADMIN-V1"||challengeId||"."||challenge||"."||email||"."||credentialId) with the hardware private key (ES256 ieee-p1363).',
      };
    } catch (err) {
      if (tableMissing(err)) return missingMigration(reply);
      throw err;
    }
  });

  fastify.post('/auth/break-glass/webauthn/verify', async (req, reply) => {
    if (!requireFeature(reply)) return reply;
    const email = normalizeEmail(req.body?.email);
    const credentialId =
      typeof req.body?.credentialId === 'string' ? req.body.credentialId.trim() : '';
    const challengeId =
      typeof req.body?.challengeId === 'string' ? req.body.challengeId.trim() : '';
    const signature =
      typeof req.body?.signature === 'string' ? req.body.signature.trim() : '';
    const ttlMinutes = clampTtlMinutes(req.body?.ttlMinutes, DEFAULT_TTL_MINUTES);
    const reason =
      typeof req.body?.reason === 'string' && req.body.reason.trim()
        ? req.body.reason.trim().slice(0, 2000)
        : 'webauthn emergency admin';
    if (!email || !credentialId || !challengeId || !signature) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'email, credentialId, challengeId, signature required',
      });
    }
    const consumed = consumeChallenge(challengeId, email);
    if (!consumed.ok) {
      return reply.code(401).send({ error: consumed.reason });
    }
    try {
      const { rows } = await db.query(
        `SELECT w.*, p.email AS principal_email, p.enabled, p.disabled_at
         FROM break_glass_admin_webauthn w
         JOIN break_glass_admin_principals p ON p.id = w.principal_id
         WHERE w.credential_id = $1 AND w.revoked_at IS NULL`,
        [credentialId],
      );
      const cred = rows[0];
      if (!cred || normalizeEmail(cred.principal_email) !== email) {
        return reply.code(401).send({ error: 'unknown_credential' });
      }
      if (!cred.enabled || cred.disabled_at) {
        return reply.code(403).send({ error: 'principal_disabled' });
      }
      const jwk =
        typeof cred.public_key_jwk === 'string'
          ? JSON.parse(cred.public_key_jwk)
          : cred.public_key_jwk;
      const msg = challengeMessage({
        challengeId: consumed.challengeId,
        challenge: consumed.challenge,
        email,
        credentialId,
      });
      if (!verifyEs256Signature(jwk, msg, signature)) {
        audit(email, 'break_glass.admin.webauthn.auth_denied', 'break-glass/webauthn/verify', {
          reason: 'bad_signature',
          credentialId,
        });
        return reply.code(401).send({ error: 'invalid_signature' });
      }
      // Bump sign_count for reuse detection (monotonic best-effort).
      await db.query(
        `UPDATE break_glass_admin_webauthn
         SET sign_count = sign_count + 1, last_used_at = now()
         WHERE id = $1::uuid`,
        [cred.id],
      );

      const grantId = randomUUID();
      const now = new Date();
      const expiresAt = new Date(now.getTime() + ttlMinutes * 60 * 1000);
      const { rows: grants } = await db.query(
        `INSERT INTO break_glass_admin_grants
           (id, principal_email, method, status, reason, requested_by,
            first_approver, first_approved_at, second_approver, second_approved_at,
            activated_at, activated_by, expires_at, ttl_minutes)
         VALUES ($1::uuid, $2, 'webauthn', 'activated', $3, $2,
                 $2, $4, $2, $4, $4, $2, $5, $6)
         RETURNING *`,
        [grantId, email, reason, now, expiresAt, ttlMinutes],
      );

      const ttlSeconds = ttlMinutes * 60;
      const session = issueBreakGlassAdminSession(reply, {
        email,
        name: `Break-glass ${email}`,
        ttlSeconds,
        grantId,
        method: 'webauthn',
      });

      await appendEvent(db, {
        grantId,
        eventType: 'webauthn_auth',
        actor: email,
        detail: { credentialId, ttlSeconds },
      });
      await appendEvent(db, {
        grantId,
        eventType: 'grant_activated',
        actor: email,
        detail: { method: 'webauthn', ttlSeconds },
      });
      audit(email, 'break_glass.admin.webauthn.auth', 'break-glass/webauthn/verify', {
        grantId,
        credentialId,
        ttlSeconds,
      });
      audit(email, 'break_glass.admin.activate', `break-glass/grants/${grantId}`, {
        method: 'webauthn',
        ttlSeconds,
      });

      return {
        ok: true,
        method: 'webauthn',
        session: { email: session.email, role: session.role, mode: session.mode, exp: session.exp },
        grant: publicGrant(grants[0]),
      };
    } catch (err) {
      if (tableMissing(err)) return missingMigration(reply);
      throw err;
    }
  });
}

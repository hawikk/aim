// Versioned signed policy packs API.
//
//   GET  /api/policy/packs           — list registered packs
//   GET  /api/policy/packs/active    — active pack + provenance + live verify
//   GET  /api/policy/packs/:packId   — one pack (metadata; no file bodies)
//   POST /api/policy/packs/sign      — build+sign from live policy dir (needs privkey)
//   POST /api/policy/packs/verify    — verify a pack body without promoting
//   POST /api/policy/packs/promote   — verify, store, set active, audit who+hash
//
// All routes: admin only (policy promotion is security posture).
// Mutations append to the immutable audit trail (policy.promote / policy.sign).

import { requireRoles } from '../auth.js';
import { audit } from '../audit.js';
import { policyPath } from '../guardrail-policy.js';
import {
  packDir,
  packMode,
  loadPublicKeyFromEnv,
  loadPrivateKeyFromEnv,
  buildPayloadFromDir,
  signPayload,
  verifyPack,
  storePack,
  loadPack,
  listPacks,
  readActive,
  writeActivePointer,
  publicPackView,
} from '../policy-pack.js';

export async function policyPackRoutes(fastify, opts = {}) {
  const dir = opts.packDir ?? packDir();
  const policyDir = opts.policyPath ?? policyPath();
  const env = opts.env ?? process.env;
  const adminOnly = requireRoles('admin');

  function pubkey() {
    return opts.publicKey ?? loadPublicKeyFromEnv(env);
  }

  function mode() {
    return opts.mode ?? packMode(env);
  }

  fastify.get('/api/policy/packs', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const packs = listPacks(dir);
    const active = readActive(dir);
    return {
      packDir: dir,
      mode: mode(),
      publicKeyConfigured: !!pubkey(),
      privateKeyConfigured: !!(opts.privateKey ?? loadPrivateKeyFromEnv(env)),
      active: active
        ? {
            packId: active.packId,
            policyHash: active.policyHash,
            promotedBy: active.promotedBy,
            promotedAt: active.promotedAt,
            keyId: active.keyId,
            verified: active.verified,
          }
        : null,
      packs,
    };
  });

  fastify.get('/api/policy/packs/active', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const active = readActive(dir);
    if (!active) {
      return {
        active: null,
        mode: mode(),
        verification: { ok: false, reason: 'no_active_pack' },
      };
    }
    const pack = loadPack(dir, active.packId);
    let verification = { ok: false, reason: 'pack_missing' };
    if (pack) {
      const pub = pubkey();
      if (!pub && mode() === 'observe') {
        verification = {
          ok: active.verified === true,
          reason: active.verified ? 'pointer_trusted_observe' : 'unsigned_or_unverified',
          checks: [{ name: 'pointer', ok: active.verified === true, detail: 'observe mode, no public key' }],
        };
      } else {
        verification = verifyPack(pack, pub, {
          expectedKeyId: env.POLICY_PACK_KEY_ID || null,
        });
      }
    }
    return {
      active: {
        packId: active.packId,
        policyHash: active.policyHash,
        policyVersion: active.policyVersion,
        keyId: active.keyId,
        signedAt: active.signedAt,
        promotedBy: active.promotedBy,
        promotedAt: active.promotedAt,
        verified: active.verified,
        mode: active.mode ?? mode(),
      },
      pack: publicPackView(pack, verification),
      verification,
      mode: mode(),
    };
  });

  fastify.get('/api/policy/packs/:packId', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const pack = loadPack(dir, req.params.packId);
    if (!pack) {
      return reply.code(404).send({ error: 'not_found', detail: `no pack ${req.params.packId}` });
    }
    const pub = pubkey();
    const verification = pub
      ? verifyPack(pack, pub, { expectedKeyId: env.POLICY_PACK_KEY_ID || null })
      : { ok: false, reason: 'no_public_key', checks: [] };
    return publicPackView(pack, verification);
  });

  // Build + sign from the live policy directory. Requires private key.
  fastify.post('/api/policy/packs/sign', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const priv = opts.privateKey ?? loadPrivateKeyFromEnv(env);
    if (!priv) {
      return reply.code(503).send({
        error: 'signing_unavailable',
        detail: 'POLICY_PACK_PRIVATE_KEY is not configured on this server',
      });
    }
    const keyId = env.POLICY_PACK_KEY_ID || 'aim-policy-default';
    let pack;
    try {
      const payload = buildPayloadFromDir(policyDir);
      pack = signPayload(payload, priv, {
        keyId,
        packId: req.body?.packId || undefined,
      });
    } catch (err) {
      req.log.error(err, 'policy pack sign failed');
      return reply.code(500).send({ error: 'sign_failed', detail: err.message });
    }

    const store = req.body?.store !== false;
    if (store) {
      try {
        storePack(dir, pack);
      } catch (err) {
        return reply.code(500).send({ error: 'store_failed', detail: err.message });
      }
    }

    const actor = req.identity?.email ?? 'unknown';
    audit(actor, 'policy.sign', `policy/pack/${pack.packId}`, {
      policyHash: pack.payload.policyHash,
      policyVersion: pack.payload.policyVersion,
      keyId: pack.keyId,
      packId: pack.packId,
      stored: store,
    });

    const pub = pubkey();
    const verification = pub
      ? verifyPack(pack, pub)
      : { ok: true, reason: 'signed_no_verify_key', checks: [] };

    return {
      pack: publicPackView(pack, verification),
      envelope: pack,
      verification,
    };
  });

  fastify.post('/api/policy/packs/verify', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const envelope = req.body?.pack ?? req.body;
    if (!envelope || typeof envelope !== 'object') {
      return reply.code(400).send({ error: 'bad_request', detail: 'body must be a policy pack envelope' });
    }
    const pub = pubkey();
    if (!pub && mode() === 'enforce') {
      return reply.code(503).send({
        error: 'verify_unavailable',
        detail: 'POLICY_PACK_PUBLIC_KEY is required to verify packs in enforce mode',
      });
    }
    const verification = verifyPack(envelope, pub, {
      expectedKeyId: env.POLICY_PACK_KEY_ID || null,
    });
    return {
      verification,
      pack: publicPackView(envelope, verification),
    };
  });

  // Promote: body may be { packId } (registry) or a full envelope.
  fastify.post('/api/policy/packs/promote', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;

    const body = req.body ?? {};
    let pack = null;
    if (body.packId && !body.payload) {
      pack = loadPack(dir, body.packId);
      if (!pack) {
        return reply.code(404).send({ error: 'not_found', detail: `no pack ${body.packId} in registry` });
      }
    } else if (body.pack || body.payload) {
      pack = body.pack ?? body;
    } else {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'provide packId of a registered pack, or a full signed pack envelope',
      });
    }

    const m = mode();
    const pub = pubkey();
    let verification;

    if (m === 'enforce') {
      if (!pub) {
        return reply.code(503).send({
          error: 'promote_unavailable',
          detail: 'POLICY_PACK_PUBLIC_KEY is required to promote packs in enforce mode',
        });
      }
      verification = verifyPack(pack, pub, {
        expectedKeyId: env.POLICY_PACK_KEY_ID || null,
      });
      if (!verification.ok) {
        return reply.code(400).send({
          error: 'verification_failed',
          detail: verification.reason,
          verification,
        });
      }
    } else if (pub) {
      verification = verifyPack(pack, pub, {
        expectedKeyId: env.POLICY_PACK_KEY_ID || null,
      });
      if (!verification.ok) {
        return reply.code(400).send({
          error: 'verification_failed',
          detail: verification.reason,
          verification,
        });
      }
    } else if (typeof pack.signature === 'string' && pack.signature) {
      verification = { ok: false, reason: 'no_public_key', checks: [] };
      return reply.code(503).send({
        error: 'verify_unavailable',
        detail: 'pack is signed but POLICY_PACK_PUBLIC_KEY is not configured',
        verification,
      });
    } else {
      verification = { ok: false, reason: 'unsigned_observe', checks: [] };
    }

    const actor = req.identity?.email ?? 'unknown';
    const previous = readActive(dir);
    let pointer;
    try {
      pointer = writeActivePointer(dir, {
        pack,
        actor,
        verified: verification.ok === true,
        mode: m,
      });
    } catch (err) {
      req.log.error(err, 'policy pack promote failed');
      return reply.code(500).send({ error: 'promote_failed', detail: err.message });
    }

    const record = audit(actor, 'policy.promote', `policy/pack/${pack.packId}`, {
      policyHash: pack.payload.policyHash,
      policyVersion: pack.payload.policyVersion,
      packId: pack.packId,
      keyId: pack.keyId,
      verified: verification.ok === true,
      mode: m,
      previousPackId: previous?.packId ?? null,
      previousPolicyHash: previous?.policyHash ?? null,
    });

    return {
      promoted: true,
      active: pointer,
      verification,
      pack: publicPackView(pack, verification),
      audit: record ? { seq: record.seq, seal: record.seal, action: 'policy.promote' } : null,
    };
  });
}

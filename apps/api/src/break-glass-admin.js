// AIM-719 — emergency admin break-glass: dual control + hardware-key crypto.
//
// Pure helpers (no Fastify). Routes and tests import this module.
// WebAuthn path: ES256 (P-256) challenge-response over a server-issued nonce.
// Full browser WebAuthn clientDataJSON/authenticatorData can wrap the same
// public keys later; the security property is hardware-held private key +
// server-verified signature over a fresh challenge.

import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  timingSafeEqual,
  verify as cryptoVerify,
  sign as cryptoSign,
} from 'node:crypto';

export const DEFAULT_TTL_MINUTES = 60;
export const MIN_TTL_MINUTES = 5;
export const MAX_TTL_MINUTES = 480;
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;
export const GRANT_PENDING_TTL_MS = 4 * 60 * 60 * 1000; // dual-control window

/** Feature flag: AIM_BREAK_GLASS_ADMIN=1 enables the emergency admin path. */
export function isBreakGlassAdminEnabled(env = process.env) {
  return env.AIM_BREAK_GLASS_ADMIN === '1';
}

export function normalizeEmail(raw) {
  const e = String(raw ?? '').trim().toLowerCase();
  if (!e || e.length > 320) return null;
  // Practical operator emails; not full RFC 5322.
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) return null;
  return e;
}

export function clampTtlMinutes(raw, fallback = DEFAULT_TTL_MINUTES) {
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(MAX_TTL_MINUTES, Math.max(MIN_TTL_MINUTES, Math.floor(n)));
}

export function hashToken(token) {
  return createHash('sha256').update(String(token), 'utf8').digest('hex');
}

export function mintActivationToken() {
  return randomBytes(32).toString('base64url');
}

export function safeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
  } catch {
    return false;
  }
}

/* ---------- WebAuthn-compatible ES256 challenge crypto ---------- */

/**
 * Validate and normalize an EC P-256 JWK public key.
 * @returns {{ kty: 'EC', crv: 'P-256', x: string, y: string }}
 */
export function normalizePublicKeyJwk(jwk) {
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) {
    throw new Error('publicKeyJwk must be an object');
  }
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error('publicKeyJwk must be EC P-256 (WebAuthn ES256)');
  }
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new Error('publicKeyJwk requires x and y (base64url)');
  }
  // Reject private material if accidentally submitted.
  if (jwk.d) throw new Error('publicKeyJwk must not include private key material (d)');
  // Prove the key is parseable.
  createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}

/**
 * Canonical message signed for hardware-key auth:
 *   SHA-256("AIM-BG-ADMIN-V1" || challengeId || "." || challenge || "." || email || "." || credentialId)
 * Keeps the signed payload bound to principal + credential + challenge.
 */
export function challengeMessage({ challengeId, challenge, email, credentialId }) {
  const payload = [
    'AIM-BG-ADMIN-V1',
    String(challengeId),
    String(challenge),
    String(email).toLowerCase(),
    String(credentialId),
  ].join('.');
  return createHash('sha256').update(payload, 'utf8').digest();
}

/**
 * Verify an ES256 (P-256 + SHA-256) signature over the challenge message.
 * @param {object} publicKeyJwk
 * @param {Buffer} messageDigest — from challengeMessage()
 * @param {string} signatureB64url — IEEE P1363 (r||s) base64url, as Node produces for ECDSA
 */
export function verifyEs256Signature(publicKeyJwk, messageDigest, signatureB64url) {
  const key = createPublicKey({
    key: normalizePublicKeyJwk(publicKeyJwk),
    format: 'jwk',
  });
  let sig;
  try {
    sig = Buffer.from(String(signatureB64url), 'base64url');
  } catch {
    return false;
  }
  if (sig.length < 64) return false;
  try {
    // Node accepts IEEE-P1363 for JWK EC keys when dsaEncoding is ieee-p1363.
    return cryptoVerify(
      'SHA256',
      messageDigest,
      { key, dsaEncoding: 'ieee-p1363' },
      sig,
    );
  } catch {
    return false;
  }
}

/** Test helper: generate an ES256 keypair and sign a challenge message. */
export function generateTestKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  return {
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y },
    privateKey,
    sign(messageDigest) {
      return cryptoSign('SHA256', messageDigest, {
        key: privateKey,
        dsaEncoding: 'ieee-p1363',
      }).toString('base64url');
    },
  };
}

/* ---------- In-memory challenge store (process-local) ---------- */

const challenges = new Map(); // id -> { challenge, email, exp, createdAt }

export function clearChallengesForTests() {
  challenges.clear();
}

export function issueChallenge(email, { now = Date.now(), ttlMs = CHALLENGE_TTL_MS } = {}) {
  const id = randomBytes(16).toString('base64url');
  const challenge = randomBytes(32).toString('base64url');
  const rec = {
    id,
    challenge,
    email: normalizeEmail(email),
    exp: now + ttlMs,
    createdAt: now,
  };
  challenges.set(id, rec);
  return { challengeId: id, challenge, expiresInSeconds: Math.floor(ttlMs / 1000) };
}

export function consumeChallenge(challengeId, email, { now = Date.now() } = {}) {
  const rec = challenges.get(challengeId);
  if (!rec) return { ok: false, reason: 'unknown_challenge' };
  challenges.delete(challengeId);
  if (rec.exp <= now) return { ok: false, reason: 'challenge_expired' };
  const want = normalizeEmail(email);
  if (!want || rec.email !== want) return { ok: false, reason: 'email_mismatch' };
  return { ok: true, challenge: rec.challenge, challengeId: rec.id };
}

/* ---------- Public grant / principal shaping ---------- */

export function publicPrincipal(row) {
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name ?? row.displayName ?? null,
    enabled: row.enabled !== false && !row.disabled_at,
    createdBy: row.created_by ?? row.createdBy ?? null,
    createdAt: row.created_at ?? row.createdAt ?? null,
  };
}

export function publicCredential(row) {
  if (!row) return null;
  return {
    id: row.id,
    principalId: row.principal_id ?? row.principalId,
    credentialId: row.credential_id ?? row.credentialId,
    nickname: row.nickname ?? null,
    signCount: Number(row.sign_count ?? row.signCount ?? 0),
    createdBy: row.created_by ?? row.createdBy ?? null,
    createdAt: row.created_at ?? row.createdAt ?? null,
    lastUsedAt: row.last_used_at ?? row.lastUsedAt ?? null,
  };
}

export function publicGrant(row, { includeActivationHint = false } = {}) {
  if (!row) return null;
  const out = {
    id: row.id,
    principalEmail: row.principal_email ?? row.principalEmail,
    method: row.method,
    status: row.status,
    reason: row.reason,
    ticketRef: row.ticket_ref ?? row.ticketRef ?? null,
    requestedBy: row.requested_by ?? row.requestedBy,
    requestedAt: row.requested_at ?? row.requestedAt,
    firstApprover: row.first_approver ?? row.firstApprover ?? null,
    firstApprovedAt: row.first_approved_at ?? row.firstApprovedAt ?? null,
    secondApprover: row.second_approver ?? row.secondApprover ?? null,
    secondApprovedAt: row.second_approved_at ?? row.secondApprovedAt ?? null,
    activatedAt: row.activated_at ?? row.activatedAt ?? null,
    expiresAt: row.expires_at ?? row.expiresAt ?? null,
    ttlMinutes: row.ttl_minutes ?? row.ttlMinutes ?? DEFAULT_TTL_MINUTES,
    revokedBy: row.revoked_by ?? row.revokedBy ?? null,
    revokedAt: row.revoked_at ?? row.revokedAt ?? null,
  };
  if (includeActivationHint) {
    out.hasActivationToken = Boolean(row.activation_token_hash ?? row.activationTokenHash);
  }
  return out;
}

/**
 * Apply one dual-control approval. Returns next state + optional activation token.
 * Approver must differ from prior approver and should differ from requested principal
 * when possible — self-approval as *sole* control is rejected only for the second
 * slot when first was same person (always reject same email twice).
 */
export function applyDualApproval(grant, approverEmail, { now = new Date() } = {}) {
  const actor = normalizeEmail(approverEmail);
  if (!actor) return { ok: false, reason: 'invalid_approver' };
  if (!grant || grant.status !== 'pending') return { ok: false, reason: 'not_pending' };
  if (grant.method !== 'dual_control') return { ok: false, reason: 'wrong_method' };

  const first = grant.first_approver ?? grant.firstApprover;
  if (!first) {
    return {
      ok: true,
      stage: 'first',
      patch: {
        first_approver: actor,
        first_approved_at: now,
        updated_at: now,
      },
    };
  }
  const firstNorm = normalizeEmail(first);
  if (firstNorm === actor) {
    return { ok: false, reason: 'duplicate_approver' };
  }
  const activationToken = mintActivationToken();
  const ttlMin = clampTtlMinutes(grant.ttl_minutes ?? grant.ttlMinutes);
  const expiresAt = new Date(now.getTime() + ttlMin * 60 * 1000);
  return {
    ok: true,
    stage: 'second',
    activationToken,
    patch: {
      second_approver: actor,
      second_approved_at: now,
      status: 'approved',
      activation_token_hash: hashToken(activationToken),
      expires_at: expiresAt,
      updated_at: now,
    },
  };
}

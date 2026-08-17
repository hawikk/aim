// Machine credentials for headless consumers of the AIM API (AIM-165).
//
// Why this exists: D3.1 §5 says the sentinel agent reads alerts through the
// authenticated API, not through Redis — the API is the only thing on the
// compose network holding a bus credential. But every identity path in
// auth.js resolves from the `aim_session` browser cookie, which a service has
// no way to obtain: there is no OIDC flow a daemon can complete. With SSO on,
// the sentinel's GET /api/alerts is a flat 401. This module is the missing
// half: a non-interactive credential that resolves to the same three-role
// model, so the contract in alertbus.js is actually reachable.
//
// Design points that are load-bearing rather than incidental:
//
// * **The file stores hashes, not tokens.** An operator who reads the config
//   file — or a backup of it, or `docker inspect` on the volume — learns
//   nothing usable. Verification hashes the presented token and compares
//   digests, so the plaintext exists only in the client's environment.
//
// * **Service tokens may not hold `admin`.** The epic's standing
//   posture is strict read-only credentials (D4); a token that can drive the
//   guardrail admin surface is not that. An `admin` entry is rejected
//   at load with a named error rather than silently downgraded, because a
//   quiet downgrade would read as "my token doesn't work" at 3am.
//
// * **A configured-but-broken token file is a boot failure, not a fallback.**
//   Degrading to "no service tokens" would leave the sentinel 401ing against
//   an API that looks healthy. Fail closed AND loud (see loadError()).
//
// Pure and transport-free on purpose: auth.js owns the request plumbing, this
// owns the credential rules, and both are testable without a server.
import { readFileSync } from 'node:fs';
import { createHash, timingSafeEqual } from 'node:crypto';

// `admin` is deliberately absent — see the header. Auditor is allowed so a
// compliance exporter can hold a token too, and viewer for aggregate-only
// consumers; neither can mutate anything.
export const ALLOWED_ROLES = ['viewer', 'analyst', 'auditor'];

const SHA256_HEX = /^[0-9a-f]{64}$/;
const NAME_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;

export function hashToken(token) {
  return createHash('sha256').update(String(token), 'utf8').digest('hex');
}

/**
 * Parse + validate the token file's contents.
 *
 * Throws on any problem, naming the offending entry. Every rejection here is
 * a refusal to start: a half-loaded token set means some consumer silently
 * loses access, and "findings stop arriving" is the failure mode this stack
 * exists to prevent.
 */
export function parseTokenFile(text) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    throw new Error(`service token file is not valid JSON: ${err.message}`, { cause: err });
  }
  const list = doc?.tokens;
  if (!Array.isArray(list)) {
    throw new Error('service token file must be {"tokens": [...]}');
  }
  if (list.length === 0) {
    // An empty list is almost certainly a templating accident. If you really
    // want no service tokens, unset AIM_SERVICE_TOKENS_FILE.
    throw new Error('service token file contains no tokens; unset AIM_SERVICE_TOKENS_FILE to disable service auth');
  }

  const seen = new Set();
  const tokens = list.map((entry, i) => {
    const where = `tokens[${i}]`;
    const name = entry?.name;
    if (typeof name !== 'string' || !NAME_RE.test(name)) {
      throw new Error(`${where}.name must be lowercase alphanumeric/dash, 1-40 chars`);
    }
    const role = entry?.role;
    if (!ALLOWED_ROLES.includes(role)) {
      // Named explicitly so the admin case reads as a policy
      // decision rather than a typo.
      throw new Error(
        `${where} (${name}): role ${JSON.stringify(role)} is not permitted for a service token; allowed: ${ALLOWED_ROLES.join(', ')}`,
      );
    }
    const sha256 = entry?.sha256;
    if (typeof sha256 !== 'string' || !SHA256_HEX.test(sha256)) {
      throw new Error(`${where} (${name}).sha256 must be a 64-character lowercase hex digest`);
    }
    if (seen.has(sha256)) {
      // Two names sharing one secret makes the audit trail a lie: you could
      // never tell which consumer made a call.
      throw new Error(`${where} (${name}) reuses a digest already assigned to another token`);
    }
    seen.add(sha256);

    let expiresAt = null;
    if (entry?.expires_at !== undefined && entry?.expires_at !== null) {
      const ms = Date.parse(entry.expires_at);
      if (Number.isNaN(ms)) {
        throw new Error(`${where} (${name}).expires_at is not an ISO-8601 timestamp`);
      }
      expiresAt = ms;
    }
    return { name, role, sha256, expiresAt };
  });
  return tokens;
}

/**
 * The verifier. `null` tokens means service auth is not configured at all,
 * which is a different answer from "that token is wrong" — auth.js reports
 * the two distinctly so a misconfigured deployment is diagnosable.
 */
export class ServiceTokens {
  #tokens;

  #error;

  constructor({ tokens = null, error = null } = {}) {
    this.#tokens = tokens;
    this.#error = error;
  }

  static fromFile(path) {
    if (!path) return new ServiceTokens();
    try {
      return new ServiceTokens({ tokens: parseTokenFile(readFileSync(path, 'utf8')) });
    } catch (err) {
      // Captured rather than thrown so server.js can log one clear line and
      // exit, instead of an unhandled rejection mid-boot.
      return new ServiceTokens({ error: `${path}: ${err.message}` });
    }
  }

  get enabled() {
    return this.#tokens !== null;
  }

  /** Non-null when the file was configured but unusable. */
  loadError() {
    return this.#error;
  }

  /** Names only — safe to log at boot so operators can see what loaded. */
  names() {
    return (this.#tokens ?? []).map((t) => t.name);
  }

  /**
   * Verify a presented bearer token.
   *
   * Returns { ok: true, identity } or { ok: false, reason }. Reasons are
   * coarse on purpose ('unknown' vs 'expired'): expiry is worth telling a
   * caller because it is actionable and leaks nothing, but we never say
   * *which* token was close to matching.
   */
  verify(presented, now = Date.now()) {
    if (!this.enabled) return { ok: false, reason: 'not-configured' };
    if (typeof presented !== 'string' || presented.length === 0) {
      return { ok: false, reason: 'unknown' };
    }
    const digest = Buffer.from(hashToken(presented), 'utf8');

    // Compare against every entry, without breaking early on a match. The
    // work is a handful of 64-byte compares, and a constant-shape loop keeps
    // the response time from revealing the token's position in the file.
    let matched = null;
    for (const token of this.#tokens) {
      const candidate = Buffer.from(token.sha256, 'utf8');
      if (candidate.length === digest.length && timingSafeEqual(candidate, digest)) {
        matched = token;
      }
    }
    if (!matched) return { ok: false, reason: 'unknown' };
    if (matched.expiresAt !== null && matched.expiresAt <= now) {
      return { ok: false, reason: 'expired', name: matched.name };
    }
    return {
      ok: true,
      identity: {
        // `svc:` prefixed so a service call is never mistaken for a person in
        // the audit trail, and so it can't collide with a real IdP address.
        email: `svc:${matched.name}`,
        name: matched.name,
        groups: [],
        role: matched.role,
        // AIM-717: service tokens are pure RBAC (role → permissions); no ABAC
        // attrs unless a future token schema adds them.
        attributes: {},
        permissionGrants: [],
        reveal: false,
        mode: 'service',
      },
    };
  }
}

/**
 * Pull the raw token out of an Authorization header.
 * Returns null when the header is absent or not a Bearer credential — a
 * Basic/Negotiate header is not our business and must fall through.
 */
export function bearerFrom(headerValue) {
  if (typeof headerValue !== 'string') return null;
  const match = /^Bearer[ \t]+(.+)$/i.exec(headerValue.trim());
  return match ? match[1].trim() : null;
}

export default ServiceTokens;

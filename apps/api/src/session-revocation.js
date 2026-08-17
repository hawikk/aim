// Session revocation store.
// Session revocation store.
//
// AIM SSO cookies are stateless HMAC tokens: role/groups are embedded at
// login and re-validated only for signature + exp. Without a server-side
// check, a leaver who already holds a cookie keeps access until TTL
// (default 8h). This module is the force-deny path:
//
//   * Admin or a designated service (identity-sync deprovision) records a
//     revoke watermark for an email.
//   * Admin (or automation) records a revoke watermark for an email.
//   * Any session with iat <= watermark is treated as unauthenticated.
//   * A later successful re-login (after re-provision) issues a fresh
//     cookie with iat > watermark and works again.
//
// Process-local Map is the source of truth on the request path (sync, no
// DB round-trip). Optional Postgres write-through survives process restart
// and is hydrated at boot when a db client is wired. Multi-replica deploys
// should share the DB and call loadFromDb on each instance after writes
// (or accept sticky sessions). Full SCIM User lifecycle remains residual
//; identity-sync suspend → revoke is the automatic deprovision
// path for pilot.
// (or accept sticky sessions); SCIM push remains a separate residual.
//
// Pure enough to unit-test without Fastify or Postgres.

/**
 * @typedef {{ email: string, revokedAtSec: number, revokedBy: string|null, reason: string|null }} RevocationEntry
 */

export function normalizeEmail(email) {
  return String(email ?? '').trim().toLowerCase();
}

export function isValidEmail(email) {
  // Minimal shape check — not full RFC; enough to reject empty / header injection.
  const e = normalizeEmail(email);
  if (!e || e.length > 254) return false;
  if (e.includes('\n') || e.includes('\r') || e.includes('\0')) return false;
  return /^[^\s@]+@[^\s@]+$/.test(e);
}

export class SessionRevocationStore {
  constructor() {
    /** @type {Map<string, RevocationEntry>} */
    this.entries = new Map();
  }

  /**
   * Record (or advance) a revoke watermark for the user.
   * Later revokes only move the watermark forward.
   * @returns {RevocationEntry}
   */
  revoke(email, { reason = null, revokedBy = null, revokedAtSec = null } = {}) {
    const key = normalizeEmail(email);
    if (!key) {
      throw new Error('email is required');
    }
    const next = {
      email: key,
      revokedAtSec: typeof revokedAtSec === 'number' && Number.isFinite(revokedAtSec)
        ? Math.floor(revokedAtSec)
        : Math.floor(Date.now() / 1000),
      revokedBy: revokedBy == null ? null : String(revokedBy),
      reason: reason == null ? null : String(reason).slice(0, 500),
    };
    const prev = this.entries.get(key);
    if (prev && prev.revokedAtSec > next.revokedAtSec) {
      return prev;
    }
    this.entries.set(key, next);
    return next;
  }

  /**
   * True when the session was issued at or before the user's revoke watermark.
   * Sessions missing email or iat are not treated as revoked (decodeToken
   * already rejects broken tokens).
   */
  isSessionRevoked(session) {
    if (!session || typeof session.email !== 'string' || typeof session.iat !== 'number') {
      return false;
    }
    const entry = this.entries.get(normalizeEmail(session.email));
    if (!entry) return false;
    return session.iat <= entry.revokedAtSec;
  }

  /** @returns {RevocationEntry|null} */
  get(email) {
    return this.entries.get(normalizeEmail(email)) ?? null;
  }

  size() {
    return this.entries.size;
  }

  /** Test / boot seam. */
  clear() {
    this.entries.clear();
  }

  /**
   * Replace cache from DB rows: `{ email, revoked_at, revoked_by, reason }`.
   * `revoked_at` may be a Date, ISO string, or epoch seconds/ms.
   */
  hydrate(rows) {
    this.entries.clear();
    for (const row of rows ?? []) {
      const email = normalizeEmail(row.email);
      if (!email) continue;
      const revokedAtSec = toEpochSec(row.revoked_at ?? row.revokedAtSec);
      if (revokedAtSec == null) continue;
      this.entries.set(email, {
        email,
        revokedAtSec,
        revokedBy: row.revoked_by ?? row.revokedBy ?? null,
        reason: row.reason ?? null,
      });
    }
    return this.entries.size;
  }
}

function toEpochSec(value) {
  if (value == null) return null;
  if (typeof value === 'number' && Number.isFinite(value)) {
    // Heuristic: ms timestamps are > 1e12.
    return value > 1e12 ? Math.floor(value / 1000) : Math.floor(value);
  }
  if (value instanceof Date) {
    const ms = value.getTime();
    return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
  }
  const ms = Date.parse(String(value));
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

/** Process-wide default used by auth.js. Tests may call clear() / replace. */
export const sessionRevocations = new SessionRevocationStore();

/**
 * Persist a revoke into Postgres (best-effort upsert). Returns true on success.
 * Callers must tolerate missing table (pre-migration) without failing the API.
 */
export async function persistRevocation(db, entry) {
  if (!db?.query || !entry?.email) return false;
  try {
    await db.query(
      `INSERT INTO session_revocations (email, revoked_at, revoked_by, reason)
       VALUES ($1, to_timestamp($2), $3, $4)
       ON CONFLICT (email) DO UPDATE SET
         revoked_at = GREATEST(session_revocations.revoked_at, EXCLUDED.revoked_at),
         revoked_by = COALESCE(EXCLUDED.revoked_by, session_revocations.revoked_by),
         reason = COALESCE(EXCLUDED.reason, session_revocations.reason)`,
      [entry.email, entry.revokedAtSec, entry.revokedBy, entry.reason],
    );
    return true;
  } catch (err) {
    // undefined_table / connection errors: memory still holds the watermark.
    err._sessionRevocationPersist = true;
    throw err;
  }
}

/**
 * Load all revocations that still matter (watermark newer than max session TTL
 * ago would be enough; we load all — table stays small for leavers).
 */
export async function loadRevocationsFromDb(db, store = sessionRevocations) {
  if (!db?.query) return 0;
  const { rows } = await db.query(
    `SELECT email, revoked_at, revoked_by, reason FROM session_revocations`,
  );
  return store.hydrate(rows);
}

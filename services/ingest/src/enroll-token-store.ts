import { createHash } from "node:crypto";
import type { PoolLike } from "./migrate";

/**
 * DB-backed enrollment-token registry.
 *
 * Backs the admin onboarding flow: the dashboard mints scoped enrollment
 * tokens (see apps/api/src/routes/onboarding.js and migration 011), and
 * POST /v1/enroll redeems them here alongside the legacy ENROLL_TOKENS env
 * path. Tokens are enrollment-only — they never authenticate /v1/events — and
 * only their SHA-256 hash is persisted, mirroring the ingest bearer-token and
 * per-device-token posture.
 *
 * Redemption is two-phase so idempotent re-enrollment does not burn quota:
 *   1. validate(token) — cheap, no write: is this a real, non-revoked,
 *      unexpired, under-cap token? Returns its id when usable.
 *   2. recordEnrollment(id) — called by the route ONLY when a genuinely new
 *      device was created (device_store returned already_enrolled=false), so a
 *      collector re-running the installer does not consume an enrollment slot.
 */

/** Reason a token was rejected — for the ingest log, never surfaced to the client. */
export type EnrollTokenReject = "not_found" | "revoked" | "expired" | "exhausted";

export type EnrollTokenValidation =
  | {
      ok: true;
      tokenId: string;
      /**
       * Directory email this token attributes new devices to.
       * When set, POST /v1/enroll registers device_id → email with identity-sync
       * so resolver rules 1–2 can fire. Null/undefined = unbound bootstrap token.
       */
      boundEmail?: string | null;
    }
  | { ok: false; reason: EnrollTokenReject };

export interface EnrollTokenStore {
  /** Is this token usable right now? No side effects. */
  validate(token: string): Promise<EnrollTokenValidation>;
  /** Count one device enrolled against a token (new device only). */
  recordEnrollment(tokenId: string): Promise<void>;
}

/** SHA-256 hex, same hashing used for the ingest and per-device tokens. */
export function hashEnrollToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export class PostgresEnrollTokenStore implements EnrollTokenStore {
  constructor(private readonly pool: PoolLike) {}

  async validate(token: string): Promise<EnrollTokenValidation> {
    const res = await this.pool.query(
      `SELECT id, expires_at, max_enrollments, enrollment_count, revoked_at, bound_email
         FROM enroll_tokens
        WHERE token_hash = $1`,
      [hashEnrollToken(token)],
    );
    if (res.rows.length === 0) return { ok: false, reason: "not_found" };
    const row = res.rows[0] as {
      id: string;
      expires_at: string | Date | null;
      max_enrollments: number | null;
      enrollment_count: number;
      revoked_at: string | Date | null;
      bound_email: string | null;
    };
    if (row.revoked_at) return { ok: false, reason: "revoked" };
    if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) {
      return { ok: false, reason: "expired" };
    }
    if (
      row.max_enrollments !== null &&
      Number(row.enrollment_count) >= Number(row.max_enrollments)
    ) {
      return { ok: false, reason: "exhausted" };
    }
    const bound =
      typeof row.bound_email === "string" && row.bound_email.trim().length > 0
        ? row.bound_email.trim().toLowerCase()
        : null;
    return { ok: true, tokenId: String(row.id), boundEmail: bound };
  }

  async recordEnrollment(tokenId: string): Promise<void> {
    // Conditional increment: the max_enrollments guard is re-checked atomically
    // so a burst of concurrent enrollments can overshoot the cap by at most the
    // in-flight count, never unboundedly. last_used_at doubles as a liveness
    // signal for the onboarding UI.
    await this.pool.query(
      `UPDATE enroll_tokens
          SET enrollment_count = enrollment_count + 1,
              last_used_at = now()
        WHERE id = $1
          AND revoked_at IS NULL
          AND (max_enrollments IS NULL OR enrollment_count < max_enrollments)`,
      [tokenId],
    );
  }
}

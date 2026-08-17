import { createHash } from "node:crypto";
import type { UsageEventV1 } from "./schema";

export interface RejectedRecord {
  /** Index of the event within its batch. */
  batchIndex: number;
  /** Validation error text (paths/messages only, never payload values). */
  error: string;
  /** Raw rejected payload. Sinks must never persist this directly. */
  payload: unknown;
}

/**
 * The only representation of a rejected payload any store we operate is
 * allowed to hold: a SHA-256 over its JSON serialization plus its top-level
 * key names. An event that failed schema validation is by definition outside
 * the metadata-only contract, so it could carry prompt text or code.
 *
 * Shared by every rejection sink (Postgres `rejected_events`, the raw-batch
 * object archive) so a stub in one store joins to the row in the other on
 * `payload_hash`.
 */
export interface PayloadFingerprint {
  payload_hash: string;
  payload_keys: string[];
}

export function fingerprintPayload(payload: unknown): PayloadFingerprint {
  return {
    payload_hash: createHash("sha256").update(safeSerialize(payload)).digest("hex"),
    payload_keys:
      payload !== null && typeof payload === "object" && !Array.isArray(payload)
        ? Object.keys(payload)
        : [],
  };
}

function safeSerialize(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

/**
 * Accepted event after identity enrichment (AIM-49). user_pseudonym/team come
 * from identity-sync POST /resolve; both are null when the batch could not be
 * attributed (unresolved events are stored, never dropped).
 */
export interface EnrichedEvent extends UsageEventV1 {
  user_pseudonym: string | null;
  team: string | null;
  /** "human" | "service" | null — see identity.ts Resolution (AIM-149). */
  principal_kind: string | null;
}

/**
 * Persistence boundary for accepted and rejected events.
 *
 * v0 ships a direct-to-Postgres implementation; a queue-backed sink can be
 * added later without touching the HTTP layer.
 */
export interface EventSink {
  /**
   * Insert accepted events. Must be idempotent on `event_id`.
   * Returns the number of rows actually inserted (duplicates excluded).
   */
  insert(events: EnrichedEvent[]): Promise<number>;
  /** Record rejected events for audit, without storing payload content. */
  insertRejected(records: RejectedRecord[]): Promise<void>;
  /** Liveness check against the backing store. */
  ping(): Promise<void>;
  close(): Promise<void>;
}

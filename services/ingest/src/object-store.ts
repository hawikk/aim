import {
  PutBucketLifecycleConfigurationCommand,
  PutObjectCommand,
  S3Client,
  type LifecycleRule,
} from "@aws-sdk/client-s3";
import type { CollectorIdentity } from "./identity";
import type { UsageEventV1 } from "./schema";
import { fingerprintPayload, type RejectedRecord } from "./sink";

/**
 * Raw-batch archive: every accepted batch is written to the object
 * store as an immutable NDJSON object, so batches can be replayed or
 * re-examined forensically even if the row-level schema changes or data is
 * lost.
 *
 * Object layout:  raw/YYYY/MM/DD/<batch-id>.ndjson   (UTC date of receipt)
 *
 * NDJSON format:
 *   line 1  — {"_batch_meta": {batch_id, received_at, collector, event_count,
 *              rejected_count}}
 *   line 2+ — one line per received event, in batch order:
 *               * schema-valid events, verbatim
 *               * a {"_rejected": {...}} fingerprint stub for everything else
 *
 * PRIVACY (no-content-egress invariant): the archive is written
 * AFTER schema validation and only ever holds events the canonical
 * metadata-only schema accepted. The schema (`additionalProperties: false`)
 * is the control that rejects content-bearing fields, so archiving the body
 * before it ran meant a buggy or malicious collector could land `prompt_text`
 * in object storage even though Postgres refused it. Rejected payloads are
 * recorded exactly the way `rejected_events` records them — validation error
 * + SHA-256 + top-level key names, never the payload (see
 * migrations/001_init.sql). The stub keeps the archive's operational value:
 * batch order and line count still match what the collector sent, and
 * `payload_hash` joins an archive line to its `rejected_events` row.
 *
 * Replay: fetch the object, drop the `_batch_meta` line and any `_rejected`
 * stub, and re-POST the remaining lines as { events: [...] } to /v1/events.
 * Ingest is idempotent on event_id, so replay never double-stores.
 */
export interface BatchArchive {
  put(key: string, body: string): Promise<void>;
}

/** Object-store retention lifecycle. The raw batch archive is
 *  event-class data, so its expiry mirrors the events retention window. */
export interface RetentionLifecycle {
  applyRetentionPolicy(eventWindowDays: number): Promise<void>;
}

/** Rule id we own on the bucket — stable so re-applying replaces, not stacks. */
export const RAW_BATCH_LIFECYCLE_ID = "aim-raw-batch-retention";

/**
 * Build the ILM rule that expires the date-partitioned `raw/` batch prefix
 * after `days`. Object keys are laid out `raw/YYYY/MM/DD/<id>.ndjson`
 * (archiveKey), so a single prefix rule covers the whole archive. MinIO
 * implements the S3 lifecycle API, so the same rule drives MinIO locally and
 * S3 in cloud — the store enforces expiry itself; no sweep job to run or trust.
 */
export function rawBatchLifecycleRule(days: number): LifecycleRule {
  return {
    ID: RAW_BATCH_LIFECYCLE_ID,
    Status: "Enabled",
    Filter: { Prefix: "raw/" },
    Expiration: { Days: days },
  };
}

export interface ObjectStoreSettings {
  endpoint: string;
  bucket: string;
  region: string;
  accessKey: string;
  secretKey: string;
}

/** S3-compatible archive (MinIO locally, S3 in cloud). Path-style is required for MinIO. */
export class S3BatchArchive implements BatchArchive, RetentionLifecycle {
  private readonly client: S3Client;
  private readonly bucket: string;

  constructor(settings: ObjectStoreSettings) {
    this.bucket = settings.bucket;
    this.client = new S3Client({
      endpoint: settings.endpoint,
      region: settings.region,
      forcePathStyle: true,
      credentials: {
        accessKeyId: settings.accessKey,
        secretAccessKey: settings.secretKey,
      },
    });
  }

  async put(key: string, body: string): Promise<void> {
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: body,
        ContentType: "application/x-ndjson",
      }),
    );
  }

  /**
   * Declare (idempotently) the retention lifecycle on the bucket so the object
   * store expires raw batches older than the events window on its own. Applied
   * at startup; re-applying with the same rule ID replaces rather than stacks.
   */
  async applyRetentionPolicy(eventWindowDays: number): Promise<void> {
    await this.client.send(
      new PutBucketLifecycleConfigurationCommand({
        Bucket: this.bucket,
        LifecycleConfiguration: { Rules: [rawBatchLifecycleRule(eventWindowDays)] },
      }),
    );
  }
}

/** Object key for a batch, date-partitioned in UTC for retention and replay scans. */
export function archiveKey(batchId: string, receivedAt: Date): string {
  const y = receivedAt.getUTCFullYear();
  const m = String(receivedAt.getUTCMonth() + 1).padStart(2, "0");
  const d = String(receivedAt.getUTCDate()).padStart(2, "0");
  return `raw/${y}/${m}/${d}/${batchId}.ndjson`;
}

export interface BatchMeta {
  batch_id: string;
  received_at: string;
  /**
   * Collector-attested endpoint identity, as parsed by the allowlist in
   * identity.ts (device_id / os_user / build) — never the raw `collector`
   * envelope, which is client-controlled and may carry unknown keys.
   */
  collector: CollectorIdentity | null;
  /** Number of event lines in the object (valid + rejected stubs). */
  event_count: number;
  /** How many of those lines are `_rejected` fingerprint stubs. */
  rejected_count: number;
}

/**
 * One archive line. A `rejected` entry carries the raw payload *into* this
 * module but never out of it: the serializer replaces it with a fingerprint.
 * Making that the only way to archive a non-validated event is what keeps the
 * guarantee out of reach of a future caller's mistake.
 */
export type ArchiveEntry =
  | { kind: "accepted"; event: UsageEventV1 }
  | { kind: "rejected"; rejected: RejectedRecord };

/** Metadata-only stand-in for an event that failed schema validation. */
interface RejectedStub {
  _rejected: {
    batch_index: number;
    error: string;
    payload_hash: string;
    payload_keys: string[];
  };
}

function rejectedStub(record: RejectedRecord): RejectedStub {
  return {
    _rejected: {
      batch_index: record.batchIndex,
      error: record.error,
      ...fingerprintPayload(record.payload),
    },
  };
}

/** Serialize a validated batch to the archive NDJSON format. */
export function toArchiveNdjson(meta: BatchMeta, entries: ArchiveEntry[]): string {
  const lines = [JSON.stringify({ _batch_meta: meta })];
  for (const entry of entries) {
    lines.push(
      JSON.stringify(entry.kind === "accepted" ? entry.event : rejectedStub(entry.rejected)),
    );
  }
  return lines.join("\n") + "\n";
}

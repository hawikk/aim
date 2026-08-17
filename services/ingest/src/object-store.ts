import {
  PutBucketLifecycleConfigurationCommand,
  PutObjectCommand,
  S3Client,
  type LifecycleRule,
} from "@aws-sdk/client-s3";

/**
 * Raw-batch archive (AIM-83): every accepted batch is written to the object
 * store as an immutable NDJSON object before the Postgres insert, so batches
 * can be replayed or re-examined forensically even if the row-level schema
 * changes or data is lost.
 *
 * Object layout:  raw/YYYY/MM/DD/<batch-id>.ndjson   (UTC date of receipt)
 *
 * NDJSON format:
 *   line 1  — {"_batch_meta": {batch_id, received_at, collector, event_count}}
 *   line 2+ — the raw event payloads exactly as received from the collector
 *
 * Replay: fetch the object, drop the `_batch_meta` line, and re-POST the
 * remaining lines as { events: [...] } to /v1/events. Ingest is idempotent
 * on event_id, so replay never double-stores.
 */
export interface BatchArchive {
  put(key: string, body: string): Promise<void>;
}

/** Object-store retention lifecycle (AIM-143). The raw batch archive is
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
  /** Collector-attested endpoint identity, exactly as received (may be null). */
  collector: unknown;
  /** Number of raw event lines in the object (valid + rejected). */
  event_count: number;
}

/** Serialize a raw batch to the archive NDJSON format. */
export function toArchiveNdjson(meta: BatchMeta, rawEvents: unknown[]): string {
  const lines = [JSON.stringify({ _batch_meta: meta })];
  for (const event of rawEvents) {
    lines.push(JSON.stringify(event));
  }
  return lines.join("\n") + "\n";
}

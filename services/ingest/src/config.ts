import { join } from "node:path";
import {
  parseAttestationMode,
  parseAttestationPublicKeys,
  type AttestationControl,
} from "./attestation";
import type { ObjectStoreSettings } from "./object-store";
import type { AdmissionControl, AdmissionMode, SharedTokenMode } from "./server";
import type { VendorPollerConfig } from "./vendor-admin/types";
import { loadVendorPollerConfig } from "./vendor-admin/poller";

export type { SharedTokenMode };

export interface IngestConfig {
  port: number;
  databaseUrl: string;
  /**
   * Shared fleet / bootstrap bearer tokens from INGEST_TOKENS.
   * May be empty when SharedTokenMode is disabled and only device tokens
   * (plus optional OTLP-scoped tokens) are expected.
   */
  ingestTokens: string[];
  /**
   * How INGEST_TOKENS authorize /v1/events. Default `full` with
   * deprecation metrics; operators move to `bootstrap` then `disabled`.
   */
  sharedTokenMode: SharedTokenMode;
  /** Per-ring enrollment tokens for POST /v1/enroll. Empty = enroll disabled. */
  enrollTokens: string[];
  migrationsDir: string;
  /** Base URL of identity-sync. Unset = store everything unattributed. */
  identityResolveUrl?: string;
  /**
   * Shared HS256 secret for minting service JWTs against identity-sync gated
   * endpoints (enroll-time device_mappings). Must match
   * IDENTITY_SYNC_JWT_HS256_SECRET on identity-sync. Unset = enroll still
   * works but does not auto-register device bindings.
   */
  identitySyncJwtHs256Secret?: string;
  /**
   * Raw-batch archival target. Unset = archival disabled; Postgres
   * remains the only store. When set, every accepted batch is written as an
   * NDJSON object before the Postgres insert.
   */
  objectStore?: ObjectStoreSettings;
  /**
   * HMAC salt for deriving host_ref from OTel service names on /v1/traces
   *. Unset = development default (fine for local pilot; set in prod).
   */
  otelHostSalt?: string;
  /**
   * Overload admission control for /v1/events. Defaults to shadow:
   * observe-and-count what would be shed without changing responses. Set
   * INGEST_ADMISSION_MODE=enforce to shed with 429/Retry-After above the cap.
   */
  admission: AdmissionControl;
  /**
   * Signed collector build identity. Default off so pilot fleets
   * keep flowing; shadow measures unsigned rate; enforce rejects them.
   */
  attestation: AttestationControl;
  /** vendor admin puller. Missing tokens degrade the feed only. */
  vendorAdmin: VendorPollerConfig;
}

const DEFAULT_MAX_INFLIGHT = 64;
const DEFAULT_RETRY_AFTER_S = 1;

function loadAdmission(env: NodeJS.ProcessEnv): AdmissionControl {
  const raw = (env.INGEST_ADMISSION_MODE ?? "shadow").trim().toLowerCase();
  const mode: AdmissionMode =
    raw === "off" || raw === "enforce" || raw === "shadow" ? (raw as AdmissionMode) : "shadow";
  const maxInflight = intFromEnv(env.INGEST_MAX_INFLIGHT, DEFAULT_MAX_INFLIGHT, "INGEST_MAX_INFLIGHT");
  const retryAfterSeconds = intFromEnv(
    env.INGEST_ADMISSION_RETRY_AFTER_S,
    DEFAULT_RETRY_AFTER_S,
    "INGEST_ADMISSION_RETRY_AFTER_S",
  );
  return { mode, maxInflight, retryAfterSeconds };
}

function intFromEnv(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined || value.trim() === "") return fallback;
  const n = Number.parseInt(value, 10);
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(`invalid ${name}: ${value} (expected a positive integer)`);
  }
  return n;
}

function loadSharedTokenMode(env: NodeJS.ProcessEnv): SharedTokenMode {
  const raw = (env.INGEST_SHARED_TOKEN_MODE ?? "full").trim().toLowerCase();
  if (raw === "full" || raw === "bootstrap" || raw === "disabled") {
    return raw;
  }
  throw new Error(
    `invalid INGEST_SHARED_TOKEN_MODE: ${env.INGEST_SHARED_TOKEN_MODE} (expected full|bootstrap|disabled)`,
  );
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): IngestConfig {
  const databaseUrl = env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required");
  }

  const sharedTokenMode = loadSharedTokenMode(env);
  // INGEST_TOKENS is bootstrap/OTLP material, not the only event
  // credential. Empty is allowed — every /v1/events call must then present a
  // live device token (or fail closed).
  const ingestTokens = (env.INGEST_TOKENS ?? "")
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  const enrollTokens = (env.ENROLL_TOKENS ?? "")
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  const port = Number.parseInt(env.PORT ?? "3000", 10);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`invalid PORT: ${env.PORT}`);
  }

  return {
    port,
    databaseUrl,
    ingestTokens,
    sharedTokenMode,
    enrollTokens,
    migrationsDir: env.MIGRATIONS_DIR ?? join(__dirname, "..", "migrations"),
    identityResolveUrl: env.IDENTITY_RESOLVE_URL?.replace(/\/+$/, "") || undefined,
    identitySyncJwtHs256Secret: env.IDENTITY_SYNC_JWT_HS256_SECRET?.trim() || undefined,
    objectStore: loadObjectStore(env),
    otelHostSalt: env.OTEL_HOST_SALT || undefined,
    admission: loadAdmission(env),
    attestation: {
      mode: parseAttestationMode(env.INGEST_ATTESTATION_MODE),
      publicKeys: parseAttestationPublicKeys(env.INGEST_ATTESTATION_PUBKEYS),
    },
    vendorAdmin: loadVendorPollerConfig(env),
  };
}

function loadObjectStore(env: NodeJS.ProcessEnv): ObjectStoreSettings | undefined {
  const endpoint = env.OBJECT_STORE_ENDPOINT;
  const bucket = env.OBJECT_STORE_BUCKET;
  if (!endpoint && !bucket) {
    return undefined;
  }
  if (!endpoint || !bucket) {
    throw new Error("OBJECT_STORE_ENDPOINT and OBJECT_STORE_BUCKET must be set together");
  }
  const accessKey = env.OBJECT_STORE_ACCESS_KEY;
  const secretKey = env.OBJECT_STORE_SECRET_KEY;
  if (!accessKey || !secretKey) {
    throw new Error(
      "OBJECT_STORE_ACCESS_KEY and OBJECT_STORE_SECRET_KEY are required when archival is enabled",
    );
  }
  return {
    endpoint,
    bucket,
    region: env.OBJECT_STORE_REGION ?? "us-east-1",
    accessKey,
    secretKey,
  };
}

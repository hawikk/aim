import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { validateEvent, type UsageEventV1 } from "./schema";
import { bearerToken, isValidOtelToken, isValidToken } from "./auth";
import type { EventSink, EnrichedEvent, RejectedRecord } from "./sink";
import {
  evaluateAttestation,
  type AttestationControl,
} from "./attestation";
import {
  NoopIdentityResolver,
  parseCollectorIdentity,
  UNRESOLVED,
  type CollectorIdentity,
  type DeviceMappingRegistrar,
  type IdentityResolver,
  type Resolution,
} from "./identity";
import type { DeviceStore, EnrollRequest, HeartbeatRequest } from "./device-store";
import type { EnrollTokenStore } from "./enroll-token-store";
import { archiveKey, toArchiveNdjson, type BatchArchive } from "./object-store";
import { mapOtlpTraceRequest, MAX_OTLP_SPANS } from "./otel";
import { mapOtlpMetricsRequest, MAX_OTLP_DATAPOINTS } from "./otel-metrics";
import { mapCopilotMetrics, mapCursorDailyUsage } from "./vendor-admin";
import type { VendorAdminStore } from "./vendor-admin/types";
import { randomUUID } from "node:crypto";

export const MAX_BATCH_SIZE = 500;
const BODY_LIMIT_BYTES = 5 * 1024 * 1024;
const MAX_ERROR_LENGTH = 500;

/**
 * Admission control (AIM-127). Above the measured within-SLO throughput ceiling
 * the ingest service was observed to *queue-and-hold* — 200 with unbounded p99
 * latency growth — instead of shedding. This caps concurrent in-flight
 * /v1/events work so a much larger fleet, a misbehaving collector, or a retry
 * storm gets a `429 Retry-After` backpressure signal (which collectors already
 * treat as retain-and-retry) rather than driving latency and memory arbitrarily
 * high. Shadow-first: `shadow` counts what it *would* shed without shedding.
 */
export type AdmissionMode = "off" | "shadow" | "enforce";
export interface AdmissionControl {
  mode: AdmissionMode;
  /** Max concurrent in-flight /v1/events requests before shedding. */
  maxInflight: number;
  /** Retry-After header value (seconds) sent on a 429 shed. */
  retryAfterSeconds: number;
}
/** Off by default so existing embeddings (tests) see no behaviour change. */
const ADMISSION_OFF: AdmissionControl = { mode: "off", maxInflight: 0, retryAfterSeconds: 1 };

/**
 * How static INGEST_TOKENS authorize POST /v1/events (AIM-319).
 * Deprecation path: full → bootstrap → disabled (device tokens only).
 */
export type SharedTokenMode = "full" | "bootstrap" | "disabled";

/**
 * Fallback HMAC salt for host_ref derivation on the OTLP path when
 * OTEL_HOST_SALT is unset. Development/pilot only — production deployments
 * MUST set OTEL_HOST_SALT (same secrecy class as the collector HMAC salt).
 */
const DEV_OTEL_HOST_SALT = "aimon-dev-otel-host-salt";

export interface ServerOptions {
  sink: EventSink;
  /**
   * Shared fleet / bootstrap bearer tokens (from INGEST_TOKENS env).
   * Device tokens (DB-backed) are first-class for /v1/events (AIM-217/307/319).
   */
  tokens: string[];
  /**
   * How shared env tokens authorize /v1/events (AIM-319). Default `full`
   * with deprecation counters; set `disabled` to refuse shared tokens on
   * the events path entirely (device tokens only).
   */
  sharedTokenMode?: SharedTokenMode;
  /** Identity resolver (AIM-49). Defaults to a no-op: all batches unattributed. */
  resolver?: IdentityResolver;
  /**
   * Collector enrollment/heartbeat registry (AIM-28). When unset, the
   * /v1/enroll, /v1/heartbeat and /v1/coverage routes respond 503.
   */
  deviceStore?: DeviceStore;
  /**
   * Admin-issued, per-ring enrollment tokens (from ENROLL_TOKENS env). Legacy
   * path for POST /v1/enroll — kept for dev compose, deprecated in favour of
   * DB-backed minted tokens (AIM-131). Not shipped in the collector package.
   */
  enrollTokens?: string[];
  /**
   * DB-backed enrollment-token registry (AIM-131). When set, POST /v1/enroll
   * redeems dashboard-minted tokens (named, scoped, revocable) in addition to
   * the legacy env tokens above. Enrollment-only: these never authorize
   * /v1/events. (Enrollment-issued *device* tokens do authorize /v1/events —
   * see DeviceStore.authenticate / AIM-217 / AIM-307.)
   */
  enrollTokenStore?: EnrollTokenStore;
  /**
   * AIM-455: when a minted enroll token carries bound_email, register
   * device_id → email with identity-sync after a new device is created.
   * Fail-open — mapping errors must not undo enrollment.
   */
  deviceMappingRegistrar?: DeviceMappingRegistrar;
  /**
   * Raw-batch archive (AIM-83). When set, every accepted batch is written as
   * an NDJSON object BEFORE the Postgres insert. Archival is fail-open: an
   * archive error is logged and counted (ingest_archive_errors_total) but the
   * batch is still stored — Postgres remains the system of record.
   */
  archive?: BatchArchive;
  /**
   * HMAC salt for deriving host_ref from OTel service names (AIM-105).
   * Falls back to a development default when unset.
   */
  otelHostSalt?: string;
  /**
   * AIM-1168 vendor admin daily rollups (Cursor / Copilot pull, Claude OTel
   * loc extras). Unset = metrics events still store; rollups are skipped.
   */
  vendorAdminStore?: VendorAdminStore;
  /** Enable pino request logging. Payloads are never logged — ids/counts only. */
  logger?: boolean;
  /**
   * Overload admission control for /v1/events (AIM-127). Defaults to off:
   * unbounded in-flight, no backpressure signal. Production sets `shadow` to
   * observe, then `enforce` to shed with 429/Retry-After above the cap.
   */
  admission?: AdmissionControl;
  /**
   * Signed collector build identity (AIM-646). Defaults to off so pilot
   * fleets without release embeds keep working. Shadow measures unsigned
   * rate; enforce rejects with 403.
   */
  attestation?: AttestationControl;
}

/** Off by default — no verification, no rejection (AIM-646 pilot path). */
const ATTESTATION_OFF: AttestationControl = { mode: "off", publicKeys: new Map() };

interface BatchBody {
  events?: unknown;
  /** Optional collector-attested endpoint identity, resolved once per batch. */
  collector?: unknown;
}

/** Minimal in-process counters, exposed as Prometheus text at /metrics. */
const metrics = {
  batchesTotal: 0,
  eventsAcceptedTotal: 0,
  eventsDuplicatesTotal: 0,
  eventsRejectedTotal: 0,
  eventsUnresolvedTotal: 0,
  identityErrorsTotal: 0,
  /**
   * AIM-1114: batches stored unattributed because resolve had no enrolled
   * device_id (wire + auth). Typical residual: shared-token auth + collector
   * that only attests os_user while service_identities are device_id-keyed.
   */
  identityUnresolvedMissingDeviceIdTotal: 0,
  /**
   * AIM-1114: enrolled device token present but /resolve still returned
   * unresolved — service_identity / device_mapping orphan or directory miss.
   */
  identityUnresolvedEnrolledDeviceTotal: 0,
  archiveErrorsTotal: 0,
  otelRequestsTotal: 0,
  otelSpansMappedTotal: 0,
  otelSpansSkippedNonGenaiTotal: 0,
  otelSpansRejectedTotal: 0,
  otelAttributesDroppedTotal: 0,
  otelMetricRequestsTotal: 0,
  otelMetricDatapointsMappedTotal: 0,
  otelMetricDatapointsSkippedTotal: 0,
  // Admission control (AIM-127).
  admissionInflight: 0,
  admissionInflightHighWater: 0,
  admissionShedTotal: 0,
  admissionShadowSheddableTotal: 0,
  // Auth-layer rejections on /v1/events (AIM-307). Previously invisible:
  // 401s never reached rejected_events and the DLQ looked empty.
  authRejectedTotal: 0,
  // Auth path counters (AIM-319): which credential class authorized events.
  authDeviceTokenTotal: 0,
  authSharedTokenTotal: 0,
  // Build attestation (AIM-646).
  attestationValidTotal: 0,
  attestationUnsignedTotal: 0,
  attestationInvalidTotal: 0,
  attestationRejectedTotal: 0,
};

function renderMetrics(admission: AdmissionControl, attestation: AttestationControl): string {
  return [
    "# HELP ingest_batches_total Event batches processed.",
    "# TYPE ingest_batches_total counter",
    `ingest_batches_total ${metrics.batchesTotal}`,
    "# HELP ingest_events_accepted_total Events stored (duplicates excluded).",
    "# TYPE ingest_events_accepted_total counter",
    `ingest_events_accepted_total ${metrics.eventsAcceptedTotal}`,
    "# HELP ingest_events_duplicates_total Events skipped as already stored (idempotent replay).",
    "# TYPE ingest_events_duplicates_total counter",
    `ingest_events_duplicates_total ${metrics.eventsDuplicatesTotal}`,
    "# HELP ingest_events_rejected_total Events rejected by schema validation.",
    "# TYPE ingest_events_rejected_total counter",
    `ingest_events_rejected_total ${metrics.eventsRejectedTotal}`,
    "# HELP ingest_events_unresolved_total Stored events with no identity attribution (unattributed usage).",
    "# TYPE ingest_events_unresolved_total counter",
    `ingest_events_unresolved_total ${metrics.eventsUnresolvedTotal}`,
    "# HELP ingest_identity_errors_total Batches where identity resolution failed (stored unattributed).",
    "# TYPE ingest_identity_errors_total counter",
    `ingest_identity_errors_total ${metrics.identityErrorsTotal}`,
    "# HELP ingest_identity_unresolved_missing_device_id_total Batches stored unattributed with no enrolled device_id on the resolve path (AIM-1114).",
    "# TYPE ingest_identity_unresolved_missing_device_id_total counter",
    `ingest_identity_unresolved_missing_device_id_total ${metrics.identityUnresolvedMissingDeviceIdTotal}`,
    "# HELP ingest_identity_unresolved_enrolled_device_total Batches where an enrolled device_id still resolved unattributed (orphan/mapping miss, AIM-1114).",
    "# TYPE ingest_identity_unresolved_enrolled_device_total counter",
    `ingest_identity_unresolved_enrolled_device_total ${metrics.identityUnresolvedEnrolledDeviceTotal}`,
    "# HELP ingest_archive_errors_total Batches that could not be written to the raw-batch object store (still stored in Postgres).",
    "# TYPE ingest_archive_errors_total counter",
    `ingest_archive_errors_total ${metrics.archiveErrorsTotal}`,
    "# HELP ingest_otel_requests_total OTLP trace export requests processed (AIM-105).",
    "# TYPE ingest_otel_requests_total counter",
    `ingest_otel_requests_total ${metrics.otelRequestsTotal}`,
    "# HELP ingest_otel_spans_mapped_total GenAI spans mapped to canonical events.",
    "# TYPE ingest_otel_spans_mapped_total counter",
    `ingest_otel_spans_mapped_total ${metrics.otelSpansMappedTotal}`,
    "# HELP ingest_otel_spans_skipped_non_genai_total Spans without gen_ai.* attributes (accepted, not metered).",
    "# TYPE ingest_otel_spans_skipped_non_genai_total counter",
    `ingest_otel_spans_skipped_non_genai_total ${metrics.otelSpansSkippedNonGenaiTotal}`,
    "# HELP ingest_otel_spans_rejected_total GenAI spans that failed mapping or schema validation.",
    "# TYPE ingest_otel_spans_rejected_total counter",
    `ingest_otel_spans_rejected_total ${metrics.otelSpansRejectedTotal}`,
    "# HELP ingest_otel_attributes_dropped_total Span/resource attributes dropped by the receiver allowlist (privacy audit signal).",
    "# TYPE ingest_otel_attributes_dropped_total counter",
    `ingest_otel_attributes_dropped_total ${metrics.otelAttributesDroppedTotal}`,
    "# HELP ingest_otel_metric_requests_total OTLP metric export requests processed (AIM-1168 Claude Code).",
    "# TYPE ingest_otel_metric_requests_total counter",
    `ingest_otel_metric_requests_total ${metrics.otelMetricRequestsTotal}`,
    "# HELP ingest_otel_metric_datapoints_mapped_total Claude Code metric datapoints mapped to events or rollups.",
    "# TYPE ingest_otel_metric_datapoints_mapped_total counter",
    `ingest_otel_metric_datapoints_mapped_total ${metrics.otelMetricDatapointsMappedTotal}`,
    "# HELP ingest_otel_metric_datapoints_skipped_total Non-Claude or unmapped metric datapoints.",
    "# TYPE ingest_otel_metric_datapoints_skipped_total counter",
    `ingest_otel_metric_datapoints_skipped_total ${metrics.otelMetricDatapointsSkippedTotal}`,
    "# HELP ingest_admission_max_inflight Configured concurrent in-flight /v1/events cap (0 = disabled).",
    "# TYPE ingest_admission_max_inflight gauge",
    `ingest_admission_max_inflight ${admission.mode === "off" ? 0 : admission.maxInflight}`,
    "# HELP ingest_admission_inflight Current concurrent in-flight /v1/events requests.",
    "# TYPE ingest_admission_inflight gauge",
    `ingest_admission_inflight ${metrics.admissionInflight}`,
    "# HELP ingest_admission_inflight_high_water Peak concurrent in-flight /v1/events requests since start.",
    "# TYPE ingest_admission_inflight_high_water gauge",
    `ingest_admission_inflight_high_water ${metrics.admissionInflightHighWater}`,
    "# HELP ingest_admission_shed_total Requests shed with 429 by admission control (enforce mode).",
    "# TYPE ingest_admission_shed_total counter",
    `ingest_admission_shed_total ${metrics.admissionShedTotal}`,
    "# HELP ingest_admission_shadow_sheddable_total Requests that would have been shed (shadow mode; served 200).",
    "# TYPE ingest_admission_shadow_sheddable_total counter",
    `ingest_admission_shadow_sheddable_total ${metrics.admissionShadowSheddableTotal}`,
    "# HELP ingest_auth_rejected_total /v1/events requests rejected at the auth layer (401/403).",
    "# TYPE ingest_auth_rejected_total counter",
    `ingest_auth_rejected_total ${metrics.authRejectedTotal}`,
    "# HELP ingest_auth_device_token_total /v1/events authorized by a DB-backed device token (AIM-319).",
    "# TYPE ingest_auth_device_token_total counter",
    `ingest_auth_device_token_total ${metrics.authDeviceTokenTotal}`,
    "# HELP ingest_auth_shared_token_total /v1/events authorized by a static INGEST_TOKENS entry (deprecated path, AIM-319).",
    "# TYPE ingest_auth_shared_token_total counter",
    `ingest_auth_shared_token_total ${metrics.authSharedTokenTotal}`,
    "# HELP ingest_attestation_mode Collector build attestation mode (0=off 1=shadow 2=enforce, AIM-646).",
    "# TYPE ingest_attestation_mode gauge",
    `ingest_attestation_mode ${attestation.mode === "off" ? 0 : attestation.mode === "shadow" ? 1 : 2}`,
    "# HELP ingest_attestation_valid_total Batches with a valid signed build identity (AIM-646).",
    "# TYPE ingest_attestation_valid_total counter",
    `ingest_attestation_valid_total ${metrics.attestationValidTotal}`,
    "# HELP ingest_attestation_unsigned_total Batches missing a build signature (AIM-646).",
    "# TYPE ingest_attestation_unsigned_total counter",
    `ingest_attestation_unsigned_total ${metrics.attestationUnsignedTotal}`,
    "# HELP ingest_attestation_invalid_total Batches with a bad/unknown build signature (AIM-646).",
    "# TYPE ingest_attestation_invalid_total counter",
    `ingest_attestation_invalid_total ${metrics.attestationInvalidTotal}`,
    "# HELP ingest_attestation_rejected_total Batches rejected by enforce-mode build attestation (AIM-646).",
    "# TYPE ingest_attestation_rejected_total counter",
    `ingest_attestation_rejected_total ${metrics.attestationRejectedTotal}`,
    "",
  ].join("\n");
}

/** Reason string written to rejected_events for auth-layer denials (AIM-307). */
export const AUTH_REJECT_REASON = "auth_rejected: invalid_or_missing_bearer";

/**
 * Record an auth-layer rejection so the DLQ is not blind to 401/403 storms.
 * Fail-open: a ledger write error must not change the 401 response itself.
 * Never stores the presented credential — only a reason + empty key set.
 */
async function recordAuthRejection(
  sink: EventSink,
  log: { error: (obj: unknown, msg: string) => void },
): Promise<void> {
  metrics.authRejectedTotal += 1;
  try {
    await sink.insertRejected([
      {
        batchIndex: -1,
        error: AUTH_REJECT_REASON,
        payload: { reason: "auth_rejected" },
      },
    ]);
  } catch (err) {
    log.error({ err }, "failed to record auth rejection in rejected_events");
  }
}

export async function buildServer(options: ServerOptions): Promise<FastifyInstance> {
  const resolver = options.resolver ?? new NoopIdentityResolver();
  const deviceStore = options.deviceStore;
  const enrollTokens = options.enrollTokens ?? [];
  const enrollTokenStore = options.enrollTokenStore;
  const deviceMappingRegistrar = options.deviceMappingRegistrar;
  const otelHostSalt = options.otelHostSalt ?? DEV_OTEL_HOST_SALT;
  const admission = options.admission ?? ADMISSION_OFF;
  const attestation = options.attestation ?? ATTESTATION_OFF;
  const app = Fastify({
    bodyLimit: BODY_LIMIT_BYTES,
    logger: options.logger
      ? {
          // Never log credentials.
          redact: { paths: ["req.headers.authorization"], censor: "[redacted]" },
        }
      : false,
  });

  // Accept protobuf bodies at the transport layer so the /v1/traces route can
  // answer with its own actionable 415 ("use http/json") instead of Fastify's
  // generic Unsupported Media Type.
  app.addContentTypeParser(
    "application/x-protobuf",
    { parseAs: "buffer" },
    (_req, _body, done) => done(null, {}),
  );

  app.get("/healthz", async () => ({ status: "ok" }));
  app.get("/readyz", async (_req, reply) => {
    try {
      await options.sink.ping();
      return { status: "ok" };
    } catch {
      return reply.code(503).send({ status: "unavailable" });
    }
  });

  app.get("/metrics", async (_req, reply) =>
    reply.type("text/plain; version=0.0.4").send(renderMetrics(admission, attestation)),
  );

  app.post("/v1/events", async (req, reply) => {
    const token = bearerToken(req.headers.authorization);
    if (!token) {
      await recordAuthRejection(options.sink, req.log);
      return reply.code(401).send({ error: "unauthorized" });
    }
    // Auth order (AIM-217 / AIM-307 / AIM-319):
    // 1. Live enrollment-issued device token (DB) — primary, survives
    //    INGEST_TOKENS rotation and stack recreation.
    // 2. Shared INGEST_TOKENS env entry — bootstrap/managed fleets only,
    //    gated by sharedTokenMode, counted as deprecated when used.
    // Enroll tokens themselves never authorize events.
    const sharedMode = options.sharedTokenMode ?? "full";
    let authorized = false;
    // AIM-455: the enrollment-issued device token is the authoritative
    // join key for identity resolution. Capture it at auth so we resolve
    // even when the batch omits `collector.device_id` (or sends a stale one).
    // Client-supplied device_id is never trusted over a verified token.
    let authenticatedDeviceId: string | undefined;

    if (deviceStore) {
      const device = await deviceStore.authenticate(token);
      if (device) {
        metrics.authDeviceTokenTotal += 1;
        authorized = true;
        authenticatedDeviceId = device.device_id;
      }
    }

    if (!authorized && sharedMode !== "disabled") {
      if (isValidToken(token, options.tokens)) {
        metrics.authSharedTokenTotal += 1;
        if (metrics.authSharedTokenTotal === 1 || metrics.authSharedTokenTotal % 1000 === 0) {
          req.log.warn(
            {
              sharedTokenMode: sharedMode,
              uses: metrics.authSharedTokenTotal,
              deprecation:
                "INGEST_TOKENS on /v1/events is bootstrap-only (AIM-319); prefer enrollment device tokens",
            },
            "deprecated shared INGEST_TOKENS authorized /v1/events",
          );
        }
        authorized = true;
      }
    }

    if (!authorized) {
      await recordAuthRejection(options.sink, req.log);
      return reply.code(401).send({ error: "unauthorized" });
    }

    // Admission control (AIM-127): cap concurrent in-flight work. Checked after
    // auth (unauthorized noise never counts) and before any archival/DB work, so
    // a shed costs almost nothing. Shadow counts-only; enforce sheds with 429.
    if (admission.mode !== "off" && metrics.admissionInflight >= admission.maxInflight) {
      if (admission.mode === "enforce") {
        metrics.admissionShedTotal += 1;
        req.log.warn(
          { inflight: metrics.admissionInflight, maxInflight: admission.maxInflight },
          "admission control: shedding /v1/events with 429 (overloaded)",
        );
        return reply
          .code(429)
          .header("Retry-After", String(admission.retryAfterSeconds))
          .send({ error: "ingest overloaded; retry after backoff", retry_after_seconds: admission.retryAfterSeconds });
      }
      // shadow: record what enforce would have shed, then serve normally.
      metrics.admissionShadowSheddableTotal += 1;
    }

    metrics.admissionInflight += 1;
    if (metrics.admissionInflight > metrics.admissionInflightHighWater) {
      metrics.admissionInflightHighWater = metrics.admissionInflight;
    }
    try {
      return await handleEvents(req, reply, authenticatedDeviceId);
    } finally {
      metrics.admissionInflight -= 1;
    }
  });

  async function handleEvents(
    req: FastifyRequest,
    reply: FastifyReply,
    authenticatedDeviceId?: string,
  ) {
    const body = req.body as BatchBody | null;
    if (!body || !Array.isArray(body.events) || body.events.length === 0) {
      return reply.code(400).send({ error: "body must be { events: [...] } with at least one event" });
    }
    if (body.events.length > MAX_BATCH_SIZE) {
      return reply
        .code(413)
        .send({ error: `batch too large: ${body.events.length} events, max ${MAX_BATCH_SIZE}` });
    }

    const parsed = parseCollectorIdentity(body.collector);
    if ("error" in parsed) {
      return reply.code(400).send({ error: parsed.error });
    }
    // Verified enrollment device_id wins over any client-claimed device_id.
    // os_user from the collector envelope is still accepted as a secondary hint
    // (resolver rules 0/2); it cannot override the token-bound device.
    const collectorIdentity: CollectorIdentity = {
      ...parsed.identity,
      ...(authenticatedDeviceId ? { device_id: authenticatedDeviceId } : {}),
    };

    // Signed build identity (AIM-646). Flag-gated: off (default) / shadow /
    // enforce. Rejects with 403 in enforce when signature is missing/invalid.
    const { verdict: attestVerdict, rejectReason: attestReject } = evaluateAttestation(
      collectorIdentity.build,
      attestation,
    );
    if (attestVerdict.status === "valid") {
      metrics.attestationValidTotal += 1;
    } else if (attestVerdict.status === "unsigned") {
      metrics.attestationUnsignedTotal += 1;
    } else if (attestVerdict.status === "invalid") {
      metrics.attestationInvalidTotal += 1;
    }
    if (attestReject) {
      metrics.attestationRejectedTotal += 1;
      metrics.authRejectedTotal += 1;
      try {
        await options.sink.insertRejected([
          {
            batchIndex: -1,
            error: `attestation_rejected: ${attestReject}`.slice(0, MAX_ERROR_LENGTH),
            payload: { reason: "attestation_rejected" },
          },
        ]);
      } catch (err) {
        req.log.error({ err }, "failed to record attestation rejection in rejected_events");
      }
      return reply.code(403).send({
        error: "collector build attestation required",
        detail: attestReject,
      });
    }

    // Raw-batch archival (AIM-83): persist the batch exactly as received
    // (valid + rejected events) before any database write, keyed by UTC
    // date/batch-id, for replay and forensics. Fail-open: an archive error
    // never blocks ingestion.
    if (options.archive) {
      const receivedAt = new Date();
      const batchId = randomUUID();
      try {
        await options.archive.put(
          archiveKey(batchId, receivedAt),
          toArchiveNdjson(
            {
              batch_id: batchId,
              received_at: receivedAt.toISOString(),
              collector: body.collector ?? null,
              event_count: body.events.length,
            },
            body.events,
          ),
        );
      } catch (err) {
        // Ids/counts only — never log event payloads.
        req.log.error({ err, batch_id: batchId }, "raw-batch archive write failed");
        metrics.archiveErrorsTotal += 1;
      }
    }

    const valid: UsageEventV1[] = [];
    const rejected: RejectedRecord[] = [];
    body.events.forEach((event: unknown, index: number) => {
      const result = validateEvent(event);
      if (result.valid) {
        valid.push(event as UsageEventV1);
      } else {
        rejected.push({
          batchIndex: index,
          error: result.errors.join("; ").slice(0, MAX_ERROR_LENGTH),
          payload: event,
        });
      }
    });

    // Identity enrichment (AIM-49): one /resolve call per batch, stamped onto
    // every accepted event. Fail-open — resolution errors store the batch
    // unattributed rather than dropping it.
    let resolution: Resolution = UNRESOLVED;
    if (valid.length > 0 && (collectorIdentity.device_id || collectorIdentity.os_user)) {
      try {
        resolution = await resolver.resolve(collectorIdentity);
      } catch (err) {
        // Ids/counts only — never log the endpoint identity itself.
        req.log.warn({ err }, "identity resolution failed; storing batch unattributed");
        metrics.identityErrorsTotal += 1;
      }
    }
    // AIM-1114: unattributed batches from registered service hosts must not be
    // silent. Count missing-device_id vs enrolled-but-unresolved separately so
    // dogfood residual (os_user-only on a device_id-keyed service principal)
    // pages operators instead of washing into generic unresolved totals.
    const attributed =
      resolution.user_pseudonym !== null || resolution.principal_kind === "service";
    if (valid.length > 0 && !attributed) {
      const hasDeviceId = Boolean(collectorIdentity.device_id);
      if (!hasDeviceId) {
        metrics.identityUnresolvedMissingDeviceIdTotal += 1;
        req.log.warn(
          {
            has_os_user: Boolean(collectorIdentity.os_user),
            auth_device: Boolean(authenticatedDeviceId),
            resolution: resolution.rule,
            principal_kind: resolution.principal_kind,
            event_count: valid.length,
          },
          "identity unresolved without device_id; service hosts keyed only by device_id will fall through to principal_kind=unknown (AIM-1114)",
        );
      } else {
        metrics.identityUnresolvedEnrolledDeviceTotal += 1;
        req.log.warn(
          {
            resolution: resolution.rule,
            principal_kind: resolution.principal_kind,
            event_count: valid.length,
            // Never log the device_id itself — ids/counts only.
            has_device_id: true,
            auth_device: Boolean(authenticatedDeviceId),
          },
          "identity unresolved for enrolled device_id; check service_identities / device_mappings join keys (AIM-1114)",
        );
      }
    }
    const accepted: EnrichedEvent[] = valid.map((e) => ({
      ...e,
      user_pseudonym: resolution.user_pseudonym,
      team: resolution.team,
      principal_kind: resolution.principal_kind,
    }));
    // Service principals may carry a pseudonym; also treat principal_kind=service
    // as attributed (Epic A / AIM-487 gate: user_pseudonym OR principal_kind=service).
    const unresolved = attributed ? 0 : accepted.length;

    let inserted = 0;
    try {
      await options.sink.insertRejected(rejected);
      inserted = await options.sink.insert(accepted);
    } catch (err) {
      // Ids/counts only — never log event payloads.
      req.log.error({ err }, "sink write failed");
      return reply.code(500).send({ error: "internal error" });
    }

    const duplicates = accepted.length - inserted;
    metrics.batchesTotal += 1;
    metrics.eventsAcceptedTotal += inserted;
    metrics.eventsDuplicatesTotal += duplicates;
    metrics.eventsRejectedTotal += rejected.length;
    metrics.eventsUnresolvedTotal += unresolved;

    req.log.info(
      { accepted: inserted, duplicates, rejected: rejected.length, unresolved },
      "event batch processed",
    );

    return reply.code(200).send({
      accepted: inserted,
      duplicates,
      unresolved,
      rejected: rejected.map((r) => ({ index: r.batchIndex, error: r.error })),
    });
  }

  // --- OTLP receiver: OTel GenAI spans from first-party apps (AIM-105) -------
  // Contract: docs/otel-genai-integration-guide.md.
  //
  // PRIVACY: the allowlist in otel.ts is enforced inside mapOtlpTraceRequest
  // BEFORE anything is validated, stored, or logged. Unlike /v1/events, the
  // raw OTLP body is deliberately NOT written to the batch archive — it may
  // carry non-allowlisted attributes (up to and including prompt text from a
  // misconfigured SDK), and those must never land in any store we operate.
  app.post("/v1/traces", async (req, reply) => {
    const token = bearerToken(req.headers.authorization);
    // App-team tokens may be scoped to this route with the `@otel` suffix
    // in INGEST_TOKENS (see auth.ts); full collector tokens also work.
    if (!token || !isValidOtelToken(token, options.tokens)) {
      return reply.code(401).send({ error: "unauthorized" });
    }

    const contentType = req.headers["content-type"] ?? "";
    if (contentType.includes("protobuf")) {
      return reply.code(415).send({
        error:
          "OTLP/HTTP protobuf is not supported yet; configure the exporter with protocol=http/json",
      });
    }

    const result = mapOtlpTraceRequest(req.body, otelHostSalt);
    if (result.stats.spansReceived > MAX_OTLP_SPANS) {
      return reply
        .code(413)
        .send({ error: `too many spans: max ${MAX_OTLP_SPANS} per request` });
    }
    if (
      result.events.length === 0 &&
      result.stats.spansReceived === 0 &&
      result.errors.length > 0
    ) {
      // Not a trace export at all.
      return reply.code(400).send({ error: result.errors[0] });
    }

    // Defense in depth: mapped events still pass canonical schema validation.
    // A mapping bug rejects here instead of storing a malformed event.
    const valid: UsageEventV1[] = [];
    const rejected: RejectedRecord[] = [];
    result.events.forEach((event, index) => {
      const check = validateEvent(event);
      if (check.valid) {
        valid.push(event);
      } else {
        rejected.push({
          batchIndex: index,
          error: check.errors.join("; ").slice(0, MAX_ERROR_LENGTH),
          payload: event,
        });
      }
    });

    // No identity resolution on this path: app telemetry is APM-class service
    // data — there is no employee to attribute.
    const accepted: EnrichedEvent[] = valid.map((e) => ({
      ...e,
      user_pseudonym: null,
      team: null,
      principal_kind: null,
    }));

    let inserted = 0;
    try {
      await options.sink.insertRejected(rejected);
      inserted = await options.sink.insert(accepted);
    } catch (err) {
      // Ids/counts only — never log payloads.
      req.log.error({ err }, "sink write failed");
      return reply.code(500).send({ error: "internal error" });
    }

    const rejectedTotal = result.stats.spansRejected + rejected.length;
    metrics.otelRequestsTotal += 1;
    metrics.otelSpansMappedTotal += inserted;
    metrics.otelSpansSkippedNonGenaiTotal += result.stats.spansSkippedNonGenai;
    metrics.otelSpansRejectedTotal += rejectedTotal;
    metrics.otelAttributesDroppedTotal += result.stats.attributesDropped;

    req.log.info(
      {
        mapped: inserted,
        skipped_non_genai: result.stats.spansSkippedNonGenai,
        rejected: rejectedTotal,
        attributes_dropped: result.stats.attributesDropped,
      },
      "otlp trace export processed",
    );

    // OTLP ExportTraceServiceResponse shape (partial success).
    return reply.code(200).send({
      partialSuccess:
        rejectedTotal > 0
          ? {
              rejectedSpans: rejectedTotal,
              errorMessage: "some GenAI spans failed mapping or validation",
            }
          : {},
    });
  });

  // --- OTLP metrics: Claude Code first-party counters (AIM-1168) -----------
  // Same auth as /v1/traces. Body is never archived (may carry emails).
  app.post("/v1/metrics", async (req, reply) => {
    const token = bearerToken(req.headers.authorization);
    if (!token || !isValidOtelToken(token, options.tokens)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const contentType = req.headers["content-type"] ?? "";
    if (contentType.includes("protobuf")) {
      return reply.code(415).send({
        error:
          "OTLP/HTTP protobuf is not supported yet; configure the exporter with protocol=http/json",
      });
    }

    const result = mapOtlpMetricsRequest(req.body, otelHostSalt);
    if (result.stats.datapointsReceived > MAX_OTLP_DATAPOINTS) {
      return reply
        .code(413)
        .send({ error: `too many datapoints: max ${MAX_OTLP_DATAPOINTS} per request` });
    }
    if (
      result.events.length === 0 &&
      result.rollups.length === 0 &&
      result.stats.datapointsReceived === 0 &&
      result.errors.length > 0
    ) {
      return reply.code(400).send({ error: result.errors[0] });
    }

    const valid: UsageEventV1[] = [];
    const rejected: RejectedRecord[] = [];
    result.events.forEach((event, index) => {
      const check = validateEvent(event);
      if (check.valid) valid.push(event);
      else {
        rejected.push({
          batchIndex: index,
          error: check.errors.join("; ").slice(0, MAX_ERROR_LENGTH),
          payload: event,
        });
      }
    });
    const accepted: EnrichedEvent[] = valid.map((e) => ({
      ...e,
      user_pseudonym: null,
      team: null,
      principal_kind: null,
    }));

    let inserted = 0;
    try {
      await options.sink.insertRejected(rejected);
      inserted = await options.sink.insert(accepted);
      if (options.vendorAdminStore && result.rollups.length > 0) {
        await options.vendorAdminStore.upsertDaily(result.rollups);
      }
    } catch (err) {
      req.log.error({ err }, "sink write failed");
      return reply.code(500).send({ error: "internal error" });
    }

    metrics.otelMetricRequestsTotal += 1;
    metrics.otelMetricDatapointsMappedTotal += result.stats.datapointsMapped;
    metrics.otelMetricDatapointsSkippedTotal += result.stats.datapointsSkipped;
    metrics.otelAttributesDroppedTotal += result.stats.attributesDropped;

    req.log.info(
      {
        mapped_events: inserted,
        rollups: result.rollups.length,
        skipped: result.stats.datapointsSkipped,
        rejected: result.stats.datapointsRejected + rejected.length,
        attributes_dropped: result.stats.attributesDropped,
      },
      "otlp metric export processed",
    );

    return reply.code(200).send({
      partialSuccess:
        result.stats.datapointsRejected + rejected.length > 0
          ? {
              rejectedDataPoints: result.stats.datapointsRejected + rejected.length,
              errorMessage: "some Claude Code metric datapoints failed mapping or validation",
            }
          : {},
    });
  });

  // Optional fixture / offline replay of vendor admin JSON (AIM-1168).
  // Same bearer as OTLP. Mapper allowlist runs before storage.
  const writeVendorFeed = async (
    feed: "copilot_metrics" | "cursor_analytics",
    body: unknown,
    hashSalt?: string,
  ) => {
    const mapped =
      feed === "copilot_metrics" ? mapCopilotMetrics(body) : mapCursorDailyUsage(body, hashSalt);
    if (!options.vendorAdminStore) {
      return { stored: 0, mapped };
    }
    const stored = await options.vendorAdminStore.upsertDaily(mapped.rollups);
    const lastDay = mapped.rollups.at(-1)?.day ?? null;
    await options.vendorAdminStore.upsertFeedState({
      feed,
      configured: true,
      lastErrorClass: mapped.rollups.length > 0 ? "ok" : "map_error",
      lastDay,
      detail: `push rows=${mapped.stats.rowsMapped} dropped_attrs=${mapped.stats.attributesDropped}`,
    });
    return { stored, mapped };
  };

  app.post("/v1/vendor-admin/copilot", async (req, reply) => {
    const token = bearerToken(req.headers.authorization);
    if (!token || !isValidOtelToken(token, options.tokens)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const { stored, mapped } = await writeVendorFeed("copilot_metrics", req.body);
    if (mapped.rollups.length === 0 && mapped.errors.length > 0) {
      return reply.code(400).send({ error: mapped.errors[0], attributesDropped: mapped.stats.attributesDropped });
    }
    return reply.code(200).send({
      accepted: stored,
      mapped: mapped.stats.rowsMapped,
      attributesDropped: mapped.stats.attributesDropped,
    });
  });

  app.post("/v1/vendor-admin/cursor", async (req, reply) => {
    const token = bearerToken(req.headers.authorization);
    if (!token || !isValidOtelToken(token, options.tokens)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    const { stored, mapped } = await writeVendorFeed("cursor_analytics", req.body, otelHostSalt);
    if (mapped.rollups.length === 0 && mapped.errors.length > 0) {
      return reply.code(400).send({ error: mapped.errors[0], attributesDropped: mapped.stats.attributesDropped });
    }
    return reply.code(200).send({
      accepted: stored,
      mapped: mapped.stats.rowsMapped,
      attributesDropped: mapped.stats.attributesDropped,
    });
  });

  // --- Collector enrollment & heartbeat (AIM-28) ---------------------------
  // Contract: docs/deployment/enrollment-and-heartbeat.md.

  // POST /v1/enroll — installer registers a device with an enrollment token
  // and receives a per-device token (once). Two token sources (AIM-131):
  //   * DB-backed minted tokens (dashboard onboarding) — named, scoped,
  //     revocable; redeemed via enrollTokenStore.
  //   * legacy ENROLL_TOKENS env — kept for dev compose, deprecation-warned.
  // A validated DB token's id is remembered and its enrollment counted only
  // when a genuinely new device is created (so idempotent re-runs don't burn
  // scoped quota).
  app.post("/v1/enroll", async (req, reply) => {
    if (!deviceStore) {
      return reply.code(503).send({ error: "device registry not configured" });
    }
    const token = bearerToken(req.headers.authorization);
    if (!token) {
      return reply.code(401).send({ error: "unauthorized" });
    }

    let enrollTokenId: string | null = null;
    let boundEmail: string | null = null;
    const legacyMatch = enrollTokens.length > 0 && isValidToken(token, enrollTokens);
    if (legacyMatch) {
      // Deprecated path: works, but nudge operators toward minted tokens.
      req.log.warn(
        "enroll via legacy ENROLL_TOKENS env var — deprecated (AIM-131); mint a scoped token from the dashboard onboarding view instead",
      );
    } else if (enrollTokenStore) {
      const check = await enrollTokenStore.validate(token);
      if (!check.ok) {
        // Reason logged for the operator (ids/counts only); the client gets a
        // uniform 401 so a probe can't distinguish revoked from unknown.
        req.log.info({ reason: check.reason }, "enroll token rejected");
        return reply.code(401).send({ error: "unauthorized" });
      }
      enrollTokenId = check.tokenId;
      boundEmail = check.boundEmail ?? null;
    } else {
      return reply.code(401).send({ error: "unauthorized" });
    }

    const body = req.body as Partial<EnrollRequest> | null;
    if (!body || typeof body.host_id !== "string" || !UUID_RE.test(body.host_id)) {
      return reply.code(400).send({ error: "host_id (uuid v4) is required" });
    }

    try {
      const result = await deviceStore.enroll({
        host_id: body.host_id,
        hostname: strOrUndef(body.hostname),
        os: strOrUndef(body.os),
        ring: strOrUndef(body.ring),
        collector_version: strOrUndef(body.collector_version),
        // Explicit reissue only — never implied. Callers that lost the local
        // device_token (host wipe / missing state dir) pass reissue:true with
        // a still-valid enroll bearer (AIM-166 dogfood recovery path).
        reissue: body.reissue === true,
      });
      // Count the enrollment against a minted token only for a new device;
      // idempotent re-runs (already_enrolled) never consume scoped quota.
      if (enrollTokenId && !result.already_enrolled) {
        try {
          await enrollTokenStore!.recordEnrollment(enrollTokenId);
        } catch (err) {
          // The device is already registered; a counter write failure must not
          // fail the enroll. Log and move on (ids only).
          req.log.warn({ err }, "enroll token counter update failed");
        }
      }
      // AIM-868: collector may present the previously stored enrollment id.
      // When ingest minted a new device_id (stack recreate / host_id row lost),
      // rebind identity-sync join keys so service_identity / device_mapping
      // rows do not silently orphan attribution on the next batch.
      const previousDeviceId = strOrUndef(
        (body as { previous_device_id?: unknown }).previous_device_id,
      );
      let joinKeysRebound = false;
      if (
        previousDeviceId &&
        previousDeviceId !== result.device_id &&
        deviceMappingRegistrar
      ) {
        try {
          const rebound = await deviceMappingRegistrar.rebindDevice({
            fromDeviceId: previousDeviceId,
            toDeviceId: result.device_id,
            reason: `enroll rebind host ${body.host_id} after device_id change`,
          });
          joinKeysRebound = true;
          req.log.info(
            {
              from_device_id: previousDeviceId,
              to_device_id: result.device_id,
              service_identities_updated: rebound.serviceIdentitiesUpdated,
              device_mappings_updated: rebound.deviceMappingsUpdated,
            },
            "identity join keys rebound at enroll (AIM-868)",
          );
        } catch (err) {
          req.log.warn(
            { err, from_device_id: previousDeviceId, to_device_id: result.device_id },
            "identity join-key rebind failed; device enrolled, attribution may stay orphaned",
          );
        }
      }
      // AIM-455: if the mint bound this token to a directory human, register
      // the join key so the next event batch resolves. Fail-open: never undo
      // a successful enroll because identity-sync is down.
      // Also re-register after a device_id rebind so the new id is mapped.
      if (
        boundEmail &&
        deviceMappingRegistrar &&
        (!result.already_enrolled || joinKeysRebound)
      ) {
        try {
          await deviceMappingRegistrar.register({
            deviceId: result.device_id,
            primaryEmail: boundEmail,
            source: "enrollment",
            reason: `enroll-time binding from token ${enrollTokenId ?? "unknown"}`,
          });
          req.log.info(
            { device_id: result.device_id, bound: true },
            "device mapping registered at enroll",
          );
        } catch (err) {
          req.log.warn(
            { err, device_id: result.device_id },
            "device mapping registration failed; device enrolled unattributed",
          );
        }
      }
      req.log.info(
        { device_id: result.device_id, already_enrolled: result.already_enrolled },
        "device enrolled",
      );
      // Idempotent re-enroll: existing identity, no fresh token (200, not 409,
      // so installer re-runs are safe; token re-issue is a deliberate admin op).
      return reply.code(result.already_enrolled ? 200 : 201).send(result);
    } catch (err) {
      req.log.error({ err }, "enroll failed");
      return reply.code(500).send({ error: "internal error" });
    }
  });

  // POST /v1/heartbeat — device reports liveness with its per-device token.
  app.post("/v1/heartbeat", async (req, reply) => {
    if (!deviceStore) {
      return reply.code(503).send({ error: "device registry not configured" });
    }
    const token = bearerToken(req.headers.authorization);
    if (!token) {
      return reply.code(401).send({ error: "unauthorized" });
    }

    const body = (req.body ?? {}) as Partial<HeartbeatRequest>;
    try {
      const result = await deviceStore.heartbeat(token, {
        collector_version: strOrUndef(body.collector_version),
        os: strOrUndef(body.os),
        counters:
          body.counters && typeof body.counters === "object" && !Array.isArray(body.counters)
            ? (body.counters as Record<string, unknown>)
            : undefined,
        config_version: strOrUndef(body.config_version),
      });
      if (!result) {
        // Unknown or revoked device token.
        return reply.code(401).send({ error: "unauthorized" });
      }
      return reply.code(200).send(result);
    } catch (err) {
      req.log.error({ err }, "heartbeat failed");
      return reply.code(500).send({ error: "internal error" });
    }
  });

  // GET /v1/coverage — deployed vs healthy vs dead rollup for the dashboard.
  // Auth: ingest bearer token (operator/dashboard read). Fleet total is joined
  // in by the dashboard from the Intune/IdP export, not stored here.
  app.get("/v1/coverage", async (req, reply) => {
    if (!deviceStore) {
      return reply.code(503).send({ error: "device registry not configured" });
    }
    const token = bearerToken(req.headers.authorization);
    if (!token || !isValidToken(token, options.tokens)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    try {
      return reply.code(200).send(await deviceStore.coverage());
    } catch (err) {
      req.log.error({ err }, "coverage query failed");
      return reply.code(500).send({ error: "internal error" });
    }
  });

  return app;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function strOrUndef(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

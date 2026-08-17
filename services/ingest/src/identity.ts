/**
 * Identity resolution client + device-mapping registrar.
 *
 * The collector attests its endpoint identity once per batch (`collector`
 * block in the POST /v1/events body). Ingest forwards it to the identity-sync
 * service's POST /resolve, which returns a pseudonym + team — never
 * an email. The result is stamped onto every event in the batch.
 *
 * Resolution is fail-open: if identity-sync is unreachable or errors, the
 * batch is stored unattributed (user_pseudonym NULL) rather than dropped.
 * Cleartext os_user/device_id never leaves the platform trust boundary and is
 * never logged or persisted by this service.
 *
 * adds the enroll-time write path: when a minted enrollment token
 * carries bound_email, ingest registers device_id → email with identity-sync
 * so resolver rules 1–2 can fire on subsequent batches.
 */

import { createHmac } from "node:crypto";
import { parseBuildIdentity, type BuildIdentity } from "./attestation";

/** Endpoint identity attested by the collector at batch level. */
export interface CollectorIdentity {
  device_id?: string;
  os_user?: string;
  /**
   * Signed build identity. Optional on the wire in pilot mode;
   * required when INGEST_ATTESTATION_MODE=enforce.
   */
  build?: BuildIdentity;
}

/** Result of identity-sync POST /resolve. */
export interface Resolution {
  /**
   * Which resolver rule fired: "device_id" | "os_user" | "email_heuristic"
   * | "service_operator" | "service_identity" | "unresolved".
   */
  rule: string;
  user_pseudonym: string | null;
  team: string | null;
  /**
   * "human" | "service" | "unknown". A declared agent host or CI
   * runner resolves as "service" even when it carries a named operator's
   * pseudonym, so machine activity never reads as a person at a keyboard.
   */
  principal_kind: string | null;
}

export const UNRESOLVED: Resolution = {
  rule: "unresolved",
  user_pseudonym: null,
  team: null,
  principal_kind: null,
};

export interface IdentityResolver {
  resolve(identity: CollectorIdentity): Promise<Resolution>;
}

/**
 * Write path for device_id/os_user → directory email and
 * device_id rebind after re-enroll. Implemented by identity-sync
 * POST /device-mappings and POST /join-keys/rebind-device; gated + audited.
 */
export interface DeviceMappingRegistrar {
  register(input: {
    deviceId: string;
    osUser?: string;
    primaryEmail: string;
    source?: "enrollment" | "manual" | "collector" | "intune";
    reason: string;
  }): Promise<void>;
  /**
   * Move service_identities + device_mappings from an obsolete device_id to
   * the newly enrolled one so re-enroll cannot silently drop attribution.
   */
  rebindDevice(input: {
    fromDeviceId: string;
    toDeviceId: string;
    reason: string;
  }): Promise<{ serviceIdentitiesUpdated: number; deviceMappingsUpdated: number }>;
}

/** Used when IDENTITY_RESOLVE_URL is not configured — everything is unattributed. */
export class NoopIdentityResolver implements IdentityResolver {
  async resolve(_identity: CollectorIdentity): Promise<Resolution> {
    return UNRESOLVED;
  }
}

/** No-op registrar when identity-sync mapping auth is not configured. */
export class NoopDeviceMappingRegistrar implements DeviceMappingRegistrar {
  async register(): Promise<void> {
    /* intentionally empty */
  }
  async rebindDevice(): Promise<{
    serviceIdentitiesUpdated: number;
    deviceMappingsUpdated: number;
  }> {
    return { serviceIdentitiesUpdated: 0, deviceMappingsUpdated: 0 };
  }
}

interface ResolveApiResponse {
  resolution?: unknown;
  user_pseudonym?: unknown;
  team?: unknown;
  principal_kind?: unknown;
}

const PRINCIPAL_KINDS = new Set(["human", "service", "unknown"]);

export class HttpIdentityResolver implements IdentityResolver {
  constructor(
    /** Base URL of identity-sync, e.g. http://identity-sync:8080. */
    private readonly baseUrl: string,
    private readonly timeoutMs = 2000,
  ) {}

  async resolve(identity: CollectorIdentity): Promise<Resolution> {
    const response = await fetch(`${this.baseUrl}/resolve`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        device_id: identity.device_id ?? null,
        os_user: identity.os_user ?? null,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) {
      throw new Error(`identity /resolve returned HTTP ${response.status}`);
    }
    const body = (await response.json()) as ResolveApiResponse;
    return {
      rule: typeof body.resolution === "string" ? body.resolution : "unresolved",
      user_pseudonym: typeof body.user_pseudonym === "string" ? body.user_pseudonym : null,
      team: typeof body.team === "string" ? body.team : null,
      // Unknown/absent values collapse to null rather than defaulting to
      // "human": guessing "a person did this" is the failure mode this label
      // exists to prevent.
      principal_kind:
        typeof body.principal_kind === "string" && PRINCIPAL_KINDS.has(body.principal_kind)
          ? body.principal_kind
          : null,
    };
  }
}

/**
 * Registers device→directory bindings with identity-sync.
 *
 * Auth: HS256 service JWT carrying the ai-monitoring-revealers grant — the
 * same gate as POST /service-identities / /reveal. The JWT is
 * minted by ingest from IDENTITY_SYNC_JWT_HS256_SECRET (shared with
 * identity-sync in compose). Mapping registration is fail-open on the enroll
 * path: a mapping failure must not roll back device enrollment (the device
 * token is already issued).
 */
export class HttpDeviceMappingRegistrar implements DeviceMappingRegistrar {
  constructor(
    private readonly baseUrl: string,
    /** Factory so each call can mint a short-lived JWT. */
    private readonly tokenFactory: () => string,
    private readonly timeoutMs = 3000,
  ) {}

  async register(input: {
    deviceId: string;
    osUser?: string;
    primaryEmail: string;
    source?: "enrollment" | "manual" | "collector" | "intune";
    reason: string;
  }): Promise<void> {
    const response = await fetch(`${this.baseUrl}/device-mappings`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.tokenFactory()}`,
      },
      body: JSON.stringify({
        device_id: input.deviceId,
        os_user: input.osUser ?? null,
        primary_email: input.primaryEmail,
        source: input.source ?? "enrollment",
        reason: input.reason,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      throw new Error(
        `identity /device-mappings returned HTTP ${response.status}${detail ? `: ${detail.slice(0, 200)}` : ""}`,
      );
    }
  }

  async rebindDevice(input: {
    fromDeviceId: string;
    toDeviceId: string;
    reason: string;
  }): Promise<{ serviceIdentitiesUpdated: number; deviceMappingsUpdated: number }> {
    const response = await fetch(`${this.baseUrl}/join-keys/rebind-device`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.tokenFactory()}`,
      },
      body: JSON.stringify({
        from_device_id: input.fromDeviceId,
        to_device_id: input.toDeviceId,
        reason: input.reason,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      throw new Error(
        `identity /join-keys/rebind-device returned HTTP ${response.status}${detail ? `: ${detail.slice(0, 200)}` : ""}`,
      );
    }
    const body = (await response.json()) as {
      service_identities_updated?: unknown;
      device_mappings_updated?: unknown;
    };
    return {
      serviceIdentitiesUpdated:
        typeof body.service_identities_updated === "number" ? body.service_identities_updated : 0,
      deviceMappingsUpdated:
        typeof body.device_mappings_updated === "number" ? body.device_mappings_updated : 0,
    };
  }
}

/**
 * Mint a short-lived HS256 service JWT for identity-sync gated endpoints.
 * Dependency-free (no jsonwebtoken) so the ingest container stays lean.
 * Payload matches the identity-sync auth contract (email + groups).
 */
export function mintIdentityServiceJwt(
  secret: string,
  opts: { sub?: string; email?: string; groups?: string[]; ttlSeconds?: number } = {},
): string {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: opts.sub ?? "ingest-enroll",
    email: opts.email ?? "ingest-enroll@local",
    groups: opts.groups ?? ["ai-monitoring-revealers"],
    iat: now,
    exp: now + (opts.ttlSeconds ?? 300),
  };
  const enc = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString("base64url");
  const data = `${enc(header)}.${enc(payload)}`;
  const sig = createHmac("sha256", secret).update(data).digest("base64url");
  return `${data}.${sig}`;
}

const MAX_IDENTITY_FIELD_LENGTH = 256;

/**
 * Validate the optional `collector` block from the batch body. Returns the
 * normalized identity, or an error string. device_id / os_user are optional
 * individually, but at least one must be present for the block to be
 * meaningful. `build` is optional at parse time — enforce mode
 * rejects missing/invalid signatures after parse.
 */
export function parseCollectorIdentity(value: unknown): { identity: CollectorIdentity } | { error: string } {
  if (value === undefined || value === null) {
    return { identity: {} };
  }
  if (typeof value !== "object" || Array.isArray(value)) {
    return { error: "collector must be an object { device_id?, os_user?, build? }" };
  }
  const raw = value as Record<string, unknown>;
  const identity: CollectorIdentity = {};
  for (const key of ["device_id", "os_user"] as const) {
    const v = raw[key];
    if (v === undefined || v === null) continue;
    if (typeof v !== "string" || v.length === 0 || v.length > MAX_IDENTITY_FIELD_LENGTH) {
      return { error: `collector.${key} must be a string of 1-${MAX_IDENTITY_FIELD_LENGTH} chars` };
    }
    identity[key] = v;
  }
  if (raw.build !== undefined) {
    const parsedBuild = parseBuildIdentity(raw.build);
    if ("error" in parsedBuild) {
      return { error: parsedBuild.error };
    }
    if (parsedBuild.build) {
      identity.build = parsedBuild.build;
    }
  }
  if (!identity.device_id && !identity.os_user) {
    return { error: "collector must carry at least one of device_id / os_user" };
  }
  return { identity };
}

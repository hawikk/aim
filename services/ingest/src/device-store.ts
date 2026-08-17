import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { PoolLike } from "./migrate";

/**
 * Collector enrollment + heartbeat registry (AIM-28).
 *
 * Contract: docs/deployment/enrollment-and-heartbeat.md. Backs POST /v1/enroll
 * (installer registers a device, gets a per-device token) and POST /v1/heartbeat
 * (device reports liveness), plus the coverage rollup for the dashboard.
 *
 * The per-device token is returned exactly once, at enroll time, and only its
 * SHA-256 hash is persisted — same posture as the ingest bearer token.
 */

export interface EnrollRequest {
  host_id: string;
  hostname?: string;
  os?: string;
  ring?: string;
  collector_version?: string;
  /**
   * When true and a live device already exists for host_id, rotate the
   * per-device token and return the new value once. Requires a valid enroll
   * bearer (same privilege as first enroll). Used when the local
   * `device_token` file is gone but the host is still registered (AIM-166
   * dogfood: post-reboot collector freeze).
   */
  reissue?: boolean;
}

export interface EnrollResult {
  device_id: string;
  /** Present only on first enrollment or deliberate reissue. Idempotent re-enroll omits it. */
  device_token?: string;
  heartbeat_interval_sec: number;
  already_enrolled: boolean;
}

export interface HeartbeatRequest {
  host_id?: string;
  collector_version?: string;
  os?: string;
  counters?: Record<string, unknown>;
  config_version?: string;
}

export interface HeartbeatResult {
  status: "ok";
  /**
   * Enrollment id for this device token (AIM-1114). Collectors that lost the
   * local `device_id` file can re-persist it on a healthy heartbeat so event
   * batches keep attesting the join key identity-sync needs for service hosts.
   */
  device_id: string;
  config_version: string | null;
  heartbeat_interval_sec: number;
}

/** Per-device row for the coverage dashboard (pseudonymous host_id only). */
export interface CoverageDevice {
  device_id: string;
  host_id: string;
  hostname: string | null;
  os: string | null;
  ring: string | null;
  collector_version: string | null;
  enrolled_at: string;
  last_heartbeat_at: string | null;
  health: "healthy" | "stale" | "dead" | "never_seen";
}

export interface CoverageSummary {
  deployed: number;
  healthy: number;
  stale: number;
  dead: number;
  never_seen: number;
  devices: CoverageDevice[];
}

/** Health thresholds are expressed in multiples of the device heartbeat interval. */
const STALE_INTERVALS = 1;
const DEAD_INTERVALS = 3;

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export interface DeviceStore {
  enroll(req: EnrollRequest): Promise<EnrollResult>;
  /** Returns null when the token matches no live (non-revoked) device. */
  heartbeat(token: string, req: HeartbeatRequest): Promise<HeartbeatResult | null>;
  /**
   * Auth-only lookup for event delivery (AIM-217 / AIM-307 / AIM-319). Returns
   * the device when the bearer is a live per-device token; does not mutate
   * heartbeat state. Enrollment-issued device tokens are first-class
   * /v1/events credentials so `aim join` alone produces a collector that can
   * flush — shared INGEST_TOKENS remain accepted for bootstrap/managed fleets
   * until the deprecation path reaches `disabled`.
   */
  authenticate(token: string): Promise<{ device_id: string; host_id: string } | null>;
  coverage(): Promise<CoverageSummary>;
}

interface DeviceRow {
  device_id: string;
  host_id: string;
  heartbeat_interval_sec: number;
  config_version: string | null;
}

export class PostgresDeviceStore implements DeviceStore {
  constructor(private readonly pool: PoolLike) {}

  async enroll(req: EnrollRequest): Promise<EnrollResult> {
    const intervalSec = 300;
    const existing = await this.pool.query(
      "SELECT device_id, heartbeat_interval_sec FROM devices WHERE host_id = $1 AND revoked_at IS NULL",
      [req.host_id],
    );
    if (existing.rows.length > 0) {
      const row = existing.rows[0] as { device_id: string; heartbeat_interval_sec: number };
      // Deliberate reissue: rotate the hash and return a fresh token once.
      // Default path stays idempotent (no token) so installer re-runs are safe.
      if (req.reissue) {
        const deviceToken = randomBytes(32).toString("hex");
        await this.pool.query(
          `UPDATE devices SET
             device_token_hash = $2,
             hostname = COALESCE($3, hostname),
             os = COALESCE($4, os),
             ring = COALESCE($5, ring),
             collector_version = COALESCE($6, collector_version)
           WHERE device_id = $1 AND revoked_at IS NULL`,
          [
            row.device_id,
            hashToken(deviceToken),
            req.hostname ?? null,
            req.os ?? null,
            req.ring ?? null,
            req.collector_version ?? null,
          ],
        );
        return {
          device_id: row.device_id,
          device_token: deviceToken,
          heartbeat_interval_sec: row.heartbeat_interval_sec,
          // Not "already_enrolled" in the no-token sense: caller must store the new token.
          already_enrolled: false,
        };
      }
      return {
        device_id: row.device_id,
        heartbeat_interval_sec: row.heartbeat_interval_sec,
        already_enrolled: true,
      };
    }

    // Host was revoked earlier: UNIQUE(host_id) still holds the row, so a
    // plain INSERT 500s (AIM-166 dogfood). Revive the row with a fresh token.
    const revoked = await this.pool.query(
      `SELECT device_id, heartbeat_interval_sec FROM devices
        WHERE host_id = $1 AND revoked_at IS NOT NULL
        ORDER BY enrolled_at DESC LIMIT 1`,
      [req.host_id],
    );
    if (revoked.rows.length > 0) {
      const row = revoked.rows[0] as { device_id: string; heartbeat_interval_sec: number };
      const deviceToken = randomBytes(32).toString("hex");
      await this.pool.query(
        `UPDATE devices SET
           device_token_hash = $2,
           hostname = COALESCE($3, hostname),
           os = COALESCE($4, os),
           ring = COALESCE($5, ring),
           collector_version = COALESCE($6, collector_version),
           revoked_at = NULL,
           enrolled_at = now(),
           last_heartbeat_at = NULL,
           last_counters = NULL
         WHERE device_id = $1`,
        [
          row.device_id,
          hashToken(deviceToken),
          req.hostname ?? null,
          req.os ?? null,
          req.ring ?? null,
          req.collector_version ?? null,
        ],
      );
      return {
        device_id: row.device_id,
        device_token: deviceToken,
        heartbeat_interval_sec: row.heartbeat_interval_sec ?? intervalSec,
        already_enrolled: false,
      };
    }

    const deviceId = randomUUID();
    const deviceToken = randomBytes(32).toString("hex");
    await this.pool.query(
      `INSERT INTO devices
         (device_id, host_id, hostname, os, ring, collector_version,
          device_token_hash, heartbeat_interval_sec)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        deviceId,
        req.host_id,
        req.hostname ?? null,
        req.os ?? null,
        req.ring ?? null,
        req.collector_version ?? null,
        hashToken(deviceToken),
        intervalSec,
      ],
    );
    return {
      device_id: deviceId,
      device_token: deviceToken,
      heartbeat_interval_sec: intervalSec,
      already_enrolled: false,
    };
  }

  async authenticate(
    token: string,
  ): Promise<{ device_id: string; host_id: string } | null> {
    const found = await this.pool.query(
      `SELECT device_id, host_id
         FROM devices
        WHERE device_token_hash = $1 AND revoked_at IS NULL`,
      [hashToken(token)],
    );
    if (found.rows.length === 0) return null;
    const row = found.rows[0] as { device_id: string; host_id: string };
    return { device_id: row.device_id, host_id: row.host_id };
  }

  async heartbeat(token: string, req: HeartbeatRequest): Promise<HeartbeatResult | null> {
    const found = await this.pool.query(
      `SELECT device_id, host_id, heartbeat_interval_sec, config_version
         FROM devices
        WHERE device_token_hash = $1 AND revoked_at IS NULL`,
      [hashToken(token)],
    );
    if (found.rows.length === 0) return null;
    const row = found.rows[0] as DeviceRow;

    await this.pool.query(
      `UPDATE devices SET
         last_heartbeat_at = now(),
         collector_version = COALESCE($2, collector_version),
         os = COALESCE($3, os),
         last_counters = $4
       WHERE device_id = $1`,
      [
        row.device_id,
        req.collector_version ?? null,
        req.os ?? null,
        req.counters ? JSON.stringify(req.counters) : null,
      ],
    );

    return {
      status: "ok",
      device_id: row.device_id,
      config_version: row.config_version,
      heartbeat_interval_sec: row.heartbeat_interval_sec,
    };
  }

  async coverage(): Promise<CoverageSummary> {
    // Health is derived per device against its own heartbeat interval (so a
    // fast ring and a slow ring can coexist) in JS rather than SQL, to stay
    // portable across Postgres and the pg-mem test double. Fleet sizes here are
    // small (one row per enrolled device), so this is not a hot path.
    const res = await this.pool.query(
      `SELECT device_id, host_id, hostname, os, ring, collector_version,
              enrolled_at, last_heartbeat_at, heartbeat_interval_sec
         FROM devices
        WHERE revoked_at IS NULL
        ORDER BY enrolled_at ASC`,
    );

    const now = Date.now();
    const devices = res.rows.map((r) => {
      const row = r as Record<string, unknown>;
      const intervalSec = Number(row.heartbeat_interval_sec) || 300;
      const lastHb = row.last_heartbeat_at ? new Date(toIso(row.last_heartbeat_at)) : null;
      return {
        device_id: String(row.device_id),
        host_id: String(row.host_id),
        hostname: (row.hostname as string) ?? null,
        os: (row.os as string) ?? null,
        ring: (row.ring as string) ?? null,
        collector_version: (row.collector_version as string) ?? null,
        enrolled_at: toIso(row.enrolled_at),
        last_heartbeat_at: lastHb ? lastHb.toISOString() : null,
        health: healthOf(lastHb, intervalSec, now),
      } satisfies CoverageDevice;
    });

    const summary: CoverageSummary = {
      deployed: devices.length,
      healthy: 0,
      stale: 0,
      dead: 0,
      never_seen: 0,
      devices,
    };
    for (const d of devices) summary[d.health] += 1;
    return summary;
  }
}

function healthOf(
  lastHeartbeat: Date | null,
  intervalSec: number,
  nowMs: number,
): CoverageDevice["health"] {
  if (!lastHeartbeat) return "never_seen";
  const ageSec = (nowMs - lastHeartbeat.getTime()) / 1000;
  if (ageSec <= intervalSec * STALE_INTERVALS) return "healthy";
  if (ageSec <= intervalSec * DEAD_INTERVALS) return "stale";
  return "dead";
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

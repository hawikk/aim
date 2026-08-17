import { randomUUID } from "node:crypto";
import type { PoolLike } from "./migrate";

/**
 * Retention enforcement (AIM-143).
 *
 * Data minimization is a launch constraint (AIM-16): every event past its
 * justified window is liability, not asset. The privacy doc proposed 90-day
 * event retention; this module is the enforcement. It purges the server-mode
 * Postgres store on a schedule, per data class, and leaves a metadata-only
 * audit record for every run (retention_audit, migration 012).
 *
 * Data classes and default windows (config-overridable, enforced-by-default):
 *   events   90d  — the raw usage telemetry (events table + its bookkeeping)
 *   findings 365d — guardrail findings (a security record, kept longer)
 *   audit   730d — the purge audit trail itself (must outlive what it explains)
 *
 * Invariant: audit >= findings >= events. A config that violates it is
 * rejected (parseRetentionConfig throws) — an audit trail shorter than the
 * data it describes would make deletions unexplainable.
 *
 * Boundary rule: a row is purged iff its class timestamp is STRICTLY older
 * than `now - window`. A row exactly at the window edge (age == window) is
 * KEPT. Documented here and asserted by the boundary test.
 *
 * Blast radius: deletes run in bounded batches (no long table locks at
 * 700-engineer volume) and never touch the retention_audit rows a recent run
 * wrote (they are inside the audit window by construction). Dry-run reports
 * what would go without deleting anything.
 */

export class RetentionConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RetentionConfigError";
  }
}

export interface RetentionWindows {
  /** event-level retention, days */
  events: number;
  /** findings retention, days */
  findings: number;
  /** audit-trail retention, days */
  audit: number;
}

export interface RetentionConfig {
  windows: RetentionWindows;
  /** report-only: count what would be deleted, delete nothing */
  dryRun: boolean;
  /** max rows deleted per DELETE statement (bounded batches, no long locks) */
  batchSize: number;
  /** how often the scheduler attempts a purge, ms; 0 = disabled */
  intervalMs: number;
}

/** Defaults — mirrored in the personal-mode collector (aim_collector/retention.py)
 *  and in docs/privacy/data-minimization-and-pseudonymization.md. Keep in sync. */
export const DEFAULT_WINDOWS: RetentionWindows = { events: 90, findings: 365, audit: 730 };
const DEFAULT_BATCH_SIZE = 5000;
const DEFAULT_INTERVAL_HOURS = 24;

function posIntEnv(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined || value.trim() === "") return fallback;
  const n = Number.parseInt(value, 10);
  if (!Number.isInteger(n) || n <= 0 || String(n) !== value.trim()) {
    throw new RetentionConfigError(`invalid ${name}: ${value} (expected a positive integer)`);
  }
  return n;
}

function nonNegIntEnv(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined || value.trim() === "") return fallback;
  const n = Number.parseInt(value, 10);
  if (!Number.isInteger(n) || n < 0 || String(n) !== value.trim()) {
    throw new RetentionConfigError(`invalid ${name}: ${value} (expected a non-negative integer)`);
  }
  return n;
}

function boolEnv(value: string | undefined): boolean {
  const v = (value ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

/**
 * Parse retention config from the environment. Throws RetentionConfigError on
 * any parse error or on an ordering violation — callers fail closed (skip the
 * purge, log) rather than guessing a window.
 */
export function parseRetentionConfig(env: NodeJS.ProcessEnv = process.env): RetentionConfig {
  const events = posIntEnv(env.RETENTION_EVENTS_DAYS, DEFAULT_WINDOWS.events, "RETENTION_EVENTS_DAYS");
  const findings = posIntEnv(env.RETENTION_FINDINGS_DAYS, DEFAULT_WINDOWS.findings, "RETENTION_FINDINGS_DAYS");
  const audit = posIntEnv(env.RETENTION_AUDIT_DAYS, DEFAULT_WINDOWS.audit, "RETENTION_AUDIT_DAYS");

  if (!(audit >= findings && findings >= events)) {
    throw new RetentionConfigError(
      `retention windows must satisfy audit >= findings >= events ` +
        `(got events=${events}, findings=${findings}, audit=${audit})`,
    );
  }

  const batchSize = posIntEnv(env.RETENTION_BATCH_SIZE, DEFAULT_BATCH_SIZE, "RETENTION_BATCH_SIZE");
  const intervalHours = nonNegIntEnv(
    env.RETENTION_INTERVAL_HOURS,
    DEFAULT_INTERVAL_HOURS,
    "RETENTION_INTERVAL_HOURS",
  );

  return {
    windows: { events, findings, audit },
    dryRun: boolEnv(env.RETENTION_DRY_RUN),
    batchSize,
    intervalMs: intervalHours * 60 * 60 * 1000,
  };
}

export type RetentionConfigResult =
  | { ok: true; config: RetentionConfig }
  | { ok: false; error: string };

/** Fail-closed wrapper: never throws, so a bad config disables the purge and
 *  leaves the ingest server running rather than crashing it. */
export function loadRetentionConfig(env: NodeJS.ProcessEnv = process.env): RetentionConfigResult {
  try {
    return { ok: true, config: parseRetentionConfig(env) };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/** A data class and how to age it out. */
interface ClassSpec {
  table: string;
  /** column whose value determines a row's age */
  tsColumn: string;
  /** primary key used to delete a bounded batch */
  idColumn: string;
  /** rows in these tables reference idColumn via FK and must go first */
  dependents: { table: string; fk: string }[];
}

const CLASS_SPECS: Record<keyof RetentionWindows, ClassSpec> = {
  events: {
    table: "events",
    tsColumn: "ts",
    idColumn: "event_id",
    dependents: [{ table: "evaluated_events", fk: "event_id" }],
  },
  findings: {
    table: "findings",
    tsColumn: "detected_at",
    idColumn: "finding_id",
    // finding_transitions (AIM-223 / AIM-432 F3) ages out with the finding it
    // describes — a disposition log that outlives its subject has no value,
    // and the FK would otherwise block findings DELETE. Order: deliveries and
    // transitions first, then findings.
    dependents: [
      { table: "finding_deliveries", fk: "finding_id" },
      { table: "finding_transitions", fk: "finding_id" },
    ],
  },
  audit: {
    table: "retention_audit",
    tsColumn: "created_at",
    idColumn: "id",
    dependents: [],
  },
};

export interface ClassPurgeResult {
  dataClass: keyof RetentionWindows;
  windowDays: number;
  cutoff: string;
  rowsDeleted: number;
  batches: number;
  dryRun: boolean;
}

export interface PurgeSummary {
  runId: string;
  startedAt: string;
  dryRun: boolean;
  classes: ClassPurgeResult[];
}

function placeholders(count: number, start = 1): string {
  const parts: string[] = [];
  for (let i = 0; i < count; i++) parts.push(`$${start + i}`);
  return parts.join(",");
}

export class RetentionPurger {
  constructor(
    private readonly pool: PoolLike,
    private readonly config: RetentionConfig,
  ) {}

  /**
   * Run one purge pass across every data class. `now` is injectable for
   * deterministic tests. Order: events, findings, audit — the audit-class pass
   * (which sweeps retention_audit) runs last, and only after the per-class
   * audit rows for this run are written, so it can never delete them.
   */
  async purge(now: Date = new Date()): Promise<PurgeSummary> {
    const runId = randomUUID();
    const startedAt = now.toISOString();
    const classes: ClassPurgeResult[] = [];
    for (const dataClass of ["events", "findings", "audit"] as (keyof RetentionWindows)[]) {
      classes.push(await this.purgeClass(dataClass, runId, now));
    }
    // AIM-1168: vendor admin daily rollups share the events window.
    try {
      await this.purgeVendorAdminDaily(now);
    } catch {
      // Table may not exist on a mid-migration replica; events purge still counts.
    }
    return { runId, startedAt, dryRun: this.config.dryRun, classes };
  }

  private async purgeVendorAdminDaily(now: Date): Promise<void> {
    const cutoff = new Date(now.getTime() - this.config.windows.events * 24 * 60 * 60 * 1000);
    if (this.config.dryRun) return;
    await this.pool.query(`DELETE FROM vendor_admin_daily WHERE day < $1::date`, [
      cutoff.toISOString().slice(0, 10),
    ]);
  }

  private async purgeClass(
    dataClass: keyof RetentionWindows,
    runId: string,
    now: Date,
  ): Promise<ClassPurgeResult> {
    const spec = CLASS_SPECS[dataClass];
    const windowDays = this.config.windows[dataClass];
    const cutoff = new Date(now.getTime() - windowDays * 24 * 60 * 60 * 1000);

    let rowsDeleted = 0;
    let batches = 0;

    if (this.config.dryRun) {
      const res = await this.pool.query(
        `SELECT COUNT(*)::bigint AS c FROM ${spec.table} WHERE ${spec.tsColumn} < $1`,
        [cutoff],
      );
      rowsDeleted = Number((res.rows[0] as { c: string | number }).c);
    } else {
      // Bounded batches: fetch a page of victim ids by age, delete dependents
      // first (FK), then the rows. Loop until a page comes back short.
      for (;;) {
        // batchSize is a validated positive integer (not user input), so it is
        // inlined — keeps the one bound param the cutoff and sidesteps engines
        // that reject a parameterized LIMIT.
        const page = await this.pool.query(
          `SELECT ${spec.idColumn} AS id FROM ${spec.table} ` +
            `WHERE ${spec.tsColumn} < $1 ORDER BY ${spec.tsColumn} ASC LIMIT ${this.config.batchSize}`,
          [cutoff],
        );
        const ids = page.rows.map((r) => (r as { id: unknown }).id);
        if (ids.length === 0) break;
        batches += 1;

        for (const dep of spec.dependents) {
          await this.pool.query(
            `DELETE FROM ${dep.table} WHERE ${dep.fk} IN (${placeholders(ids.length)})`,
            ids,
          );
        }
        const del = await this.pool.query(
          `DELETE FROM ${spec.table} WHERE ${spec.idColumn} IN (${placeholders(ids.length)})`,
          ids,
        );
        rowsDeleted += del.rowCount ?? 0;
        if (ids.length < this.config.batchSize) break;
      }
    }

    // Metadata-only audit record for this class's sweep (written even in
    // dry-run, flagged as such). This INSERT lands after any audit-class
    // delete above, so the audit pass never removes the record it just made.
    await this.pool.query(
      `INSERT INTO retention_audit
         (run_id, data_class, window_days, cutoff_ts, rows_deleted, dry_run)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [runId, dataClass, windowDays, cutoff, rowsDeleted, this.config.dryRun],
    );

    return {
      dataClass,
      windowDays,
      cutoff: cutoff.toISOString(),
      rowsDeleted,
      batches,
      dryRun: this.config.dryRun,
    };
  }
}

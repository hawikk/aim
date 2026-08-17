import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** Minimal pool interface so real `pg` pools and pg-mem pools both fit. */
export interface PoolLike {
  query(text: string, params?: unknown[]): Promise<{ rows: unknown[]; rowCount: number | null }>;
  end(): Promise<void>;
}

export interface RunMigrationsOptions {
  /**
   * Optional filter. Return false to skip a file (e.g. plpgsql/triggers that
   * pg-mem cannot parse — those still run against real Postgres in CI/prod
   * and in dedicated integration tests).
   */
  includeFile?: (file: string) => boolean;
}

/**
 * Apply numbered migrations (*.sql, sorted lexicographically) that have not
 * been recorded in schema_migrations yet. Each runs in its own transaction.
 */
export async function runMigrations(
  pool: PoolLike,
  migrationsDir: string,
  options: RunMigrationsOptions = {},
): Promise<string[]> {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
       id TEXT PRIMARY KEY,
       applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
     )`,
  );

  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .filter((f) => (options.includeFile ? options.includeFile(f) : true))
    .sort();

  const applied: string[] = [];
  for (const file of files) {
    const existing = await pool.query("SELECT id FROM schema_migrations WHERE id = $1", [file]);
    if (existing.rows.length > 0) continue;

    const sql = readFileSync(join(migrationsDir, file), "utf8");
    await pool.query("BEGIN");
    try {
      await pool.query(sql);
      await pool.query("INSERT INTO schema_migrations (id) VALUES ($1)", [file]);
      await pool.query("COMMIT");
    } catch (err) {
      await pool.query("ROLLBACK");
      throw err;
    }
    applied.push(file);
  }
  return applied;
}

/** Default migrations directory, relative to the compiled or source file. */
export function defaultMigrationsDir(): string {
  return join(__dirname, "..", "migrations");
}

/**
 * Migration files that use plpgsql/triggers/CHECK helpers pg-mem cannot parse
 * or execute. Unit tests under pg-mem skip these via {@link includeFileForPgMem};
 * real Postgres (compose + CI acceptance) still applies them.
 */
export const PG_ONLY_MIGRATIONS = new Set([
  "020_finding_transitions_append_only.sql", // plpgsql trigger + REVOKE/GRANT
  "022_sanctioned_tools.sql", // CHECK (char_length(...)) — pg-mem has no char_length
  "034_shadow_ai_ops.sql", // plpgsql append-only trigger + REVOKE/GRANT
  "035_break_glass_grants.sql", // CHECK (char_length(...)) — pg-mem has no char_length
  "036_break_glass_admin.sql", // CHECK (char_length(...)) — pg-mem has no char_length
]);

/** Filter for pg-mem unit tests: skip migrations that need real Postgres. */
export function includeFileForPgMem(file: string): boolean {
  return !PG_ONLY_MIGRATIONS.has(file);
}

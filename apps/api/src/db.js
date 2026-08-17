import pg from 'pg';

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL ?? 'postgres://aim:aim@localhost:5432/aim',
  max: 10,
});

export function query(text, params) {
  return pool.query(text, params);
}

/**
 * Run `fn` on a single pooled client inside BEGIN…COMMIT.
 * On any throw: ROLLBACK, then rethrow. Guarantees the status update and
 * transition insert for findings triage share one connection (AIM-432 F1).
 *
 * @template T
 * @param {(client: { query: typeof pool.query }) => Promise<T>} fn
 * @returns {Promise<T>}
 */
export async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // Connection may already be dead; the original error is more useful.
    }
    throw err;
  } finally {
    client.release();
  }
}

export async function close() {
  await pool.end();
}

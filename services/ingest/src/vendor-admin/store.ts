import type { PoolLike } from "../migrate";
import type {
  VendorAdminStore,
  VendorDailyRollup,
  VendorErrorClass,
  VendorFeedId,
  VendorFeedState,
} from "./types";

const UPSERT_DAILY = `
  INSERT INTO vendor_admin_daily (
    day, feed, tool, tool_raw,
    active_users, engaged_users, sessions,
    tokens_in, tokens_out, cost_usd,
    loc_suggested, loc_accepted, loc_committed_ai,
    extras, updated_at
  ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb, now())
  ON CONFLICT (day, feed) DO UPDATE SET
    tool = EXCLUDED.tool,
    tool_raw = EXCLUDED.tool_raw,
    active_users = EXCLUDED.active_users,
    engaged_users = EXCLUDED.engaged_users,
    sessions = EXCLUDED.sessions,
    tokens_in = EXCLUDED.tokens_in,
    tokens_out = EXCLUDED.tokens_out,
    cost_usd = EXCLUDED.cost_usd,
    loc_suggested = EXCLUDED.loc_suggested,
    loc_accepted = EXCLUDED.loc_accepted,
    loc_committed_ai = EXCLUDED.loc_committed_ai,
    extras = EXCLUDED.extras,
    updated_at = now()
`;

const UPSERT_FEED = `
  INSERT INTO vendor_admin_feeds (
    feed, configured, last_attempt_at, last_success_at,
    last_error_class, last_day, detail
  ) VALUES ($1,$2, now(), $3, $4, $5, $6)
  ON CONFLICT (feed) DO UPDATE SET
    configured = EXCLUDED.configured,
    last_attempt_at = now(),
    last_success_at = COALESCE(EXCLUDED.last_success_at, vendor_admin_feeds.last_success_at),
    last_error_class = EXCLUDED.last_error_class,
    last_day = COALESCE(EXCLUDED.last_day, vendor_admin_feeds.last_day),
    detail = EXCLUDED.detail
`;

export class PostgresVendorAdminStore implements VendorAdminStore {
  constructor(private readonly pool: PoolLike) {}

  async upsertDaily(rows: VendorDailyRollup[]): Promise<number> {
    let n = 0;
    for (const r of rows) {
      await this.pool.query(UPSERT_DAILY, [
        r.day,
        r.feed,
        r.tool,
        r.tool_raw ?? null,
        r.active_users,
        r.engaged_users,
        r.sessions,
        r.tokens_in,
        r.tokens_out,
        r.cost_usd,
        r.loc_suggested,
        r.loc_accepted,
        r.loc_committed_ai,
        JSON.stringify(r.extras ?? {}),
      ]);
      n += 1;
    }
    return n;
  }

  async upsertFeedState(state: VendorFeedState): Promise<void> {
    const successAt = state.lastErrorClass === "ok" ? new Date().toISOString() : null;
    await this.pool.query(UPSERT_FEED, [
      state.feed,
      state.configured,
      successAt,
      state.lastErrorClass,
      state.lastDay ?? null,
      state.detail.slice(0, 500),
    ]);
  }

  async listFeedState(): Promise<VendorFeedState[]> {
    const { rows } = await this.pool.query(
      `SELECT feed, configured, last_attempt_at, last_success_at,
              last_error_class, last_day, detail
         FROM vendor_admin_feeds`,
    );
    return (rows as Array<Record<string, unknown>>).map((r) => ({
      feed: r.feed as VendorFeedId,
      configured: Boolean(r.configured),
      lastAttemptAt: r.last_attempt_at ? String(r.last_attempt_at) : undefined,
      lastSuccessAt: r.last_success_at ? String(r.last_success_at) : null,
      lastErrorClass: (r.last_error_class as VendorErrorClass) ?? "not_attempted",
      lastDay: r.last_day ? String(r.last_day) : null,
      detail: typeof r.detail === "string" ? r.detail : "",
    }));
  }
}

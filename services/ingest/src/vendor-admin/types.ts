/** First-party vendor admin daily rollup. Org-level only. */

export const VENDOR_FEEDS = ["copilot_metrics", "cursor_analytics", "claude_otel"] as const;
export type VendorFeedId = (typeof VENDOR_FEEDS)[number];

export type VendorErrorClass =
  | "ok"
  | "credential_missing"
  | "upstream_error"
  | "map_error"
  | "not_attempted";

export interface VendorDailyRollup {
  day: string; // YYYY-MM-DD
  feed: VendorFeedId;
  tool: "claude_code" | "cursor" | "other";
  tool_raw?: string | null;
  active_users: number;
  engaged_users: number;
  sessions: number;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
  loc_suggested: number;
  loc_accepted: number;
  loc_committed_ai: number;
  /** Allowlisted numeric/name aggregates only. Never emails or paths. */
  extras: Record<string, unknown>;
}

export interface VendorMapStats {
  rowsReceived: number;
  rowsMapped: number;
  rowsSkipped: number;
  attributesDropped: number;
}

export interface VendorMapResult {
  rollups: VendorDailyRollup[];
  stats: VendorMapStats;
  errors: string[];
}

export interface VendorFeedState {
  feed: VendorFeedId;
  configured: boolean;
  lastAttemptAt?: string;
  lastSuccessAt?: string | null;
  lastErrorClass: VendorErrorClass;
  lastDay?: string | null;
  detail: string;
}

export interface VendorAdminStore {
  upsertDaily(rows: VendorDailyRollup[]): Promise<number>;
  upsertFeedState(state: VendorFeedState): Promise<void>;
  listFeedState(): Promise<VendorFeedState[]>;
}

export interface VendorPollerConfig {
  /** Read-only GitHub token for Copilot Metrics. Unset = feed dark. */
  copilotToken?: string;
  copilotOrg?: string;
  copilotEnterprise?: string;
  copilotApiBase: string;
  /** Cursor Admin API key. Unset = feed dark. */
  cursorApiKey?: string;
  cursorApiBase: string;
  /** Poll interval in seconds. 0 = do not schedule (manual/sync only). */
  pollIntervalSeconds: number;
  /**
   * HMAC salt for per-user Cursor rows. Used only in memory to count
   * distinct users; raw emails are never persisted. Unset = count rows
   * without hashing (still no email stored).
   */
  hashSalt?: string;
}

import { mapCopilotMetrics } from "./copilot";
import { mapCursorDailyUsage } from "./cursor";
import type {
  VendorAdminStore,
  VendorFeedId,
  VendorFeedState,
  VendorPollerConfig,
} from "./types";

export interface VendorPollerDeps {
  store: VendorAdminStore;
  fetchImpl?: typeof fetch;
  now?: () => Date;
  log?: (msg: string, fields?: Record<string, unknown>) => void;
}

export interface VendorPollTickResult {
  feed: VendorFeedId;
  status: VendorFeedState["lastErrorClass"];
  rows: number;
  detail: string;
}

const DEFAULT_LOOKBACK_DAYS = 14;

function basicAuth(apiKey: string): string {
  return `Basic ${Buffer.from(`${apiKey}:`, "utf8").toString("base64")}`;
}

async function writeState(
  store: VendorAdminStore,
  feed: VendorFeedId,
  configured: boolean,
  lastErrorClass: VendorFeedState["lastErrorClass"],
  detail: string,
  lastDay?: string | null,
): Promise<void> {
  await store.upsertFeedState({
    feed,
    configured,
    lastErrorClass,
    detail,
    lastDay: lastDay ?? null,
  });
}

async function pollCopilot(
  cfg: VendorPollerConfig,
  deps: VendorPollerDeps,
): Promise<VendorPollTickResult> {
  const feed: VendorFeedId = "copilot_metrics";
  if (!cfg.copilotToken) {
    const detail = "COPILOT_METRICS_TOKEN unset — feed dark; ingest continues";
    await writeState(deps.store, feed, false, "credential_missing", detail);
    return { feed, status: "credential_missing", rows: 0, detail };
  }
  if (!cfg.copilotOrg && !cfg.copilotEnterprise) {
    const detail = "COPILOT_METRICS_ORG / COPILOT_METRICS_ENTERPRISE unset — feed dark";
    await writeState(deps.store, feed, false, "credential_missing", detail);
    return { feed, status: "credential_missing", rows: 0, detail };
  }

  const fetchImpl = deps.fetchImpl ?? fetch;
  const path = cfg.copilotEnterprise
    ? `/enterprises/${encodeURIComponent(cfg.copilotEnterprise)}/copilot/metrics`
    : `/orgs/${encodeURIComponent(cfg.copilotOrg as string)}/copilot/metrics`;
  const url = `${cfg.copilotApiBase.replace(/\/+$/, "")}${path}`;
  try {
    const res = await fetchImpl(url, {
      method: "GET",
      headers: {
        authorization: `Bearer ${cfg.copilotToken}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "ai-monitoring-vendor-admin",
      },
    });
    if (!res.ok) {
      const detail = `copilot metrics upstream HTTP ${res.status}`;
      await writeState(deps.store, feed, true, "upstream_error", detail);
      return { feed, status: "upstream_error", rows: 0, detail };
    }
    const body: unknown = await res.json();
    const mapped = mapCopilotMetrics(body);
    await deps.store.upsertDaily(mapped.rollups);
    const lastDay = mapped.rollups.at(-1)?.day ?? null;
    const detail = `ok rows=${mapped.stats.rowsMapped} dropped_attrs=${mapped.stats.attributesDropped}`;
    await writeState(deps.store, feed, true, "ok", detail, lastDay);
    return { feed, status: "ok", rows: mapped.stats.rowsMapped, detail };
  } catch (err) {
    const detail = `copilot metrics fetch failed: ${err instanceof Error ? err.name : "error"}`;
    await writeState(deps.store, feed, true, "upstream_error", detail);
    return { feed, status: "upstream_error", rows: 0, detail };
  }
}

async function pollCursor(
  cfg: VendorPollerConfig,
  deps: VendorPollerDeps,
): Promise<VendorPollTickResult> {
  const feed: VendorFeedId = "cursor_analytics";
  if (!cfg.cursorApiKey) {
    const detail = "CURSOR_ADMIN_API_KEY unset — feed dark; ingest continues";
    await writeState(deps.store, feed, false, "credential_missing", detail);
    return { feed, status: "credential_missing", rows: 0, detail };
  }

  const fetchImpl = deps.fetchImpl ?? fetch;
  const now = deps.now ? deps.now() : new Date();
  const end = now.getTime();
  const start = end - DEFAULT_LOOKBACK_DAYS * 24 * 60 * 60 * 1000;
  const url = `${cfg.cursorApiBase.replace(/\/+$/, "")}/teams/daily-usage-data`;
  try {
    const res = await fetchImpl(url, {
      method: "POST",
      headers: {
        authorization: basicAuth(cfg.cursorApiKey),
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({ startDate: start, endDate: end }),
    });
    if (!res.ok) {
      const detail = `cursor analytics upstream HTTP ${res.status}`;
      await writeState(deps.store, feed, true, "upstream_error", detail);
      return { feed, status: "upstream_error", rows: 0, detail };
    }
    const body: unknown = await res.json();
    const mapped = mapCursorDailyUsage(body, cfg.hashSalt);
    await deps.store.upsertDaily(mapped.rollups);
    const lastDay = mapped.rollups.at(-1)?.day ?? null;
    const detail = `ok rows=${mapped.stats.rowsMapped} dropped_attrs=${mapped.stats.attributesDropped}`;
    await writeState(deps.store, feed, true, "ok", detail, lastDay);
    return { feed, status: "ok", rows: mapped.stats.rowsMapped, detail };
  } catch (err) {
    const detail = `cursor analytics fetch failed: ${err instanceof Error ? err.name : "error"}`;
    await writeState(deps.store, feed, true, "upstream_error", detail);
    return { feed, status: "upstream_error", rows: 0, detail };
  }
}

/**
 * One poller tick. Missing credentials degrade the feed; they never throw.
 * Ingest / the poller process stay up.
 */
export async function pollVendorAdminOnce(
  cfg: VendorPollerConfig,
  deps: VendorPollerDeps,
): Promise<VendorPollTickResult[]> {
  const results = [await pollCopilot(cfg, deps), await pollCursor(cfg, deps)];
  deps.log?.("vendor-admin poll tick", {
    results: results.map((r) => ({ feed: r.feed, status: r.status, rows: r.rows })),
  });
  return results;
}

export function loadVendorPollerConfig(env: NodeJS.ProcessEnv = process.env): VendorPollerConfig {
  const intervalRaw = (env.VENDOR_ADMIN_POLL_INTERVAL_S ?? "3600").trim();
  const interval = Number.parseInt(intervalRaw, 10);
  return {
    copilotToken: env.COPILOT_METRICS_TOKEN?.trim() || undefined,
    copilotOrg: env.COPILOT_METRICS_ORG?.trim() || undefined,
    copilotEnterprise: env.COPILOT_METRICS_ENTERPRISE?.trim() || undefined,
    copilotApiBase: (env.COPILOT_METRICS_API_BASE ?? "https://api.github.com").trim(),
    cursorApiKey: env.CURSOR_ADMIN_API_KEY?.trim() || undefined,
    cursorApiBase: (env.CURSOR_ADMIN_API_BASE ?? "https://api.cursor.com").trim(),
    pollIntervalSeconds: Number.isInteger(interval) && interval >= 0 ? interval : 3600,
    hashSalt: env.AIM_HASH_SALT?.trim() || env.OTEL_HOST_SALT?.trim() || undefined,
  };
}

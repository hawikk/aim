import {
  asDay,
  asNonNegInt,
  pickAllowlisted,
  type AllowlistStats,
} from "./allowlist";
import type { VendorDailyRollup, VendorMapResult } from "./types";

/**
 * GitHub Copilot usage metrics API (org or enterprise daily).
 * https://docs.github.com/rest/copilot/copilot-metrics
 *
 * Already aggregated — we never invent users. Language / editor / model
 * *names* are infrastructure metadata (like mcp_server), not content.
 */
const COPILOT_ALLOWLIST = new Set([
  "date",
  "total_active_users",
  "total_engaged_users",
  "copilot_ide_code_completions",
  "copilot_ide_chat",
  "copilot_dotcom_chat",
  "copilot_dotcom_pull_requests",
  "total_engaged_users",
  "total_code_suggestions",
  "total_code_acceptances",
  "total_code_lines_suggested",
  "total_code_lines_accepted",
  "languages",
  "editors",
  "models",
  "name",
  "is_custom_model",
]);

function emptyStats(): AllowlistStats {
  return { attributesDropped: 0 };
}

function locFrom(node: unknown): { suggested: number; accepted: number } {
  if (!node || typeof node !== "object") return { suggested: 0, accepted: 0 };
  const rec = node as Record<string, unknown>;
  let suggested = asNonNegInt(rec.total_code_lines_suggested);
  let accepted = asNonNegInt(rec.total_code_lines_accepted);
  for (const key of ["languages", "editors", "models"] as const) {
    const arr = rec[key];
    if (!Array.isArray(arr)) continue;
    for (const item of arr) {
      const nested = locFrom(item);
      suggested += nested.suggested;
      accepted += nested.accepted;
    }
  }
  return { suggested, accepted };
}

function mapOneDay(raw: unknown, stats: AllowlistStats): VendorDailyRollup | null {
  const filtered = pickAllowlisted(raw, COPILOT_ALLOWLIST, stats);
  if (!filtered || typeof filtered !== "object" || Array.isArray(filtered)) return null;
  const rec = filtered as Record<string, unknown>;
  const day = asDay(rec.date);
  if (!day) return null;

  const completions = rec.copilot_ide_code_completions;
  const loc = locFrom(completions);
  return {
    day,
    feed: "copilot_metrics",
    tool: "other",
    tool_raw: "github_copilot",
    active_users: asNonNegInt(rec.total_active_users),
    engaged_users: asNonNegInt(rec.total_engaged_users),
    sessions: 0,
    tokens_in: 0,
    tokens_out: 0,
    cost_usd: 0,
    loc_suggested: loc.suggested,
    loc_accepted: loc.accepted,
    loc_committed_ai: loc.accepted,
    extras: {
      ide_chat_engaged: asNonNegInt(
        rec.copilot_ide_chat && typeof rec.copilot_ide_chat === "object"
          ? (rec.copilot_ide_chat as { total_engaged_users?: unknown }).total_engaged_users
          : 0,
      ),
      dotcom_chat_engaged: asNonNegInt(
        rec.copilot_dotcom_chat && typeof rec.copilot_dotcom_chat === "object"
          ? (rec.copilot_dotcom_chat as { total_engaged_users?: unknown }).total_engaged_users
          : 0,
      ),
    },
  };
}

/** Accept a Copilot metrics array or `{ metrics: [...] }` wrapper. */
export function mapCopilotMetrics(body: unknown): VendorMapResult {
  const stats = { rowsReceived: 0, rowsMapped: 0, rowsSkipped: 0, attributesDropped: 0 };
  const errors: string[] = [];
  const allowStats = emptyStats();

  let rows: unknown[] = [];
  if (Array.isArray(body)) rows = body;
  else if (body && typeof body === "object" && Array.isArray((body as { metrics?: unknown }).metrics)) {
    rows = (body as { metrics: unknown[] }).metrics;
  } else {
    return { rollups: [], stats, errors: ["body must be a Copilot metrics array"] };
  }

  const byDay = new Map<string, VendorDailyRollup>();
  for (const raw of rows) {
    stats.rowsReceived += 1;
    const mapped = mapOneDay(raw, allowStats);
    if (!mapped) {
      stats.rowsSkipped += 1;
      if (errors.length < 25) errors.push("copilot row missing date or not an object");
      continue;
    }
    byDay.set(mapped.day, mapped);
    stats.rowsMapped += 1;
  }
  stats.attributesDropped = allowStats.attributesDropped;
  return { rollups: [...byDay.values()].sort((a, b) => a.day.localeCompare(b.day)), stats, errors };
}

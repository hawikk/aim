import { createHash, createHmac } from "node:crypto";
import {
  asDay,
  asNonNegInt,
  pickAllowlisted,
  type AllowlistStats,
} from "./allowlist";
import type { VendorDailyRollup, VendorMapResult } from "./types";

/**
 * Cursor Team Daily Usage Data (Admin API).
 * Per-user rows may carry `email` — that key is denied by the allowlist and
 * never copied. Distinct-user counts are computed in memory (HMAC of the
 * raw email if a salt is provided, otherwise a count of active rows) and
 * only the integer lands in the rollup.
 */
const CURSOR_ALLOWLIST = new Set([
  "date",
  "isActive",
  "is_active",
  "totalLinesAdded",
  "totalLinesDeleted",
  "acceptedLinesAdded",
  "acceptedLinesDeleted",
  "totalApplies",
  "totalAccepts",
  "totalRejects",
  "totalTabsShown",
  "totalTabsAccepted",
  "composerRequests",
  "chatRequests",
  "agentRequests",
  "cmdkUsages",
  "subscriptionIncludedReqs",
  "apiKeyReqs",
  "usageBasedReqs",
  "mostUsedModel",
  "model",
]);

function emptyStats(): AllowlistStats {
  return { attributesDropped: 0 };
}

function activeFlag(raw: Record<string, unknown>): boolean {
  return raw.isActive === true || raw.is_active === true;
}

function rawEmail(raw: unknown): string | null {
  if (!raw || typeof raw !== "object") return null;
  const rec = raw as Record<string, unknown>;
  for (const key of ["email", "userEmail", "user_email"]) {
    if (typeof rec[key] === "string" && (rec[key] as string).length > 0) {
      return rec[key] as string;
    }
  }
  return null;
}

function identityToken(email: string | null, salt?: string): string | null {
  if (!email) return null;
  if (salt && salt.length > 0) {
    return createHmac("sha256", salt).update(email).digest("hex");
  }
  return createHash("sha256").update(`cursor-count:${email}`).digest("hex");
}

interface DayAcc {
  rollup: VendorDailyRollup;
  users: Set<string>;
}

/** Accept `{ data: [...] }` or a bare array of daily-usage rows. */
export function mapCursorDailyUsage(body: unknown, hashSalt?: string): VendorMapResult {
  const stats = { rowsReceived: 0, rowsMapped: 0, rowsSkipped: 0, attributesDropped: 0 };
  const errors: string[] = [];
  const allowStats = emptyStats();

  let rows: unknown[] = [];
  if (Array.isArray(body)) rows = body;
  else if (body && typeof body === "object" && Array.isArray((body as { data?: unknown }).data)) {
    rows = (body as { data: unknown[] }).data;
  } else {
    return { rollups: [], stats, errors: ["body must be a Cursor daily-usage array or { data: [] }"] };
  }

  const byDay = new Map<string, DayAcc>();
  for (const raw of rows) {
    stats.rowsReceived += 1;
    if (!raw || typeof raw !== "object") {
      stats.rowsSkipped += 1;
      continue;
    }
    const rec = raw as Record<string, unknown>;
    const filtered = pickAllowlisted(rec, CURSOR_ALLOWLIST, allowStats) as Record<string, unknown>;
    const day = asDay(filtered.date) ?? asDay(rec.date);
    if (!day) {
      stats.rowsSkipped += 1;
      if (errors.length < 25) errors.push("cursor row missing date");
      continue;
    }

    let acc = byDay.get(day);
    if (!acc) {
      acc = {
        rollup: {
          day,
          feed: "cursor_analytics",
          tool: "cursor",
          tool_raw: null,
          active_users: 0,
          engaged_users: 0,
          sessions: 0,
          tokens_in: 0,
          tokens_out: 0,
          cost_usd: 0,
          loc_suggested: 0,
          loc_accepted: 0,
          loc_committed_ai: 0,
          extras: { composer_requests: 0, chat_requests: 0, agent_requests: 0 },
        },
        users: new Set<string>(),
      };
      byDay.set(day, acc);
    }

    acc.rollup.loc_suggested += asNonNegInt(filtered.totalLinesAdded);
    acc.rollup.loc_accepted += asNonNegInt(filtered.acceptedLinesAdded);
    acc.rollup.loc_committed_ai += asNonNegInt(filtered.acceptedLinesAdded);
    acc.rollup.sessions +=
      asNonNegInt(filtered.composerRequests) +
      asNonNegInt(filtered.chatRequests) +
      asNonNegInt(filtered.agentRequests);
    const extras = acc.rollup.extras as {
      composer_requests: number;
      chat_requests: number;
      agent_requests: number;
    };
    extras.composer_requests += asNonNegInt(filtered.composerRequests);
    extras.chat_requests += asNonNegInt(filtered.chatRequests);
    extras.agent_requests += asNonNegInt(filtered.agentRequests);

    if (activeFlag(rec) || activeFlag(filtered)) {
      const token = identityToken(rawEmail(raw), hashSalt) ?? `row:${stats.rowsReceived}`;
      acc.users.add(token);
    }
    stats.rowsMapped += 1;
  }

  const rollups: VendorDailyRollup[] = [];
  for (const acc of byDay.values()) {
    acc.rollup.active_users = acc.users.size;
    acc.rollup.engaged_users = acc.users.size;
    rollups.push(acc.rollup);
  }
  stats.attributesDropped = allowStats.attributesDropped;
  return { rollups: rollups.sort((a, b) => a.day.localeCompare(b.day)), stats, errors };
}

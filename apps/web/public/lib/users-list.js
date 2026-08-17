/* Users list honesty helpers (§4.2).
 *
 * Production GET /api/users hard-caps at 500 rows. At a 700-seat pilot that
 * can hide 200 active users. The API now prefers { total, limit, truncated };
 * when those fields are missing the client still treats a full page
 * (length === known limit) as "may be capped" so the view never implies full
 * population coverage from a truncated page.
 */

/** Server hard cap for GET /api/users (apps/api dashboard route). */
export const USERS_LIST_LIMIT = 500;

/**
 * @param {object|null|undefined} payload  /api/users JSON body
 * @returns {{ truncated: boolean, shown: number, limit: number, total: number|null }}
 */
export function usersListTruncation(payload) {
  const users = Array.isArray(payload?.users) ? payload.users : [];
  const shown = users.length;
  const limitRaw = Number(payload?.limit);
  const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : USERS_LIST_LIMIT;
  const totalRaw = Number(payload?.total);
  const total = Number.isFinite(totalRaw) && totalRaw >= 0 ? Math.floor(totalRaw) : null;

  let truncated;
  if (payload?.truncated === true || payload?.truncated === false) {
    truncated = Boolean(payload.truncated);
  } else if (total != null) {
    truncated = total > shown;
  } else {
    // No total from API: a full page is the only honest signal that more may exist.
    truncated = shown >= limit;
  }

  return { truncated, shown, limit, total };
}

/**
 * Banner copy for a truncated users list, or null when the list is complete.
 * Prefer "showing N of M" when total is known.
 *
 * @param {{ truncated: boolean, shown: number, limit: number, total: number|null }} info
 * @returns {string|null}
 */
export function usersTruncationBannerCopy(info) {
  if (!info?.truncated) return null;
  const { shown, limit, total } = info;
  if (total != null && total > shown) {
    return `Showing ${shown} of ${total} active users (list capped at ${limit} by token volume). Export CSV or filter after pagination lands to reach the rest.`;
  }
  return `List capped at ${limit} users (by token volume). More active users may exist beyond this page — export CSV or wait for pagination.`;
}

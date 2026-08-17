/**
 * Privacy boundary for vendor admin JSON.
 *
 * Only allowlisted keys are copied. Content-bearing names (prompt, email,
 * path, repo URL, raw username) are counted as dropped and never returned.
 * The function is pure: it does not log values.
 */

export const CONTENT_BEARING_KEYS = new Set([
  "email",
  "user_email",
  "useremail",
  "mail",
  "username",
  "user_name",
  "login",
  "user",
  "display_name",
  "displayname",
  "full_name",
  "fullname",
  "prompt",
  "completion",
  "message",
  "content",
  "text",
  "body",
  "path",
  "filepath",
  "file_path",
  "filename",
  "file_name",
  "repo",
  "repository",
  "repo_url",
  "html_url",
  "clone_url",
  "cwd",
  "workspace",
  "authorization",
  "token",
  "access_token",
  "api_key",
]);

export interface AllowlistStats {
  attributesDropped: number;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function keyDenied(key: string): boolean {
  const k = key.toLowerCase().replace(/[-.]/g, "_");
  if (CONTENT_BEARING_KEYS.has(k)) return true;
  if (k.endsWith("_email") || k.endsWith("_login") || k.endsWith("_prompt")) return true;
  return false;
}

/**
 * Deep-copy `value`, keeping only `allowlist` keys. Denied / unknown keys
 * increment `stats.attributesDropped`. Arrays of objects are filtered
 * element-wise. Primitive array elements are kept only when the parent key
 * was already allowlisted.
 */
export function pickAllowlisted(
  value: unknown,
  allowlist: Set<string>,
  stats: AllowlistStats,
): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => pickAllowlisted(item, allowlist, stats));
  }
  if (!isPlainObject(value)) return value;

  const out: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    if (keyDenied(key) || !allowlist.has(key)) {
      stats.attributesDropped += 1;
      continue;
    }
    out[key] = pickAllowlisted(child, allowlist, stats);
  }
  return out;
}

export function asNonNegInt(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) {
    return Math.floor(value);
  }
  if (typeof value === "string" && /^\d+$/.test(value)) {
    return Number.parseInt(value, 10);
  }
  return 0;
}

export function asDay(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const m = /^(\d{4}-\d{2}-\d{2})/.exec(value);
  return m?.[1] ?? null;
}

/** Recursively assert a value tree contains none of the forbidden substrings. */
export function serializedHasForbidden(value: unknown, needles: string[]): boolean {
  let blob: string;
  try {
    blob = JSON.stringify(value) ?? "";
  } catch {
    return false;
  }
  const lower = blob.toLowerCase();
  return needles.some((n) => lower.includes(n.toLowerCase()));
}

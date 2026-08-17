/* — pure helpers for MCP allowlist management (DOM-free for node:test).
 *
 * Mirrors apps/api/src/routes/mcp.js normalizeMcpAllowlist so the UI rejects
 * bad names before the round-trip. Mutations go to PUT /api/mcp-allowlist;
 * the server writes machine-owned mcp-allowlist.yaml and audits
 * mcp.allowlist_update with actor + before/after content hashes.
 */

export const MCP_NAME_MAX = 128;
/** Exact server ids only — no wildcards, spaces, or shell metacharacters. */
export const MCP_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._@+/-]{0,127}$/;
export const MAX_REASON_LEN = 2000;
export const MAX_ALLOWLIST = 500;

/**
 * Validate a single MCP server id.
 * @returns {{ ok: true, value: string } | { ok: false, error: string }}
 */
export function validateServerName(raw) {
  if (typeof raw !== 'string' || !raw.trim()) {
    return { ok: false, error: 'Enter a server id (exact name, no wildcards).' };
  }
  const name = raw.trim();
  if (name.length > MCP_NAME_MAX || !MCP_NAME_RE.test(name)) {
    return {
      ok: false,
      error:
        `Invalid MCP server name — use 1–${MCP_NAME_MAX} chars matching ` +
        '[A-Za-z0-9][A-Za-z0-9._@+/-]* (exact id, no wildcards).',
    };
  }
  return { ok: true, value: name };
}

/**
 * Normalize a proposed full allowlist (trim, dedupe, sort).
 * @returns {{ ok: true, servers: string[] } | { ok: false, error: string }}
 */
export function normalizeAllowlist(raw) {
  if (!Array.isArray(raw)) {
    return { ok: false, error: 'approvedMcpServers must be an array of server name strings' };
  }
  if (raw.length > MAX_ALLOWLIST) {
    return { ok: false, error: `Allowlist may contain at most ${MAX_ALLOWLIST} entries` };
  }
  const seen = new Set();
  const out = [];
  for (const item of raw) {
    if (typeof item !== 'string') {
      return { ok: false, error: 'Each allowlist entry must be a string' };
    }
    const name = item.trim();
    if (!name) continue;
    const v = validateServerName(name);
    if (!v.ok) return v;
    if (seen.has(v.value)) continue;
    seen.add(v.value);
    out.push(v.value);
  }
  out.sort((a, b) => a.localeCompare(b));
  return { ok: true, servers: out };
}

/** Order-insensitive allowlist diff. */
export function diffAllowlist(before = [], after = []) {
  const b = new Set(before);
  const a = new Set(after);
  return {
    added: [...a].filter((s) => !b.has(s)).sort((x, y) => x.localeCompare(y)),
    removed: [...b].filter((s) => !a.has(s)).sort((x, y) => x.localeCompare(y)),
  };
}

/**
 * Propose adding a server to the allowlist (Allow action).
 * @returns {{ ok: true, servers: string[] } | { ok: false, error: string }}
 */
export function proposeAllow(current, server) {
  const v = validateServerName(server);
  if (!v.ok) return v;
  if ((current ?? []).includes(v.value)) {
    return { ok: false, error: `'${v.value}' is already on the allowlist` };
  }
  return normalizeAllowlist([...(current ?? []), v.value]);
}

/**
 * Propose removing a server from the allowlist (Deny action).
 * @returns {{ ok: true, servers: string[] } | { ok: false, error: string }}
 */
export function proposeDeny(current, server) {
  const v = validateServerName(server);
  if (!v.ok) return v;
  if (!(current ?? []).includes(v.value)) {
    return { ok: false, error: `'${v.value}' is not on the allowlist` };
  }
  return normalizeAllowlist((current ?? []).filter((n) => n !== v.value));
}

/**
 * Optional reason for the audit trail.
 * @returns {{ ok: true, reason: string|null } | { ok: false, error: string }}
 */
export function validateReason(raw) {
  if (raw == null || raw === '') return { ok: true, reason: null };
  if (typeof raw !== 'string') return { ok: false, error: 'Reason must be text.' };
  const reason = raw.trim() || null;
  if (reason && reason.length > MAX_REASON_LEN) {
    return { ok: false, error: `Reason must be at most ${MAX_REASON_LEN} characters.` };
  }
  return { ok: true, reason };
}

/**
 * Build PUT /api/mcp-allowlist body from a proposed next list.
 * @returns {{ ok: true, body: object } | { ok: false, error: string }}
 */
export function buildAllowlistPutBody(nextServers, { reason } = {}) {
  const n = normalizeAllowlist(nextServers);
  if (!n.ok) return n;
  const r = validateReason(reason);
  if (!r.ok) return r;
  const body = { approvedMcpServers: n.servers };
  if (r.reason) body.reason = r.reason;
  return { ok: true, body };
}

/** Short hash for UI status lines (first 12 hex chars). */
export function shortHash(hash) {
  if (hash == null || hash === '') return '—';
  return `${String(hash).slice(0, 12)}…`;
}

/**
 * Status line after a successful allowlist write.
 * Surfaces actor + content-hash change for the acceptance check.
 */
export function formatSaveStatus({
  actor,
  contentHash,
  previousContentHash,
  added = [],
  removed = [],
} = {}) {
  const parts = ['Saved'];
  if (actor) parts.push(`by ${actor}`);
  if (previousContentHash && contentHash) {
    parts.push(`hash ${shortHash(previousContentHash)} → ${shortHash(contentHash)}`);
  }
  if (added.length) parts.push(`+${added.join(', ')}`);
  if (removed.length) parts.push(`−${removed.join(', ')}`);
  return parts.join(' · ');
}

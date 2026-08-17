/* AIM-667 — pure MCP analyst-override helpers (DOM-free for node:test).
 *
 * Runtime deny → analyst permanent override is an allowlist add via
 * PUT /api/mcp-allowlist. Dual control is optional: when requested, a second
 * approver identity must be supplied and is audited with the write.
 */

/** Diff two allowlists (order-insensitive). */
export function diffAllowlist(before = [], after = []) {
  const b = new Set(before);
  const a = new Set(after);
  return {
    added: [...a].filter((s) => !b.has(s)).sort((x, y) => x.localeCompare(y)),
    removed: [...b].filter((s) => !a.has(s)).sort((x, y) => x.localeCompare(y)),
  };
}

/**
 * Validate the override dialog before submit.
 * @returns {string|null} error message or null when valid
 */
export function validateOverrideForm({
  server,
  reason,
  dualControl = false,
  dualControlApprover = '',
  confirm = false,
} = {}) {
  const name = String(server ?? '').trim();
  if (!name) return 'Choose an MCP server to override.';
  const note = String(reason ?? '').trim();
  if (!note) return 'A reason is required for the audit trail.';
  if (note.length > 2000) return 'Reason must be ≤2000 characters.';
  if (!confirm) return 'Confirm that you understand this permanently adds the server to the allowlist.';
  if (dualControl) {
    const approver = String(dualControlApprover ?? '').trim();
    if (!approver) return 'Dual control requires a second approver identity.';
    if (approver.length > 320) return 'Second approver identity must be ≤320 characters.';
  }
  return null;
}

/**
 * Build PUT /api/mcp-allowlist body that adds `server` to the current list.
 * @throws {Error} when validation fails
 */
export function buildApproveOverridePayload(currentList, server, opts = {}) {
  const err = validateOverrideForm({
    server,
    reason: opts.reason,
    dualControl: opts.dualControl,
    dualControlApprover: opts.dualControlApprover,
    confirm: opts.confirm ?? true,
  });
  if (err) throw new Error(err);
  const name = String(server).trim();
  const next = [...new Set([...(currentList ?? []), name])].sort((a, b) => a.localeCompare(b));
  const body = {
    approvedMcpServers: next,
    reason: String(opts.reason).trim(),
  };
  if (opts.dualControl) {
    body.dualControl = { approver: String(opts.dualControlApprover).trim() };
  }
  return body;
}

/** True when a server is a candidate for runtime-deny override (unapproved). */
export function isOverrideCandidate(serverRow, _endpointEnforce) {
  if (!serverRow || !serverRow.name) return false;
  if (serverRow.status === 'approved') return false;
  // Show override CTA whenever unapproved; enforce flag only changes urgency copy.
  return true;
}

export function overrideUrgency(endpointEnforce) {
  return endpointEnforce
    ? 'Endpoint enforce is ON — unapproved MCP tool calls are denied at PreToolUse.'
    : 'Endpoint enforce is off/shadow — denials are observe/would_block only; override still updates the allowlist.';
}

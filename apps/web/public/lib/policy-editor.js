/* — pure helpers for the analyst-facing policy editor.
 *
 * Safe subset (no raw YAML):
 *   - sanctioned-tool allowlist (GET/POST/DELETE /api/sanctioned)
 *   - model/provider allowlist with observe|enforce modes
 *     (GET/POST/DELETE /api/governance/model-allowlist)
 *
 * Validation mirrors the API so the UI rejects bad input before the round-trip
 * and surfaces the same rules the server enforces. Keep this module free of DOM
 * so unit tests can cover every branch without a harness.
 */

export const MODES = Object.freeze(['observe', 'enforce']);
export const SCOPE_TYPES = Object.freeze(['global', 'team']);

const TOOL_RE = /^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,127}$/;
const MAX_TOOL_LEN = 128;
const MAX_REASON_LEN = 2000;
const MAX_NOTE_LEN = 2000;
const MAX_SCOPE_ID = 128;
const MAX_PROVIDER_MODEL = 256;

/**
 * Validate a sanctioned-tool mutation payload.
 * @returns {{ ok: true, value: { tool: string, reason: string, note: string|null } } | { ok: false, error: string, field?: string }}
 */
export function validateSanctioned({ tool, reason, note } = {}) {
  if (typeof tool !== 'string' || !tool.trim()) {
    return { ok: false, error: 'Tool name is required.', field: 'tool' };
  }
  const t = tool.trim();
  if (t.length > MAX_TOOL_LEN || !TOOL_RE.test(t)) {
    return {
      ok: false,
      error: 'Tool must be 1–128 characters: letters, digits, . _ + - (must start with alnum).',
      field: 'tool',
    };
  }
  if (typeof reason !== 'string' || !reason.trim()) {
    return { ok: false, error: 'A reason is required (recorded in the audit trail).', field: 'reason' };
  }
  const r = reason.trim();
  if (r.length > MAX_REASON_LEN) {
    return { ok: false, error: `Reason must be at most ${MAX_REASON_LEN} characters.`, field: 'reason' };
  }
  let n = null;
  if (note != null && note !== '') {
    if (typeof note !== 'string') {
      return { ok: false, error: 'Note must be text.', field: 'note' };
    }
    n = note.trim() || null;
    if (n && n.length > MAX_NOTE_LEN) {
      return { ok: false, error: `Note must be at most ${MAX_NOTE_LEN} characters.`, field: 'note' };
    }
  }
  return { ok: true, value: { tool: t, reason: r, note: n } };
}

/**
 * Validate a model/provider allowlist entry (create or mode-toggle body).
 * @returns {{ ok: true, value: object } | { ok: false, error: string, field?: string }}
 */
export function validateModelAllowlist({
  scope_type,
  scope_id,
  provider,
  model,
  mode = 'observe',
  enabled = true,
  note,
} = {}) {
  if (!SCOPE_TYPES.includes(scope_type)) {
    return { ok: false, error: 'Scope must be global or team.', field: 'scope_type' };
  }
  let sid = null;
  if (scope_type === 'team') {
    if (typeof scope_id !== 'string' || !scope_id.trim()) {
      return { ok: false, error: 'Team scope requires a team id.', field: 'scope_id' };
    }
    sid = scope_id.trim();
    if (sid.length > MAX_SCOPE_ID) {
      return { ok: false, error: `Team id must be at most ${MAX_SCOPE_ID} characters.`, field: 'scope_id' };
    }
  } else if (scope_id != null && String(scope_id).trim() !== '') {
    return { ok: false, error: 'Global scope must not set a team id.', field: 'scope_id' };
  }

  const prov = provider == null || provider === '' ? null : String(provider).trim();
  const mod = model == null || model === '' ? null : String(model).trim();
  if (!prov && !mod) {
    return { ok: false, error: 'Provider or model is required.', field: 'provider' };
  }
  if (prov && prov.length > MAX_PROVIDER_MODEL) {
    return { ok: false, error: `Provider must be at most ${MAX_PROVIDER_MODEL} characters.`, field: 'provider' };
  }
  if (mod && mod.length > MAX_PROVIDER_MODEL) {
    return { ok: false, error: `Model must be at most ${MAX_PROVIDER_MODEL} characters.`, field: 'model' };
  }

  if (!MODES.includes(mode)) {
    return { ok: false, error: 'Mode must be observe or enforce.', field: 'mode' };
  }
  if (typeof enabled !== 'boolean') {
    return { ok: false, error: 'Enabled must be true or false.', field: 'enabled' };
  }

  let n = null;
  if (note != null && note !== '') {
    if (typeof note !== 'string') {
      return { ok: false, error: 'Note must be text.', field: 'note' };
    }
    n = note.trim() || null;
    if (n && n.length > MAX_NOTE_LEN) {
      return { ok: false, error: `Note must be at most ${MAX_NOTE_LEN} characters.`, field: 'note' };
    }
  }

  return {
    ok: true,
    value: {
      scope_type,
      scope_id: sid,
      provider: prov,
      model: mod,
      mode,
      enabled,
      note: n,
    },
  };
}

/** Flip observe ↔ enforce. Returns null if mode is unknown. */
export function flipMode(mode) {
  if (mode === 'observe') return 'enforce';
  if (mode === 'enforce') return 'observe';
  return null;
}

/**
 * Build the POST body to re-create an allowlist entry with a new mode
 * (existing API has no PATCH — delete + create is the safe-subset toggle).
 */
export function rebuildAllowlistBody(entry, nextMode) {
  return validateModelAllowlist({
    scope_type: entry.scope_type ?? entry.scopeType,
    scope_id: entry.scope_id ?? entry.scopeId,
    provider: entry.provider,
    model: entry.model,
    mode: nextMode,
    enabled: entry.enabled !== false,
    note: entry.note,
  });
}

/**
 * Summarise enforcement rule modes from guardrail settings (read-only YAML surface).
 * @returns {Array<{ id: string, enforce: boolean, modeLabel: string }>}
 */
export function enforcementRuleModes(settings) {
  const rules = settings?.enforcement?.rules;
  if (!rules || typeof rules !== 'object') return [];
  return Object.entries(rules).map(([id, cfg]) => {
    const enforce = Boolean(cfg && typeof cfg === 'object' && cfg.enforce === true);
    return {
      id,
      enforce,
      modeLabel: enforce ? 'enforce' : 'observe',
    };
  });
}

/** Human label for an allowlist row. */
export function allowlistLabel(entry) {
  const parts = [];
  if (entry.provider) parts.push(entry.provider);
  if (entry.model) parts.push(entry.model);
  const target = parts.join(' / ') || '(empty)';
  const scope = (entry.scope_type ?? entry.scopeType) === 'team'
    ? `team:${entry.scope_id ?? entry.scopeId ?? '?'}`
    : 'global';
  return `${target} · ${scope}`;
}

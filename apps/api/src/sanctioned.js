// Sanctioned tool list — AIM-484 persisted allow-list (seeded from AIM-16).
//
// Policy decisions sit with Security/Legal/CEO; this module is the
// enforcement mechanism, not the decision. The live list lives in the
// event-store table `sanctioned_tools`. The in-process Set is a cache that
// is mutated in place so existing `import { SANCTIONED_TOOLS }` call sites
// see updates without a restart (activity-score is pure/sync).
//
// Fail-open on a missing table (pre-migration / cold boot race): fall back
// to the AIM-16 seed so the fleet does not suddenly treat Claude Code as
// unapproved while ingest is still applying migrations.

import { query as defaultQuery } from './db.js';

/** AIM-16 locked seed — also the migration 022 INSERT and the offline fallback. */
export const DEFAULT_SANCTIONED_TOOLS = Object.freeze([
  'claude_code',
  'cursor',
  'kilo_code',
]);

/**
 * Live cache of sanctioned tool names. Mutated in place by
 * {@link refreshSanctionedTools} / mutation helpers so importers that hold
 * a reference to this Set observe changes without re-importing.
 *
 * Prefer {@link listSanctionedToolNames} in async request handlers so the
 * response reflects the DB even across multi-instance deployments.
 */
export const SANCTIONED_TOOLS = new Set(DEFAULT_SANCTIONED_TOOLS);

const MAX_TOOL_LEN = 128;
const MAX_NOTE_LEN = 2000;
const MAX_REASON_LEN = 2000;
const TOOL_RE = /^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,127}$/;

function isMissingTable(err) {
  const msg = String(err?.message || err);
  // pg: relation "sanctioned_tools" does not exist
  // pg-mem / other: various "does not exist" / "no such table"
  return /sanctioned_tools/i.test(msg) && /does not exist|no such table|undefined_table/i.test(msg);
}

function replaceCache(tools) {
  SANCTIONED_TOOLS.clear();
  for (const t of tools) SANCTIONED_TOOLS.add(t);
  if (SANCTIONED_TOOLS.size === 0) {
    for (const t of DEFAULT_SANCTIONED_TOOLS) SANCTIONED_TOOLS.add(t);
  }
  return SANCTIONED_TOOLS;
}

export function isSanctioned(tool) {
  return SANCTIONED_TOOLS.has(tool);
}

export function normalizeToolName(raw) {
  if (typeof raw !== 'string') return null;
  const tool = raw.trim();
  if (!tool || tool.length > MAX_TOOL_LEN || !TOOL_RE.test(tool)) return null;
  return tool;
}

export function normalizeReason(raw, { required = true } = {}) {
  if (raw == null || raw === '') {
    return required ? { error: 'reason is required' } : { value: null };
  }
  if (typeof raw !== 'string') return { error: 'reason must be a string' };
  const reason = raw.trim();
  if (!reason) return required ? { error: 'reason is required' } : { value: null };
  if (reason.length > MAX_REASON_LEN) {
    return { error: `reason must be at most ${MAX_REASON_LEN} characters` };
  }
  return { value: reason };
}

export function normalizeNote(raw) {
  if (raw == null || raw === '') return { value: null };
  if (typeof raw !== 'string') return { error: 'note must be a string' };
  const note = raw.trim();
  if (note.length > MAX_NOTE_LEN) {
    return { error: `note must be at most ${MAX_NOTE_LEN} characters` };
  }
  return { value: note || null };
}

function rowView(r) {
  return {
    tool: r.tool,
    note: r.note ?? null,
    createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : (r.created_at ?? null),
    createdBy: r.created_by ?? null,
    updatedAt: r.updated_at instanceof Date ? r.updated_at.toISOString() : (r.updated_at ?? null),
    updatedBy: r.updated_by ?? null,
  };
}

/**
 * Reload the in-process cache from the DB. Safe to call on every request
 * that needs the live list; three rows is negligible.
 *
 * @param {{ query: typeof defaultQuery }} [db]
 * @returns {Promise<Set<string>>}
 */
export async function refreshSanctionedTools(db = { query: defaultQuery }) {
  try {
    const { rows } = await db.query(
      `SELECT tool FROM sanctioned_tools ORDER BY tool`,
    );
    return replaceCache(rows.map((r) => r.tool));
  } catch (err) {
    if (isMissingTable(err)) {
      return replaceCache([...DEFAULT_SANCTIONED_TOOLS]);
    }
    throw err;
  }
}

/**
 * Full row list for the admin/read API. Also refreshes the cache.
 *
 * @param {{ query: typeof defaultQuery }} [db]
 * @returns {Promise<Array<ReturnType<typeof rowView>>>}
 */
export async function listSanctionedTools(db = { query: defaultQuery }) {
  try {
    const { rows } = await db.query(
      `SELECT tool, note, created_at, created_by, updated_at, updated_by
         FROM sanctioned_tools
        ORDER BY tool`,
    );
    replaceCache(rows.map((r) => r.tool));
    return rows.map(rowView);
  } catch (err) {
    if (isMissingTable(err)) {
      replaceCache([...DEFAULT_SANCTIONED_TOOLS]);
      return DEFAULT_SANCTIONED_TOOLS.map((tool) => ({
        tool,
        note: 'AIM-16 seed (table not yet migrated)',
        createdAt: null,
        createdBy: 'system:fallback',
        updatedAt: null,
        updatedBy: 'system:fallback',
      }));
    }
    throw err;
  }
}

/**
 * Tool name array for SQL `= ANY($n)` bindings. Refreshes cache.
 *
 * @param {{ query: typeof defaultQuery }} [db]
 * @returns {Promise<string[]>}
 */
export async function listSanctionedToolNames(db = { query: defaultQuery }) {
  await refreshSanctionedTools(db);
  return [...SANCTIONED_TOOLS];
}

/**
 * Add a tool to the allow-list (idempotent). Returns { status, before, after, row }.
 *
 * @param {{ query: typeof defaultQuery }} db
 * @param {{ tool: string, actor: string, note?: string|null, reason: string }} opts
 */
export async function sanctionTool(db, { tool, actor, note = null, reason }) {
  const before = await listSanctionedToolNames(db);
  const { rows } = await db.query(
    `INSERT INTO sanctioned_tools (tool, note, created_by, updated_by)
     VALUES ($1, $2, $3, $3)
     ON CONFLICT (tool) DO UPDATE SET
       note = COALESCE(EXCLUDED.note, sanctioned_tools.note),
       updated_at = now(),
       updated_by = EXCLUDED.updated_by
     RETURNING tool, note, created_at, created_by, updated_at, updated_by`,
    [tool, note, actor],
  );
  const after = await listSanctionedToolNames(db);
  const already = before.includes(tool);
  return {
    status: already ? 'already_sanctioned' : 'sanctioned',
    before,
    after,
    row: rowView(rows[0]),
    reason,
  };
}

/**
 * Remove a tool from the allow-list. Returns null row when not present.
 *
 * @param {{ query: typeof defaultQuery }} db
 * @param {{ tool: string, actor: string, reason: string }} opts
 */
export async function unsanctionTool(db, { tool, actor, reason }) {
  const before = await listSanctionedToolNames(db);
  if (!before.includes(tool)) {
    return {
      status: 'not_sanctioned',
      before,
      after: before,
      row: null,
      reason,
    };
  }
  const { rows } = await db.query(
    `DELETE FROM sanctioned_tools WHERE tool = $1
     RETURNING tool, note, created_at, created_by, updated_at, updated_by`,
    [tool],
  );
  // Touch updated_by is N/A on delete; actor is carried in the audit record.
  void actor;
  const after = await listSanctionedToolNames(db);
  return {
    status: 'unsanctioned',
    before,
    after,
    row: rows[0] ? rowView(rows[0]) : null,
    reason,
  };
}

/**
 * Update the free-text note on a sanctioned tool.
 *
 * @param {{ query: typeof defaultQuery }} db
 * @param {{ tool: string, actor: string, note: string|null, reason: string }} opts
 */
export async function setSanctionedNote(db, { tool, actor, note, reason }) {
  const before = await listSanctionedToolNames(db);
  if (!before.includes(tool)) {
    return {
      status: 'not_sanctioned',
      before,
      after: before,
      row: null,
      reason,
    };
  }
  const { rows } = await db.query(
    `UPDATE sanctioned_tools
        SET note = $2,
            updated_at = now(),
            updated_by = $3
      WHERE tool = $1
      RETURNING tool, note, created_at, created_by, updated_at, updated_by`,
    [tool, note, actor],
  );
  const after = await listSanctionedToolNames(db);
  return {
    status: 'note_updated',
    before,
    after,
    row: rows[0] ? rowView(rows[0]) : null,
    reason,
  };
}

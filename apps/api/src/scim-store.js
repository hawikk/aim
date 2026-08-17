// SCIM 2.0 directory store (AIM-713).
//
// In-process Map is the request-path source of truth (sync, no DB round-trip
// per auth check). Optional Postgres write-through survives restarts; tests
// inject a pure memory store without Postgres.
//
// Semantics:
//   * userName is always a lowercased email.
//   * Deactivate (PATCH active=false or DELETE) sets active=false; rows are
//     retained so re-activate and externalId rebinding stay stable.
//   * Group membership drives role mapping when SCIM groups are merged into
//     the session group list at login / auth check.

import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';

export function normalizeEmail(email) {
  return String(email ?? '').trim().toLowerCase();
}

export function isValidEmail(email) {
  const e = normalizeEmail(email);
  if (!e || e.length > 254) return false;
  if (e.includes('\n') || e.includes('\r') || e.includes('\0')) return false;
  return /^[^\s@]+@[^\s@]+$/.test(e);
}

export function hashScimToken(raw) {
  return createHash('sha256').update(String(raw ?? ''), 'utf8').digest('hex');
}

/** Constant-time compare of two hex digests (or reject length mismatch). */
export function tokenHashEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  try {
    const ba = Buffer.from(a, 'hex');
    const bb = Buffer.from(b, 'hex');
    if (ba.length === 0 || ba.length !== bb.length) return false;
    return timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

/**
 * @typedef {{
 *   id: string,
 *   userName: string,
 *   externalId: string|null,
 *   displayName: string|null,
 *   active: boolean,
 *   createdAt: string,
 *   updatedAt: string,
 * }} ScimUser
 *
 * @typedef {{
 *   id: string,
 *   displayName: string,
 *   externalId: string|null,
 *   active: boolean,
 *   memberIds: string[],
 *   createdAt: string,
 *   updatedAt: string,
 * }} ScimGroup
 */

export class ScimConflictError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ScimConflictError';
    this.statusCode = 409;
  }
}

export class ScimValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ScimValidationError';
    this.statusCode = 400;
  }
}

export class ScimNotFoundError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ScimNotFoundError';
    this.statusCode = 404;
  }
}

function nowIso() {
  return new Date().toISOString();
}

export class ScimDirectory {
  constructor() {
    /** @type {Map<string, ScimUser>} */
    this.usersById = new Map();
    /** @type {Map<string, string>} userName → id */
    this.userIdByName = new Map();
    /** @type {Map<string, string>} externalId → id */
    this.userIdByExternal = new Map();
    /** @type {Map<string, ScimGroup>} */
    this.groupsById = new Map();
    /** @type {Map<string, string>} displayName (lower) → id */
    this.groupIdByName = new Map();
    /** @type {Map<string, string>} externalId → id */
    this.groupIdByExternal = new Map();
  }

  clear() {
    this.usersById.clear();
    this.userIdByName.clear();
    this.userIdByExternal.clear();
    this.groupsById.clear();
    this.groupIdByName.clear();
    this.groupIdByExternal.clear();
  }

  /** @returns {ScimUser|null} */
  getUser(id) {
    return this.usersById.get(id) ?? null;
  }

  /** @returns {ScimUser|null} */
  getUserByName(userName) {
    const id = this.userIdByName.get(normalizeEmail(userName));
    return id ? this.usersById.get(id) ?? null : null;
  }

  /**
   * Auth path helper: true when the email is known and active=false.
   * Unknown users return false (soft mode lets OIDC-only users through).
   */
  isDeprovisioned(email) {
    const user = this.getUserByName(email);
    return Boolean(user && user.active === false);
  }

  /**
   * True when enforce mode requires a live SCIM user and this email is not
   * an active provisioned user.
   */
  isEnforceDenied(email, { enforce }) {
    if (!enforce) return this.isDeprovisioned(email);
    const user = this.getUserByName(email);
    return !user || user.active === false;
  }

  /** Group displayNames the user is a member of (active groups only). */
  groupsForUser(email) {
    const user = this.getUserByName(email);
    if (!user || !user.active) return [];
    const names = [];
    for (const group of this.groupsById.values()) {
      if (!group.active) continue;
      if (group.memberIds.includes(user.id)) names.push(group.displayName);
    }
    return names;
  }

  listUsers({ filterUserName } = {}) {
    let users = [...this.usersById.values()];
    if (filterUserName) {
      const want = normalizeEmail(filterUserName);
      users = users.filter((u) => u.userName === want);
    }
    users.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    return users;
  }

  /**
   * Create or rebind a SCIM user. Conflicts when externalId and email map to
   * different existing rows.
   * @returns {ScimUser}
   */
  upsertUser({ userName, externalId = null, displayName = null, active = true, id = null }) {
    const email = normalizeEmail(userName);
    if (!isValidEmail(email)) {
      throw new ScimValidationError('SCIM userName or email is required');
    }
    if (typeof active !== 'boolean') {
      throw new ScimValidationError('SCIM active must be a boolean');
    }
    const ext = externalId == null || externalId === '' ? null : String(externalId);

    const byName = this.getUserByName(email);
    const byExt = ext ? this.usersById.get(this.userIdByExternal.get(ext) ?? '') ?? null : null;
    if (byName && byExt && byName.id !== byExt.id) {
      throw new ScimConflictError('SCIM external_id and email are already bound to different users');
    }
    if (ext && byName?.externalId && byName.externalId !== ext) {
      throw new ScimConflictError('email is already bound to a different SCIM external_id');
    }

    let user = byExt || byName;
    const ts = nowIso();
    if (!user) {
      user = {
        id: id || randomUUID(),
        userName: email,
        externalId: ext,
        displayName: displayName == null ? null : String(displayName),
        active,
        createdAt: ts,
        updatedAt: ts,
      };
      this.usersById.set(user.id, user);
    } else {
      // Rebind indexes if identity fields change.
      if (user.userName !== email) {
        this.userIdByName.delete(user.userName);
        user.userName = email;
      }
      if (user.externalId && user.externalId !== ext) {
        this.userIdByExternal.delete(user.externalId);
      }
      user.externalId = ext ?? user.externalId;
      if (displayName !== null && displayName !== undefined) {
        user.displayName = String(displayName);
      }
      user.active = active;
      user.updatedAt = ts;
    }
    this.userIdByName.set(user.userName, user.id);
    if (user.externalId) this.userIdByExternal.set(user.externalId, user.id);
    return { ...user };
  }

  /** @returns {ScimUser} */
  setUserActive(id, active) {
    if (typeof active !== 'boolean') {
      throw new ScimValidationError('SCIM active must be a boolean');
    }
    const user = this.usersById.get(id);
    if (!user) throw new ScimNotFoundError('SCIM user not found');
    user.active = active;
    user.updatedAt = nowIso();
    return { ...user };
  }

  /** Soft-delete: active=false. Returns the user or null if missing. */
  deprovisionUser(id) {
    const user = this.usersById.get(id);
    if (!user) return null;
    user.active = false;
    user.updatedAt = nowIso();
    return { ...user };
  }

  listGroups({ filterDisplayName } = {}) {
    let groups = [...this.groupsById.values()];
    if (filterDisplayName != null) {
      const want = String(filterDisplayName);
      groups = groups.filter((g) => g.displayName === want);
    }
    groups.sort((a, b) => a.displayName.localeCompare(b.displayName));
    return groups.map((g) => ({ ...g, memberIds: [...g.memberIds] }));
  }

  /** @returns {ScimGroup|null} */
  getGroup(id) {
    const g = this.groupsById.get(id);
    return g ? { ...g, memberIds: [...g.memberIds] } : null;
  }

  /**
   * @returns {ScimGroup}
   */
  upsertGroup({ displayName, externalId = null, memberIds = null, active = true, id = null }) {
    const name = String(displayName ?? '').trim();
    if (!name) throw new ScimValidationError('SCIM group displayName is required');
    const ext = externalId == null || externalId === '' ? null : String(externalId);
    const nameKey = name.toLowerCase();

    const byName = this.groupsById.get(this.groupIdByName.get(nameKey) ?? '') ?? null;
    const byExt = ext ? this.groupsById.get(this.groupIdByExternal.get(ext) ?? '') ?? null : null;
    if (byName && byExt && byName.id !== byExt.id) {
      throw new ScimConflictError('SCIM group external_id and displayName are already bound to different groups');
    }

    let group = byExt || byName;
    const ts = nowIso();
    if (!group) {
      group = {
        id: id || randomUUID(),
        displayName: name,
        externalId: ext,
        active,
        memberIds: [],
        createdAt: ts,
        updatedAt: ts,
      };
      this.groupsById.set(group.id, group);
    } else {
      if (group.displayName.toLowerCase() !== nameKey) {
        this.groupIdByName.delete(group.displayName.toLowerCase());
        group.displayName = name;
      }
      if (group.externalId && group.externalId !== ext) {
        this.groupIdByExternal.delete(group.externalId);
      }
      group.externalId = ext ?? group.externalId;
      group.active = active;
      group.updatedAt = ts;
    }
    this.groupIdByName.set(group.displayName.toLowerCase(), group.id);
    if (group.externalId) this.groupIdByExternal.set(group.externalId, group.id);

    if (memberIds != null) {
      this.replaceGroupMembers(group.id, memberIds);
    }
    return this.getGroup(group.id);
  }

  replaceGroupMembers(groupId, userIds) {
    const group = this.groupsById.get(groupId);
    if (!group) throw new ScimNotFoundError('SCIM group not found');
    const unique = [...new Set((userIds ?? []).map(String))];
    for (const uid of unique) {
      const u = this.usersById.get(uid);
      if (!u || !u.active) {
        throw new ScimValidationError('SCIM group contains unknown or inactive tenant user');
      }
    }
    group.memberIds = unique;
    group.updatedAt = nowIso();
    return this.getGroup(groupId);
  }

  setGroupDisplayName(groupId, displayName) {
    const group = this.groupsById.get(groupId);
    if (!group) throw new ScimNotFoundError('SCIM group not found');
    const name = String(displayName ?? '').trim();
    if (!name) throw new ScimValidationError('SCIM group displayName is required');
    const nameKey = name.toLowerCase();
    const existing = this.groupIdByName.get(nameKey);
    if (existing && existing !== groupId) {
      throw new ScimConflictError('SCIM group displayName already in use');
    }
    this.groupIdByName.delete(group.displayName.toLowerCase());
    group.displayName = name;
    group.updatedAt = nowIso();
    this.groupIdByName.set(nameKey, groupId);
    return this.getGroup(groupId);
  }

  /** Hard-delete group (members cascade). */
  deleteGroup(groupId) {
    const group = this.groupsById.get(groupId);
    if (!group) return null;
    this.groupIdByName.delete(group.displayName.toLowerCase());
    if (group.externalId) this.groupIdByExternal.delete(group.externalId);
    this.groupsById.delete(groupId);
    return group;
  }

  /**
   * Replace cache from DB rows.
   * @param {{ users?: any[], groups?: any[], members?: any[] }} rows
   */
  hydrate({ users = [], groups = [], members = [] } = {}) {
    this.clear();
    for (const row of users) {
      const user = {
        id: String(row.id),
        userName: normalizeEmail(row.user_name ?? row.userName),
        externalId: row.external_id ?? row.externalId ?? null,
        displayName: row.display_name ?? row.displayName ?? null,
        active: row.active !== false && row.active !== 'f',
        createdAt: toIso(row.created_at ?? row.createdAt) ?? nowIso(),
        updatedAt: toIso(row.updated_at ?? row.updatedAt) ?? nowIso(),
      };
      if (!user.userName) continue;
      this.usersById.set(user.id, user);
      this.userIdByName.set(user.userName, user.id);
      if (user.externalId) this.userIdByExternal.set(user.externalId, user.id);
    }
    for (const row of groups) {
      const group = {
        id: String(row.id),
        displayName: String(row.display_name ?? row.displayName ?? ''),
        externalId: row.external_id ?? row.externalId ?? null,
        active: row.active !== false && row.active !== 'f',
        memberIds: [],
        createdAt: toIso(row.created_at ?? row.createdAt) ?? nowIso(),
        updatedAt: toIso(row.updated_at ?? row.updatedAt) ?? nowIso(),
      };
      if (!group.displayName) continue;
      this.groupsById.set(group.id, group);
      this.groupIdByName.set(group.displayName.toLowerCase(), group.id);
      if (group.externalId) this.groupIdByExternal.set(group.externalId, group.id);
    }
    for (const row of members) {
      const gid = String(row.group_id ?? row.groupId);
      const uid = String(row.user_id ?? row.userId);
      const group = this.groupsById.get(gid);
      if (!group || !this.usersById.has(uid)) continue;
      if (!group.memberIds.includes(uid)) group.memberIds.push(uid);
    }
    return {
      users: this.usersById.size,
      groups: this.groupsById.size,
    };
  }
}

function toIso(value) {
  if (value == null) return null;
  if (value instanceof Date) return value.toISOString();
  if (typeof value === 'string') return value;
  return null;
}

/** Process-wide directory used by routes + auth. Tests may clear/replace. */
export const scimDirectory = new ScimDirectory();

/**
 * Persist a user row. Best-effort — memory remains authoritative on failure.
 * @param {{ query: Function }} db
 * @param {ScimUser} user
 */
export async function persistUser(db, user) {
  if (!db?.query) return false;
  await db.query(
    `INSERT INTO scim_users (id, user_name, external_id, display_name, active, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz)
     ON CONFLICT (id) DO UPDATE SET
       user_name = EXCLUDED.user_name,
       external_id = EXCLUDED.external_id,
       display_name = EXCLUDED.display_name,
       active = EXCLUDED.active,
       updated_at = EXCLUDED.updated_at`,
    [
      user.id,
      user.userName,
      user.externalId,
      user.displayName,
      user.active,
      user.createdAt,
      user.updatedAt,
    ],
  );
  return true;
}

export async function persistGroup(db, group) {
  if (!db?.query) return false;
  await db.query(
    `INSERT INTO scim_groups (id, display_name, external_id, active, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5::timestamptz, $6::timestamptz)
     ON CONFLICT (id) DO UPDATE SET
       display_name = EXCLUDED.display_name,
       external_id = EXCLUDED.external_id,
       active = EXCLUDED.active,
       updated_at = EXCLUDED.updated_at`,
    [
      group.id,
      group.displayName,
      group.externalId,
      group.active,
      group.createdAt,
      group.updatedAt,
    ],
  );
  return true;
}

export async function persistGroupMembers(db, groupId, memberIds) {
  if (!db?.query) return false;
  await db.query('DELETE FROM scim_group_members WHERE group_id = $1', [groupId]);
  for (const uid of memberIds) {
    await db.query(
      `INSERT INTO scim_group_members (group_id, user_id) VALUES ($1, $2)
       ON CONFLICT DO NOTHING`,
      [groupId, uid],
    );
  }
  return true;
}

export async function deleteGroupRow(db, groupId) {
  if (!db?.query) return false;
  await db.query('DELETE FROM scim_groups WHERE id = $1', [groupId]);
  return true;
}

export async function loadScimDirectory(db, directory = scimDirectory) {
  if (!db?.query) return { users: 0, groups: 0, ok: false };
  try {
    const users = await db.query(
      'SELECT id, user_name, external_id, display_name, active, created_at, updated_at FROM scim_users',
    );
    const groups = await db.query(
      'SELECT id, display_name, external_id, active, created_at, updated_at FROM scim_groups',
    );
    const members = await db.query(
      'SELECT group_id, user_id FROM scim_group_members',
    );
    const counts = directory.hydrate({
      users: users.rows,
      groups: groups.rows,
      members: members.rows,
    });
    return { ...counts, ok: true };
  } catch (err) {
    // Missing table (pre-migration) — leave directory empty; routes still work in memory.
    return { users: 0, groups: 0, ok: false, error: err.message };
  }
}

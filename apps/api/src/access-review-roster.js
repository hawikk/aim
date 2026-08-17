// Build the live AIM-role access roster.
//
// Source of truth for *who holds a role* is the SCIM directory when it is
// live: group membership → mapGroupsToRole / hasRevealGrant. When SCIM is
// off or empty we still return the configured role-group map so reviewers
// can attest the IdP configuration, with an honest empty-principal note.
//
// Pure enough to unit-test without Fastify.

import {
  DEFAULT_ROLE_GROUPS,
  DEFAULT_REVEAL_GROUPS,
  mapGroupsToRole,
  hasRevealGrant,
  ROLE_PRECEDENCE,
} from './auth.js';

function splitCsv(value) {
  return String(value ?? '')
    .split(',')
    .map((g) => g.trim())
    .filter(Boolean);
}

/** Current process role-group config (mirrors auth.js config). */
export function currentRoleGroups() {
  return {
    admin: splitCsv(process.env.AIM_ROLE_GROUPS_ADMIN ?? DEFAULT_ROLE_GROUPS.admin.join(',')),
    analyst: splitCsv(process.env.AIM_ROLE_GROUPS_ANALYST ?? DEFAULT_ROLE_GROUPS.analyst.join(',')),
    auditor: splitCsv(process.env.AIM_ROLE_GROUPS_AUDITOR ?? DEFAULT_ROLE_GROUPS.auditor.join(',')),
    viewer: splitCsv(process.env.AIM_ROLE_GROUPS_VIEWER ?? DEFAULT_ROLE_GROUPS.viewer.join(',')),
  };
}

export function currentRevealGroups() {
  return splitCsv(process.env.AIM_REVEAL_GROUPS ?? DEFAULT_REVEAL_GROUPS.join(','));
}

function emptyByRole() {
  return { admin: 0, analyst: 0, auditor: 0, viewer: 0, none: 0 };
}

/**
 * Group membership for a user including when the user is inactive.
 * `ScimDirectory.groupsForUser` intentionally returns [] for inactive users
 * (auth fail-closed). Access review must still surface deprovisioned role
 * holders so the campaign can attest cleanup.
 *
 * @param {{ listGroups: Function, getUser: Function }} directory
 * @param {string} userId
 * @returns {string[]}
 */
function groupsForUserIncludingInactive(directory, userId) {
  const names = [];
  for (const group of directory.listGroups()) {
    if (!group.active) continue;
    if ((group.memberIds ?? []).includes(userId)) names.push(group.displayName);
  }
  return names;
}

/**
 * @param {{
 *   directory: { listUsers: Function, listGroups: Function, getUser?: Function },
 *   scimEnabled?: boolean,
 *   scimEnforce?: boolean,
 *   roleGroups?: Record<string, string[]>,
 *   revealGroups?: string[],
 *   mapRole?: typeof mapGroupsToRole,
 *   mapReveal?: typeof hasRevealGrant,
 *   now?: () => Date,
 * }} opts
 */
export function buildAccessRoster(opts) {
  const directory = opts.directory;
  const scimEnabled = Boolean(opts.scimEnabled);
  const scimEnforce = Boolean(opts.scimEnforce);
  const roleGroups = opts.roleGroups ?? currentRoleGroups();
  const revealGroups = opts.revealGroups ?? currentRevealGroups();
  const mapRole = opts.mapRole ?? mapGroupsToRole;
  const mapReveal = opts.mapReveal ?? hasRevealGrant;
  const generatedAt = (opts.now?.() ?? new Date()).toISOString();

  const users = scimEnabled && directory ? directory.listUsers() : [];
  /** @type {import('./access-review-store.js').AccessPrincipal[]} */
  const principals = [];

  for (const user of users) {
    const groups = groupsForUserIncludingInactive(directory, user.id);
    const role = mapRole(groups, roleGroups);
    const reveal = mapReveal(groups, revealGroups);
    // Include principals who hold a mapped role OR the reveal grant. Pure
    // unmapped SCIM users with no AIM group are omitted — they cannot call
    // gated APIs (fail closed) and would drown the review list.
    if (!role && !reveal) continue;
    principals.push({
      email: user.userName,
      displayName: user.displayName ?? null,
      role: role ?? null,
      reveal: Boolean(reveal),
      active: Boolean(user.active),
      groups: [...groups].sort(),
      source: 'scim',
    });
  }

  // Stable sort: role rank (admin first), then email.
  const rank = Object.fromEntries(ROLE_PRECEDENCE.map((r, i) => [r, ROLE_PRECEDENCE.length - i]));
  rank.none = 0;
  principals.sort((a, b) => {
    const ra = rank[a.role ?? 'none'] ?? 0;
    const rb = rank[b.role ?? 'none'] ?? 0;
    if (rb !== ra) return rb - ra;
    return a.email.localeCompare(b.email);
  });

  const byRole = emptyByRole();
  let activePrincipals = 0;
  let inactivePrincipals = 0;
  let withReveal = 0;
  let unmapped = 0;
  for (const p of principals) {
    if (p.active) activePrincipals += 1;
    else inactivePrincipals += 1;
    if (p.reveal) withReveal += 1;
    if (p.role) byRole[p.role] = (byRole[p.role] ?? 0) + 1;
    else {
      byRole.none += 1;
      unmapped += 1;
    }
  }

  const source = scimEnabled && users.length > 0 ? 'scim' : 'config_only';
  let note;
  if (!scimEnabled) {
    note =
      'SCIM directory is not configured. Roster lists role-group configuration only; ' +
      'IdP group membership is the live source of truth until SCIM is enabled.';
  } else if (principals.length === 0) {
    note =
      'SCIM is live but no provisioned users map to AIM role groups or the reveal grant. ' +
      'Confirm IdP groups match AIM_ROLE_GROUPS_* / AIM_REVEAL_GROUPS.';
  } else {
    note =
      'Roster derived from SCIM group membership mapped through AIM_ROLE_GROUPS_* ' +
      'and AIM_REVEAL_GROUPS. Highest rank wins (admin > analyst > auditor > viewer).';
  }

  return {
    generatedAt,
    source,
    scimEnabled,
    scimEnforce,
    roleGroups: {
      admin: [...roleGroups.admin],
      analyst: [...roleGroups.analyst],
      auditor: [...roleGroups.auditor],
      viewer: [...roleGroups.viewer],
    },
    revealGroups: [...revealGroups],
    summary: {
      totalPrincipals: principals.length,
      activePrincipals,
      inactivePrincipals,
      byRole,
      withReveal,
      unmapped,
    },
    principals,
    note,
  };
}

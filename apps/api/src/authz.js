// Fine-grained RBAC + optional ABAC.
//
// Coarse roles (admin / analyst / auditor / viewer) remain the default IdP
// mapping surface. This module makes *permissions* the unit of authorization:
//
//   role  ──►  permission set  ──►  route / data gates
//                  ▲
//   optional extra grants (identity.permissionGrants)
//
// ABAC is optional. When a gate or evaluateAccess call supplies attribute
// conditions, they are AND-evaluated against principal attributes (and
// optionally resource attributes). No conditions ⇒ pure RBAC.
//
// Fail closed: unknown role / null role ⇒ empty permission set. Unknown
// permission strings never match. Missing attributes fail attribute ops.
//
// Compatibility: ROLE_CAPS booleans in auth.js stay the UI capability map;
// each capability maps to one or more permissions below. requireRoles()
// remains valid; new code should prefer requirePermission().

/* ---------- permission catalog ---------- */

/** @typedef {string} Permission */

/**
 * Canonical permission ids. Naming: `<surface>.<action>`.
 * Surfaces align with the product API and the legacy capability flags.
 */
export const PERMISSIONS = Object.freeze([
  // Aggregate dashboards / overview
  'dashboard.read',
  // Findings triage console
  'findings.read',
  'findings.write',
  // Per-engineer / pseudonymized user rows
  'users.read',
  'activity.read',
  // Fleet inventory
  'fleet.read',
  // Coverage gaps (analyst+; attacker's roadmap)
  'coverage.read',
  // Guardrail / policy config
  'guardrail.read',
  'guardrail.write',
  // Compliance evidence
  'compliance.read',
  'compliance.export',
  // Access-audit trail
  'audit.read',
  'audit.export',
  // Platform admin surfaces
  'admin.read',
  'admin.write',
  'admin.sessions',
  'admin.tokens',
  'admin.scim',
  // Operational product surfaces
  'cases.read',
  'cases.write',
  'enforcement.read',
  'enforcement.write',
  'mcp.read',
  'mcp.write',
  'policy_packs.read',
  'policy_packs.write',
  'shadow_ai.read',
  'governance.read',
  // Reveal grant (orthogonal to role; also listed so grants can add it)
  'reveal.use',
]);

export const PERMISSION_SET = Object.freeze(new Set(PERMISSIONS));

/** Map legacy capability flags → fine-grained permissions (for docs / UI). */
export const CAPABILITY_PERMISSIONS = Object.freeze({
  dashboard: Object.freeze(['dashboard.read']),
  findingsConsole: Object.freeze(['findings.read', 'findings.write']),
  userLevel: Object.freeze(['users.read', 'activity.read']),
  fleet: Object.freeze(['fleet.read']),
  guardrail: Object.freeze(['guardrail.read', 'guardrail.write']),
  compliance: Object.freeze(['compliance.read', 'compliance.export']),
  auditTrail: Object.freeze(['audit.read', 'audit.export']),
  admin: Object.freeze([
    'admin.read',
    'admin.write',
    'admin.sessions',
    'admin.tokens',
    'admin.scim',
    'policy_packs.read',
    'policy_packs.write',
    'enforcement.write',
  ]),
  coverage: Object.freeze(['coverage.read']),
  reveal: Object.freeze(['reveal.use']),
});

/* ---------- role → permission matrix ---------- */

const VIEWER_PERMS = Object.freeze([
  'dashboard.read',
  'compliance.read',
]);

const AUDITOR_PERMS = Object.freeze([
  ...VIEWER_PERMS,
  'compliance.export',
  'audit.read',
  'audit.export',
  'governance.read',
]);

const ANALYST_PERMS = Object.freeze([
  ...VIEWER_PERMS,
  'findings.read',
  'findings.write',
  'users.read',
  'activity.read',
  'fleet.read',
  'coverage.read',
  'compliance.export',
  'cases.read',
  'cases.write',
  'enforcement.read',
  'mcp.read',
  'mcp.write',
  'shadow_ai.read',
  'governance.read',
  'policy_packs.read',
]);

const ADMIN_PERMS = Object.freeze([
  ...ANALYST_PERMS,
  'guardrail.read',
  'guardrail.write',
  'audit.read',
  'audit.export',
  'admin.read',
  'admin.write',
  'admin.sessions',
  'admin.tokens',
  'admin.scim',
  'enforcement.write',
  'policy_packs.write',
]);

/**
 * Default role → permission matrix. Highest-privilege role is admin.
 * Roles are pure bundles; they never grant `reveal.use` (that is a separate
 * grant bit / IdP group, same as).
 */
export const ROLE_PERMISSIONS = Object.freeze({
  admin: ADMIN_PERMS,
  analyst: ANALYST_PERMS,
  auditor: AUDITOR_PERMS,
  viewer: VIEWER_PERMS,
});

/* ---------- ABAC attribute helpers ---------- */

/**
 * Normalize principal attributes from a session/identity.
 * Unknown keys are kept as-is (string or string[] only after coerce).
 *
 * @param {object|null|undefined} raw
 * @returns {Record<string, string|string[]|null>}
 */
export function normalizeAttributes(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  /** @type {Record<string, string|string[]|null>} */
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    const key = String(k).trim();
    if (!key) continue;
    if (v == null) {
      out[key] = null;
      continue;
    }
    if (Array.isArray(v)) {
      out[key] = v.map((x) => String(x).trim()).filter(Boolean);
      continue;
    }
    if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
      out[key] = String(v);
      continue;
    }
    // Drop nested objects — attributes are flat scalars or string lists.
  }
  return out;
}

/**
 * Build default principal attributes from identity fields already on session.
 * Groups become `teams` (IdP group names) so ABAC can scope by membership
 * without a second claim when operators have not configured attr claims.
 *
 * @param {{ groups?: string[], attributes?: object, email?: string, role?: string|null }} identity
 */
export function attributesFromIdentity(identity) {
  const base = normalizeAttributes(identity?.attributes);
  const groups = Array.isArray(identity?.groups) ? identity.groups.map(String) : [];
  if (base.teams == null && groups.length) {
    base.teams = groups;
  }
  if (base.email == null && identity?.email) {
    base.email = String(identity.email);
  }
  if (base.role == null && identity?.role != null) {
    base.role = String(identity.role);
  }
  return base;
}

/**
 * @typedef {object} AttrCondition
 * @property {string} attr                 Principal attribute name
 * @property {'eq'|'neq'|'in'|'contains'|'exists'|'resource_eq'} op
 * @property {string|string[]|boolean|number} [value]
 * @property {string} [resourceAttr]       For resource_eq: resource attribute name
 */

/**
 * Evaluate a single attribute condition.
 * Missing principal attributes fail closed (except op=exists with value false).
 *
 * @param {Record<string, string|string[]|null>} principal
 * @param {Record<string, string|string[]|null>} [resource]
 * @param {AttrCondition} condition
 * @returns {boolean}
 */
export function matchCondition(principal, resource, condition) {
  if (!condition || typeof condition !== 'object') return false;
  const attr = String(condition.attr || '').trim();
  if (!attr) return false;
  const op = condition.op || 'eq';
  const have = principal[attr];

  switch (op) {
    case 'exists': {
      const want = condition.value === undefined ? true : Boolean(condition.value);
      const exists = have != null && !(Array.isArray(have) && have.length === 0) && have !== '';
      return want ? exists : !exists;
    }
    case 'eq': {
      if (have == null) return false;
      const want = String(condition.value);
      if (Array.isArray(have)) return have.map(String).includes(want);
      return String(have) === want;
    }
    case 'neq': {
      if (have == null) return true; // null ≠ value
      const want = String(condition.value);
      if (Array.isArray(have)) return !have.map(String).includes(want);
      return String(have) !== want;
    }
    case 'in': {
      if (have == null) return false;
      const list = Array.isArray(condition.value)
        ? condition.value.map(String)
        : String(condition.value ?? '')
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean);
      if (!list.length) return false;
      if (Array.isArray(have)) return have.map(String).some((h) => list.includes(h));
      return list.includes(String(have));
    }
    case 'contains': {
      // Principal list/string contains the needle (team membership checks).
      if (have == null) return false;
      const needle = String(condition.value);
      if (Array.isArray(have)) return have.map(String).includes(needle);
      return String(have).includes(needle);
    }
    case 'resource_eq': {
      // Principal.attr must equal resource[resourceAttr || attr].
      if (!resource || typeof resource !== 'object') return false;
      const rKey = String(condition.resourceAttr || attr).trim();
      const rVal = resource[rKey];
      if (have == null || rVal == null) return false;
      const rList = Array.isArray(rVal) ? rVal.map(String) : [String(rVal)];
      if (Array.isArray(have)) return have.map(String).some((h) => rList.includes(h));
      return rList.includes(String(have));
    }
    default:
      return false;
  }
}

/**
 * Evaluate optional ABAC conditions. Empty / missing conditions always pass
 * (pure RBAC). allOf is AND; anyOf is OR. Both may be present (AND of the two
 * groups). Single condition object is treated as allOf:[condition].
 *
 * @param {Record<string, string|string[]|null>} principal
 * @param {object|null|undefined} conditions
 * @param {Record<string, string|string[]|null>} [resource]
 * @returns {{ ok: boolean, reason?: string }}
 */
export function matchAttributes(principal, conditions, resource = {}) {
  if (conditions == null || conditions === false) return { ok: true };
  if (conditions === true) return { ok: true };

  /** @type {AttrCondition[]} */
  let allOf = [];
  /** @type {AttrCondition[]} */
  let anyOf = [];

  if (Array.isArray(conditions)) {
    allOf = conditions;
  } else if (typeof conditions === 'object') {
    if (conditions.attr && conditions.op) {
      allOf = [/** @type {AttrCondition} */ (conditions)];
    } else {
      if (Array.isArray(conditions.allOf)) allOf = conditions.allOf;
      if (Array.isArray(conditions.anyOf)) anyOf = conditions.anyOf;
    }
  } else {
    return { ok: false, reason: 'invalid_conditions' };
  }

  for (const c of allOf) {
    if (!matchCondition(principal, resource, c)) {
      return { ok: false, reason: `attr_denied:${c.attr || '?'}:${c.op || '?'}` };
    }
  }
  if (anyOf.length) {
    const anyOk = anyOf.some((c) => matchCondition(principal, resource, c));
    if (!anyOk) {
      return { ok: false, reason: 'attr_denied:anyOf' };
    }
  }
  return { ok: true };
}

/* ---------- permission resolution ---------- */

/**
 * Resolve the effective permission set for an identity.
 *
 * @param {{ role?: string|null, reveal?: boolean, permissionGrants?: string[] }|null|undefined} identity
 * @returns {Set<string>}
 */
export function permissionsFor(identity) {
  const out = new Set();
  const role = identity?.role ?? null;
  const fromRole = role ? ROLE_PERMISSIONS[role] : null;
  if (fromRole) {
    for (const p of fromRole) out.add(p);
  }
  // Extra grants (future custom roles / break-glass permission overlays).
  const grants = identity?.permissionGrants;
  if (Array.isArray(grants)) {
    for (const g of grants) {
      const p = String(g);
      if (PERMISSION_SET.has(p)) out.add(p);
    }
  }
  // Reveal is a grant bit, not a role bundle.
  if (identity?.reveal) out.add('reveal.use');
  return out;
}

/**
 * Sorted permission list for /api/me and audits.
 * @param {object|null|undefined} identity
 * @returns {string[]}
 */
export function permissionList(identity) {
  return [...permissionsFor(identity)].sort();
}

/**
 * @param {object|null|undefined} identity
 * @param {string} permission
 * @returns {boolean}
 */
export function hasPermission(identity, permission) {
  if (!identity || !permission) return false;
  if (!PERMISSION_SET.has(permission)) return false;
  return permissionsFor(identity).has(permission);
}

/**
 * Full AuthZ decision: permission + optional ABAC conditions.
 *
 * @param {object} opts
 * @param {object|null|undefined} opts.identity
 * @param {string} opts.permission
 * @param {object|null|undefined} [opts.conditions]
 * @param {object|null|undefined} [opts.resource]
 * @returns {{ allow: boolean, reason: string, permissions?: string[] }}
 */
export function evaluateAccess({ identity, permission, conditions, resource } = {}) {
  if (!identity) {
    return { allow: false, reason: 'unauthenticated' };
  }
  if (!permission || !PERMISSION_SET.has(permission)) {
    return { allow: false, reason: 'unknown_permission' };
  }
  if (!hasPermission(identity, permission)) {
    return {
      allow: false,
      reason: 'missing_permission',
      permissions: permissionList(identity),
    };
  }
  const principal = attributesFromIdentity(identity);
  const resAttrs = normalizeAttributes(resource);
  const attr = matchAttributes(principal, conditions, resAttrs);
  if (!attr.ok) {
    return { allow: false, reason: attr.reason || 'attr_denied' };
  }
  return { allow: true, reason: 'allow' };
}

/**
 * Human-readable role × permission matrix (tests + docs generators).
 * @returns {Record<string, string[]>}
 */
export function rolePermissionMatrix() {
  /** @type {Record<string, string[]>} */
  const out = {};
  for (const [role, perms] of Object.entries(ROLE_PERMISSIONS)) {
    out[role] = [...perms].sort();
  }
  return out;
}

/**
 * Assert the matrix is internally consistent (used by unit tests).
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateMatrix() {
  const errors = [];
  for (const [role, perms] of Object.entries(ROLE_PERMISSIONS)) {
    for (const p of perms) {
      if (!PERMISSION_SET.has(p)) {
        errors.push(`role ${role} references unknown permission ${p}`);
      }
    }
    // Roles must not embed reveal — orthogonal grant.
    if (perms.includes('reveal.use')) {
      errors.push(`role ${role} must not include reveal.use`);
    }
  }
  // Admin should be a superset of analyst for the shared product surfaces
  // (except auditor-only audit trail which admin also has).
  const admin = new Set(ROLE_PERMISSIONS.admin);
  for (const p of ROLE_PERMISSIONS.analyst) {
    if (!admin.has(p)) errors.push(`admin missing analyst permission ${p}`);
  }
  for (const p of ROLE_PERMISSIONS.viewer) {
    if (!admin.has(p)) errors.push(`admin missing viewer permission ${p}`);
  }
  return { ok: errors.length === 0, errors };
}

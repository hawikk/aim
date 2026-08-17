// SCIM 2.0 User/Group provisioning surface (AIM-713).
//
// IdPs authenticate with AIM_SCIM_BEARER_TOKEN (Bearer). Routes are exempt
// from the SSO cookie hook; this module is the only gate on /scim/v2/*.
//
// Supported (enterprise-checklist):
//   GET  /scim/v2/ServiceProviderConfig|Schemas|ResourceTypes
//   CRUD Users  (POST/GET/PATCH/DELETE + filter userName eq)
//   CRUD Groups (POST/GET/PATCH/DELETE + filter displayName eq)
//
// Deactivate sets active=false and is enforced on every SSO request via
// scim-store (immediate mid-session deny for provisioned leavers).

import { timingSafeEqual } from 'node:crypto';
import { audit } from '../audit.js';
import * as defaultDb from '../db.js';
import {
  ScimConflictError,
  ScimNotFoundError,
  ScimValidationError,
  deleteGroupRow,
  hashScimToken,
  normalizeEmail,
  persistGroup,
  persistGroupMembers,
  persistUser,
  scimDirectory,
} from '../scim-store.js';

const SCIM_USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const SCIM_GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const SCIM_LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const SCIM_ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';
const SCIM_PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

function scimEnabled() {
  const token = process.env.AIM_SCIM_BEARER_TOKEN;
  return Boolean(token && String(token).length >= 16);
}

function configuredTokenHash() {
  const token = process.env.AIM_SCIM_BEARER_TOKEN;
  if (!token || String(token).length < 16) return null;
  return hashScimToken(token);
}

function bearerFrom(authorization) {
  if (!authorization) return null;
  const [scheme, ...rest] = String(authorization).split(' ');
  if (scheme.toLowerCase() !== 'bearer') return null;
  const token = rest.join(' ').trim();
  return token || null;
}

function scimError(reply, status, detail, scimType = null) {
  const body = {
    schemas: [SCIM_ERROR_SCHEMA],
    status: String(status),
    detail,
  };
  if (scimType) body.scimType = scimType;
  return reply.code(status).type('application/scim+json').send(body);
}

function requireScimAuth(req, reply) {
  if (!scimEnabled()) {
    return scimError(reply, 503, 'SCIM is not configured (set AIM_SCIM_BEARER_TOKEN, min 16 chars)');
  }
  const raw = bearerFrom(req.headers.authorization);
  if (!raw) {
    return scimError(reply, 401, 'SCIM bearer token required', 'invalidCredentials');
  }
  const expected = configuredTokenHash();
  const got = hashScimToken(raw);
  // timingSafeEqual requires equal length buffers; hashScimToken always returns 64 hex chars.
  const ok =
    expected &&
    got.length === expected.length &&
    timingSafeEqual(Buffer.from(got, 'utf8'), Buffer.from(expected, 'utf8'));
  if (!ok) {
    audit('scim', 'authz.deny', req.url.split('?')[0], { reason: 'invalid_scim_token' });
    return scimError(reply, 401, 'Invalid SCIM bearer token', 'invalidCredentials');
  }
  return null;
}

function extractEmail(payload) {
  const userName = normalizeEmail(payload?.userName);
  if (userName) return userName;
  for (const item of payload?.emails || []) {
    if (item && typeof item === 'object') {
      const value = normalizeEmail(item.value);
      if (value) return value;
    }
  }
  throw new ScimValidationError('SCIM userName or email is required');
}

function extractName(payload) {
  const name = payload?.name;
  if (name && typeof name === 'object') {
    if (name.formatted) return String(name.formatted);
    const parts = [name.givenName, name.familyName].filter(Boolean);
    if (parts.length) return parts.map(String).join(' ');
  }
  if (payload?.displayName) return String(payload.displayName);
  return null;
}

function extractActive(payload, defaultActive = true) {
  if (payload == null || !Object.prototype.hasOwnProperty.call(payload, 'active')) {
    return defaultActive;
  }
  if (typeof payload.active !== 'boolean') {
    throw new ScimValidationError('SCIM active must be a boolean');
  }
  return payload.active;
}

function memberUserIds(payload) {
  const members = payload?.members;
  if (members == null) return null;
  if (!Array.isArray(members)) {
    throw new ScimValidationError('SCIM group members must be a list');
  }
  return members.map((m) => {
    if (!m || typeof m !== 'object' || !m.value) {
      throw new ScimValidationError('SCIM group member value is required');
    }
    return String(m.value);
  });
}

function scimUser(user) {
  const body = {
    schemas: [SCIM_USER_SCHEMA],
    id: user.id,
    userName: user.userName,
    active: Boolean(user.active),
    name: { formatted: user.displayName || '' },
    emails: [{ value: user.userName, primary: true, type: 'work' }],
    meta: {
      resourceType: 'User',
      created: user.createdAt,
      lastModified: user.updatedAt,
    },
  };
  if (user.externalId) body.externalId = user.externalId;
  if (user.displayName) body.displayName = user.displayName;
  return body;
}

function scimGroup(group, directory) {
  const members = (group.memberIds || []).map((uid) => {
    const u = directory.getUser(uid);
    return {
      value: uid,
      display: u?.userName ?? uid,
      $ref: `../Users/${uid}`,
    };
  });
  const body = {
    schemas: [SCIM_GROUP_SCHEMA],
    id: group.id,
    displayName: group.displayName,
    members,
    meta: {
      resourceType: 'Group',
      created: group.createdAt,
      lastModified: group.updatedAt,
    },
  };
  if (group.externalId) body.externalId = group.externalId;
  return body;
}

function listResponse(resources) {
  return {
    schemas: [SCIM_LIST_SCHEMA],
    totalResults: resources.length,
    startIndex: 1,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}

function parseFilterEq(filter, attribute) {
  if (!filter) return null;
  // userName eq "x" / displayName eq "x"  (SCIM filter, double-quoted)
  const re = new RegExp(`^${attribute}\\s+eq\\s+"(.*)"$`, 'i');
  const m = String(filter).trim().match(re);
  if (!m) {
    throw new ScimValidationError(`Only ${attribute} eq filters are supported`);
  }
  return m[1];
}

function handleStoreError(reply, err) {
  if (
    err instanceof ScimValidationError ||
    err instanceof ScimConflictError ||
    err instanceof ScimNotFoundError
  ) {
    const scimType =
      err instanceof ScimConflictError
        ? 'uniqueness'
        : err instanceof ScimNotFoundError
          ? null
          : 'invalidValue';
    return scimError(reply, err.statusCode, err.message, scimType);
  }
  throw err;
}

/**
 * @param {import('fastify').FastifyInstance} fastify
 * @param {{ db?: typeof defaultDb, directory?: typeof scimDirectory }} [opts]
 */
export async function scimRoutes(fastify, opts = {}) {
  const db = opts.db ?? defaultDb;
  const directory = opts.directory ?? scimDirectory;

  const send = (reply, code, body) =>
    reply.code(code).type('application/scim+json').send(body);

  // ---------- discovery (auth still required when SCIM enabled) ----------

  fastify.get('/scim/v2/ServiceProviderConfig', async (req, reply) => {
    const denied = requireScimAuth(req, reply);
    if (denied) return denied;
    return send(reply, 200, {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
      documentationUri: 'https://github.com/hawikk/aim',
      patch: { supported: true },
      bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
      filter: { supported: true, maxResults: 200 },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
      authenticationSchemes: [
        {
          type: 'oauthbearertoken',
          name: 'OAuth Bearer Token',
          description: 'Authentication using AIM_SCIM_BEARER_TOKEN as Bearer.',
          specUri: 'https://www.rfc-editor.org/rfc/rfc6750.html',
          primary: true,
        },
      ],
    });
  });

  fastify.get('/scim/v2/ResourceTypes', async (req, reply) => {
    const denied = requireScimAuth(req, reply);
    if (denied) return denied;
    return send(reply, 200, listResponse([
      {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
        id: 'User',
        name: 'User',
        endpoint: '/scim/v2/Users',
        schema: SCIM_USER_SCHEMA,
      },
      {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
        id: 'Group',
        name: 'Group',
        endpoint: '/scim/v2/Groups',
        schema: SCIM_GROUP_SCHEMA,
      },
    ]));
  });

  fastify.get('/scim/v2/Schemas', async (req, reply) => {
    const denied = requireScimAuth(req, reply);
    if (denied) return denied;
    return send(reply, 200, listResponse([
      { id: SCIM_USER_SCHEMA, name: 'User', description: 'User Account' },
      { id: SCIM_GROUP_SCHEMA, name: 'Group', description: 'Group' },
    ]));
  });

  // ---------- Users ----------

  fastify.post('/scim/v2/Users', async (req, reply) => {
    const denied = requireScimAuth(req, reply);
    if (denied) return denied;
    try {
      const payload = req.body || {};
      const user = directory.upsertUser({
        userName: extractEmail(payload),
        externalId: payload.externalId ?? null,
        displayName: extractName(payload),
        active: extractActive(payload, true),
      });
      try {
        await persistUser(db, user);
      } catch (err) {
        req.log?.warn?.({ err: err.message }, 'SCIM user persist failed (memory only)');
      }
      audit('scim', 'identity.user_provisioned', `scim/Users/${user.id}`, {
        email: user.userName,
        active: user.active,
        externalId: user.externalId,
      });
      return send(reply, 201, scimUser(user));
    } catch (err) {
      return handleStoreError(reply, err);
    }
  });

  fastify.get('/scim/v2/Users', async (req, reply) => {
    const denied = requireScimAuth(req, reply);
    if (denied) return denied;
    try {
      const filterUserName = parseFilterEq(req.query?.filter, 'userName');
      const users = directory.listUsers({ filterUserName });
      return send(reply, 200, listResponse(users.map(scimUser)));
    } catch (err) {
      return handleStoreError(reply, err);
    }
  });

  fastify.get('/scim/v2/Users/:id', async (req, reply) => {
    const denied = requireScimAuth(req, reply);
    if (denied) return denied;
    const user = directory.getUser(req.params.id);
    if (!user) return scimError(reply, 404, 'SCIM user not found');
    return send(reply, 200, scimUser(user));
  });

  fastify.put('/scim/v2/Users/:id', async (req, reply) => {
    const denied = requireScimAuth(req, reply);
    if (denied) return denied;
    try {
      const existing = directory.getUser(req.params.id);
      if (!existing) return scimError(reply, 404, 'SCIM user not found');
      const payload = req.body || {};
      const user = directory.upsertUser({
        id: existing.id,
        userName: extractEmail(payload),
        externalId: payload.externalId ?? existing.externalId,
        displayName: extractName(payload) ?? existing.displayName,
        active: extractActive(payload, existing.active),
      });
      // Ensure id stable if upsert rebounded by email/externalId
      if (user.id !== existing.id) {
        throw new ScimConflictError('PUT would rebind to a different SCIM user');
      }
      try {
        await persistUser(db, user);
      } catch (err) {
        req.log?.warn?.({ err: err.message }, 'SCIM user persist failed (memory only)');
      }
      audit('scim', 'identity.user_updated', `scim/Users/${user.id}`, {
        email: user.userName,
        active: user.active,
      });
      return send(reply, 200, scimUser(user));
    } catch (err) {
      return handleStoreError(reply, err);
    }
  });

  fastify.patch('/scim/v2/Users/:id', async (req, reply) => {
    const denied = requireScimAuth(req, reply);
    if (denied) return denied;
    try {
      let user = directory.getUser(req.params.id);
      if (!user) return scimError(reply, 404, 'SCIM user not found');
      const payload = req.body || {};
      const operations = payload.Operations || payload.operations || [];
      if (!Array.isArray(operations) || operations.length === 0) {
        throw new ScimValidationError('SCIM PatchOp operations are required');
      }
      // schemas optional; accept missing for IdP quirks
      if (payload.schemas && !payload.schemas.includes(SCIM_PATCH_SCHEMA)) {
        // tolerate non-standard clients
      }
      for (const operation of operations) {
        if (!operation || typeof operation !== 'object') {
          throw new ScimValidationError('Invalid SCIM PatchOp operation');
        }
        const op = String(operation.op || 'replace').toLowerCase();
        if (op !== 'replace' && op !== 'add') {
          throw new ScimValidationError('Only replace/add PatchOp is supported for Users');
        }
        const path = operation.path;
        let active;
        if (path === 'active') {
          active = operation.value;
        } else if (operation.value && typeof operation.value === 'object' && 'active' in operation.value) {
          active = operation.value.active;
        } else if (path == null && typeof operation.value === 'boolean') {
          // Some IdPs send bare boolean value; not a supported active path form.
          throw new ScimValidationError('Only active PatchOp is supported for Users');
        } else {
          throw new ScimValidationError('Only active PatchOp is supported for Users');
        }
        if (typeof active !== 'boolean') {
          throw new ScimValidationError('SCIM active must be a boolean');
        }
        user = directory.setUserActive(user.id, active);
        if (!active) {
          audit('scim', 'identity.user_deprovisioned', `scim/Users/${user.id}`, {
            email: user.userName,
            via: 'patch_active_false',
          });
        } else {
          audit('scim', 'identity.user_provisioned', `scim/Users/${user.id}`, {
            email: user.userName,
            via: 'patch_active_true',
          });
        }
      }
      try {
        await persistUser(db, user);
      } catch (err) {
        req.log?.warn?.({ err: err.message }, 'SCIM user persist failed (memory only)');
      }
      return send(reply, 200, scimUser(user));
    } catch (err) {
      return handleStoreError(reply, err);
    }
  });

  fastify.delete('/scim/v2/Users/:id', async (req, reply) => {
    const denied = requireScimAuth(req, reply);
    if (denied) return denied;
    const user = directory.deprovisionUser(req.params.id);
    if (!user) return scimError(reply, 404, 'SCIM user not found');
    try {
      await persistUser(db, user);
    } catch (err) {
      req.log?.warn?.({ err: err.message }, 'SCIM user persist failed (memory only)');
    }
    audit('scim', 'identity.user_deprovisioned', `scim/Users/${user.id}`, {
      email: user.userName,
      via: 'delete',
    });
    return reply.code(204).send();
  });

  // ---------- Groups ----------

  fastify.post('/scim/v2/Groups', async (req, reply) => {
    const denied = requireScimAuth(req, reply);
    if (denied) return denied;
    try {
      const payload = req.body || {};
      const group = directory.upsertGroup({
        displayName: payload.displayName,
        externalId: payload.externalId ?? null,
        memberIds: memberUserIds(payload) ?? [],
        active: true,
      });
      try {
        await persistGroup(db, group);
        await persistGroupMembers(db, group.id, group.memberIds);
      } catch (err) {
        req.log?.warn?.({ err: err.message }, 'SCIM group persist failed (memory only)');
      }
      audit('scim', 'identity.group_upserted', `scim/Groups/${group.id}`, {
        displayName: group.displayName,
        memberCount: group.memberIds.length,
      });
      return send(reply, 201, scimGroup(group, directory));
    } catch (err) {
      return handleStoreError(reply, err);
    }
  });

  fastify.get('/scim/v2/Groups', async (req, reply) => {
    const denied = requireScimAuth(req, reply);
    if (denied) return denied;
    try {
      const filterDisplayName = parseFilterEq(req.query?.filter, 'displayName');
      const groups = directory.listGroups({ filterDisplayName });
      return send(reply, 200, listResponse(groups.map((g) => scimGroup(g, directory))));
    } catch (err) {
      return handleStoreError(reply, err);
    }
  });

  fastify.get('/scim/v2/Groups/:id', async (req, reply) => {
    const denied = requireScimAuth(req, reply);
    if (denied) return denied;
    const group = directory.getGroup(req.params.id);
    if (!group) return scimError(reply, 404, 'SCIM group not found');
    return send(reply, 200, scimGroup(group, directory));
  });

  fastify.patch('/scim/v2/Groups/:id', async (req, reply) => {
    const denied = requireScimAuth(req, reply);
    if (denied) return denied;
    try {
      let group = directory.getGroup(req.params.id);
      if (!group) return scimError(reply, 404, 'SCIM group not found');
      const payload = req.body || {};
      const operations = payload.Operations || payload.operations || [];
      if (!Array.isArray(operations) || operations.length === 0) {
        throw new ScimValidationError('SCIM PatchOp operations are required');
      }
      for (const operation of operations) {
        if (!operation || typeof operation !== 'object') {
          throw new ScimValidationError('Invalid SCIM PatchOp operation');
        }
        const op = String(operation.op || 'replace').toLowerCase();
        if (op !== 'replace' && op !== 'add') {
          throw new ScimValidationError('Only replace/add PatchOp is supported for Groups');
        }
        const path = operation.path;
        if (path === 'displayName') {
          group = directory.setGroupDisplayName(group.id, operation.value);
        } else if (path === 'members' || (path == null && Array.isArray(operation.value))) {
          const ids = memberUserIds({ members: operation.value });
          group = directory.replaceGroupMembers(group.id, ids);
        } else if (
          operation.value &&
          typeof operation.value === 'object' &&
          !Array.isArray(operation.value)
        ) {
          if ('displayName' in operation.value) {
            group = directory.setGroupDisplayName(group.id, operation.value.displayName);
          }
          if ('members' in operation.value) {
            const ids = memberUserIds({ members: operation.value.members });
            group = directory.replaceGroupMembers(group.id, ids);
          }
        } else {
          throw new ScimValidationError('Only displayName and members PatchOp are supported');
        }
      }
      try {
        await persistGroup(db, group);
        await persistGroupMembers(db, group.id, group.memberIds);
      } catch (err) {
        req.log?.warn?.({ err: err.message }, 'SCIM group persist failed (memory only)');
      }
      audit('scim', 'identity.group_upserted', `scim/Groups/${group.id}`, {
        displayName: group.displayName,
        memberCount: group.memberIds.length,
        via: 'patch',
      });
      return send(reply, 200, scimGroup(group, directory));
    } catch (err) {
      return handleStoreError(reply, err);
    }
  });

  fastify.delete('/scim/v2/Groups/:id', async (req, reply) => {
    const denied = requireScimAuth(req, reply);
    if (denied) return denied;
    const group = directory.deleteGroup(req.params.id);
    if (!group) return scimError(reply, 404, 'SCIM group not found');
    try {
      await deleteGroupRow(db, group.id);
    } catch (err) {
      req.log?.warn?.({ err: err.message }, 'SCIM group delete persist failed (memory only)');
    }
    audit('scim', 'identity.group_deleted', `scim/Groups/${group.id}`, {
      displayName: group.displayName,
      memberCount: group.memberIds.length,
    });
    return reply.code(204).send();
  });
}

/** Test seam: is SCIM surface configured from env. */
export function isScimConfigured() {
  return scimEnabled();
}

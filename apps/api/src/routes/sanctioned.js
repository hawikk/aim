// Sanctioned-tool management API.
//
// Read: any authenticated dashboard role (same as /api/overview).
// Mutate: admin only (Authelia group → role map in auth.js). No new token
// scopes; service tokens cannot hold admin (servicetoken.js).
//
// Every mutation is audit-logged with:
//   * actor identity from the verified session (req.identity.email) —
// never a forgeable header (lesson)
//   * action (sanctioned.sanction | sanctioned.unsanction | sanctioned.note)
//   * before/after tool lists, reason text, optional note
//
// Downstream coverage / unapproved / activity-score read the live list via
// sanctioned.js — mutations refresh the in-process cache so no restart is
// required on this instance.

import { query } from '../db.js';
import { requireRoles } from '../auth.js';
import { audit } from '../audit.js';
import {
  listSanctionedTools,
  normalizeToolName,
  normalizeReason,
  normalizeNote,
  sanctionTool,
  unsanctionTool,
  setSanctionedNote,
} from '../sanctioned.js';

function actorEmail(req) {
  // Verified session only. Never fall back to a client-supplied header.
  return req.identity?.email ?? null;
}

export async function sanctionedRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const anyRole = requireRoles('admin', 'analyst', 'auditor', 'viewer');
  const adminOnly = requireRoles('admin');

  // ---- List (read stays as today — any dashboard role) ----
  fastify.get('/api/sanctioned', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const tools = await listSanctionedTools(db);
    return {
      tools,
      // Display labels for the static-hint replacement in the Security tab.
      labels: tools.map((t) => displayLabel(t.tool)),
      note:
        'Fleet sanctioned-tool allow-list. Mutations require admin. ' +
        'Changes take effect immediately for coverage, unapproved discovery, and activity scoring.',
    };
  });

  // ---- Sanction (admin) ----
  // POST /api/sanctioned  { tool, reason, note? }
  fastify.post('/api/sanctioned', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const actor = actorEmail(req);
    if (!actor) {
      // Fail closed: mutation without a verified actor must never succeed.
      return reply.code(401).send({
        error: 'unauthenticated',
        detail: 'verified session required for sanctioned-tool mutations',
      });
    }

    const body = req.body ?? {};
    const tool = normalizeToolName(body.tool);
    if (!tool) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'tool is required (1..128 chars, alphanumerics and ._+-)',
      });
    }
    const reasonR = normalizeReason(body.reason, { required: true });
    if (reasonR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: reasonR.error });
    }
    const noteR = normalizeNote(body.note);
    if (noteR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: noteR.error });
    }

    let result;
    try {
      result = await sanctionTool(db, {
        tool,
        actor,
        note: noteR.value,
        reason: reasonR.value,
      });
    } catch (err) {
      if (String(err?.message || err).includes('sanctioned_tools')) {
        return reply.code(503).send({
          error: 'unavailable',
          detail: 'sanctioned_tools table missing — apply migration 022',
        });
      }
      throw err;
    }

    audit(actor, 'sanctioned.sanction', `sanctioned/${tool}`, {
      tool,
      reason: reasonR.value,
      note: noteR.value,
      before: result.before,
      after: result.after,
      status: result.status,
    });

    const code = result.status === 'already_sanctioned' ? 200 : 201;
    return reply.code(code).send({
      status: result.status,
      tool: result.row,
      before: result.before,
      after: result.after,
      reason: reasonR.value,
    });
  });

  // ---- Unsanction (admin) ----
  // DELETE /api/sanctioned/:tool  body { reason }
  // Also accepts POST /api/sanctioned/:tool/unsanction for clients that
  // cannot send a DELETE body (some browsers/proxies strip it).
  async function handleUnsanction(req, reply) {
    if (!adminOnly(req, reply)) return reply;
    const actor = actorEmail(req);
    if (!actor) {
      return reply.code(401).send({
        error: 'unauthenticated',
        detail: 'verified session required for sanctioned-tool mutations',
      });
    }

    const tool = normalizeToolName(req.params.tool);
    if (!tool) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'tool path parameter is invalid',
      });
    }
    const body = req.body ?? {};
    const reasonR = normalizeReason(body.reason, { required: true });
    if (reasonR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: reasonR.error });
    }

    let result;
    try {
      result = await unsanctionTool(db, {
        tool,
        actor,
        reason: reasonR.value,
      });
    } catch (err) {
      if (String(err?.message || err).includes('sanctioned_tools')) {
        return reply.code(503).send({
          error: 'unavailable',
          detail: 'sanctioned_tools table missing — apply migration 022',
        });
      }
      throw err;
    }

    if (result.status === 'not_sanctioned') {
      return reply.code(404).send({
        error: 'not_found',
        detail: `${tool} is not on the sanctioned list`,
        before: result.before,
        after: result.after,
      });
    }

    audit(actor, 'sanctioned.unsanction', `sanctioned/${tool}`, {
      tool,
      reason: reasonR.value,
      before: result.before,
      after: result.after,
      status: result.status,
      removed: result.row,
    });

    return {
      status: result.status,
      tool: result.row,
      before: result.before,
      after: result.after,
      reason: reasonR.value,
    };
  }

  fastify.delete('/api/sanctioned/:tool', handleUnsanction);
  fastify.post('/api/sanctioned/:tool/unsanction', handleUnsanction);

  // ---- Update note (admin) ----
  // PATCH /api/sanctioned/:tool  { note, reason }
  fastify.patch('/api/sanctioned/:tool', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const actor = actorEmail(req);
    if (!actor) {
      return reply.code(401).send({
        error: 'unauthenticated',
        detail: 'verified session required for sanctioned-tool mutations',
      });
    }

    const tool = normalizeToolName(req.params.tool);
    if (!tool) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'tool path parameter is invalid',
      });
    }
    const body = req.body ?? {};
    if (!Object.prototype.hasOwnProperty.call(body, 'note')) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'note is required (string or null)',
      });
    }
    const noteR = normalizeNote(body.note);
    if (noteR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: noteR.error });
    }
    const reasonR = normalizeReason(body.reason, { required: true });
    if (reasonR.error) {
      return reply.code(400).send({ error: 'bad_request', detail: reasonR.error });
    }

    let result;
    try {
      result = await setSanctionedNote(db, {
        tool,
        actor,
        note: noteR.value,
        reason: reasonR.value,
      });
    } catch (err) {
      if (String(err?.message || err).includes('sanctioned_tools')) {
        return reply.code(503).send({
          error: 'unavailable',
          detail: 'sanctioned_tools table missing — apply migration 022',
        });
      }
      throw err;
    }

    if (result.status === 'not_sanctioned') {
      return reply.code(404).send({
        error: 'not_found',
        detail: `${tool} is not on the sanctioned list`,
      });
    }

    audit(actor, 'sanctioned.note', `sanctioned/${tool}`, {
      tool,
      reason: reasonR.value,
      note: noteR.value,
      before: result.before,
      after: result.after,
      status: result.status,
    });

    return {
      status: result.status,
      tool: result.row,
      before: result.before,
      after: result.after,
      reason: reasonR.value,
    };
  });
}

/** Human label for UI hints — snake_case → Title Case with known overrides. */
function displayLabel(tool) {
  const known = {
    claude_code: 'Claude Code',
    cursor: 'Cursor',
    kilo_code: 'Kilo Code',
    kimi_code: 'Kimi Code',
    grok_build: 'Grok Build',
  };
  if (known[tool]) return known[tool];
  return String(tool)
    .split(/[_-]+/)
    .map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w))
    .join(' ');
}

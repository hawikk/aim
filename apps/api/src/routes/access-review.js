// Access review / attestation workflow for AIM roles (AIM-718).
//
// Compliance UX + API:
//   GET  /api/access-review/roster              live role holders (JSON or CSV)
//   GET  /api/access-review/campaigns           past reviews
//   POST /api/access-review/campaigns           open a review (snapshot roster)
//   GET  /api/access-review/campaigns/:id       campaign detail (+ CSV export)
//   POST /api/access-review/campaigns/:id/attest seal with statement
//
// Gates:
//   read  — admin, auditor (who custodes the role list)
//   write (open campaign, attest) — admin or auditor
// Analyst/viewer never see this surface (not a day-to-day triage tool).

import { requireRoles } from '../auth.js';
import { audit } from '../audit.js';
import { wantsCsv, checkFormat, toCsv } from '../csv.js';
import { scimDirectory } from '../scim-store.js';
import { isScimConfigured } from './scim.js';
import { buildAccessRoster } from '../access-review-roster.js';
import {
  accessReviewStore,
  persistCampaign,
  hashRoster,
} from '../access-review-store.js';
import * as defaultDb from '../db.js';

const ROSTER_COLS = [
  { key: 'email', label: 'email' },
  { key: 'displayName', label: 'display_name' },
  { key: 'role', label: 'role' },
  { key: 'reveal', label: 'reveal' },
  { key: 'active', label: 'active' },
  { key: 'groups', label: 'groups' },
  { key: 'source', label: 'source' },
];

function scimOn() {
  return isScimConfigured();
}

function publicCampaign(c) {
  if (!c) return null;
  return {
    id: c.id,
    createdAt: c.createdAt,
    status: c.status,
    periodLabel: c.periodLabel,
    notes: c.notes,
    createdBy: c.createdBy,
    principalCount: c.principalCount,
    rosterHash: c.rosterHash,
    attestedAt: c.attestedAt,
    attestedBy: c.attestedBy,
    statement: c.statement,
    summary: c.roster?.summary ?? null,
  };
}

/**
 * @param {import('fastify').FastifyInstance} fastify
 * @param {{
 *   store?: import('../access-review-store.js').AccessReviewStore,
 *   directory?: typeof scimDirectory,
 *   appendAudit?: typeof audit,
 *   persist?: ((campaign: any) => Promise<void>) | null,
 *   db?: { query: Function },
 *   scimEnabled?: () => boolean,
 * }} opts
 */
export async function accessReviewRoutes(fastify, opts = {}) {
  const store = opts.store ?? accessReviewStore;
  const directory = opts.directory ?? scimDirectory;
  const appendAudit = opts.appendAudit ?? audit;
  const db = opts.db ?? defaultDb;
  const persist = opts.persist === undefined
    ? (campaign) => persistCampaign(db, campaign)
    : opts.persist;
  const scimEnabledFn = opts.scimEnabled ?? scimOn;
  // admin + auditor: compliance ownership of "who has privileged access".
  const reviewers = requireRoles('admin', 'auditor');

  function liveRoster() {
    return buildAccessRoster({
      directory,
      scimEnabled: scimEnabledFn(),
      scimEnforce: process.env.AIM_SCIM_ENFORCE === '1',
    });
  }

  function sendRosterCsv(reply, roster, filename) {
    const rows = (roster.principals ?? []).map((p) => ({
      email: p.email,
      displayName: p.displayName ?? '',
      role: p.role ?? '',
      reveal: p.reveal ? 'true' : 'false',
      active: p.active ? 'true' : 'false',
      groups: (p.groups ?? []).join(';'),
      source: p.source,
    }));
    const meta = [
      `# access-review roster generatedAt=${roster.generatedAt}`,
      `# source=${roster.source} scimEnabled=${roster.scimEnabled}`,
      `# rosterHash=${hashRoster(roster)}`,
      `# totalPrincipals=${roster.summary?.totalPrincipals ?? 0}`,
      `# note=${String(roster.note ?? '').replace(/[\r\n]+/g, ' ')}`,
    ].join('\r\n');
    const body = `${meta}\r\n${toCsv(ROSTER_COLS, rows)}`;
    const safe = String(filename).replace(/[^A-Za-z0-9._-]/g, '_');
    return reply
      .header('content-type', 'text/csv; charset=utf-8')
      .header('content-disposition', `attachment; filename="${safe}"`)
      .send(body);
  }

  /* ---------- live roster ---------- */

  fastify.get('/api/access-review/roster', async (req, reply) => {
    if (!reviewers(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;

    const roster = liveRoster();
    appendAudit(
      req.identity?.email ?? 'unknown',
      'access_review.roster_read',
      'access-review/roster',
      {
        source: roster.source,
        totalPrincipals: roster.summary.totalPrincipals,
        format: wantsCsv(req) ? 'csv' : 'json',
      },
    );

    if (wantsCsv(req)) {
      return sendRosterCsv(reply, roster, `aim-access-review-roster-${roster.generatedAt.slice(0, 10)}.csv`);
    }
    return {
      ...roster,
      rosterHash: hashRoster(roster),
    };
  });

  /* ---------- campaigns ---------- */

  fastify.get('/api/access-review/campaigns', async (req, reply) => {
    if (!reviewers(req, reply)) return reply;
    const limit = Number(req.query?.limit) || 50;
    const items = store.list({ limit }).map(publicCampaign);
    return { items, total: items.length };
  });

  fastify.post('/api/access-review/campaigns', async (req, reply) => {
    if (!reviewers(req, reply)) return reply;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const roster = liveRoster();
    const campaign = store.createCampaign({
      periodLabel: body.periodLabel ?? body.period_label ?? null,
      notes: body.notes ?? null,
      createdBy: req.identity?.email ?? 'unknown',
      roster,
    });
    if (persist) {
      try {
        await persist(campaign);
      } catch (err) {
        // Non-fatal: in-memory store remains authoritative for this process.
        req.log?.warn?.({ err }, 'access-review campaign persist failed');
      }
    }
    appendAudit(
      req.identity?.email ?? 'unknown',
      'access_review.campaign_opened',
      `access-review/campaigns/${campaign.id}`,
      {
        principalCount: campaign.principalCount,
        rosterHash: campaign.rosterHash,
        periodLabel: campaign.periodLabel,
      },
    );
    reply.code(201);
    return {
      ...publicCampaign(campaign),
      roster: campaign.roster,
    };
  });

  fastify.get('/api/access-review/campaigns/:id', async (req, reply) => {
    if (!reviewers(req, reply)) return reply;
    if (!checkFormat(req, reply)) return reply;
    const campaign = store.get(req.params.id);
    if (!campaign) {
      return reply.code(404).send({ error: 'not_found', detail: 'campaign not found' });
    }
    if (wantsCsv(req)) {
      return sendRosterCsv(
        reply,
        campaign.roster,
        `aim-access-review-${campaign.id.slice(0, 8)}.csv`,
      );
    }
    return {
      ...publicCampaign(campaign),
      roster: campaign.roster,
    };
  });

  fastify.post('/api/access-review/campaigns/:id/attest', async (req, reply) => {
    if (!reviewers(req, reply)) return reply;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    let campaign;
    try {
      campaign = store.attest(req.params.id, {
        attestedBy: req.identity?.email ?? 'unknown',
        statement: body.statement,
      });
    } catch (err) {
      const code = err.statusCode || 500;
      return reply.code(code).send({
        error: code === 404 ? 'not_found' : code === 409 ? 'conflict' : 'bad_request',
        detail: err.message,
      });
    }
    if (persist) {
      try {
        await persist(campaign);
      } catch (err) {
        req.log?.warn?.({ err }, 'access-review attest persist failed');
      }
    }
    appendAudit(
      req.identity?.email ?? 'unknown',
      'access_review.attested',
      `access-review/campaigns/${campaign.id}`,
      {
        principalCount: campaign.principalCount,
        rosterHash: campaign.rosterHash,
        statementLen: (campaign.statement ?? '').length,
      },
    );
    return {
      ...publicCampaign(campaign),
      roster: campaign.roster,
    };
  });
}

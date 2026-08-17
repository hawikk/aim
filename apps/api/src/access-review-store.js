// Access review campaign store.
//
// Compliance operators periodically review who holds AIM roles (admin /
// analyst / auditor / viewer) and the orthogonal reveal grant, export the
// roster, and attest that the review completed.
//
// Process-local Map is the request-path source of truth (sync, no DB
// round-trip). Optional Postgres write-through survives process restart.
// Tests inject a pure memory store without Postgres.

import { createHash, randomUUID } from 'node:crypto';

/**
 * @typedef {{
 *   email: string,
 *   displayName: string|null,
 *   role: 'admin'|'analyst'|'auditor'|'viewer'|null,
 *   reveal: boolean,
 *   active: boolean,
 *   groups: string[],
 *   source: string,
 * }} AccessPrincipal
 *
 * @typedef {{
 *   generatedAt: string,
 *   source: 'scim'|'config_only',
 *   scimEnabled: boolean,
 *   scimEnforce: boolean,
 *   roleGroups: Record<string, string[]>,
 *   revealGroups: string[],
 *   summary: {
 *     totalPrincipals: number,
 *     activePrincipals: number,
 *     inactivePrincipals: number,
 *     byRole: Record<string, number>,
 *     withReveal: number,
 *     unmapped: number,
 *   },
 *   principals: AccessPrincipal[],
 *   note: string,
 * }} AccessRoster
 *
 * @typedef {{
 *   id: string,
 *   createdAt: string,
 *   status: 'open'|'attested'|'cancelled',
 *   periodLabel: string|null,
 *   notes: string|null,
 *   createdBy: string,
 *   roster: AccessRoster,
 *   principalCount: number,
 *   rosterHash: string,
 *   attestedAt: string|null,
 *   attestedBy: string|null,
 *   statement: string|null,
 * }} AccessReviewCampaign
 */

export function hashRoster(roster) {
  // Stable content hash over the principal list + role config — attestation
  // seals against this so a later mutation of the live directory cannot claim
  // the signed review covered a different population.
  const payload = {
    principals: (roster?.principals ?? []).map((p) => ({
      email: p.email,
      role: p.role,
      reveal: Boolean(p.reveal),
      active: Boolean(p.active),
      groups: [...(p.groups ?? [])].sort(),
    })),
    roleGroups: roster?.roleGroups ?? {},
    revealGroups: [...(roster?.revealGroups ?? [])].sort(),
  };
  return createHash('sha256').update(JSON.stringify(payload), 'utf8').digest('hex');
}

function nowIso() {
  return new Date().toISOString();
}

export class AccessReviewStore {
  constructor() {
    /** @type {Map<string, AccessReviewCampaign>} */
    this.campaigns = new Map();
  }

  clear() {
    this.campaigns.clear();
  }

  /**
   * @param {{ periodLabel?: string|null, notes?: string|null, createdBy: string, roster: AccessRoster }} input
   * @returns {AccessReviewCampaign}
   */
  createCampaign({ periodLabel = null, notes = null, createdBy, roster }) {
    if (!createdBy) throw new Error('createdBy is required');
    if (!roster || typeof roster !== 'object') throw new Error('roster is required');
    const id = randomUUID();
    const campaign = {
      id,
      createdAt: nowIso(),
      status: 'open',
      periodLabel: periodLabel == null || periodLabel === '' ? null : String(periodLabel).slice(0, 200),
      notes: notes == null || notes === '' ? null : String(notes).slice(0, 2000),
      createdBy: String(createdBy),
      roster: structuredClone(roster),
      principalCount: Array.isArray(roster.principals) ? roster.principals.length : 0,
      rosterHash: hashRoster(roster),
      attestedAt: null,
      attestedBy: null,
      statement: null,
    };
    this.campaigns.set(id, campaign);
    return structuredClone(campaign);
  }

  /** @returns {AccessReviewCampaign|null} */
  get(id) {
    const c = this.campaigns.get(id);
    return c ? structuredClone(c) : null;
  }

  /**
   * Newest first.
   * @returns {AccessReviewCampaign[]}
   */
  list({ limit = 50 } = {}) {
    const n = Math.max(1, Math.min(200, Number(limit) || 50));
    return [...this.campaigns.values()]
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, n)
      .map((c) => structuredClone(c));
  }

  /**
   * Seal an open campaign. Statement is required (compliance evidence).
   * @returns {AccessReviewCampaign}
   */
  attest(id, { attestedBy, statement }) {
    const c = this.campaigns.get(id);
    if (!c) {
      const err = new Error('campaign not found');
      err.statusCode = 404;
      throw err;
    }
    if (c.status !== 'open') {
      const err = new Error(`campaign is ${c.status}, not open`);
      err.statusCode = 409;
      throw err;
    }
    const who = String(attestedBy ?? '').trim();
    const stmt = String(statement ?? '').trim();
    if (!who) {
      const err = new Error('attestedBy is required');
      err.statusCode = 400;
      throw err;
    }
    if (stmt.length < 8) {
      const err = new Error('statement must be at least 8 characters');
      err.statusCode = 400;
      throw err;
    }
    c.status = 'attested';
    c.attestedAt = nowIso();
    c.attestedBy = who;
    c.statement = stmt.slice(0, 4000);
    return structuredClone(c);
  }

  /**
   * @param {{ campaigns?: any[] }} rows
   */
  hydrate({ campaigns = [] } = {}) {
    this.campaigns.clear();
    for (const row of campaigns) {
      if (!row?.id) continue;
      this.campaigns.set(row.id, {
        id: row.id,
        createdAt: row.createdAt ?? row.created_at ?? nowIso(),
        status: row.status ?? 'open',
        periodLabel: row.periodLabel ?? row.period_label ?? null,
        notes: row.notes ?? null,
        createdBy: row.createdBy ?? row.created_by ?? 'unknown',
        roster: row.roster ?? { principals: [] },
        principalCount: Number(row.principalCount ?? row.principal_count ?? 0),
        rosterHash: row.rosterHash ?? row.roster_hash ?? hashRoster(row.roster ?? {}),
        attestedAt: row.attestedAt ?? row.attested_at ?? null,
        attestedBy: row.attestedBy ?? row.attested_by ?? null,
        statement: row.statement ?? null,
      });
    }
  }
}

export const accessReviewStore = new AccessReviewStore();

/**
 * Optional Postgres write-through.
 * @param {{ query: Function }} db
 * @param {AccessReviewCampaign} campaign
 */
export async function persistCampaign(db, campaign) {
  await db.query(
    `INSERT INTO access_review_campaigns (
       id, created_at, status, period_label, notes, created_by, roster,
       principal_count, attested_at, attested_by, statement, roster_hash
     ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12)
     ON CONFLICT (id) DO UPDATE SET
       status = EXCLUDED.status,
       attested_at = EXCLUDED.attested_at,
       attested_by = EXCLUDED.attested_by,
       statement = EXCLUDED.statement`,
    [
      campaign.id,
      campaign.createdAt,
      campaign.status,
      campaign.periodLabel,
      campaign.notes,
      campaign.createdBy,
      JSON.stringify(campaign.roster),
      campaign.principalCount,
      campaign.attestedAt,
      campaign.attestedBy,
      campaign.statement,
      campaign.rosterHash,
    ],
  );
}

/**
 * @param {{ query: Function }} db
 * @param {AccessReviewStore} [store]
 */
export async function loadAccessReviewCampaigns(db, store = accessReviewStore) {
  try {
    const { rows } = await db.query(
      `SELECT id, created_at, status, period_label, notes, created_by, roster,
              principal_count, attested_at, attested_by, statement, roster_hash
         FROM access_review_campaigns
        ORDER BY created_at DESC
        LIMIT 200`,
    );
    store.hydrate({ campaigns: rows });
  } catch (err) {
    // Table may not exist yet (migration not applied). Leave store empty.
    if (err?.code === '42P01') return;
    throw err;
  }
}

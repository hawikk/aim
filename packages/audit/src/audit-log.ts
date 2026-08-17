/**
 * Immutable audit trail (v1).
 *
 * Threat model: an attacker (or an admin covering tracks) modifies or deletes
 * historical audit records. Defense: every record is hash-chained to its
 * predecessor and sealed with an HMAC-SHA256 keyed by a server-held secret,
 * so any tampering with stored content breaks verification detectably.
 *
 * Record = { seq, ts, actor, action, resource, detail, prevSeal, seal }
 *   seal = HMAC_SHA256(key, canonicalJSON({seq,ts,actor,action,resource,detail,prevSeal}))
 *
 * Storage v1: append-only JSONL file (single writer per path).
 * Production target: Postgres table with INSERT/SELECT-only grants (no
 * UPDATE/DELETE for app roles) + periodic anchor of the head seal to an
 * external WORM store (Azure Immutable Blob) — see docs/design. The record
 * format and verifier stay identical across backends.
 *
 * Audited action families (per AIM-27):
 *   dashboard.view                — who accessed which dashboard/data view
 *   policy.create|update|delete   — guardrail policy changes (incl. actor + diff ref)
 *   policy.sign|policy.promote    — signed policy packs (AIM-688: who sealed/promoted which policy_hash)
 *   policy.canary.start|expand|complete|rollback|clear — progressive canary + FP auto-rollback (AIM-687)
 *   finding.open|ack|resolve      — finding lifecycle transitions
 *   alert.forwarded               — finding batches sent to Sentinel
 *   audit.verify                  — periodic chain-verification runs (self-audit)
 *   auth.login|auth.login.failed|auth.logout — SSO session lifecycle (AIM-95)
 *   authz.deny                    — rejected requests: 401 unauthenticated and
 *                                   403 wrong-role, incl. required roles (AIM-95)
 */

import { createHmac } from 'node:crypto';
import { appendFileSync, readFileSync, existsSync, writeFileSync } from 'node:fs';

const GENESIS = 'GENESIS';

/**
 * Well-known compose fallback that used to ship in docker-compose.yml
 * (`localdev-audit-hmac-not-a-secret`). Public in the repo — anyone can forge
 * seals computed with it. Kept so verify/open can name the cause when an old
 * volume was sealed under this key and the operator switched to a real one
 * (or vice versa). AIM-244.
 */
export const WELL_KNOWN_DEV_HMAC_KEY = 'localdev-audit-hmac-not-a-secret';

export interface AuditRecord {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  resource: string;
  detail: Record<string, unknown>;
  prevSeal: string;
  seal: string;
}

export interface AppendInput {
  actor: string;
  action: string;
  resource: string;
  detail?: Record<string, unknown>;
}

export interface VerifyResult {
  ok: boolean;
  count: number;
  failedSeq?: number;
  reason?: string;
}

export interface QueryFilter {
  path: string;
  actor?: string;
  action?: string | string[];
  /** Substring match on resource. */
  resource?: string;
  /** ISO timestamp, inclusive lower bound. */
  since?: string;
  /** ISO timestamp, inclusive upper bound. */
  until?: string;
}

type UnsignedRecord = Omit<AuditRecord, 'seal'>;

function canonical(value: unknown): string {
  // Deterministic JSON: sort object keys recursively. Matches JSON.stringify
  // semantics for undefined: object keys with undefined values are OMITTED
  // (they never reach disk), array entries become null. Without this a
  // caller passing { days: undefined } seals a string containing the literal
  // "undefined" while the stored record drops the key — every such record
  // then fails verification (found via AIM-87 smoke test).
  if (value === undefined) return 'null'; // only reachable inside arrays
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(',')}}`;
}

export function sealRecord(key: string, unsigned: UnsignedRecord): string {
  return createHmac('sha256', key).update(canonical(unsigned), 'utf8').digest('hex');
}

export class AuditLog {
  private readonly path: string;
  private readonly key: string;
  #tail: AuditRecord | null;

  /**
   * @param path JSONL file path (created if missing)
   * @param key  HMAC secret (from KMS/secret store in prod)
   */
  constructor({ path, key }: { path: string; key: string }) {
    if (!path) throw new Error('path is required');
    if (!key) throw new Error('HMAC key is required');
    this.path = path;
    this.key = key;
    if (!existsSync(path)) writeFileSync(path, '');
    const records = AuditLog.readAll(path);
    if (records.length > 0) {
      // AIM-244: refuse a non-empty chain sealed under the public compose
      // fallback. Using that key while a volume already holds records either
      // means we just re-keyed off a real secret (crash loop) or we are about
      // to append forgeable seals. Name the key, not "content tampered".
      if (key === WELL_KNOWN_DEV_HMAC_KEY) {
        throw new Error(
          `audit chain has ${records.length} record(s) but AUDIT_HMAC_KEY is the ` +
            `well-known dev fallback (${WELL_KNOWN_DEV_HMAC_KEY}). That key is ` +
            `public in the repo — refuse to open. Restore the launcher-generated ` +
            `key from the stack .env (AIM_AUDIT_HMAC_KEY → AUDIT_HMAC_KEY), or ` +
            `start with an empty audit volume if this is intentional (AIM-244).`,
        );
      }
      // Never append to a broken chain silently.
      const result = AuditLog.verify({ path, key });
      if (!result.ok) {
        const hint =
          result.reason?.includes('seal mismatch')
            ? ' — usually content tampered OR AUDIT_HMAC_KEY does not match the key that sealed this volume (AIM-244)'
            : '';
        throw new Error(`audit chain corrupt at seq ${result.failedSeq}: ${result.reason}${hint}`);
      }
      this.#tail = records[records.length - 1] ?? null;
    } else {
      this.#tail = null;
    }
  }

  /**
   * Append a record. Single-writer: pipeline and API must route audit writes
   * through one process (or serialize behind a lock) per path.
   */
  append({ actor, action, resource, detail = {} }: AppendInput): AuditRecord {
    if (!actor || !action || !resource) throw new Error('actor, action, resource are required');
    const unsigned: UnsignedRecord = {
      seq: this.#tail ? this.#tail.seq + 1 : 1,
      ts: new Date().toISOString(),
      actor,
      action,
      resource,
      detail,
      prevSeal: this.#tail ? this.#tail.seal : GENESIS,
    };
    const record: AuditRecord = { ...unsigned, seal: sealRecord(this.key, unsigned) };
    appendFileSync(this.path, JSON.stringify(record) + '\n', 'utf8');
    this.#tail = record;
    return record;
  }

  static readAll(path: string): AuditRecord[] {
    if (!existsSync(path)) return [];
    const content = readFileSync(path, 'utf8');
    return content
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as AuditRecord);
  }

  /**
   * Verify the full chain: sequence continuity, prevSeal linkage, and every
   * record's HMAC.
   */
  static verify({ path, key }: { path: string; key: string }): VerifyResult {
    const records = AuditLog.readAll(path);
    let prevSeal = GENESIS;
    for (let i = 0; i < records.length; i++) {
      const r = records[i]!;
      if (r.seq !== i + 1) return { ok: false, count: i, failedSeq: r.seq, reason: 'sequence gap' };
      if (r.prevSeal !== prevSeal) return { ok: false, count: i, failedSeq: r.seq, reason: 'broken chain link' };
      const { seal, ...unsigned } = r;
      if (sealRecord(key, unsigned) !== seal) {
        // AIM-244: keep the short reason stable for existing tests/callers;
        // constructors that need operator guidance add the key-mismatch hint.
        return {
          ok: false,
          count: i,
          failedSeq: r.seq,
          reason: 'seal mismatch (content tampered or wrong key)',
        };
      }
      prevSeal = seal;
    }
    return { ok: true, count: records.length };
  }

  /** Query records; all filters optional. Action accepts one value or a list. */
  static query({ path, actor, action, resource, since, until }: QueryFilter): AuditRecord[] {
    const actions = action == null ? null : new Set(Array.isArray(action) ? action : [action]);
    return AuditLog.readAll(path).filter((r) => {
      if (actor && r.actor !== actor) return false;
      if (actions && !actions.has(r.action)) return false;
      if (resource && !r.resource.includes(resource)) return false;
      if (since && r.ts < since) return false;
      if (until && r.ts > until) return false;
      return true;
    });
  }
}

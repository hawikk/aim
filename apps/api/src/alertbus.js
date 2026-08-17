// Cursor-based consumer client for the unified alert bus (AIM-158).
//
// The browser never speaks Redis (D3.1 §5): the inbox UI and the sentinel
// agent read alerts through the authenticated API, which is the only thing
// on the compose network holding bus credentials. This module is the read
// half of that hop — transport plus the §7 consumer rules, with no HTTP in
// it, so both can be tested without a server or a Redis.
//
// One access shape: readRange(), replay by cursor. Stateless, idempotent and
// safe to call concurrently — it is what the inbox paginates with and what a
// consumer uses to catch up after downtime. Every read is a pure XRANGE: no
// XACK, no XDEL, no trim, no consumer-group state, so a reader can never
// affect what another reader sees.
//
// Consumer groups are deliberately NOT used here. A group would move the
// "where did I get to" state into the bus, where the API would be acking on
// behalf of a consumer whose work it cannot observe — an alert acked at read
// time but lost before the sentinel triaged it would be gone with no trace.
// A durable cursor held by the consumer has the opposite failure mode: it
// re-reads, and consumers are already required to be idempotent on alert_id
// (§7.2). Re-delivery is the safe direction for a security inbox.
//
// Every entry is validated against the *consumer profile* of the contract
// (D3.1 §6.1) before it is handed to a caller, and projected onto the fields
// this consumer knows (§2) before it leaves this module. §7.10: a malformed
// publish must never crash a consumer or stall it — it is counted and skipped.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const here = dirname(fileURLToPath(import.meta.url));

export const STREAM_KEY = process.env.ALERT_BUS_STREAM ?? 'secstack:alerts:v1';
export const DEFAULT_LIMIT = 50;
export const MAX_LIMIT = 500;
// Wire field name, owned by packages/schema/conformance/security-alert-wire.json
// (AIM-392). Publishers MUST write this field. Consumers accept LEGACY_WIRE_FIELDS
// as a one-release compatibility shim so pre-AIM-392 dogfood streams (gatehouse
// wrote `payload`) still page instead of rendering as an empty inbox while every
// health check stays green — the exact silent-drop class AIM-392 closed for
// publishers and that sentinel already shims in services/sentinel/.../bus.py.
export const WIRE_FIELD = 'alert';
export const LEGACY_WIRE_FIELDS = ['payload'];
// When a page is full of dropped (legacy/malformed) entries, keep scanning so
// the inbox never presents "0 loaded" while valid alerts sit one page further
// on the stream (AIM-476). Cap the scan so a fully-poisoned stream cannot burn
// unbounded Redis round-trips per request.
export const MAX_SCAN_MULTIPLIER = 10;

const schemaDir = join(here, '..', '..', '..', 'packages', 'schema', 'schema', 'v1');

// TWO schemas, one home, and the distinction is load-bearing (D3.1 §6.1):
//
//   publisher schema — strict. What a publisher must emit. Used HERE only as
//     the projection map (§2): the set of fields this consumer knows.
//   consumer profile — the derivation's committed output. What a consumer
//     validates against: unknown fields tolerated, open-vocabulary enums
//     tolerated, and every security constraint (patterns, caps, ranges,
//     required) still strict.
//
// Validating against the strict schema here would be the AIM-174 defect: the
// first additive minor bump — one new optional field, one new severity member
// — would be dropped as invalid by exactly the consumer §7.4 tells to keep it.
// The profile is DERIVED by packages/schema/validate.py and CI fails if this
// file drifts from it, so reading it is not a fork.
const profilePath = join(schemaDir, 'security-alert.consumer.schema.json');
const strictPath = join(schemaDir, 'security-alert.schema.json');

function load(path, what) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    // Worth its own message: if the contract file is missing from the image,
    // every alert fails validation and the inbox reads as "no alerts" — the
    // silent-drop failure this contract exists to prevent. Checked again at
    // startup by schemaLoadError() so it surfaces before a request does.
    throw new Error(`alert contract ${what} unreadable at ${path}: ${err.message}`,
      { cause: err });
  }
}

let COMPILED = null;
function compiled() {
  if (!COMPILED) {
    const profile = load(profilePath, 'consumer profile');
    const strict = load(strictPath, 'publisher schema');
    // strictSchemas:false — the profile deliberately carries `additionalProperties:
    // true` alongside `properties`, which ajv's strict mode flags as redundant.
    // It is not redundant here; it is the derivation's entire point.
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    COMPILED = { validate: ajv.compile(profile), strict };
  }
  return COMPILED;
}

/**
 * Startup probe: null when the contract is loadable, else the reason.
 * Called by the wiring so a packaging mistake is a loud boot-time log rather
 * than a 502 the first time an analyst opens the inbox.
 */
export function schemaLoadError() {
  try {
    compiled();
    return null;
  } catch (err) {
    return err.message;
  }
}

/**
 * Validate one alert against the consumer profile (§7.10).
 *
 * Tolerant, not credulous. The profile accepts an unknown field and an unknown
 * open-vocabulary enum member — that is what keeps an additive minor bump
 * consumable. It still enforces everything a consumer's safety rests on:
 * required fields, types, the length caps, the severity_id range, the pseudonym
 * pattern (plaintext identity) and the source_uri pattern (traversal / open
 * redirect on the one field that becomes a URL).
 *
 * Returns an array of error strings; empty means valid.
 */
export function validateAlert(alert) {
  if (alert === null || typeof alert !== 'object' || Array.isArray(alert)) {
    return ['alert is not an object'];
  }
  const { validate } = compiled();
  if (validate(alert)) return [];
  // ajv reports JSON-pointer paths ("/subject_ref/user_ref"); rendered as
  // dotted field paths because these strings land in logs and in the API's
  // invalidSamples, where they are read by a human triaging a publisher.
  return validate.errors.map((e) => {
    const where = e.instancePath ? e.instancePath.slice(1).replace(/\//g, '.') : '(root)';
    return `${where}: ${e.message}`;
  });
}

/**
 * §2 — project onto the fields this consumer knows, before anything persists,
 * renders or logs the alert.
 *
 * This is the security cost of the §6.1 split, and the rule that pays it. The
 * profile opens `additionalProperties` so an unknown field does not cause a
 * drop — but "ignore unknown fields" must mean DROP them, not carry them. An
 * unknown field is by definition one no contract rule constrains, so a
 * publisher bug or a compromised publisher could park prompt text, a secret
 * value or plaintext identity in it, and without this projection the inbox
 * would store and render whatever it was handed. The strict publisher schema
 * is the field list, so the projection tracks the contract automatically.
 *
 * `labels` is kept whole: it is an open *map* in the strict schema
 * (propertyNames pattern + string cap), not a closed object, so its keys are
 * known-by-shape and already validated.
 */
export function projectAlert(alert) {
  const { strict } = compiled();
  return project(alert, strict);
}

function project(value, spec) {
  if (!spec || value === null || typeof value !== 'object') return value;
  // Array items are projected through the item schema. The contract has no
  // array node today, so this is reach rather than live behaviour — but the
  // projection has to be total over the schema it is handed, not over the
  // schema as it happens to look this week. §6 lets a minor bump add an array
  // of objects, and an unknown field inside an item is the same hole as one at
  // the top level: a place prompt text or a secret can ride into storage
  // through a rule no consumer applies. Tuple-form `items` (an array of
  // schemas) is not used by this contract and is left alone rather than
  // guessed at.
  if (Array.isArray(value)) {
    const items = spec.items;
    if (!items || typeof items !== 'object' || Array.isArray(items)) return value;
    return value.map((item) => project(item, items));
  }
  // Only closed objects are projected. `additionalProperties` as a schema
  // (labels) means the extra keys ARE known by shape and were validated.
  if (spec.additionalProperties !== false || !spec.properties) return value;
  const out = {};
  for (const [key, child] of Object.entries(spec.properties)) {
    if (value[key] !== undefined) out[key] = project(value[key], child);
  }
  return out;
}

// Exported for the conformance test only. The contract has no array node, so
// the array branch of project() is unreachable through projectAlert() and would
// otherwise ship untested — which is how a branch written for a future minor
// bump is wrong by the time that bump arrives.
export { project as projectWithSchema };

const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 };

/**
 * Rank an alert for ordering and thresholds (§7.4, revision 6).
 *
 * Ranks on `severity_id`, NOT on the `severity` label. The two carry the same
 * information only while the label is in vocabulary, and §6 lets a minor bump
 * add a member — at which point the label is unknown to this consumer and the
 * id still is not. Corpus line 6 is the case: `severity: "catastrophic"`,
 * `severity_id: 5`, a publicly-readable S3 bucket. Ranking that as medium
 * files a critical finding in the middle of the inbox, where nobody triaging
 * top-down will reach it. Dropping a critical finding and burying it are the
 * same failure at different speeds.
 *
 * `severity_id` is required and the profile holds it to 1..5, so it is present
 * and in range for anything that passed validateAlert(). The label is the
 * fallback only for a caller ranking an unvalidated alert.
 */
export function severityRank(alert) {
  const id = alert?.severity_id;
  if (Number.isInteger(id) && id >= 1 && id <= 5) return id;
  return SEVERITY_RANK[alert?.severity] ?? SEVERITY_RANK.medium;
}

/**
 * The band a severity *label* names, or undefined if the label is not in this
 * consumer's vocabulary.
 *
 * Deliberately not severityRank(): that one always answers with a usable rank
 * because its caller is ordering something and needs a number. A caller
 * matching a filter needs "unknown" to stay unknown — degrading a typo onto
 * medium would make `?severity=criticl` match every medium alert.
 */
export function severityBand(label) {
  return SEVERITY_RANK[label];
}

/**
 * §7.4 — reject only an unknown MAJOR version. A minor bump is additive by
 * §6, so a v1.2 alert must still be consumed by a v1.1 consumer.
 */
export function isSupportedVersion(alert) {
  return typeof alert.schema_version === 'string'
    && alert.schema_version.split('.')[0] === '1';
}

/**
 * Pull the alert JSON string out of a stream entry's field map.
 *
 * Prefers the contract field (`alert`); falls back to LEGACY_WIRE_FIELDS so a
 * stream that still carries pre-AIM-392 `payload` entries is consumable. An
 * entry with neither is malformed — counted, not fatal (§7.10).
 */
export function wireRaw(entry) {
  const fields = entry?.message ?? entry;
  if (!fields || typeof fields !== 'object') return { raw: undefined, legacy: false };
  if (fields[WIRE_FIELD] !== undefined) {
    return { raw: fields[WIRE_FIELD], legacy: false };
  }
  for (const name of LEGACY_WIRE_FIELDS) {
    if (fields[name] !== undefined) return { raw: fields[name], legacy: true };
  }
  return { raw: undefined, legacy: false };
}

/**
 * Decode one stream entry into an alert, or null if it is unusable.
 * Counters are accumulated on `stats` so a caller can export them.
 */
export function decodeEntry(entry, stats) {
  const { raw, legacy } = wireRaw(entry);
  if (raw === undefined) {
    stats.malformed += 1;
    return null;
  }
  if (legacy) stats.legacyWire += 1;
  let alert;
  try {
    alert = JSON.parse(raw);
  } catch {
    stats.malformed += 1;
    return null;
  }
  // `JSON.parse` succeeds for "null", "5" and "\"x\"" — valid JSON, not an
  // object. Reading a field off the null case throws a TypeError that escapes
  // this function entirely, so the route reports a bus outage AND the cursor
  // never advances: one poisoned entry wedges the inbox permanently, which is
  // precisely what the counters below exist to prevent.
  if (alert === null || typeof alert !== 'object' || Array.isArray(alert)) {
    stats.malformed += 1;
    return null;
  }
  if (!isSupportedVersion(alert)) {
    stats.unsupportedVersion += 1;
    return null;
  }
  const errors = validateAlert(alert);
  if (errors.length) {
    stats.invalid += 1;
    stats.invalidSamples.push({ id: entry.id, alertId: alert.alert_id, error: errors[0] });
    return null;
  }
  if (!(alert.severity in SEVERITY_RANK)) stats.unknownSeverity += 1;
  // §2 — projected at the boundary, so no caller of this module can forget to.
  // Counted, because a nonzero rate here means publishers are emitting fields
  // this consumer does not model: either a minor bump we should adopt, or a
  // publisher leaking data the contract never sanctioned.
  const projected = projectAlert(alert);
  if (!sameShape(alert, projected)) stats.projectedFields += 1;
  return { cursor: entry.id, alert: projected };
}

// Cheap "did the projection remove anything" test. Key-count comparison over
// the closed objects, not a deep equal: the projection only ever drops keys.
function sameShape(before, after) {
  if (before === null || typeof before !== 'object') return true;
  // Descends into arrays for the same reason project() does: a key dropped
  // inside an array item is a projection that happened, and a projection that
  // is not counted is one nobody finds out about.
  if (Array.isArray(before)) {
    if (!Array.isArray(after) || before.length !== after.length) return false;
    return before.every((item, i) => sameShape(item, after[i]));
  }
  if (Object.keys(before).length !== Object.keys(after).length) return false;
  return Object.keys(after).every((k) => sameShape(before[k], after[k]));
}

export function newStats() {
  return {
    malformed: 0, invalid: 0, unsupportedVersion: 0, unknownSeverity: 0,
    projectedFields: 0, legacyWire: 0, invalidSamples: [], scanned: 0,
  };
}

/**
 * Replay a cursor range. `after` is an opaque stream cursor from a previous
 * page — opaque on purpose, so pagination survives a transport change.
 *
 * `direction`:
 *   - `newest` (default for the inbox): XREVRANGE from the newest end, so the
 *     first page is recent alerts rather than the retention-window oldest
 *     (AIM-476: oldest-first + a mid-stream block of legacy `payload` entries
 *     made the first page look empty while 728 ai_usage alerts sat later).
 *   - `oldest`: classic XRANGE from the oldest end (completeness scan).
 *
 * §7.1 still holds: stream order is publish order, not event time. The inbox
 * additionally sorts the loaded page on last_seen_at; newest-first just means
 * the first page is the one operators actually look at.
 *
 * Fill semantics (AIM-476): a single Redis page may be 100% dropped (legacy
 * wire, malformed). We keep scanning (up to MAX_SCAN_MULTIPLIER × limit stream
 * entries) until we have `limit` valid alerts or the stream is exhausted, so
 * "0 loaded / Load more" is never the face of a stream that still has alerts.
 */
export async function readRange(client, {
  after = '-',
  limit = DEFAULT_LIMIT,
  streamKey = STREAM_KEY,
  direction = 'newest',
} = {}) {
  const want = Math.min(Math.max(Number(limit) || DEFAULT_LIMIT, 1), MAX_LIMIT);
  const reverse = direction !== 'oldest';
  const stats = newStats();
  const alerts = [];
  let cursor = after;
  let exhausted = false;
  let lastId = after;
  const maxScan = want * MAX_SCAN_MULTIPLIER;

  while (alerts.length < want && stats.scanned < maxScan) {
    const batch = Math.min(want, maxScan - stats.scanned);
    let entries;
    if (reverse) {
      // XREVRANGE end start: from high (newest) down to low (oldest).
      // Exclusive high bound when resuming: '(' + cursor.
      const endBound = cursor === '-' || cursor === '+' ? '+' : `(${cursor}`;
      if (typeof client.xrevrange === 'function') {
        entries = await client.xrevrange(streamKey, endBound, '-', batch);
      } else {
        // Test fakes that only implement xrange: fall back to forward scan.
        // Production createBusClient always provides xrevrange.
        const startBound = cursor === '-' ? '-' : `(${cursor}`;
        entries = await client.xrange(streamKey, startBound, '+', batch);
      }
    } else {
      const startBound = cursor === '-' ? '-' : `(${cursor}`;
      entries = await client.xrange(streamKey, startBound, '+', batch);
    }

    if (!entries.length) {
      exhausted = true;
      break;
    }
    stats.scanned += entries.length;
    for (const entry of entries) {
      lastId = entry.id;
      const decoded = decodeEntry(entry, stats);
      if (decoded) alerts.push(decoded);
      if (alerts.length >= want) break;
    }
    // Resume strictly past the last entry we examined, even if every entry was
    // dropped — a poisoned block must not wedge the consumer on the same id.
    cursor = lastId;
    if (entries.length < batch) {
      exhausted = true;
      break;
    }
    if (alerts.length >= want) break;
  }

  return {
    alerts,
    // Advances even when every entry in the page was dropped, so a poisoned
    // entry cannot wedge a consumer in a retry loop on the same cursor.
    nextCursor: (lastId === after && after === '-') ? after : lastId,
    exhausted,
    stats,
    direction: reverse ? 'newest' : 'oldest',
  };
}

// A stream id is "<ms>-<seq>". Cursors are opaque to callers but not
// unvalidated: a malformed one gets a 400 rather than a Redis error the route
// would have to report as a bus failure, and "your cursor is wrong" must never
// be indistinguishable from "the bus is down".
const CURSOR_RE = /^\d{1,20}-\d{1,20}$/;

export function isValidCursor(cursor) {
  return cursor === '-' || CURSOR_RE.test(String(cursor));
}

/**
 * The production transport: a read-only adapter over node-redis exposing only
 * the one call this module makes.
 *
 * Narrow on purpose. The API holds a bus credential, and the smallest thing
 * that can hold it is an object with a single XRANGE method — there is no
 * XADD, XACK, XDEL or XTRIM reachable from the request path even if a future
 * route asked for one. Redis ACLs (`secbus_sub`, +xrange on this key) enforce
 * the same boundary server-side; this is the client half of it.
 *
 * The connection is lazy and shared: opened on first read, reused after, and
 * reconnected by node-redis. A bus that is down must surface as a failed read
 * (§7.3 — never an empty, all-clear inbox), not as a boot failure that takes
 * the whole dashboard with it.
 */
export function createBusClient({ url = process.env.ALERT_BUS_URL, createClient } = {}) {
  if (!url) return null;
  let connecting = null;

  async function connection() {
    if (!connecting) {
      connecting = (async () => {
        const { createClient: create } = createClient
          ? { createClient }
          : await import('redis');
        const client = create({ url });
        // node-redis emits 'error' on the client; without a listener an
        // unhandled 'error' event would take the API process down on a bus
        // blip. Reads surface the failure through their own rejection.
        client.on('error', () => {});
        await client.connect();
        return client;
      })().catch((err) => {
        connecting = null; // let the next request retry rather than latch the failure
        throw err;
      });
    }
    return connecting;
  }

  return {
    async xrange(key, start, end, count) {
      const client = await connection();
      const entries = await client.xRange(key, start, end, { COUNT: count });
      // node-redis v5+ already returns [{ id, message }]; normalized here so
      // the reader's shape assumption is stated in one place.
      return entries.map((e) => ({ id: e.id, message: e.message }));
    },
    async xrevrange(key, end, start, count) {
      const client = await connection();
      const entries = await client.xRevRange(key, end, start, { COUNT: count });
      return entries.map((e) => ({ id: e.id, message: e.message }));
    },
    async close() {
      if (!connecting) return;
      const client = await connecting.catch(() => null);
      connecting = null;
      if (client) await client.destroy?.();
    },
  };
}

export default {
  readRange, validateAlert, projectAlert, decodeEntry, severityRank,
  isSupportedVersion, STREAM_KEY, WIRE_FIELD, LEGACY_WIRE_FIELDS,
};

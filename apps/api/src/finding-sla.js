// finding lifecycle SLAs + backlog aging + SLA-breach alerts.
//
// Critical findings must be acknowledged within a defined window. An
// unacknowledged critical past that window is a first-class alert on the
// same security.alert/v1 bus Sentinel already pages — not a soft dashboard
// hint. Pure evaluators live here so unit tests need no Postgres/Redis.
//
// Defaults (override with env):
//   FINDING_CRITICAL_ACK_SLA_HOURS=4
//   FINDING_SLA_ALERTS=1          — enable background publisher
//   FINDING_SLA_ALERT_INTERVAL_SEC=300

import { createHash } from 'node:crypto';
import { query } from './db.js';

const HOUR_MS = 3600 * 1000;
const DAY_MS = 24 * HOUR_MS;

export function criticalAckSlaHours() {
  const n = Number(process.env.FINDING_CRITICAL_ACK_SLA_HOURS ?? 4);
  if (!Number.isFinite(n) || n <= 0) return 4;
  return Math.min(n, 168); // cap at 7d so a typo cannot silence breaches
}

export function criticalAckSlaMs(hours = criticalAckSlaHours()) {
  return hours * HOUR_MS;
}

function envInt(name, def) {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : def;
}

/**
 * Age buckets for open findings. Keys are stable UI/API labels.
 * @param {number} ageMs
 */
export function ageBucket(ageMs) {
  if (!Number.isFinite(ageMs) || ageMs < 0) return 'unknown';
  if (ageMs < DAY_MS) return '<1d';
  if (ageMs < 3 * DAY_MS) return '1-3d';
  if (ageMs < 7 * DAY_MS) return '3-7d';
  return '>7d';
}

/**
 * Pure: classify one finding against the critical-ack SLA.
 * Only severity=critical + status=new can breach (ack/resolve clears it).
 */
export function evaluateFindingSla(finding, {
  nowMs = Date.now(),
  slaHours = criticalAckSlaHours(),
} = {}) {
  const slaMs = criticalAckSlaMs(slaHours);
  const detectedAt = finding?.detectedAt ?? finding?.detected_at ?? null;
  const detectedMs = detectedAt ? new Date(detectedAt).getTime() : NaN;
  const ageMs = Number.isFinite(detectedMs) ? Math.max(0, nowMs - detectedMs) : null;
  const severity = finding?.severity ?? null;
  const status = finding?.status ?? null;
  const isCriticalNew = severity === 'critical' && status === 'new';
  const breached = Boolean(isCriticalNew && ageMs != null && ageMs > slaMs);
  const remainingMs = isCriticalNew && ageMs != null ? slaMs - ageMs : null;
  return {
    findingId: finding?.findingId ?? finding?.finding_id ?? null,
    severity,
    status,
    detectedAt: Number.isFinite(detectedMs) ? new Date(detectedMs).toISOString() : null,
    ageMs,
    ageHours: ageMs == null ? null : Math.round((ageMs / HOUR_MS) * 10) / 10,
    ageBucket: ageMs == null ? null : ageBucket(ageMs),
    slaHours,
    slaMs,
    applies: isCriticalNew,
    breached,
    remainingMs,
    overdueMs: breached && ageMs != null ? ageMs - slaMs : 0,
  };
}

/**
 * Pure: aggregate backlog + SLA posture from a list of open findings
 * (status in new|acknowledged). Closed findings should not be passed in.
 */
export function summarizeFindingsBacklog(findings, {
  nowMs = Date.now(),
  slaHours = criticalAckSlaHours(),
} = {}) {
  const open = findings ?? [];
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byStatus = { new: 0, acknowledged: 0 };
  const ageBuckets = { '<1d': 0, '1-3d': 0, '3-7d': 0, '>7d': 0, unknown: 0 };
  let unhandledCritical = 0; // status=new, severity=critical
  let openCritical = 0;      // status in new|acknowledged, severity=critical
  let oldestCriticalAgeMs = null;
  let oldestCriticalId = null;
  const breaches = [];

  for (const f of open) {
    const sev = f.severity;
    if (sev && bySeverity[sev] != null) bySeverity[sev] += 1;
    const st = f.status;
    if (st && byStatus[st] != null) byStatus[st] += 1;

    const evald = evaluateFindingSla(f, { nowMs, slaHours });
    if (evald.ageBucket && ageBuckets[evald.ageBucket] != null) {
      ageBuckets[evald.ageBucket] += 1;
    } else {
      ageBuckets.unknown += 1;
    }

    if (sev === 'critical' && (st === 'new' || st === 'acknowledged')) {
      openCritical += 1;
      if (evald.ageMs != null && (oldestCriticalAgeMs == null || evald.ageMs > oldestCriticalAgeMs)) {
        oldestCriticalAgeMs = evald.ageMs;
        oldestCriticalId = evald.findingId;
      }
    }
    if (sev === 'critical' && st === 'new') {
      unhandledCritical += 1;
    }
    if (evald.breached) {
      breaches.push(evald);
    }
  }

  breaches.sort((a, b) => (b.overdueMs ?? 0) - (a.overdueMs ?? 0));

  return {
    asOf: new Date(nowMs).toISOString(),
    sla: {
      criticalAckHours: slaHours,
      criticalAckMs: criticalAckSlaMs(slaHours),
      definition: `Critical findings must leave status=new (acknowledged or terminal) within ${slaHours}h of detected_at`,
    },
    openCount: open.length,
    bySeverity,
    byStatus,
    ageBuckets,
    unhandledCritical,
    openCritical,
    oldestCritical: oldestCriticalAgeMs == null ? null : {
      findingId: oldestCriticalId,
      ageMs: oldestCriticalAgeMs,
      ageHours: Math.round((oldestCriticalAgeMs / HOUR_MS) * 10) / 10,
      ageBucket: ageBucket(oldestCriticalAgeMs),
    },
    slaBreaches: {
      count: breaches.length,
      // Cap sample so a 10k backlog cannot blow the response; full count is above.
      sample: breaches.slice(0, 25).map((b) => ({
        findingId: b.findingId,
        ageHours: b.ageHours,
        overdueMs: b.overdueMs,
        detectedAt: b.detectedAt,
      })),
    },
  };
}

function stableAlertId(dedupeHex) {
  const hexed = dedupeHex.slice(0, 32).padEnd(32, '0');
  const variant = '89ab'[parseInt(hexed[16], 16) % 4];
  return `${hexed.slice(0, 8)}-${hexed.slice(8, 12)}-4${hexed.slice(13, 16)}-${variant}${hexed.slice(17, 20)}-${hexed.slice(20, 32)}`;
}

function dedupeHex(parts) {
  return createHash('sha256').update(parts.join('|')).digest('hex');
}

/**
 * Pure: one standing alert for the critical-ack SLA breach set.
 * Deduped by count band so re-pages fire when the backlog grows, not on
 * every tick for the same N.
 */
export function slaBreachAlert(summary, { now = new Date() } = {}) {
  const n = summary?.slaBreaches?.count ?? 0;
  if (n <= 0) return null;
  const stamp = now instanceof Date ? now.toISOString().replace(/\.\d{3}Z$/, 'Z') : String(now);
  const slaH = summary?.sla?.criticalAckHours ?? criticalAckSlaHours();
  // Band: 1, 2-5, 6-20, 21-50, 51+ so growth re-pages without per-finding spam.
  const band = n === 1 ? '1' : n <= 5 ? '2-5' : n <= 20 ? '6-20' : n <= 50 ? '21-50' : '51+';
  const dedupe = dedupeHex(['finding-sla', 'critical-ack', band, String(slaH)]);
  const oldestH = summary?.oldestCritical?.ageHours;
  const title = n === 1
    ? `Critical finding unacknowledged past ${slaH}h SLA`
    : `${n} critical findings unacknowledged past ${slaH}h SLA`;
  return {
    schema_version: '1.1',
    alert_id: stableAlertId(dedupe),
    dedupe_key: dedupe,
    pillar: 'ai_usage',
    producer: { name: 'aim-finding-sla', version: '1.0.0' },
    finding_type: 'ai_usage.finding_sla_breach',
    title: title.slice(0, 200),
    severity: 'high',
    severity_id: 30,
    status: 'new',
    observed_at: stamp,
    first_seen_at: stamp,
    last_seen_at: stamp,
    resource: {
      kind: 'host',
      ref: 'aim:findings/sla/critical-ack',
      display: 'Finding lifecycle SLA',
      provider: null,
      account_ref: null,
      region: null,
    },
    subject_ref: null,
    evidence: {
      source_uri: 'aim:/findings?status=new&severity=critical',
      detail_count: n,
      summary: (
        oldestH != null
          ? `${n} critical finding(s) still status=new past the ${slaH}h ack SLA (oldest ~${oldestH}h). Open #/findings.`
          : `${n} critical finding(s) still status=new past the ${slaH}h ack SLA. Open #/findings.`
      ).slice(0, 240),
    },
    labels: {
      sla_hours: String(slaH).slice(0, 128),
      breach_count: String(n).slice(0, 128),
      breach_band: band,
      unhandled_critical: String(summary?.unhandledCritical ?? n).slice(0, 128),
    },
    remediation_hint: (
      'Open #/findings filtered to severity=critical&status=new. Acknowledge or disposition each finding with a recorded reason. ' +
      'A critical nobody acknowledges is indistinguishable from no alert.'
    ).slice(0, 500),
  };
}

/**
 * Load open findings (new+acknowledged) and build the backlog summary.
 * Caps at 10k rows — enough for pilot; larger fleets should aggregate in SQL.
 */
export async function loadFindingsBacklogSummary(db = { query }, {
  nowMs = Date.now(),
  slaHours = criticalAckSlaHours(),
  limit = 10_000,
} = {}) {
  const { rows } = await db.query(
    `SELECT finding_id, severity, status, detected_at
       FROM findings
      WHERE status = ANY($1)
      ORDER BY detected_at ASC
      LIMIT $2`,
    [['new', 'acknowledged'], limit],
  );
  const findings = rows.map((r) => ({
    findingId: r.finding_id,
    severity: r.severity,
    status: r.status,
    detectedAt: r.detected_at,
  }));
  const summary = summarizeFindingsBacklog(findings, { nowMs, slaHours });
  summary.truncated = rows.length >= limit;
  return summary;
}

/**
 * Background publisher: standing critical-ack SLA breaches → alert bus.
 * Opt-in via FINDING_SLA_ALERTS=1 (and ALERT_BUS_URL via the publish fn).
 * Never XADDs on the request path.
 */
export function startFindingSlaAlerter({
  db = { query },
  publish,
  intervalMs,
  log = console,
  slaHours = criticalAckSlaHours(),
} = {}) {
  if (process.env.FINDING_SLA_ALERTS !== '1' && process.env.FINDING_SLA_ALERTS !== 'true') {
    return { stop() {}, enabled: false };
  }
  if (typeof publish !== 'function') {
    log.warn?.('FINDING_SLA_ALERTS set but no publish function — alerter idle');
    return { stop() {}, enabled: false };
  }
  const ms = intervalMs ?? (envInt('FINDING_SLA_ALERT_INTERVAL_SEC', 300) * 1000);
  const seen = new Map(); // dedupe_key -> last published ms
  const TTL = 6 * 60 * 60 * 1000; // re-emit standing breaches every 6h

  let timer = null;
  let running = false;

  async function tick() {
    if (running) return;
    running = true;
    try {
      const summary = await loadFindingsBacklogSummary(db, { slaHours });
      const alert = slaBreachAlert(summary);
      const now = Date.now();
      if (alert) {
        const last = seen.get(alert.dedupe_key) ?? 0;
        if (now - last >= TTL) {
          await publish(alert);
          seen.set(alert.dedupe_key, now);
          log.info?.(
            { breachCount: summary.slaBreaches.count, dedupe: alert.dedupe_key },
            'finding SLA breach alert published',
          );
        }
      }
      // Drop resolved keys so a re-breach pages again.
      const live = alert ? new Set([alert.dedupe_key]) : new Set();
      for (const k of seen.keys()) {
        if (!live.has(k)) seen.delete(k);
      }
    } catch (err) {
      log.error?.({ err }, 'finding SLA alerter tick failed');
    } finally {
      running = false;
    }
  }

  timer = setInterval(tick, ms);
  const boot = setTimeout(tick, Math.min(ms, 15_000));
  return {
    enabled: true,
    stop() {
      clearInterval(timer);
      clearTimeout(boot);
    },
    _tick: tick,
    _seen: seen,
  };
}

// ---- noise suppression (proven false-positive classes) ------------------

/**
 * Proven noise classes.
 * Each predicate decides whether a finding row should be auto-closed as
 * false_positive. Reasons are recorded on the transition row.
 *
 * Proven classes (measured live or dogfood):
 * - Bare-email-only `pii-in-prompt`
 * - Multi-vendor secret canary fingerprint (live pilot)
 * - First-class-but-unapproved inventory tools (kimi_code / grok_build) on
 *   `unapproved-tool` — keep in tools inventory; do not flood the findings queue
 * High-sensitivity PII and single-detector secrets stay open.
 * Truly unknown tools (e.g. genai_app / other) stay open on unapproved-tool.
 */
export const NOISE_SUPPRESSIONS = [
  {
    id: 'pii-email-only',
    ruleId: 'pii-in-prompt',
    reason:
      'Auto-suppress: bare pii:email only (proven noise — git authorship/test fixtures, not exfil). ' +
      'High-sensitivity PII and email co-occurring with secrets remain open.',
    /**
     * @param {{ rule_id: string, evidence: unknown }} row
     */
    matches(row) {
      if (row.rule_id !== 'pii-in-prompt') return false;
      const detectors = extractDetectors(row.evidence);
      if (detectors.length === 0) return false;
      return detectors.every((d) => d === 'pii:email');
    },
  },
  // live pilot: 20/20 stack secret findings co-fired the same multi-vendor
  // canary fingerprint (AWS + OpenAI + Slack, usually + credit-card) in one
  // 9-minute kimi_code session. Organic single-secret leaks almost never look
  // like this. Suppress as operational noise; single-detector secrets stay open.
  {
    id: 'secret-multi-canary-bundle',
    ruleId: 'secret-pattern-in-prompt',
    reason:
      'Auto-suppress: multi-vendor synthetic canary fingerprint ' +
      '(secret:aws-access-key + secret:openai-key + secret:slack-token co-firing; usually with pii:credit-card). ' +
      'Live pilot 20/20 stack findings were this shape in one dogfood session — not organic single-secret leaks. ' +
      'Single-detector secret findings remain open.',
    /**
     * @param {{ rule_id: string, evidence: unknown }} row
     */
    matches(row) {
      if (row.rule_id !== 'secret-pattern-in-prompt') return false;
      const detectors = new Set(extractDetectors(row.evidence));
      return (
        detectors.has('secret:aws-access-key') &&
        detectors.has('secret:openai-key') &&
        detectors.has('secret:slack-token')
      );
    },
  },
  // Dogfood / pilot: kimi_code and grok_build are first-class schema tools with
  // collectors, but still outside approved_tools until Security promotes them.
  // Leaving unapproved-tool open for those tools floods the queue (10k+ rows) and
  // hides secrets/PII. Suppress as inventory noise; promote via policy when ready.
  {
    id: 'unapproved-inventory-first-class',
    ruleId: 'unapproved-tool',
    reason:
      'Auto-suppress: first-class collected tools (kimi_code / grok_build) still outside ' +
      'approved_tools — tracked in inventory/tools views, not a secrets or PII signal. ' +
      'Unknown tools (other / genai_app / …) remain open. Promote via policies/guardrail approved_tools when Security signs off.',
    /**
     * @param {{ rule_id: string, evidence: unknown }} row
     */
    matches(row) {
      if (row.rule_id !== 'unapproved-tool') return false;
      const tool = extractContextTool(row.evidence);
      return tool === 'kimi_code' || tool === 'grok_build';
    },
  },
];

/** Walk guardrail evidence JSON for detector ids (metadata only). */
export function extractDetectors(evidence) {
  const out = new Set();
  if (!evidence || typeof evidence !== 'object') return [];
  const matched = evidence.matched;
  if (!Array.isArray(matched)) return [];
  for (const m of matched) {
    const actual = m?.actual;
    if (!Array.isArray(actual)) continue;
    for (const a of actual) {
      if (a && typeof a.detector === 'string') out.add(a.detector);
    }
  }
  return [...out].sort();
}

/** Tool name from guardrail evidence.context (metadata only). */
export function extractContextTool(evidence) {
  if (!evidence || typeof evidence !== 'object') return null;
  const ctx = evidence.context;
  if (!ctx || typeof ctx !== 'object') return null;
  return typeof ctx.tool === 'string' ? ctx.tool : null;
}

/**
 * Apply configured noise suppressions to open findings.
 * Records false_positive transitions with the suppression reason (auditability).
 * Returns counts; never touches critical secret findings.
 *
 * @param {object} db — { query, withTransaction }
 * @param {{ actor?: string, dryRun?: boolean, limit?: number }} opts
 */
export async function applyNoiseSuppressions(db, {
  actor = 'aim-noise-suppressor',
  dryRun = false,
  limit = 2000,
  suppressions = NOISE_SUPPRESSIONS,
} = {}) {
  const ruleIds = [...new Set(suppressions.map((s) => s.ruleId))];
  if (ruleIds.length === 0) {
    return { dryRun, updated: 0, byClass: {}, scanned: 0 };
  }

  const { rows } = await db.query(
    `SELECT finding_id, rule_id, status, evidence
       FROM findings
      WHERE status = ANY($1)
        AND rule_id = ANY($2)
      ORDER BY detected_at ASC
      LIMIT $3`,
    [['new', 'acknowledged'], ruleIds, limit],
  );

  /** @type {Map<string, { ids: string[], reason: string }>} */
  const buckets = new Map();
  for (const row of rows) {
    for (const s of suppressions) {
      if (!s.matches(row)) continue;
      let b = buckets.get(s.id);
      if (!b) {
        b = { ids: [], reason: s.reason };
        buckets.set(s.id, b);
      }
      b.ids.push(row.finding_id);
      break; // first matching class wins
    }
  }

  const byClass = {};
  let updated = 0;
  for (const [id, b] of buckets) {
    byClass[id] = b.ids.length;
    if (dryRun || b.ids.length === 0) continue;

    // Batch in chunks of 200 (triage API bound).
    for (let i = 0; i < b.ids.length; i += 200) {
      const chunk = b.ids.slice(i, i + 200);
      await db.withTransaction(async (client) => {
        // Same param shape as bulk triage (ids, status, note, actor) so any
        // db stub that already handles /api/findings/triage works here too.
        const { rows: updatedRows } = await client.query(
          `WITH old AS (
             SELECT finding_id, status FROM findings WHERE finding_id = ANY($1)
           )
           UPDATE findings f
              SET status = $2,
                  triage_note = $3,
                  triaged_by = $4,
                  triaged_at = now()
             FROM old
            WHERE f.finding_id = old.finding_id
           RETURNING f.finding_id, old.status AS from_status`,
          [chunk, 'false_positive', b.reason, actor],
        );
        if (updatedRows.length === 0) return;
        const params = [];
        const values = [];
        let p = 1;
        for (const r of updatedRows) {
          values.push(`($${p++}, $${p++}, $${p++}, $${p++}, $${p++})`);
          params.push(r.finding_id, r.from_status, 'false_positive', actor, b.reason);
        }
        await client.query(
          `INSERT INTO finding_transitions (finding_id, from_status, to_status, actor, reason)
           VALUES ${values.join(', ')}`,
          params,
        );
        updated += updatedRows.length;
      });
    }
  }

  return {
    dryRun,
    scanned: rows.length,
    updated,
    byClass,
    truncated: rows.length >= limit,
  };
}

export default {
  criticalAckSlaHours,
  evaluateFindingSla,
  summarizeFindingsBacklog,
  slaBreachAlert,
  loadFindingsBacklogSummary,
  startFindingSlaAlerter,
  applyNoiseSuppressions,
  extractDetectors,
  NOISE_SUPPRESSIONS,
  ageBucket,
};

// Coverage & Trust — the "what are we NOT seeing?" endpoint.
//
// One aggregate per column of the Coverage & Trust screen, each built on the
// same known vs covered vs dark idea:
//
// aiTools known = sanctioned catalog ∪ tools ever observed in
//                 events; covered = emitting into the stack in the last 24h;
//                 dark = known but silent. All derivable today from the events
//                 table + the sanctioned catalog — no new collection.
//   cloudAccounts known/scanned/dark from the CNAPP pillar's
// GET /accounts/coverage (contract — its docstring
//                 names this issue as the consumer). Fetched server-side via
//                 CNAPP_COVERAGE_URL + CNAPP_API_KEY so the cross-pillar
//                 credential never reaches the browser. Unconfigured or
//                 unreachable renders as an explicit not-wired/error state —
//                 never an invented number.
//   repos         known = every org/installation repo from the forge API
// (gatehouse GET /coverage/repos) — not just repos
//                 that phoned home. covered = recent gate run within the
//                 staleness window; dark carries an explicit reason
//                 (not_onboarded / never_scanned / runner_offline /
//                 policy_excluded). Unconfigured gatehouse → not_wired.
//
// Hard rules from the issue, enforced here:
//   * No mock data. A source that is missing yields state 'not_wired' (naming
//     the endpoint that will provide it) or 'error' — counts stay null, never
//     zero. Zero is a measurement; null is "we cannot see".
//   * Stale is a state. Each wired column carries freshness {lastEventAt,
//     ageSeconds, stale} computed server-side against now(); the UI degrades
//     visibly on it rather than rendering old data as current.
//   * Metadata only. Tool names, repo pseudonyms/labels, account ids, counts
//     and timestamps — no prompt content, no file contents, nothing beyond
//     what the ingest contract already stores.
//
// Access: analyst + admin (same tier as /api/fleet). Coverage gaps
// are an attacker's roadmap — this endpoint is deliberately NOT in the
// all-roles dashboard tier, and the web module activates only on the
// server-computed `coverage` capability.

import { query } from '../db.js';
import { requireRoles } from '../auth.js';
import { audit } from '../audit.js';
import { listSanctionedToolNames } from '../sanctioned.js';
import { idleThresholdSeconds } from './pipeline.js';

const COVERAGE_WINDOW_SECONDS = 24 * 60 * 60; // "emitting in the last 24h"
/** Sustained-coverage window (AC): hosts + active days over 3d. */
const SUSTAINED_WINDOW_SECONDS = 3 * 24 * 60 * 60;
/** Acceptance thresholds for "sustained" sanctioned-tool coverage. */
const SUSTAINED_MIN_HOSTS = 3;
const SUSTAINED_MIN_DAYS = 3;
/**
 * precision defaults (env-overridable):
 *  - silence grace: dark after 24h, but pageable "stopped reporting" only after
 *    this many seconds of silence (default 48h) — cuts weekend / intermittent FP.
 *  - never-seen fleet gate: critical "never reported" only when the enrolled
 *    fleet has enough healthy hosts that absence is surprising. Thin pilot
 *    fleets (1-host dogfood) stay dark in the ledger without banner fatigue.
 */
const DEFAULT_ALERT_SILENCE_SECONDS = 48 * 60 * 60;
// never-seen critical only when fleet is ready (default = sustained host floor).
// Override with COVERAGE_ALERT_NEVER_SEEN_MIN_HEALTHY_HOSTS=0 for raw fire-on-dark.
const DEFAULT_NEVER_SEEN_MIN_HEALTHY_HOSTS = SUSTAINED_MIN_HOSTS;
const CLOUD_TIMEOUT_MS = 5000;

function envInt(name, fallback) {
  const raw = process.env[name];
  if (raw == null || raw === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
}

/** Live precision knobs for coverage alerts (read per-request so tests can flip). */
export function coverageAlertPrecisionConfig() {
  return {
    silenceThresholdSeconds: envInt(
      'COVERAGE_ALERT_SILENCE_SECONDS',
      DEFAULT_ALERT_SILENCE_SECONDS,
    ),
    neverSeenMinHealthyHosts: envInt(
      'COVERAGE_ALERT_NEVER_SEEN_MIN_HEALTHY_HOSTS',
      DEFAULT_NEVER_SEEN_MIN_HEALTHY_HOSTS,
    ),
    // Escape hatch: force never-seen critical even on thin fleets (post-pilot).
    neverSeenForce: process.env.COVERAGE_ALERT_NEVER_SEEN_FORCE === '1',
  };
}

const NOTE =
  'Known vs covered vs dark per surface. Counts are live measurements; a source that is not wired ' +
  'reports null counts with an explicit not-wired state — zero is a measurement, null is "we cannot see". ' +
  'Metadata only: tool names, repo pseudonyms, account ids, counts and timestamps — never content.';

// What will provide each unwired source, named so the UI can point at it.
const CLOUD_NOT_WIRED = {
  endpoint: 'GET /accounts/coverage (CNAPP backend)',
  awaiting: 'CNAPP coverage backend',
  detail:
    'Cloud account discovery + scan-set coverage is the CNAPP pillar\u2019s /accounts/coverage contract. ' +
    'Set CNAPP_COVERAGE_URL and CNAPP_API_KEY on aim-api to wire it; until then this column shows nothing ' +
    'rather than inventing a number.',
};
const REPO_GATE_NOT_WIRED = {
  endpoint: 'GET /coverage/repos (gatehouse)',
  awaiting: 'GATEHOUSE_COVERAGE_URL + gatehouse GitHub App credentials',
  detail:
    'Repo coverage is the gatehouse forge ledger: every installation repo from the GitHub App API, ' +
    'joined to last gate run. Set GATEHOUSE_COVERAGE_URL on aim-api (compose default: http://gatehouse:8090/coverage/repos). ' +
    'Until then this column shows nothing rather than inventing a number.',
};

const REPO_TIMEOUT_MS = 5000;

const num = (v) => Number(v ?? 0);
const iso = (v) => (v ? new Date(v).toISOString() : null);

function freshness(lastEventAt, ageSeconds, thresholdSeconds) {
  const age = ageSeconds == null ? null : Math.max(0, Math.round(Number(ageSeconds)));
  return {
    lastEventAt: iso(lastEventAt),
    ageSeconds: age,
    stale: age == null ? true : age > thresholdSeconds,
  };
}

/**
 * Pure: classify a sanctioned tool's coverage alert.
 *
 * Dark tools always stay on the ledger. Pageable / banner alerts fire only
 * when precision gates pass:
 *  - never-seen → critical only if fleet is ready (≥ min healthy hosts) or force
 *  - stopped-reporting → high only if silence age ≥ silence threshold (default 48h)
 *
 * Returns { fireable, alert, suppressReason, silenceAgeSeconds, candidate }.
 * `alert` is the full payload when fireable; otherwise null.
 * Suppressed candidates carry the same shape under `candidate` for operators.
 */
export function classifySanctionedToolCoverage(item, opts = {}) {
  const {
    silenceThresholdSeconds = DEFAULT_ALERT_SILENCE_SECONDS,
    neverSeenMinHealthyHosts = DEFAULT_NEVER_SEEN_MIN_HEALTHY_HOSTS,
    neverSeenForce = false,
    healthyHosts = 0,
    nowMs = Date.now(),
  } = opts;

  if (!item?.sanctioned || item.covered) {
    return {
      fireable: false,
      alert: null,
      candidate: null,
      suppressReason: null,
      silenceAgeSeconds: null,
    };
  }

  const neverSeen = !item.observed;
  let silenceAgeSeconds = null;
  if (!neverSeen && item.lastEventAt) {
    const t = new Date(item.lastEventAt).getTime();
    if (Number.isFinite(t)) {
      silenceAgeSeconds = Math.max(0, Math.round((nowMs - t) / 1000));
    }
  }

  const base = {
    kind: 'sanctioned_tool_dark',
    tool: item.tool,
    severity: neverSeen ? 'critical' : 'high',
    neverSeen,
    lastEventAt: item.lastEventAt ?? null,
    lastVerifiedEndToEnd: item.lastVerifiedEndToEnd ?? item.lastEventAt ?? null,
    hosts3d: item.hosts3d ?? 0,
    activeDays3d: item.activeDays3d ?? 0,
    silenceAgeSeconds,
    message: neverSeen
      ? `Sanctioned tool ${item.tool} has never reported telemetry — absence is not "no usage".`
      : `Sanctioned tool ${item.tool} stopped reporting (last event ${item.lastEventAt ?? 'unknown'}); ` +
        `coverage alert, not silent disappearance.`,
  };

  if (neverSeen) {
    const ready = neverSeenForce || num(healthyHosts) >= neverSeenMinHealthyHosts;
    if (!ready) {
      return {
        fireable: false,
        alert: null,
        candidate: {
          ...base,
          severity: 'informational',
          suppressReason: 'fleet_thin_pilot',
          message:
            `Sanctioned tool ${item.tool} has never reported telemetry, but the fleet has only ` +
            `${num(healthyHosts)} healthy host(s) (need ≥${neverSeenMinHealthyHosts} for a ` +
            `pageable never-seen alert). Dark on the ledger; not a critical banner on thin pilot fleets.`,
        },
        suppressReason: 'fleet_thin_pilot',
        silenceAgeSeconds: null,
      };
    }
    return {
      fireable: true,
      alert: base,
      candidate: base,
      suppressReason: null,
      silenceAgeSeconds: null,
    };
  }

  // Observed-then-dark: require silence beyond the coverage window (grace).
  if (silenceAgeSeconds == null || silenceAgeSeconds < silenceThresholdSeconds) {
    return {
      fireable: false,
      alert: null,
      candidate: {
        ...base,
        severity: 'informational',
        suppressReason: 'silence_grace',
        silenceThresholdSeconds,
        message:
          `Sanctioned tool ${item.tool} is dark in the ${COVERAGE_WINDOW_SECONDS / 3600}h coverage window ` +
          `(last event ${item.lastEventAt ?? 'unknown'}), but silence age ` +
          `${silenceAgeSeconds == null ? 'unknown' : `${Math.round(silenceAgeSeconds / 3600)}h`} ` +
          `is under the ${silenceThresholdSeconds / 3600}h pageable threshold.`,
      },
      suppressReason: 'silence_grace',
      silenceAgeSeconds,
    };
  }

  return {
    fireable: true,
    alert: { ...base, silenceThresholdSeconds },
    candidate: { ...base, silenceThresholdSeconds },
    suppressReason: null,
    silenceAgeSeconds,
  };
}

/**
 * Pure: fireable coverage alert only.
 * Dark sanctioned tools raise an alert so silence is never read as "no usage",
 * subject to precision gates — see classifySanctionedToolCoverage.
 */
export function sanctionedToolCoverageAlert(item, opts = {}) {
  return classifySanctionedToolCoverage(item, opts).alert;
}

/**
 * Pure: whether a tool meets sustained-coverage thresholds
 * (≥3 distinct hosts and ≥3 active UTC days in the 3-day window).
 */
export function meetsSustainedCoverage(item, {
  minHosts = SUSTAINED_MIN_HOSTS,
  minDays = SUSTAINED_MIN_DAYS,
} = {}) {
  return num(item?.hosts3d) >= minHosts && num(item?.activeDays3d) >= minDays;
}

/**
 * Fleet size never-seen gate. Mirrors fleet.js health: healthy =
 * last heartbeat within 1× the device's own heartbeat_interval_sec.
 * Fail soft: missing devices table / empty fleet → 0 healthy (suppress never-seen).
 */
async function fleetHostStats(db) {
  try {
    const { rows } = await db.query(
      `SELECT
         count(*) FILTER (WHERE revoked_at IS NULL) AS enrolled,
         count(*) FILTER (
           WHERE revoked_at IS NULL
             AND last_heartbeat_at IS NOT NULL
             AND EXTRACT(EPOCH FROM (now() - last_heartbeat_at))
                 <= COALESCE(heartbeat_interval_sec, 300)
         ) AS healthy
       FROM devices`
    );
    const r = rows[0] ?? {};
    return { enrolled: num(r.enrolled), healthy: num(r.healthy) };
  } catch {
    return { enrolled: 0, healthy: 0 };
  }
}

async function aiToolsColumn(db, thresholdSeconds, alertOpts = {}) {
  // live allow-list so coverage recomputes without a restart.
  const sanctionedTools = await listSanctionedToolNames(db);
  const sanctionedSet = new Set(sanctionedTools);
  const precision = coverageAlertPrecisionConfig();
  const [toolsRes, feedRes, fleet] = await Promise.all([
    db.query(
      `SELECT tool,
              max(received_at) AS last_event_at,
              count(*) FILTER (WHERE received_at >= now() - ($1 || ' seconds')::interval) AS events_24h,
              count(DISTINCT user_ref) FILTER (WHERE received_at >= now() - ($1 || ' seconds')::interval) AS users_24h,
              count(DISTINCT host_ref) FILTER (WHERE received_at >= now() - ($1 || ' seconds')::interval) AS hosts_24h,
              count(*) FILTER (WHERE ts >= now() - ($2 || ' seconds')::interval) AS events_3d,
              count(DISTINCT host_ref) FILTER (WHERE ts >= now() - ($2 || ' seconds')::interval) AS hosts_3d,
              count(DISTINCT (ts AT TIME ZONE 'UTC')::date)
                FILTER (WHERE ts >= now() - ($2 || ' seconds')::interval) AS active_days_3d
         FROM events
        GROUP BY tool`,
      [COVERAGE_WINDOW_SECONDS, SUSTAINED_WINDOW_SECONDS]
    ),
    db.query(
      `SELECT max(received_at) AS last_received,
              EXTRACT(EPOCH FROM (now() - max(received_at))) AS age_seconds
         FROM events`
    ),
    fleetHostStats(db),
  ]);

  const classifyOpts = {
    silenceThresholdSeconds: precision.silenceThresholdSeconds,
    neverSeenMinHealthyHosts: precision.neverSeenMinHealthyHosts,
    neverSeenForce: precision.neverSeenForce,
    healthyHosts: fleet.healthy,
    nowMs: alertOpts.nowMs ?? Date.now(),
  };

  const byTool = new Map();
  for (const r of toolsRes.rows) {
    const lastEventAt = iso(r.last_event_at);
    const item = {
      tool: r.tool,
      sanctioned: sanctionedSet.has(r.tool),
      inCatalog: sanctionedSet.has(r.tool),
      observed: true,
      events24h: num(r.events_24h),
      users24h: num(r.users_24h),
      hosts24h: num(r.hosts_24h),
      events3d: num(r.events_3d),
      hosts3d: num(r.hosts_3d),
      activeDays3d: num(r.active_days_3d),
      lastEventAt,
      lastVerifiedEndToEnd: lastEventAt,
      covered: num(r.events_24h) > 0,
      sustained: false,
      coverageAlert: null,
      coverageAlertSuppressed: null,
    };
    item.sustained = meetsSustainedCoverage(item);
    const cls = classifySanctionedToolCoverage(item, classifyOpts);
    item.coverageAlert = cls.alert;
    item.coverageAlertSuppressed = cls.fireable
      ? null
      : (cls.candidate
        ? { reason: cls.suppressReason, ...cls.candidate }
        : null);
    byTool.set(r.tool, item);
  }
  for (const tool of sanctionedTools) {
    if (!byTool.has(tool)) {
      const item = {
        tool,
        sanctioned: true,
        inCatalog: true,
        observed: false,
        events24h: 0,
        users24h: 0,
        hosts24h: 0,
        events3d: 0,
        hosts3d: 0,
        activeDays3d: 0,
        lastEventAt: null,
        lastVerifiedEndToEnd: null,
        covered: false,
        sustained: false,
        coverageAlert: null,
        coverageAlertSuppressed: null,
      };
      const cls = classifySanctionedToolCoverage(item, classifyOpts);
      item.coverageAlert = cls.alert;
      item.coverageAlertSuppressed = cls.fireable
        ? null
        : (cls.candidate
          ? { reason: cls.suppressReason, ...cls.candidate }
          : null);
      byTool.set(tool, item);
    }
  }

  const items = [...byTool.values()].sort((a, b) => a.tool.localeCompare(b.tool));
  const darkItems = items
    .filter((t) => !t.covered)
    .map((t) => ({
      id: t.tool,
      label: t.tool,
      sanctioned: t.sanctioned,
      lastEventAt: t.lastEventAt,
      lastVerifiedEndToEnd: t.lastVerifiedEndToEnd,
      hosts3d: t.hosts3d,
      activeDays3d: t.activeDays3d,
      neverSeen: !t.observed,
      alert: t.coverageAlert,
      alertSuppressed: t.coverageAlertSuppressed,
      detail: !t.observed
        ? `${t.sanctioned ? 'Sanctioned tool' : 'Tool'} never seen in this stack`
        : `Silent for more than ${COVERAGE_WINDOW_SECONDS / 3600}h`,
    }));

  const alerts = items
    .map((t) => t.coverageAlert)
    .filter(Boolean)
    .sort((a, b) => a.tool.localeCompare(b.tool));

  const suppressed = items
    .map((t) => t.coverageAlertSuppressed)
    .filter(Boolean)
    .sort((a, b) => a.tool.localeCompare(b.tool));

  const sanctionedItems = items.filter((t) => t.sanctioned);
  const feed = feedRes.rows[0] ?? {};
  const alertPrecision = {
    silenceThresholdSeconds: precision.silenceThresholdSeconds,
    neverSeenMinHealthyHosts: precision.neverSeenMinHealthyHosts,
    neverSeenForce: precision.neverSeenForce,
    healthyHosts: fleet.healthy,
    enrolledHosts: fleet.enrolled,
    fireable: alerts.length,
    suppressed: suppressed.length,
    suppressedReasons: Object.fromEntries(
      ['fleet_thin_pilot', 'silence_grace'].map((r) => [
        r,
        suppressed.filter((s) => s.reason === r).length,
      ]),
    ),
    note:
      'Pageable sanctioned-tool coverage alerts require precision gates: ' +
      `never-seen critical only when healthy hosts ≥ ${precision.neverSeenMinHealthyHosts} ` +
      `(or COVERAGE_ALERT_NEVER_SEEN_FORCE=1); stopped-reporting high only after ` +
      `${precision.silenceThresholdSeconds / 3600}h silence. Dark ledger is unchanged — ` +
      'silence is still not "no usage".',
  };

  return {
    state: 'ok',
    known: items.length,
    covered: items.filter((t) => t.covered).length,
    dark: darkItems.length,
    freshness: freshness(feed.last_received, feed.age_seconds, thresholdSeconds),
    darkItems,
    items,
    alerts,
    suppressedAlerts: suppressed,
    alertPrecision,
    sanctioned: {
      tools: sanctionedItems.map((t) => t.tool),
      covered: sanctionedItems.filter((t) => t.covered).length,
      dark: sanctionedItems.filter((t) => !t.covered).length,
      sustained: sanctionedItems.filter((t) => t.sustained).length,
      thresholds: {
        coverageWindowSeconds: COVERAGE_WINDOW_SECONDS,
        sustainedWindowSeconds: SUSTAINED_WINDOW_SECONDS,
        minHosts: SUSTAINED_MIN_HOSTS,
        minDays: SUSTAINED_MIN_DAYS,
        alertSilenceSeconds: precision.silenceThresholdSeconds,
        neverSeenMinHealthyHosts: precision.neverSeenMinHealthyHosts,
      },
    },
    note:
      'Known = sanctioned catalog plus every tool observed in events. ' +
      `Covered = at least one event received in the last ${COVERAGE_WINDOW_SECONDS / 3600}h. ` +
      `Sustained = ≥${SUSTAINED_MIN_HOSTS} hosts and ≥${SUSTAINED_MIN_DAYS} active UTC days in the last ` +
      `${SUSTAINED_WINDOW_SECONDS / 86400}d (measured on event ts). ` +
      'Dark sanctioned tools stay on the ledger; pageable coverage alerts fire only precision gates. ' +
      'lastVerifiedEndToEnd is the server-side received_at of the newest event for that tool. ' +
      'Freshness is the whole ingest feed — if it is stale, every number on this column is old.',
  };
}


async function cloudAccountsColumn(fetchImpl, config) {
  if (!config.url || !config.apiKey) {
    return { state: 'not_wired', known: null, covered: null, dark: null, freshness: null, darkItems: null, notWired: CLOUD_NOT_WIRED };
  }
  let d;
  try {
    const res = await fetchImpl(config.url, {
      headers: { 'X-API-Key': config.apiKey, accept: 'application/json' },
      signal: AbortSignal.timeout(CLOUD_TIMEOUT_MS),
    });
    if (!res.ok) {
      return {
        state: 'error',
        known: null, covered: null, dark: null, freshness: null, darkItems: null,
        error: `CNAPP coverage endpoint answered HTTP ${res.status}`,
        notWired: null,
        source: { endpoint: 'GET /accounts/coverage (CNAPP backend)' },
      };
    }
    d = await res.json();
  } catch (err) {
    return {
      state: 'error',
      known: null, covered: null, dark: null, freshness: null, darkItems: null,
      error: `CNAPP coverage endpoint unreachable: ${err.message}`,
      notWired: null,
      source: { endpoint: 'GET /accounts/coverage (CNAPP backend)' },
    };
  }
  return {
    state: 'ok',
    known: num(d.accounts_known),
    covered: num(d.accounts_scanned),
    dark: num(d.accounts_dark),
    freshness: { lastEventAt: iso(d.as_of), ageSeconds: 0, stale: false, asOf: iso(d.as_of) },
    costUsd30d: d.cost_usd_30d ?? null,
    byProvider: d.by_provider ?? null,
    darkItems: (d.dark ?? []).map((a) => ({
      id: a.id,
      label: a.name || a.cloud_account_id,
      provider: a.provider,
      cloudAccountId: a.cloud_account_id,
      billingAccountId: a.billing_account_id ?? null,
      costUsd30d: a.cost_usd_30d ?? null,
      costRank: a.cost_rank ?? null,
      lastEventAt: iso(a.last_seen_at),
      neverSeen: false,
      detail: 'Discovered but not in the enabled scan set',
    })),
    definitions: d.definitions ?? null,
    source: { endpoint: 'GET /accounts/coverage (CNAPP backend, contract)' },
    note: 'Known/scanned/dark per the CNAPP pillar\u2019s discovery inventory, billing-ranked. Fetched server-side; the API key never leaves aim-api.',
  };
}

/**
 * forge-enumerated repo ledger via gatehouse.
 *
 * When GATEHOUSE_COVERAGE_URL is unset → not_wired (counts null).
 * When gatehouse answers state not_wired/error → pass that through, still
 * null counts. When ok/partial → map the contract into the same
 * known/covered/dark column shape the UI already understands, plus the
 * per-repo ledger (last gate run, mode, conclusion, dark reason).
 */
async function reposColumn(fetchImpl, config, thresholdSeconds, req) {
  // Audit every read of the ledger: repo names are an attacker's roadmap
  // the same way labels are. Analyst+ only (enforced by the route gate).
  audit(req.identity?.email ?? 'unknown', 'repo.coverage.view', 'coverage', { column: 'repos' });

  if (!config.url) {
    return {
      state: 'not_wired',
      known: null,
      covered: null,
      dark: null,
      freshness: null,
      darkItems: null,
      items: null,
      notWired: REPO_GATE_NOT_WIRED,
    };
  }

  let d;
  try {
    const headers = { accept: 'application/json' };
    if (config.token) headers.Authorization = `Bearer ${config.token}`;
    const res = await fetchImpl(config.url, {
      headers,
      signal: AbortSignal.timeout(REPO_TIMEOUT_MS),
    });
    if (!res.ok) {
      return {
        state: 'error',
        known: null, covered: null, dark: null, freshness: null, darkItems: null, items: null,
        error: `Gatehouse coverage endpoint answered HTTP ${res.status}`,
        source: { endpoint: 'GET /coverage/repos (gatehouse)' },
      };
    }
    d = await res.json();
  } catch (err) {
    return {
      state: 'error',
      known: null, covered: null, dark: null, freshness: null, darkItems: null, items: null,
      error: `Gatehouse coverage endpoint unreachable: ${err.message}`,
      source: { endpoint: 'GET /coverage/repos (gatehouse)' },
    };
  }

  // Gatehouse itself may report not_wired (no App credentials) or error.
  if (d.state === 'not_wired') {
    return {
      state: 'not_wired',
      known: null, covered: null, dark: null, freshness: null, darkItems: null, items: null,
      notWired: d.not_wired || REPO_GATE_NOT_WIRED,
      source: d.source || { endpoint: 'GET /coverage/repos (gatehouse)' },
    };
  }
  if (d.state === 'error' || (d.repos_known == null && d.error)) {
    return {
      state: 'error',
      known: null, covered: null, dark: null, freshness: null, darkItems: null, items: null,
      error: d.error || 'Gatehouse coverage returned an error state',
      source: d.source || { endpoint: 'GET /coverage/repos (gatehouse)' },
    };
  }

  const staleThreshold = num(d.stale_threshold_seconds) || thresholdSeconds;
  const f = d.freshness || {};
  const age = f.age_seconds == null ? null : num(f.age_seconds);
  const items = (d.repos || []).map((r) => ({
    fullName: r.full_name,
    label: r.full_name,
    onboarded: !!r.onboarded,
    covered: !!r.covered,
    darkReason: r.dark_reason || null,
    detail: r.detail || null,
    lastGateRunAt: iso(r.last_gate_run_at),
    lastGateAgeSeconds: r.last_gate_age_seconds == null ? null : num(r.last_gate_age_seconds),
    lastConclusion: r.last_conclusion || null,
    mode: r.mode || null,
    failOn: r.fail_on || null,
    lastPr: r.last_pr ?? null,
    stale: !!r.stale,
    private: r.private ?? null,
    archived: r.archived ?? null,
    // Keep lastEventAt alias so older UI helpers still render a timestamp.
    lastEventAt: iso(r.last_gate_run_at),
  }));

  return {
    state: d.state === 'partial' ? 'partial' : 'ok',
    known: num(d.repos_known),
    covered: num(d.repos_covered),
    dark: num(d.repos_dark),
    freshness: {
      lastEventAt: iso(f.last_gate_run_at),
      ageSeconds: age,
      stale: f.stale == null ? (age == null ? true : age > staleThreshold) : !!f.stale,
    },
    darkItems: (d.dark || []).map((r) => ({
      id: r.full_name || r.id || r.name,
      label: r.full_name || r.name || r.id,
      reason: r.reason || null,
      detail: r.detail || '',
      lastEventAt: iso(r.last_gate_run_at),
      lastConclusion: r.last_conclusion || null,
      mode: r.mode || null,
      neverSeen: !!r.never_seen,
    })),
    items,
    definitions: d.definitions || null,
    staleThresholdSeconds: staleThreshold,
    source: d.source || { endpoint: 'GET /coverage/repos (gatehouse)' },
    note:
      'Known = every repo the forge App reports (plus optional org inventory), not only ones that phoned home. ' +
      'Covered = onboarded, not policy-excluded, last gate run within the staleness window. ' +
      'Dark always carries a reason: not_onboarded / never_scanned / runner_offline / policy_excluded. ' +
      'Covered is not the same as a green check conclusion — a recent failure still counts as covered.',
  };
}

// opts.db and opts.fetch are injectable for tests; env is read per-request so
// tests can flip CNAPP_* / GATEHOUSE_* without rebuilding the app.
export async function coverageRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const fetchImpl = opts?.fetch ?? globalThis.fetch;
  const gated = requireRoles('admin', 'analyst');

  fastify.get('/api/coverage', async (req, reply) => {
    if (!gated(req, reply)) return reply;
    const thresholdSeconds = idleThresholdSeconds();
    const cloudConfig = {
      url: process.env.CNAPP_COVERAGE_URL || '',
      apiKey: process.env.CNAPP_API_KEY || '',
    };
    const repoConfig = {
      url: process.env.GATEHOUSE_COVERAGE_URL || '',
      token: process.env.GATEHOUSE_COVERAGE_TOKEN || '',
    };
    const [aiTools, cloudAccounts, repos] = await Promise.all([
      aiToolsColumn(db, thresholdSeconds),
      cloudAccountsColumn(fetchImpl, cloudConfig),
      reposColumn(fetchImpl, repoConfig, thresholdSeconds, req),
    ]);
    const generatedAt = new Date().toISOString();
    return {
      generatedAt,
      lastVerifiedEndToEnd: generatedAt,
      note: NOTE,
      coverageWindowSeconds: COVERAGE_WINDOW_SECONDS,
      sustainedWindowSeconds: SUSTAINED_WINDOW_SECONDS,
      staleThresholdSeconds: thresholdSeconds,
      columns: { aiTools, cloudAccounts, repos },
      // Fireable only (precision). Dark tools still in columns.aiTools.darkItems.
      coverageAlerts: aiTools.alerts ?? [],
      coverageAlertsSuppressed: aiTools.suppressedAlerts ?? [],
      coverageAlertPrecision: aiTools.alertPrecision ?? null,
    };
  });
}

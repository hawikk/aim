// Fleet enforce coverage (residual C /).
//
// Answers the SOC question "who can enforce today?" without SQL:
//   * install-path coverage — hosts with a loaded enforcement.json bundle
//     (enforcement_posture.policy=loaded), optionally mode=enforce and the
//     desired policy_hash
//   * honor rate — blocked / (blocked + would_block); would_block under
//     enforce mode is fail-open or delivery skew
//   * fail-open inventory — reporting hosts with no loaded bundle (or shadow
//     / stale hash)
//   * pilot SLO alerts when coverage or honor rate drop below thresholds
//
// Denominator doctrine: zero blocks is only a clean number when
// endpoints actually ran a loaded policy. Absence of posture is coverage-
// absent, not a clean fleet.
//
// host_ref (event HMAC) and devices.host_id (enroll UUID) do not join — the
// inventory is event host_ref based. Enrolled device counts are reported
// separately so silent enrollments stay visible as coverage gaps.
//
// Access: analyst + admin (same tier as /api/fleet). Metadata only.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { query } from '../db.js';
import { requireRoles } from '../auth.js';

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(here, '..', '..', '..', '..');

/** Default observation window for posture + disposition rollups. */
export const DEFAULT_WINDOW_DAYS = 7;
export const MAX_WINDOW_DAYS = 90;
/** Pilot install SLO: share of reporting hosts that can enforce. */
export const DEFAULT_MIN_COVERAGE_PCT = 90;
/** Pilot honor SLO when there are enough enforce decisions to measure. */
export const DEFAULT_MIN_HONOR_RATE = 0.95;
/** Floor before honor-rate SLO fires (noise guard). */
export const DEFAULT_HONOR_MIN_DECISIONS = 5;
/** Cap fail-open / host inventory rows returned on the wire. */
export const MAX_INVENTORY = 200;

const SHADOW_BAKE_PREFIX = 'aim117-shadow-bake';

const NOTE =
  'Install-path coverage is measured from schema v1.7 enforcement_posture on ' +
  'endpoint events (policy loaded / mode / policy_hash). Honor rate is ' +
  'blocked/(blocked+would_block) from enforcement audit records. Fail-open ' +
  'hosts are reporting host_refs with no loaded bundle (or shadow/stale). ' +
  'Zero blocks without posture coverage is coverage-absent, not clean. ' +
  'Metadata only — no prompt/response content.';

const num = (v) => Number(v ?? 0);
const iso = (v) => (v ? new Date(v).toISOString() : null);

function envInt(name, fallback) {
  const raw = process.env[name];
  if (raw == null || raw === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
}

function envFloat(name, fallback) {
  const raw = process.env[name];
  if (raw == null || raw === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function parseDays(q, def = DEFAULT_WINDOW_DAYS) {
  const d = Number(q?.days ?? def);
  if (!Number.isFinite(d) || d < 1) return def;
  return Math.min(Math.floor(d), MAX_WINDOW_DAYS);
}

/**
 * Resolve the desired (current) enforce policy_hash for "current bundle" claims.
 * Order: env → packaged enforce JSON → null (then "any loaded enforce" counts).
 */
export function resolveDesiredPolicy({
  env = process.env,
  readFile = readFileSync,
  exists = existsSync,
  filePath,
} = {}) {
  const fromEnv = env.AIM_ENFORCEMENT_DESIRED_POLICY_HASH
    || env.ENFORCEMENT_DESIRED_POLICY_HASH
    || '';
  if (fromEnv && String(fromEnv).trim()) {
    return {
      policyHash: String(fromEnv).trim().slice(0, 64),
      mode: 'enforce',
      source: 'env',
    };
  }
  const path = filePath
    || env.AIM_ENFORCEMENT_DESIRED_FILE
    || join(REPO_ROOT, 'deploy', 'enforcement', 'enforcement.enforce.json');
  if (exists(path)) {
    try {
      const raw = readFile(path, 'utf8');
      const j = JSON.parse(raw);
      const h = typeof j.policy_hash === 'string' ? j.policy_hash.slice(0, 64) : null;
      if (h) {
        return {
          policyHash: h,
          mode: j.mode === 'shadow' ? 'shadow' : 'enforce',
          source: path,
        };
      }
    } catch {
      // fall through
    }
  }
  return { policyHash: null, mode: 'enforce', source: 'unconfigured' };
}

/**
 * Classify one host's latest posture into an operator-facing reason.
 * Pure — unit-tested without a DB.
 *
 * @param {{ policy?: string|null, mode?: string|null, policyHash?: string|null, aware?: boolean }} posture
 * @param {{ policyHash?: string|null }} desired
 */
export function classifyHostPosture(posture, desired = {}) {
  const policy = posture?.policy ?? null;
  const mode = posture?.mode ?? null;
  const hash = posture?.policyHash ?? null;
  const desiredHash = desired?.policyHash ?? null;

  if (!posture?.aware && policy == null) {
    return {
      canEnforce: false,
      current: false,
      reason: 'pre_aim110',
      label: 'No posture marker (earlier collector or non-endpoint source)',
    };
  }
  if (policy !== 'loaded') {
    return {
      canEnforce: false,
      current: false,
      reason: 'no_bundle',
      label: 'No enforcement.json bundle loaded — fail-open',
    };
  }
  if (mode !== 'enforce') {
    return {
      canEnforce: false,
      current: false,
      reason: 'shadow_mode',
      label: 'Bundle loaded but mode is shadow (would_block only)',
    };
  }
  if (hash && String(hash).startsWith(SHADOW_BAKE_PREFIX)) {
    return {
      canEnforce: false,
      current: false,
      reason: 'stale_shadow_bake',
      label: 'Stale shadow bake still installed',
    };
  }
  if (desiredHash && hash !== desiredHash) {
    return {
      canEnforce: true,
      current: false,
      reason: 'stale_bundle',
      label: `Enforce mode but policy_hash is not current (want ${desiredHash})`,
    };
  }
  return {
    canEnforce: true,
    current: true,
    reason: 'current',
    label: desiredHash
      ? 'Loaded enforce bundle matches desired policy_hash'
      : 'Loaded enforce bundle (desired hash not configured)',
  };
}

/**
 * Honor rate for a disposition bag.
 * honor = blocked / (blocked + would_block); null when no decisions.
 * breakGlass = confirmed / (blocked + confirmed); null when none.
 */
export function honorMetrics({ blocked = 0, would_block = 0, confirmed = 0 } = {}) {
  const b = Math.max(0, num(blocked));
  const w = Math.max(0, num(would_block));
  const c = Math.max(0, num(confirmed));
  const denom = b + w;
  const bgDenom = b + c;
  return {
    blocked: b,
    wouldBlock: w,
    confirmed: c,
    decisions: denom,
    honorRate: denom > 0 ? Math.round((b / denom) * 10000) / 10000 : null,
    breakGlassRate: bgDenom > 0 ? Math.round((c / bgDenom) * 10000) / 10000 : null,
  };
}

/**
 * Pure install-coverage rollup from per-host classifications + enrolled count.
 */
export function installCoverageSummary(hosts, {
  enrolledDevices = 0,
  desired = {},
  minCoveragePct = DEFAULT_MIN_COVERAGE_PCT,
} = {}) {
  const reporting = hosts.length;
  let postureAware = 0;
  let bundleLoaded = 0;
  let enforceMode = 0;
  let currentBundle = 0;
  let canEnforce = 0;
  let failOpen = 0;

  for (const h of hosts) {
    if (h.aware || h.policy) postureAware += 1;
    if (h.policy === 'loaded') bundleLoaded += 1;
    if (h.policy === 'loaded' && h.mode === 'enforce') enforceMode += 1;
    if (h.classification?.current) currentBundle += 1;
    if (h.classification?.canEnforce) canEnforce += 1;
    if (!h.classification?.canEnforce) failOpen += 1;
  }

  // Primary pilot metric: current enforce bundle among reporting hosts.
  // When desired hash is unconfigured, "current" == canEnforce (any enforce load).
  const covered = desired?.policyHash ? currentBundle : canEnforce;
  const coveragePct = reporting > 0
    ? Math.round((covered / reporting) * 1000) / 10
    : null;
  // Enrolled denominator is informative only — host_ref ↛ host_id.
  const enrolledCoveragePct = enrolledDevices > 0
    ? Math.round((covered / enrolledDevices) * 1000) / 10
    : null;

  const sloMet = coveragePct == null
    ? null
    : (reporting === 0 ? null : coveragePct >= minCoveragePct);

  return {
    enrolledDevices: num(enrolledDevices),
    reportingHosts: reporting,
    postureAwareHosts: postureAware,
    bundleLoadedHosts: bundleLoaded,
    enforceModeHosts: enforceMode,
    currentBundleHosts: currentBundle,
    canEnforceHosts: canEnforce,
    failOpenHosts: failOpen,
    coveragePct,
    enrolledCoveragePct,
    slo: {
      minCoveragePct,
      met: sloMet,
      metric: desired?.policyHash
        ? 'current_bundle_hosts / reporting_hosts'
        : 'can_enforce_hosts / reporting_hosts',
    },
  };
}

/**
 * Pure alert candidates for pilot SLOs.
 * @returns {Array<{kind: string, severity: string, message: string, labels: object}>}
 */
export function enforceCoverageAlerts({
  install,
  honor,
  minCoveragePct = DEFAULT_MIN_COVERAGE_PCT,
  minHonorRate = DEFAULT_MIN_HONOR_RATE,
  honorMinDecisions = DEFAULT_HONOR_MIN_DECISIONS,
} = {}) {
  const alerts = [];
  if (install?.reportingHosts === 0 && install?.enrolledDevices > 0) {
    alerts.push({
      kind: 'enforce_coverage_dark',
      severity: 'high',
      message: `${install.enrolledDevices} enrolled device(s) but zero reporting hosts with telemetry in the window — enforce coverage is dark, not clean.`,
      labels: {
        enrolled: String(install.enrolledDevices),
        reporting: '0',
      },
    });
  } else if (
    install?.coveragePct != null
    && install.reportingHosts > 0
    && install.coveragePct < minCoveragePct
  ) {
    alerts.push({
      kind: 'enforce_coverage_below_slo',
      severity: install.coveragePct < minCoveragePct / 2 ? 'high' : 'medium',
      message: `Enforce install coverage ${install.coveragePct}% of reporting hosts is below pilot SLO ${minCoveragePct}% `
        + `(${install.canEnforceHosts}/${install.reportingHosts} can enforce; ${install.failOpenHosts} fail-open).`,
      labels: {
        coverage_pct: String(install.coveragePct),
        slo_pct: String(minCoveragePct),
        fail_open: String(install.failOpenHosts),
        can_enforce: String(install.canEnforceHosts),
      },
    });
  }

  if (
    honor?.honorRate != null
    && honor.decisions >= honorMinDecisions
    && honor.honorRate < minHonorRate
  ) {
    alerts.push({
      kind: 'enforce_honor_rate_below_slo',
      severity: honor.honorRate < 0.5 ? 'high' : 'medium',
      message: `Enforce honor rate ${(honor.honorRate * 100).toFixed(1)}% is below pilot SLO ${(minHonorRate * 100).toFixed(0)}% `
        + `(${honor.blocked} blocked / ${honor.wouldBlock} would_block — would_block under enforce means fail-open or delivery skew).`,
      labels: {
        honor_rate: String(honor.honorRate),
        slo: String(minHonorRate),
        blocked: String(honor.blocked),
        would_block: String(honor.wouldBlock),
      },
    });
  }

  return alerts;
}

/**
 * Map coverage alerts → system-status tile state.
 * Pure so status assembly does not need the full inventory.
 */
export function tileEnforceCoverage(summary, {
  minCoveragePct = DEFAULT_MIN_COVERAGE_PCT,
} = {}) {
  const slo = {
    text: `≥${minCoveragePct}% of reporting hosts carry a loaded enforce enforcement.json (pilot SLO)`,
    minCoveragePct,
  };
  if (!summary) {
    return {
      id: 'enforce_coverage',
      pillar: 'aim',
      title: 'Fleet enforce coverage',
      state: 'never_configured',
      breach: true,
      slo,
      value: null,
      message: 'Enforce coverage summary unavailable',
    };
  }
  const {
    enrolledDevices = 0,
    reportingHosts = 0,
    canEnforceHosts = 0,
    failOpenHosts = 0,
    coveragePct = null,
    currentBundleHosts = 0,
  } = summary;
  const value = {
    enrolledDevices,
    reportingHosts,
    canEnforceHosts,
    currentBundleHosts,
    failOpenHosts,
    coveragePct,
  };
  if (enrolledDevices === 0 && reportingHosts === 0) {
    return {
      id: 'enforce_coverage',
      pillar: 'aim',
      title: 'Fleet enforce coverage',
      state: 'never_configured',
      breach: true,
      slo,
      value,
      message: 'No enrolled devices and no reporting hosts — enforce coverage undefined',
    };
  }
  if (reportingHosts === 0) {
    return {
      id: 'enforce_coverage',
      pillar: 'aim',
      title: 'Fleet enforce coverage',
      state: 'broken',
      breach: true,
      slo,
      value,
      message: `${enrolledDevices} enrolled but no hosts reported posture in the window — dark, not clean`,
    };
  }
  if (coveragePct == null) {
    return {
      id: 'enforce_coverage',
      pillar: 'aim',
      title: 'Fleet enforce coverage',
      state: 'degraded',
      breach: true,
      slo,
      value,
      message: 'Coverage percentage unavailable',
    };
  }
  if (coveragePct < minCoveragePct) {
    const state = coveragePct < minCoveragePct / 2 ? 'broken' : 'degraded';
    return {
      id: 'enforce_coverage',
      pillar: 'aim',
      title: 'Fleet enforce coverage',
      state,
      breach: true,
      slo,
      value,
      message: `${coveragePct}% of reporting hosts can enforce (SLO ≥${minCoveragePct}%); ${failOpenHosts} fail-open`,
    };
  }
  return {
    id: 'enforce_coverage',
    pillar: 'aim',
    title: 'Fleet enforce coverage',
    state: 'ok',
    breach: false,
    slo,
    value,
    message: `${canEnforceHosts}/${reportingHosts} reporting hosts can enforce (${coveragePct}%)`,
  };
}

/**
 * Build per-host rows from raw SQL aggregates, classify, and assemble response body.
 * Pure core of GET /api/enforcement/fleet-coverage.
 */
export function assembleEnforceCoverage({
  hostRows = [],
  dispositionRows = [],
  enrolledDevices = 0,
  desired = { policyHash: null, mode: 'enforce', source: 'unconfigured' },
  window = {},
  now = new Date(),
  minCoveragePct = DEFAULT_MIN_COVERAGE_PCT,
  minHonorRate = DEFAULT_MIN_HONOR_RATE,
  honorMinDecisions = DEFAULT_HONOR_MIN_DECISIONS,
  maxInventory = MAX_INVENTORY,
} = {}) {
  const hosts = hostRows.map((r) => {
    const policy = r.policy ?? null;
    const mode = r.mode ?? null;
    const policyHash = r.policy_hash ?? r.policyHash ?? null;
    const aware = Boolean(r.aware ?? (policy != null));
    const classification = classifyHostPosture(
      { policy, mode, policyHash, aware },
      desired,
    );
    const dispositions = honorMetrics({
      blocked: r.blocked,
      would_block: r.would_block ?? r.wouldBlock,
      confirmed: r.confirmed,
    });
    return {
      hostRef: String(r.host_ref ?? r.hostRef),
      policy,
      mode,
      policyHash,
      aware,
      events: num(r.events),
      lastEventAt: iso(r.last_event_at ?? r.lastEventAt),
      classification,
      canEnforce: classification.canEnforce,
      current: classification.current,
      failOpenReason: classification.canEnforce ? null : classification.reason,
      dispositions,
    };
  });

  // Sort: fail-open first (SOC attention), then by lastEventAt desc.
  hosts.sort((a, b) => {
    const af = a.canEnforce ? 1 : 0;
    const bf = b.canEnforce ? 1 : 0;
    if (af !== bf) return af - bf;
    const at = a.lastEventAt ? Date.parse(a.lastEventAt) : 0;
    const bt = b.lastEventAt ? Date.parse(b.lastEventAt) : 0;
    return bt - at;
  });

  const install = installCoverageSummary(hosts, {
    enrolledDevices,
    desired,
    minCoveragePct,
  });

  // Global + per-rule honor rates from disposition rows.
  const totals = { blocked: 0, would_block: 0, confirmed: 0 };
  const byRuleMap = new Map();
  for (const r of dispositionRows) {
    const action = r.action;
    const n = num(r.n ?? r.count);
    if (action === 'blocked' || action === 'would_block' || action === 'confirmed') {
      totals[action] += n;
    }
    const ruleId = r.rule_id ?? r.ruleId ?? '(unknown)';
    const policyHash = r.policy_hash ?? r.policyHash ?? null;
    const key = `${ruleId}\0${policyHash ?? ''}`;
    if (!byRuleMap.has(key)) {
      byRuleMap.set(key, {
        ruleId,
        policyHash,
        blocked: 0,
        would_block: 0,
        confirmed: 0,
      });
    }
    const bag = byRuleMap.get(key);
    if (action === 'blocked' || action === 'would_block' || action === 'confirmed') {
      bag[action] += n;
    }
  }
  const honor = honorMetrics(totals);
  honor.slo = {
    minHonorRate,
    minDecisions: honorMinDecisions,
    met: honor.honorRate == null || honor.decisions < honorMinDecisions
      ? null
      : honor.honorRate >= minHonorRate,
  };
  honor.byRule = [...byRuleMap.values()]
    .map((bag) => ({
      ruleId: bag.ruleId,
      policyHash: bag.policyHash,
      ...honorMetrics(bag),
    }))
    .sort((a, b) => b.decisions - a.decisions || a.ruleId.localeCompare(b.ruleId));

  const alerts = enforceCoverageAlerts({
    install,
    honor,
    minCoveragePct,
    minHonorRate,
    honorMinDecisions,
  });

  const failOpenInventory = hosts
    .filter((h) => !h.canEnforce)
    .slice(0, maxInventory)
    .map((h) => ({
      hostRef: h.hostRef,
      reason: h.failOpenReason,
      label: h.classification.label,
      policy: h.policy,
      mode: h.mode,
      policyHash: h.policyHash,
      events: h.events,
      lastEventAt: h.lastEventAt,
    }));

  const whoCanEnforce = hosts
    .filter((h) => h.canEnforce)
    .slice(0, maxInventory)
    .map((h) => ({
      hostRef: h.hostRef,
      current: h.current,
      mode: h.mode,
      policyHash: h.policyHash,
      events: h.events,
      lastEventAt: h.lastEventAt,
      blocked: h.dispositions.blocked,
      wouldBlock: h.dispositions.wouldBlock,
      confirmed: h.dispositions.confirmed,
    }));

  const generatedAt = now instanceof Date ? now.toISOString() : String(now);

  return {
    generatedAt,
    lastVerifiedAt: generatedAt,
    window: {
      days: window.days ?? DEFAULT_WINDOW_DAYS,
      from: window.from ?? null,
      to: window.to ?? generatedAt,
    },
    desiredPolicy: {
      policyHash: desired.policyHash ?? null,
      mode: desired.mode ?? 'enforce',
      source: desired.source ?? 'unconfigured',
    },
    install: {
      ...install,
      note:
        'coveragePct = hosts that can enforce (loaded + mode=enforce'
        + (desired.policyHash ? ' + current policy_hash' : '')
        + ') / reporting hosts with endpoint events in the window. '
        + 'enrolledCoveragePct uses enrolled device count as denominator but host_ref '
        + 'does not join devices.host_id — treat it as a lower-bound signal only.',
    },
    honorRate: {
      ...honor,
      note:
        'honorRate = blocked/(blocked+would_block). Under mode=enforce, would_block '
        + 'should be ~0; residual would_block is fail-open or a host still on shadow/stale. '
        + 'breakGlassRate = confirmed/(blocked+confirmed) for secret override resubmits.',
    },
    failOpenInventory,
    whoCanEnforce,
    hosts: hosts.slice(0, maxInventory).map((h) => ({
      hostRef: h.hostRef,
      canEnforce: h.canEnforce,
      current: h.current,
      reason: h.classification.reason,
      label: h.classification.label,
      policy: h.policy,
      mode: h.mode,
      policyHash: h.policyHash,
      events: h.events,
      lastEventAt: h.lastEventAt,
      blocked: h.dispositions.blocked,
      wouldBlock: h.dispositions.wouldBlock,
      confirmed: h.dispositions.confirmed,
    })),
    alerts,
    truncated: hosts.length > maxInventory,
    note: NOTE,
  };
}

/**
 * Load raw rows and assemble. Separated so system-status can reuse a lighter path.
 */
export async function loadEnforceCoverage(db, {
  days = DEFAULT_WINDOW_DAYS,
  now = new Date(),
  desired,
  minCoveragePct,
  minHonorRate,
  honorMinDecisions,
} = {}) {
  const windowDays = Math.min(Math.max(1, Math.floor(days)), MAX_WINDOW_DAYS);
  const to = now instanceof Date ? now : new Date(now);
  const from = new Date(to.getTime() - windowDays * 24 * 60 * 60 * 1000);
  const desiredPolicy = desired ?? resolveDesiredPolicy();
  const minCov = minCoveragePct
    ?? envInt('ENFORCE_COVERAGE_MIN_PCT', DEFAULT_MIN_COVERAGE_PCT);
  const minHon = minHonorRate
    ?? envFloat('ENFORCE_HONOR_MIN_RATE', DEFAULT_MIN_HONOR_RATE);
  const honFloor = honorMinDecisions
    ?? envInt('ENFORCE_HONOR_MIN_DECISIONS', DEFAULT_HONOR_MIN_DECISIONS);

  const [enrolledRes, hostRes, dispRes] = await Promise.all([
    db.query(
      `SELECT COUNT(*)::int AS n FROM devices WHERE revoked_at IS NULL`,
    ),
    // One row per host_ref: dominant posture from the most recent event that
    // carries enforcement_posture; fall back to "aware=false" for hosts that
    // only sent pre-posture events. Disposition counts ride the same host.
    db.query(
      `WITH windowed AS (
         SELECT host_ref,
                ts,
                received_at,
                payload->'enforcement_posture' AS posture,
                payload->'enforcement' AS enf
           FROM events
          WHERE ts >= $1 AND ts < $2
            AND source = 'endpoint'
       ),
       latest_posture AS (
         SELECT DISTINCT ON (host_ref)
                host_ref,
                posture->>'policy' AS policy,
                posture->>'mode' AS mode,
                posture->>'policy_hash' AS policy_hash,
                (posture IS NOT NULL) AS aware,
                COALESCE(received_at, ts) AS last_event_at
           FROM windowed
          WHERE posture IS NOT NULL
          ORDER BY host_ref, COALESCE(received_at, ts) DESC
       ),
       host_events AS (
         SELECT host_ref,
                COUNT(*)::int AS events,
                MAX(COALESCE(received_at, ts)) AS last_event_at
           FROM windowed
          GROUP BY host_ref
       ),
       host_disp AS (
         SELECT host_ref,
                COUNT(*) FILTER (WHERE enf->>'action' = 'blocked')::int AS blocked,
                COUNT(*) FILTER (WHERE enf->>'action' = 'would_block')::int AS would_block,
                COUNT(*) FILTER (WHERE enf->>'action' = 'confirmed')::int AS confirmed
           FROM windowed
          WHERE enf IS NOT NULL
          GROUP BY host_ref
       )
       SELECT he.host_ref,
              he.events,
              he.last_event_at,
              lp.policy,
              lp.mode,
              lp.policy_hash,
              COALESCE(lp.aware, false) AS aware,
              COALESCE(hd.blocked, 0) AS blocked,
              COALESCE(hd.would_block, 0) AS would_block,
              COALESCE(hd.confirmed, 0) AS confirmed
         FROM host_events he
         LEFT JOIN latest_posture lp ON lp.host_ref = he.host_ref
         LEFT JOIN host_disp hd ON hd.host_ref = he.host_ref
        ORDER BY he.host_ref`,
      [from.toISOString(), to.toISOString()],
    ),
    db.query(
      `SELECT payload->'enforcement'->>'action' AS action,
              payload->'enforcement'->>'rule_id' AS rule_id,
              payload->'enforcement'->>'policy_hash' AS policy_hash,
              COUNT(*)::int AS n
         FROM events
        WHERE ts >= $1 AND ts < $2
          AND source = 'endpoint'
          AND payload ? 'enforcement'
        GROUP BY 1, 2, 3
        ORDER BY 1, 2, 3`,
      [from.toISOString(), to.toISOString()],
    ),
  ]);

  return assembleEnforceCoverage({
    hostRows: hostRes.rows,
    dispositionRows: dispRes.rows,
    enrolledDevices: num(enrolledRes.rows[0]?.n),
    desired: desiredPolicy,
    window: {
      days: windowDays,
      from: from.toISOString(),
      to: to.toISOString(),
    },
    now: to,
    minCoveragePct: minCov,
    minHonorRate: minHon,
    honorMinDecisions: honFloor,
  });
}

/** Lightweight summary for system-status tile (reuses full loader). */
export async function loadEnforceCoverageSummary(db, opts = {}) {
  const full = await loadEnforceCoverage(db, opts);
  return {
    enrolledDevices: full.install.enrolledDevices,
    reportingHosts: full.install.reportingHosts,
    canEnforceHosts: full.install.canEnforceHosts,
    currentBundleHosts: full.install.currentBundleHosts,
    failOpenHosts: full.install.failOpenHosts,
    coveragePct: full.install.coveragePct,
    honorRate: full.honorRate.honorRate,
    alerts: full.alerts,
    lastVerifiedAt: full.lastVerifiedAt,
  };
}

export async function enforcementCoverageRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const gated = requireRoles('admin', 'analyst');

  fastify.get('/api/enforcement/fleet-coverage', async (req, reply) => {
    if (!gated(req, reply)) return reply;
    const days = parseDays(req.query, DEFAULT_WINDOW_DAYS);
    const body = await loadEnforceCoverage(db, { days });
    return body;
  });
}

// Stable alert id helper kept local so this module does not import system-status.
export function stableDedupe(...parts) {
  return createHash('sha256').update(parts.join('|')).digest('hex');
}

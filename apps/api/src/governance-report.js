// Executive AI-governance report — report builder, renderers, diff.
//
// Answers "what did AI tools do last month?" as a stored, hashed, diffable
// artifact instead of a dashboard screenshot:
//
//   * usage by team/tool/model (events, sessions, users, tokens, cost),
//   * policy violations with their disposition trail (triage transitions by
//     actor, endpoint enforcement actions by rule + policy hash),
//   * the coverage statement — devices reporting vs enrolled vs dark, tool
//     coverage, feed freshness — so the report cannot overclaim. The
//     green-when-blind rule applies to reporting itself: when the feed is
//     stale or enforcement posture coverage is missing, the report says
//     BLIND rather than presenting zeros as clean numbers.
//   * spend estimate (list prices, same COST_SQL as the dashboards).
//
// Everything is aggregated from stored events/findings/devices — no new
// collection. Per-person rows are deliberately absent (privacy gate: those
// stay behind the analyst+ aggregate API); the report carries org-level
// breakdowns only.
//
// Pure functions where possible: buildReport takes an injected db, the
// renderers and diffReports are deterministic pure functions of the report
// JSON so stored reports re-render and diff identically forever.

import { COST_SQL } from './pricing.js';
import { listSanctionedToolNames } from './sanctioned.js';
import { hashEvidencePayload } from './compliance-bundle.js';

export const REPORT_KIND = 'aim-governance-report';
export const REPORT_VERSION = 1;

// Seal the report: content hash over the pre-hash payload (same canonical
// construction as compliance evidence bundles), then stamp reportHash so the
// rendered HTML/PDF carry a stable identifier.
export function sealReport(report) {
  const reportHash = hashEvidencePayload({
    kind: REPORT_KIND,
    version: report.version,
    period: report.period,
    headline: report.headline,
    usage: report.usage,
    violations: report.violations,
    enforcementPosture: report.enforcementPosture,
    coverage: report.coverage,
    spend: report.spend,
    blind: report.blind,
    blindReasons: report.blindReasons,
    provenance: report.provenance,
  });
  return { ...report, reportHash };
}

const DAY_MS = 86400_000;
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const STATUSES = ['new', 'acknowledged', 'resolved', 'false_positive'];
const OPEN_STATUSES = new Set(['new', 'acknowledged']);

const num = (v) => Number(v ?? 0);
const money = (v) => Math.round(num(v) * 100) / 100;
const iso = (v) => (v ? new Date(v).toISOString() : null);

// Fleet health semantics mirror routes/fleet.js (healthy ≤1x the device's own
// heartbeat interval, stale ≤3x, dead beyond, never_seen without a heartbeat).
function deviceHealth(lastHeartbeat, intervalSec, nowMs) {
  if (!lastHeartbeat) return 'never_seen';
  const ageSec = (nowMs - new Date(lastHeartbeat).getTime()) / 1000;
  if (ageSec <= intervalSec) return 'healthy';
  if (ageSec <= intervalSec * 3) return 'stale';
  return 'dead';
}

/* ---------------- builder ---------------- */

// deps: { db, verifyChain, getAuditHead, now } — all injectable for tests.
export async function buildReport(period, deps) {
  const { db } = deps;
  const now = deps.now ?? new Date();
  const p = [period.from, period.to];
  // live allow-list (not the process-boot seed).
  const sanctionedTools = new Set(await listSanctionedToolNames(db));

  const [
    totalsRes, byToolRes, byModelRes, byTeamRes,
    findingsRes, transitionsRes, enforcementRes, postureRes,
    devicesRes, feedRes,
  ] = await Promise.all([
    db.query(
      `SELECT COUNT(*)::int AS events, COUNT(DISTINCT e.session_id)::int AS sessions,
              COUNT(DISTINCT e.user_ref)::int AS users, COUNT(DISTINCT e.host_ref)::int AS hosts,
              COALESCE(SUM(e.tokens_in), 0) AS tokens_in, COALESCE(SUM(e.tokens_out), 0) AS tokens_out,
              COALESCE(SUM(${COST_SQL}), 0) AS cost
         FROM events e WHERE e.ts >= $1 AND e.ts < $2`, p),
    db.query(
      `SELECT e.tool AS key, COUNT(*)::int AS events, COUNT(DISTINCT e.user_ref)::int AS users,
              COALESCE(SUM(e.tokens_in + e.tokens_out), 0) AS tokens, COALESCE(SUM(${COST_SQL}), 0) AS cost
         FROM events e WHERE e.ts >= $1 AND e.ts < $2 GROUP BY e.tool ORDER BY cost DESC`, p),
    db.query(
      `SELECT COALESCE(e.model, 'unknown') AS key, COUNT(*)::int AS events,
              COALESCE(SUM(e.tokens_in + e.tokens_out), 0) AS tokens, COALESCE(SUM(${COST_SQL}), 0) AS cost
         FROM events e WHERE e.ts >= $1 AND e.ts < $2 GROUP BY COALESCE(e.model, 'unknown') ORDER BY cost DESC`, p),
    db.query(
      `SELECT COALESCE(e.team, '(unattributed)') AS key, COUNT(*)::int AS events, COUNT(DISTINCT e.user_ref)::int AS users,
              COALESCE(SUM(${COST_SQL}), 0) AS cost
         FROM events e WHERE e.ts >= $1 AND e.ts < $2 GROUP BY COALESCE(e.team, '(unattributed)') ORDER BY cost DESC`, p),
    db.query(
      `SELECT rule_id, severity, status, policy_hash, COUNT(*)::int AS n
         FROM findings WHERE detected_at >= $1 AND detected_at < $2
        GROUP BY rule_id, severity, status, policy_hash`, p),
    db.query(
      `SELECT to_status, COUNT(*)::int AS n, COUNT(DISTINCT actor)::int AS actors,
              COUNT(*) FILTER (WHERE reason IS NOT NULL)::int AS with_reason
         FROM finding_transitions WHERE created_at >= $1 AND created_at < $2
        GROUP BY to_status`, p),
    db.query(
      `SELECT payload->'enforcement'->>'action' AS action,
              payload->'enforcement'->>'rule_id' AS rule_id,
              payload->'enforcement'->>'policy_hash' AS policy_hash,
              COUNT(*)::int AS n
         FROM events WHERE ts >= $1 AND ts < $2 AND payload ? 'enforcement'
        GROUP BY 1, 2, 3 ORDER BY 1, 2, 3`, p),
    db.query(
      `SELECT COUNT(*)::int AS events_total,
              COUNT(*) FILTER (WHERE payload->'enforcement_posture'->>'policy' = 'loaded')::int AS posture_loaded,
              COUNT(*) FILTER (WHERE payload->'enforcement_posture'->>'evaluated' = 'true')::int AS evaluated
         FROM events WHERE ts >= $1 AND ts < $2`, p),
    db.query(
      `SELECT device_id, last_heartbeat_at, heartbeat_interval_sec
         FROM devices WHERE revoked_at IS NULL`, []),
    db.query(
      `SELECT max(received_at) AS last_received,
              EXTRACT(EPOCH FROM (now() - max(received_at))) AS age_seconds
         FROM events`, []),
  ]);

  /* ---- usage ---- */
  const t = totalsRes.rows[0] ?? {};
  const byTool = byToolRes.rows.map((r) => ({ tool: r.key, events: num(r.events), users: num(r.users), tokens: num(r.tokens), costUsd: money(r.cost) }));
  const byModel = byModelRes.rows.map((r) => ({ model: r.key, events: num(r.events), tokens: num(r.tokens), costUsd: money(r.cost) }));
  const byTeam = byTeamRes.rows.map((r) => ({ team: r.key, events: num(r.events), users: num(r.users), costUsd: money(r.cost) }));

  /* ---- violations + disposition trail ---- */
  const ruleMap = new Map();
  const currentStatus = Object.fromEntries(STATUSES.map((s) => [s, 0]));
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const r of findingsRes.rows) {
    currentStatus[r.status] = (currentStatus[r.status] ?? 0) + num(r.n);
    bySeverity[r.severity] = (bySeverity[r.severity] ?? 0) + num(r.n);
    // Key by rule + policy so the disposition trail answers "by which policy".
    const mapKey = `${r.rule_id}\0${r.policy_hash ?? ''}`;
    if (!ruleMap.has(mapKey)) {
      ruleMap.set(mapKey, {
        ruleId: r.rule_id,
        policyHash: r.policy_hash ?? null,
        total: 0,
        open: 0,
        bySeverity: Object.fromEntries(SEVERITIES.map((s) => [s, 0])),
        byStatus: {},
      });
    }
    const rule = ruleMap.get(mapKey);
    rule.total += num(r.n);
    if (OPEN_STATUSES.has(r.status)) rule.open += num(r.n);
    rule.bySeverity[r.severity] = (rule.bySeverity[r.severity] ?? 0) + num(r.n);
    rule.byStatus[r.status] = (rule.byStatus[r.status] ?? 0) + num(r.n);
  }
  const byRule = [...ruleMap.values()].sort((a, b) => b.total - a.total || a.ruleId.localeCompare(b.ruleId)
    || String(a.policyHash ?? '').localeCompare(String(b.policyHash ?? '')));
  const findingsTotal = byRule.reduce((a, r) => a + r.total, 0);
  const findingsOpen = byRule.reduce((a, r) => a + r.open, 0);

  const transitions = transitionsRes.rows.map((r) => ({
    toStatus: r.to_status, count: num(r.n), distinctActors: num(r.actors), withReason: num(r.with_reason),
  }));

  const enforcementActions = enforcementRes.rows.map((r) => ({
    action: r.action,
    ruleId: r.rule_id,
    policyHash: r.policy_hash ?? null,
    count: num(r.n),
  }));
  const enforcementTotals = { blocked: 0, would_block: 0, confirmed: 0 };
  for (const a of enforcementActions) enforcementTotals[a.action] = (enforcementTotals[a.action] ?? 0) + a.count;

  // Enforcement coverage denominator (doctrine): zero blocks is only
  // a clean number when endpoints actually ran a policy bundle.
  const postureRow = postureRes.rows[0] ?? {};
  const posture = {
    eventsTotal: num(postureRow.events_total),
    postureLoaded: num(postureRow.posture_loaded),
    evaluated: num(postureRow.evaluated),
  };
  const enforcementCovered = posture.postureLoaded > 0;

  /* ---- coverage truth ---- */
  const nowMs = now.getTime();
  const health = { healthy: 0, stale: 0, dead: 0, never_seen: 0 };
  for (const d of devicesRes.rows) {
    health[deviceHealth(d.last_heartbeat_at, num(d.heartbeat_interval_sec) || 300, nowMs)] += 1;
  }
  const enrolled = devicesRes.rows.length;
  const reporting = health.healthy + health.stale;
  const devicesDark = health.dead + health.never_seen;

  const seenTools = new Set(byTool.map((r) => r.tool));
  const knownTools = new Set([...seenTools, ...sanctionedTools]);
  const darkTools = [...knownTools].filter((tool) => !seenTools.has(tool)).sort();

  const feedRow = feedRes.rows[0] ?? {};
  const feedAgeSeconds = feedRow.age_seconds == null ? null : Math.max(0, Math.round(num(feedRow.age_seconds)));
  // A report covering days is blind when the feed itself has been silent for
  // longer than the report's own smallest meaningful bucket (1 day).
  const feedStale = feedAgeSeconds == null ? true : feedAgeSeconds > DAY_MS / 1000;

  /* ---- blind flags: green-when-blind applied to the report itself ---- */
  const blindReasons = [];
  if (feedStale) blindReasons.push('ingest feed stale at generation time — period numbers may be incomplete');
  if (enrolled > 0 && reporting === 0) blindReasons.push('no enrolled device is reporting — fleet numbers are dark, not zero');
  if (!enforcementCovered) blindReasons.push('no endpoint reported a loaded enforcement policy — zero blocks means no coverage, not a clean fleet');
  const blind = blindReasons.length > 0;

  const auditChain = deps.verifyChain ? deps.verifyChain() : { enabled: false };

  return {
    kind: REPORT_KIND,
    version: REPORT_VERSION,
    generatedAt: now.toISOString(),
    period: { from: period.from.toISOString(), to: period.to.toISOString(), days: Math.round((period.to - period.from) / DAY_MS) },
    blind,
    blindReasons,
    headline: {
      events: num(t.events), sessions: num(t.sessions), users: num(t.users), hosts: num(t.hosts),
      tokensIn: num(t.tokens_in), tokensOut: num(t.tokens_out),
      costUsd: money(t.cost),
      findingsTotal, findingsOpen,
      enforcement: enforcementTotals,
    },
    usage: { byTool, byModel, byTeam },
    violations: {
      total: findingsTotal,
      open: findingsOpen,
      bySeverity,
      currentStatus,
      byRule,
      dispositions: {
        transitions,
        // Endpoint enforcement dispositions, by rule + policy_hash — the
        // "blocked / overridden, by which policy" half of the trail.
        enforcement: enforcementActions,
        // No redacting enforcement surface is deployed; null, not zero.
        redactions: null,
        // Exception workflow is not yet in stored data; null so
        // the report cannot invent a clean "0 exceptions" claim.
        exceptions: null,
        note: 'Triage dispositions from the append-only finding_transitions log (actor + reason). ' +
          'Enforcement dispositions from endpoint enforcement audit records (blocked = denied, would_block = shadow, confirmed = user overrode a challenge) keyed by rule_id + policy_hash. ' +
          'Redactions / exceptions: no redacting surface and no exception-workflow table exist yet in stored data — reported as unknown, never as zero.',
      },
    },
    enforcementPosture: {
      ...posture,
      covered: enforcementCovered,
      note: enforcementCovered
        ? `${posture.postureLoaded}/${posture.eventsTotal} events came from endpoints with a loaded enforcement policy; ${posture.evaluated} ran rule evaluation.`
        : 'No event in this period carried a loaded enforcement-posture marker. Block/override counts above are coverage-absent, not evidence of a clean fleet.',
    },
    coverage: {
      devices: {
        enrolled, reporting, dark: devicesDark,
        byHealth: health,
        hostsSeenInEvents: num(t.hosts),
      },
      tools: {
        known: knownTools.size, covered: seenTools.size, dark: darkTools.length,
        darkItems: darkTools.map((tool) => ({ tool, sanctioned: sanctionedTools.has(tool) })),
      },
      feed: { lastReceivedAt: iso(feedRow.last_received), ageSeconds: feedAgeSeconds, stale: feedStale },
      statement:
        `Fleet: ${reporting} of ${enrolled} enrolled devices reporting (${devicesDark} dark). ` +
        `Tools: ${seenTools.size} of ${knownTools.size} known tools emitted in the period (${darkTools.length} dark). ` +
        'AI usage on devices without a collector is invisible to this report by construction — ' +
        'numbers are a lower bound on true usage, never a claim of complete visibility.',
    },
    spend: {
      totalUsd: money(t.cost),
      byTool: byTool.map((r) => ({ tool: r.tool, costUsd: r.costUsd })),
      byTeam: byTeam.map((r) => ({ team: r.team, costUsd: r.costUsd })),
      note: 'List-price estimate (public per-token prices); actual contracts may differ. Collector-computed cost wins when present.',
    },
    auditChain,
    provenance: 'Aggregated from stored events/findings/devices/enrollment tables only — no new collection. Metadata-only rollups; no prompt or response content.',
  };
}

/* ---------------- diff ---------------- */

function delta(before, after) {
  const b = num(before); const a = num(after);
  const pct = b === 0 ? (a === 0 ? 0 : null) : Math.round(((a - b) / b) * 1000) / 10;
  return { before: b, after: a, delta: a - b, pct };
}

// Structured diff of two stored report JSONs (oldest first reads best, but
// either order works — fields are named before/after).
export function diffReports(before, after) {
  const bh = before.headline ?? {}; const ah = after.headline ?? {};
  const metricKeys = ['events', 'sessions', 'users', 'hosts', 'tokensIn', 'tokensOut', 'costUsd', 'findingsTotal', 'findingsOpen'];
  const headline = Object.fromEntries(metricKeys.map((k) => [k, delta(bh[k], ah[k])]));

  const sev = Object.fromEntries(SEVERITIES.map((s) => [s, delta(before.violations?.bySeverity?.[s], after.violations?.bySeverity?.[s])]));
  const enf = Object.fromEntries(['blocked', 'would_block', 'confirmed'].map((a) => [a, delta(bh.enforcement?.[a], ah.enforcement?.[a])]));

  const movers = (beforeRows, afterRows, keyField, valueField, topN = 5) => {
    const bMap = new Map((beforeRows ?? []).map((r) => [r[keyField], num(r[valueField])]));
    const aMap = new Map((afterRows ?? []).map((r) => [r[keyField], num(r[valueField])]));
    const keys = new Set([...bMap.keys(), ...aMap.keys()]);
    const rows = [...keys].map((k) => ({ key: k, ...delta(bMap.get(k), aMap.get(k)) }));
    const up = rows.filter((r) => r.delta > 0).sort((x, y) => y.delta - x.delta).slice(0, topN);
    const down = rows.filter((r) => r.delta < 0).sort((x, y) => x.delta - y.delta).slice(0, topN);
    return { up, down };
  };

  return {
    kind: 'aim-governance-report-diff',
    version: 1,
    before: { generatedAt: before.generatedAt, period: before.period, hash: before.reportHash ?? null },
    after: { generatedAt: after.generatedAt, period: after.period, hash: after.reportHash ?? null },
    headline,
    violations: { bySeverity: sev, enforcement: enf },
    coverage: {
      devicesEnrolled: delta(before.coverage?.devices?.enrolled, after.coverage?.devices?.enrolled),
      devicesReporting: delta(before.coverage?.devices?.reporting, after.coverage?.devices?.reporting),
      devicesDark: delta(before.coverage?.devices?.dark, after.coverage?.devices?.dark),
      toolsCovered: delta(before.coverage?.tools?.covered, after.coverage?.tools?.covered),
      toolsDark: delta(before.coverage?.tools?.dark, after.coverage?.tools?.dark),
    },
    movers: {
      toolsByEvents: movers(before.usage?.byTool, after.usage?.byTool, 'tool', 'events'),
      teamsByCost: movers(before.usage?.byTeam, after.usage?.byTeam, 'team', 'costUsd'),
    },
  };
}

/* ---------------- HTML renderer ---------------- */

function escapeHtml(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function table(headers, rows) {
  const th = headers.map((h) => `<th>${escapeHtml(h)}</th>`).join('');
  const trs = rows.map((r) => `<tr>${r.map((c) => `<td>${escapeHtml(c)}</td>`).join('')}</tr>`).join('\n');
  return `<table><thead><tr>${th}</tr></thead><tbody>\n${trs}\n</tbody></table>`;
}

// Deterministic pure renderer: same report JSON ⇒ same HTML. Self-contained
// (inline CSS, no external assets) so the stored artifact prints to PDF from
// any browser and survives as a standalone file.
export function renderHtml(report) {
  const h = report.headline;
  const blindBanner = report.blind
    ? `<div class="blind"><strong>BLIND SPOTS — read before the numbers:</strong><ul>${report.blindReasons.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}</ul></div>`
    : '';

  const usageTool = table(['tool', 'events', 'users', 'tokens', 'cost_usd'],
    report.usage.byTool.map((r) => [r.tool, r.events, r.users, r.tokens, r.costUsd.toFixed(2)]));
  const usageModel = table(['model', 'events', 'tokens', 'cost_usd'],
    report.usage.byModel.map((r) => [r.model, r.events, r.tokens, r.costUsd.toFixed(2)]));
  const usageTeam = table(['team', 'events', 'users', 'cost_usd'],
    report.usage.byTeam.map((r) => [r.team, r.events, r.users, r.costUsd.toFixed(2)]));

  const v = report.violations;
  const violRules = v.byRule.length
    ? table(['rule', 'policy', 'total', 'open', ...SEVERITIES, ...STATUSES],
        v.byRule.map((r) => [r.ruleId, r.policyHash ?? '—', r.total, r.open,
          ...SEVERITIES.map((s) => r.bySeverity[s] ?? 0), ...STATUSES.map((s) => r.byStatus[s] ?? 0)]))
    : '<p>No policy violations in this period.</p>';
  const dispositions = v.dispositions.transitions.length
    ? table(['disposition', 'transitions', 'distinct actors', 'with reason'],
        v.dispositions.transitions.map((t) => [t.toStatus, t.count, t.distinctActors, t.withReason]))
    : '<p>No triage transitions in this period.</p>';
  const enforcement = v.dispositions.enforcement.length
    ? table(['action', 'rule', 'policy', 'count'],
        v.dispositions.enforcement.map((e) => [e.action, e.ruleId, e.policyHash ?? '—', e.count]))
    : '<p>No endpoint enforcement actions in this period.</p>';

  const c = report.coverage;
  const darkTools = c.tools.darkItems.length
    ? `<p>Dark tools: ${c.tools.darkItems.map((d) => escapeHtml(d.tool)).join(', ')}</p>` : '';

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>AI Governance Report — ${escapeHtml(report.period.from.slice(0, 10))} to ${escapeHtml(report.period.to.slice(0, 10))}</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:2em auto;max-width:960px;color:#1a1a1a}
h1{font-size:1.5em;border-bottom:2px solid #333;padding-bottom:.3em}
h2{font-size:1.15em;margin-top:1.6em}
table{border-collapse:collapse;width:100%;font-size:.9em;margin:.5em 0}
th,td{border:1px solid #ccc;padding:4px 8px;text-align:left}
th{background:#f0f0f0}
.meta{color:#555;font-size:.85em}
.blind{border:2px solid #b3261e;background:#fdecea;padding:.8em;margin:1em 0}
.coverage{border:1px solid #666;background:#f7f7f7;padding:.8em;margin:1em 0}
.footer{margin-top:2em;font-size:.8em;color:#555;border-top:1px solid #ccc;padding-top:.5em}
@media print{body{margin:0;max-width:none}.blind{break-inside:avoid}}
</style></head><body>
<h1>Executive AI-governance report</h1>
<p class="meta">Period: ${escapeHtml(report.period.from)} → ${escapeHtml(report.period.to)} (${report.period.days} days) ·
Generated: ${escapeHtml(report.generatedAt)} · Report hash: <code>${escapeHtml(report.reportHash ?? 'unhashed')}</code></p>
${blindBanner}
<h2>Headline</h2>
${table(['events', 'sessions', 'users', 'hosts', 'tokens in', 'tokens out', 'spend est. (USD)', 'violations', 'open', 'blocked', 'would-block (shadow)', 'overridden'],
  [[h.events, h.sessions, h.users, h.hosts, h.tokensIn, h.tokensOut, h.costUsd.toFixed(2), h.findingsTotal, h.findingsOpen, h.enforcement.blocked ?? 0, h.enforcement.would_block ?? 0, h.enforcement.confirmed ?? 0]])}
<h2>Coverage statement — what this report can and cannot see</h2>
<div class="coverage"><p>${escapeHtml(c.statement)}</p>${darkTools}
<p>Feed: last event received ${escapeHtml(c.feed.lastReceivedAt ?? 'never')}${c.feed.stale ? ' — <strong>STALE</strong>' : ''}.
Enforcement posture: ${escapeHtml(report.enforcementPosture.note)}</p></div>
<h2>Usage by tool</h2>${usageTool}
<h2>Usage by model</h2>${usageModel}
<h2>Usage by team</h2>${usageTeam}
<h2>Policy violations (${v.total}, ${v.open} open)</h2>${violRules}
<h2>Disposition trail</h2>
<p class="meta">${escapeHtml(v.dispositions.note)}</p>
<h3>Triage transitions</h3>${dispositions}
<h3>Endpoint enforcement dispositions</h3>${enforcement}
<h2>Spend estimate</h2>
<p>Total: $${report.spend.totalUsd.toFixed(2)} — ${escapeHtml(report.spend.note)}</p>
${table(['team', 'cost_usd'], report.spend.byTeam.map((r) => [r.team, r.costUsd.toFixed(2)]))}
<div class="footer">
<p>${escapeHtml(report.provenance)}</p>
<p>Audit chain: ${report.auditChain?.enabled ? (report.auditChain.ok ? `verified (${report.auditChain.records} records)` : `FAILED — ${escapeHtml(report.auditChain.reason ?? 'unknown')}`) : 'not configured'} ·
Retention: one quarter of scheduled reports kept and diffable via /api/governance/reports/:id/diff.</p>
</div>
</body></html>`;
}

/* ---------------- text renderer (for PDF) ---------------- */

const COLS = 96;

function rowLine(cells, widths) {
  return cells.map((c, i) => String(c ?? '').slice(0, widths[i]).padEnd(widths[i])).join(' ').trimEnd();
}

function textTable(headers, rows, widths) {
  const sep = widths.map((w) => '-'.repeat(w)).join(' ');
  return [rowLine(headers, widths), sep, ...rows.map((r) => rowLine(r, widths))];
}

// Plain-text rendering, deterministic, fixed-width — input to the PDF
// renderer. Same numbers as the HTML, per the no-drift rule.
export function renderText(report) {
  const h = report.headline;
  const lines = [];
  const push = (...xs) => lines.push(...xs);

  push(
    'EXECUTIVE AI-GOVERNANCE REPORT',
    `Period: ${report.period.from} -> ${report.period.to} (${report.period.days} days)`,
    `Generated: ${report.generatedAt}`,
    `Report hash: ${report.reportHash ?? 'unhashed'}`,
    '',
  );
  if (report.blind) {
    push('BLIND SPOTS - read before the numbers:');
    for (const r of report.blindReasons) push(`  * ${r}`.slice(0, COLS));
    push('');
  }
  push('HEADLINE',
    ...textTable(
      ['events', 'sessions', 'users', 'hosts', 'tokens_in', 'tokens_out', 'spend_usd', 'violations', 'open', 'blocked', 'would_block', 'overridden'].map((x) => x.slice(0, 11)),
      [[h.events, h.sessions, h.users, h.hosts, h.tokensIn, h.tokensOut, h.costUsd.toFixed(2), h.findingsTotal, h.findingsOpen, h.enforcement.blocked ?? 0, h.enforcement.would_block ?? 0, h.enforcement.confirmed ?? 0]],
      [10, 9, 7, 7, 11, 11, 10, 11, 6, 8, 11, 10],
    ),
    '',
    'COVERAGE STATEMENT');
  // Word-wrap the statement.
  const words = report.coverage.statement.split(' ');
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > COLS) { push(line); line = w; } else line = (line + ' ' + w).trim();
  }
  if (line) push(line);
  push(`Feed: last event ${report.coverage.feed.lastReceivedAt ?? 'never'}${report.coverage.feed.stale ? ' — STALE' : ''}`);
  push(`Enforcement posture: ${report.enforcementPosture.note}`.slice(0, COLS));
  push('', 'USAGE BY TOOL',
    ...textTable(['tool', 'events', 'users', 'tokens', 'cost_usd'],
      report.usage.byTool.map((r) => [r.tool, r.events, r.users, r.tokens, r.costUsd.toFixed(2)]),
      [28, 10, 8, 16, 12]),
    '', 'USAGE BY MODEL',
    ...textTable(['model', 'events', 'tokens', 'cost_usd'],
      report.usage.byModel.map((r) => [r.model, r.events, r.tokens, r.costUsd.toFixed(2)]),
      [32, 10, 16, 12]),
    '', 'USAGE BY TEAM',
    ...textTable(['team', 'events', 'users', 'cost_usd'],
      report.usage.byTeam.map((r) => [r.team, r.events, r.users, r.costUsd.toFixed(2)]),
      [32, 10, 8, 12]),
    '', `POLICY VIOLATIONS (${report.violations.total}, ${report.violations.open} open)`);
  if (report.violations.byRule.length) {
    push(...textTable(['rule', 'policy', 'total', 'open', 'crit', 'high', 'med', 'low'],
      report.violations.byRule.map((r) => [r.ruleId, r.policyHash ?? '-', r.total, r.open, ...SEVERITIES.map((s) => r.bySeverity[s] ?? 0)]),
      [32, 16, 8, 8, 6, 6, 6, 6]));
  } else push('No policy violations in this period.');
  push('', 'DISPOSITION TRAIL');
  if (report.violations.dispositions.transitions.length) {
    push(...textTable(['disposition', 'transitions', 'actors', 'with_reason'],
      report.violations.dispositions.transitions.map((t) => [t.toStatus, t.count, t.distinctActors, t.withReason]),
      [20, 12, 8, 12]));
  } else push('No triage transitions in this period.');
  push('');
  if (report.violations.dispositions.enforcement.length) {
    push(...textTable(['action', 'rule', 'policy', 'count'],
      report.violations.dispositions.enforcement.map((e) => [e.action, e.ruleId, e.policyHash ?? '-', e.count]),
      [14, 32, 16, 8]));
  } else push('No endpoint enforcement actions in this period.');
  push('', `SPEND ESTIMATE: $${report.spend.totalUsd.toFixed(2)} (list-price estimate)`,
    ...textTable(['team', 'cost_usd'], report.spend.byTeam.map((r) => [r.team, r.costUsd.toFixed(2)]), [40, 12]),
    '', report.provenance,
    `Audit chain: ${report.auditChain?.enabled ? (report.auditChain.ok ? `verified (${report.auditChain.records} records)` : 'FAILED') : 'not configured'}`,
  );
  return lines;
}

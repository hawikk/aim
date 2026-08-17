// MCP server / tool-call inventory API (AIM-97 + AIM-505 + AIM-547 + AIM-667).
//
// Two complementary rails feed the catalogue (metadata only — never commands,
// URLs, env, args, or results):
//
//   1. configured — event_type='inventory' (schema v1.2): MCP servers present
//      in a tool's config files. Latest snapshot per (host_ref, tool) is the
//      current config state; a removed server drops out on the next snapshot.
//   2. discovered — event_type='tool_use' (schema v1.1): tool_calls[] entries
//      with action_class='mcp_call' and a non-null mcp_server. Covers live
//      MCP invocations even when config inventory is missing for a collector.
//
// Approval status is evaluated against settings.approved_mcp_servers from the
// same guardrail policy the engine hashes into findings.policy_hash. AIM-441:
// empty allowlist under mcp_allowlist_mode=deny_unlisted is a formal deny-all
// (not open-ended discovery). discoveryMode is only true when mode=discovery.
//
// AIM-547: GET/PUT /api/mcp-allowlist lets analyst+admin manage the allowlist
// without hand-editing core.yaml. Writes land in machine-owned
// mcp-allowlist.yaml (same pattern as ui-overrides.yaml / alerts.yaml) and
// are audited. Endpoint enforce flip stays PR-managed in core.yaml.
//
// Privacy gate: fleet rollup is org-level (any authenticated role). ?server=
// drill-down carries user/host attribution and requires analyst or admin.
import { writeFileSync, renameSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import yaml from 'js-yaml';
import { query } from '../db.js';
import { requireRoles } from '../auth.js';
import { audit } from '../audit.js';
import { loadPolicy, policyPath } from '../guardrail-policy.js';

const ALLOWLIST_FILE = 'mcp-allowlist.yaml';
const ALLOWLIST_HEADER =
  '# Managed by the dashboard MCP allowlist UI (AIM-547). Do not edit by hand —\n' +
  '# changes here are written by PUT /api/mcp-allowlist and audited.\n' +
  '# Merged after core.yaml: settings.approved_mcp_servers (array replace) and\n' +
  '# settings.enforcement.approved_mcp_servers (shallow key on enforcement).\n';

const MCP_NAME_MAX = 128;
const MCP_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._@+/-]{0,127}$/;

function writeYamlAtomic(file, header, data) {
  const tmp = `${file}.tmp-${process.pid}`;
  writeFileSync(tmp, header + yaml.dump(data));
  renameSync(tmp, file);
}

/** Normalize + validate a proposed approved_mcp_servers list. */
export function normalizeMcpAllowlist(raw) {
  if (!Array.isArray(raw)) {
    return { error: 'approvedMcpServers must be an array of server name strings' };
  }
  if (raw.length > 500) {
    return { error: 'approvedMcpServers may contain at most 500 entries' };
  }
  const seen = new Set();
  const out = [];
  for (const item of raw) {
    if (typeof item !== 'string') {
      return { error: 'each approvedMcpServers entry must be a string' };
    }
    const name = item.trim();
    if (!name) continue;
    if (name.length > MCP_NAME_MAX || !MCP_NAME_RE.test(name)) {
      return {
        error:
          `invalid MCP server name '${name.slice(0, 40)}' — use 1–${MCP_NAME_MAX} ` +
          'chars matching [A-Za-z0-9][A-Za-z0-9._@+/-]* (exact id, no wildcards)',
      };
    }
    if (seen.has(name)) continue;
    seen.add(name);
    out.push(name);
  }
  out.sort((a, b) => a.localeCompare(b));
  return { servers: out };
}

function parseDays(q, def = 30, max = 365) {
  const d = Number(q?.days ?? def);
  if (!Number.isFinite(d) || d < 1) return def;
  return Math.min(Math.floor(d), max);
}

const num = (v) => Number(v ?? 0);

const NOTE =
  'Fleet MCP catalogue: configured (latest inventory snapshot per host+tool) ' +
  'union discovered (tool_use mcp_call metadata). Metadata only — server names, ' +
  'tool names, scopes, counts; never commands, URLs, env, args, or results. ' +
  'status is evaluated against settings.approved_mcp_servers in the live ' +
  'guardrail policy (empty deny_unlisted allowlist = all unapproved; AIM-441).';

// Latest config snapshot per (host_ref, tool). $1 = day range.
const LATEST_CTE = `
  WITH latest AS (
    SELECT DISTINCT ON (e.host_ref, e.tool)
           e.host_ref, e.tool, e.user_ref, e.user_pseudonym, e.team, e.ts,
           e.payload -> 'configured_mcp_servers' AS server_list
      FROM events e
     WHERE e.event_type = 'inventory'
       AND e.ts >= now() - ($1 || ' days')::interval
     ORDER BY e.host_ref, e.tool, e.ts DESC
  ),
  sightings AS (
    SELECT srv ->> 'name' AS name, MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen
      FROM events e, LATERAL jsonb_array_elements(e.payload -> 'configured_mcp_servers') AS srv
     WHERE e.event_type = 'inventory'
       AND e.ts >= now() - ($1 || ' days')::interval
     GROUP BY 1
  )`;

// Discovered MCP servers from live tool_use events. $1 = day range.
// mcp_server null (unknown) is excluded from the named catalogue — those still
// fire unapproved-mcp-server findings, but cannot be keyed as inventory rows.
const DISCOVERED_SQL = `
  SELECT tc ->> 'mcp_server'                         AS name,
         ARRAY_AGG(DISTINCT e.tool)                  AS tools,
         ARRAY_AGG(DISTINCT tc ->> 'tool_name')
           FILTER (WHERE tc ->> 'tool_name' IS NOT NULL) AS mcp_tools,
         COUNT(DISTINCT e.host_ref)                  AS hosts,
         COUNT(DISTINCT e.user_ref)                  AS users,
         COALESCE(SUM((tc ->> 'count')::bigint), 0)  AS call_count,
         MIN(e.ts)                                   AS first_seen,
         MAX(e.ts)                                   AS last_seen
    FROM events e,
         LATERAL jsonb_array_elements(
           COALESCE(e.payload -> 'tool_calls', '[]'::jsonb)
         ) AS tc
   WHERE e.event_type = 'tool_use'
     AND e.ts >= now() - ($1 || ' days')::interval
     AND tc ->> 'action_class' = 'mcp_call'
     AND tc ->> 'mcp_server' IS NOT NULL
     AND btrim(tc ->> 'mcp_server') <> ''
   GROUP BY 1`;

function approvalMeta(policyLoader) {
  try {
    const policy = policyLoader();
    const approved = Array.isArray(policy.settings?.approved_mcp_servers)
      ? policy.settings.approved_mcp_servers.filter((s) => typeof s === 'string' && s.trim())
      : [];
    // AIM-441: discovery mode is an explicit setting, not "empty list".
    // Empty list under deny_unlisted is a formal allowlist (deny all).
    const mode = policy.settings?.mcp_allowlist_mode ?? 'deny_unlisted';
    const discoveryMode = mode === 'discovery' && approved.length === 0;
    return {
      contentHash: policy.contentHash,
      approvedMcpServers: approved,
      mcpAllowlistMode: mode,
      discoveryMode,
    };
  } catch {
    // Fail open for inventory display: unknown approval status rather than
    // 500 the whole catalogue when policy files are temporarily unreadable.
    return {
      contentHash: null,
      approvedMcpServers: [],
      mcpAllowlistMode: 'deny_unlisted',
      discoveryMode: false,
      policyLoadError: true,
    };
  }
}

function statusFor(name, meta) {
  // Empty deny-unlisted allowlist: every server is unapproved (active policy).
  // Discovery mode (legacy) also marks everything unapproved for inventory.
  if (meta.discoveryMode || meta.approvedMcpServers.length === 0) return 'unapproved';
  return meta.approvedMcpServers.includes(name) ? 'approved' : 'unapproved';
}

function mergeServerMaps(configuredRows, discoveredRows, meta) {
  const byName = new Map();

  for (const r of configuredRows) {
    const name = r.name;
    if (!name) continue;
    byName.set(name, {
      name,
      status: statusFor(name, meta),
      sources: ['configured'],
      scopes: [...(r.scopes ?? [])].filter(Boolean).sort(),
      tools: [...(r.tools ?? [])].filter(Boolean).sort(),
      mcpTools: [],
      hosts: num(r.hosts),
      users: num(r.users),
      callCount: 0,
      firstSeen: r.first_seen ?? null,
      lastSeen: r.last_seen ?? null,
    });
  }

  for (const r of discoveredRows) {
    const name = r.name;
    if (!name) continue;
    const existing = byName.get(name);
    if (!existing) {
      byName.set(name, {
        name,
        status: statusFor(name, meta),
        sources: ['discovered'],
        scopes: [],
        tools: [...(r.tools ?? [])].filter(Boolean).sort(),
        mcpTools: [...(r.mcp_tools ?? [])].filter(Boolean).sort(),
        hosts: num(r.hosts),
        users: num(r.users),
        callCount: num(r.call_count),
        firstSeen: r.first_seen ?? null,
        lastSeen: r.last_seen ?? null,
      });
      continue;
    }
    if (!existing.sources.includes('discovered')) existing.sources.push('discovered');
    existing.sources.sort();
    const toolSet = new Set([...existing.tools, ...(r.tools ?? []).filter(Boolean)]);
    existing.tools = [...toolSet].sort();
    existing.mcpTools = [...(r.mcp_tools ?? [])].filter(Boolean).sort();
    existing.hosts = Math.max(existing.hosts, num(r.hosts));
    existing.users = Math.max(existing.users, num(r.users));
    existing.callCount = num(r.call_count);
    // earliest first / latest last across both rails
    if (r.first_seen && (!existing.firstSeen || r.first_seen < existing.firstSeen)) {
      existing.firstSeen = r.first_seen;
    }
    if (r.last_seen && (!existing.lastSeen || r.last_seen > existing.lastSeen)) {
      existing.lastSeen = r.last_seen;
    }
  }

  return [...byName.values()].sort((a, b) => {
    if (b.users !== a.users) return b.users - a.users;
    return a.name.localeCompare(b.name);
  });
}

function summarize(servers, configuredSummary) {
  let configured = 0;
  let discoveredOnly = 0;
  let unapproved = 0;
  let approved = 0;
  for (const s of servers) {
    if (s.sources.includes('configured')) configured += 1;
    if (!s.sources.includes('configured') && s.sources.includes('discovered')) {
      discoveredOnly += 1;
    }
    if (s.status === 'approved') approved += 1;
    else unapproved += 1;
  }
  return {
    servers: servers.length,
    configured,
    discoveredOnly,
    unapproved,
    approved,
    hostsReporting: num(configuredSummary?.hosts_reporting),
    newLast7d: num(configuredSummary?.new_last_7d),
  };
}

// opts.db is injectable for tests; opts.loadPolicy injects policy reader.
// opts.policyPath / opts.writeAllowlist let tests redirect the machine-owned file.
export async function mcpRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const resolvedPolicyPath = () => opts?.policyPath ?? policyPath();
  const policyLoader = opts?.loadPolicy
    ?? (() => loadPolicy(resolvedPolicyPath()));
  const writeAllowlist = opts?.writeAllowlist
    ?? ((servers) => {
      const dir = resolvedPolicyPath();
      writeYamlAtomic(join(dir, ALLOWLIST_FILE), ALLOWLIST_HEADER, {
        version: 1,
        settings: {
          approved_mcp_servers: servers,
          // Shallow-merge key under enforcement — does not replace rules.
          enforcement: {
            approved_mcp_servers: servers,
          },
        },
      });
    });
  const anyRole = requireRoles('admin', 'analyst', 'auditor', 'viewer');
  const userLevel = requireRoles('analyst', 'admin');

  // ---- AIM-547: allowlist read/write (analyst can manage) ----------------
  fastify.get('/api/mcp-allowlist', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    let policy;
    try {
      policy = policyLoader();
    } catch (err) {
      return reply.code(500).send({
        error: 'policy_unavailable',
        detail: `could not load guardrail policy: ${err.message}`,
      });
    }
    const approved = Array.isArray(policy.settings?.approved_mcp_servers)
      ? policy.settings.approved_mcp_servers.filter((s) => typeof s === 'string' && s.trim())
      : [];
    const mode = policy.settings?.mcp_allowlist_mode ?? 'deny_unlisted';
    const enf = policy.settings?.enforcement ?? {};
    const mcpRule = enf?.rules?.['unapproved-mcp-server'] ?? {};
    return {
      approvedMcpServers: approved,
      mcpAllowlistMode: mode,
      contentHash: policy.contentHash,
      // Endpoint interrupt posture (policy-as-code). UI shows it; only PRs
      // flip enforce — allowlist writes never change this flag.
      endpointEnforce: mcpRule.enforce === true && enf.mode === 'enforce',
      globalMode: enf.mode ?? null,
      note:
        'deny_unlisted: servers not on this list are unapproved. ' +
        'PUT replaces the full list (machine-owned mcp-allowlist.yaml). ' +
        'Endpoint PreToolUse deny is separate (enforcement.rules.unapproved-mcp-server).',
    };
  });

  // AIM-667: analyst override path — allowlist write is the permanent
  // override of runtime MCP deny. Optional reason + dualControl ride along
  // for full audit (dual control is optional; when present, approver is required).
  fastify.put('/api/mcp-allowlist', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const body = req.body ?? {};
    const allowedKeys = new Set(['approvedMcpServers', 'reason', 'dualControl']);
    const unknown = Object.keys(body).filter((k) => !allowedKeys.has(k));
    if (unknown.length > 0) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: `unknown field(s): ${unknown.join(', ')} (allowed: approvedMcpServers, reason, dualControl)`,
      });
    }
    if (!('approvedMcpServers' in body)) {
      return reply.code(400).send({
        error: 'bad_request',
        detail: 'approvedMcpServers is required (array; use [] to clear)',
      });
    }
    const normalized = normalizeMcpAllowlist(body.approvedMcpServers);
    if (normalized.error) {
      return reply.code(400).send({ error: 'bad_request', detail: normalized.error });
    }

    let reason = null;
    if (body.reason !== undefined && body.reason !== null) {
      if (typeof body.reason !== 'string') {
        return reply.code(400).send({ error: 'bad_request', detail: 'reason must be a string' });
      }
      reason = body.reason.trim() || null;
      if (reason && reason.length > 2000) {
        return reply.code(400).send({ error: 'bad_request', detail: 'reason must be ≤2000 characters' });
      }
    }

    let dualControl = null;
    if (body.dualControl !== undefined && body.dualControl !== null) {
      if (typeof body.dualControl !== 'object' || Array.isArray(body.dualControl)) {
        return reply.code(400).send({ error: 'bad_request', detail: 'dualControl must be an object or null' });
      }
      const dcUnknown = Object.keys(body.dualControl).filter((k) => k !== 'approver');
      if (dcUnknown.length > 0) {
        return reply.code(400).send({
          error: 'bad_request',
          detail: `unknown dualControl field(s): ${dcUnknown.join(', ')} (allowed: approver)`,
        });
      }
      if (typeof body.dualControl.approver !== 'string' || !body.dualControl.approver.trim()) {
        return reply.code(400).send({
          error: 'bad_request',
          detail: 'dualControl.approver is required when dualControl is set (second analyst identity)',
        });
      }
      const approver = body.dualControl.approver.trim();
      if (approver.length > 320) {
        return reply.code(400).send({ error: 'bad_request', detail: 'dualControl.approver must be ≤320 characters' });
      }
      dualControl = { approver };
    }

    let before = [];
    let beforeHash = null;
    try {
      const prior = policyLoader();
      before = Array.isArray(prior.settings?.approved_mcp_servers)
        ? prior.settings.approved_mcp_servers.filter((s) => typeof s === 'string')
        : [];
      beforeHash = prior.contentHash;
    } catch {
      // Still allow write when prior load fails — deploy recovery path.
    }

    try {
      writeAllowlist(normalized.servers);
    } catch (err) {
      req.log?.error?.(err, 'failed to write mcp-allowlist.yaml');
      return reply.code(500).send({
        error: 'policy_write_failed',
        detail: `could not write mcp-allowlist.yaml: ${err.message}`,
      });
    }

    let after;
    try {
      after = policyLoader();
    } catch (err) {
      return reply.code(500).send({
        error: 'policy_unavailable',
        detail: `wrote allowlist but reload failed: ${err.message}`,
      });
    }
    const approved = Array.isArray(after.settings?.approved_mcp_servers)
      ? after.settings.approved_mcp_servers.filter((s) => typeof s === 'string' && s.trim())
      : [];
    const beforeSet = new Set(before);
    const afterSet = new Set(approved);
    const added = approved.filter((s) => !beforeSet.has(s));
    const removed = before.filter((s) => !afterSet.has(s));
    const actor = req.identity?.email ?? 'unknown';
    // Permanent analyst override of runtime MCP deny = allowlist mutation.
    // action name stays mcp.allowlist_update for audit filter continuity; kind
    // distinguishes override-from-deny vs bulk edit when reason/dualControl set.
    audit(actor, 'mcp.allowlist_update', 'guardrail/mcp-allowlist', {
      before,
      after: approved,
      added,
      removed,
      beforeHash,
      afterHash: after.contentHash,
      count: approved.length,
      reason,
      dualControl,
      kind: added.length && !removed.length ? 'override_approve' : removed.length && !added.length ? 'revoke' : 'replace',
    });

    const enf = after.settings?.enforcement ?? {};
    const mcpRule = enf?.rules?.['unapproved-mcp-server'] ?? {};
    return {
      approvedMcpServers: approved,
      mcpAllowlistMode: after.settings?.mcp_allowlist_mode ?? 'deny_unlisted',
      contentHash: after.contentHash,
      previousContentHash: beforeHash,
      endpointEnforce: mcpRule.enforce === true && enf.mode === 'enforce',
      globalMode: enf.mode ?? null,
      added,
      removed,
      reason,
      dualControl,
      // AIM-569: surface actor for the UI status line (audit may be no-op in tests).
      actor,
      note: 'Allowlist updated and audited. Endpoint collectors pick up enforcement.approved_mcp_servers on next bundle refresh.',
    };
  });

  fastify.get('/api/mcp-servers', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const server = req.query?.server;
    if (server !== undefined && !userLevel(req, reply)) return reply;
    const days = parseDays(req.query);
    const meta = approvalMeta(policyLoader);

    // ---- per-server drill-down (gated): who has this server configured ----
    if (server !== undefined) {
      const { rows } = await db.query(
        `${LATEST_CTE}
         SELECT srv ->> 'scope'                        AS scope,
                l.tool                                 AS tool,
                l.host_ref                             AS host,
                COALESCE(l.user_pseudonym, l.user_ref) AS "user",
                l.team                                 AS team,
                l.ts                                   AS last_seen
           FROM latest l, LATERAL jsonb_array_elements(l.server_list) AS srv
          WHERE srv ->> 'name' = $2
          ORDER BY "user" ASC NULLS LAST, l.tool ASC`,
        [days, server]
      );
      return {
        rangeDays: days,
        server,
        note: NOTE,
        status: statusFor(server, meta),
        policy: {
          contentHash: meta.contentHash,
          discoveryMode: meta.discoveryMode,
        },
        installations: rows.map((r) => ({
          user: r.user ?? null,
          team: r.team ?? null,
          host: r.host,
          tool: r.tool,
          scope: r.scope,
          lastSeen: r.last_seen,
        })),
      };
    }

    // ---- fleet-wide rollup: configured ∪ discovered + approval status ----
    const [configured, summary, discovered] = await Promise.all([
      db.query(
        `${LATEST_CTE}
         SELECT srv ->> 'name'                    AS name,
                ARRAY_AGG(DISTINCT srv ->> 'scope') AS scopes,
                ARRAY_AGG(DISTINCT l.tool)        AS tools,
                COUNT(DISTINCT l.host_ref)        AS hosts,
                COUNT(DISTINCT l.user_ref)        AS users,
                s.first_seen                      AS first_seen,
                s.last_seen                       AS last_seen
           FROM latest l, LATERAL jsonb_array_elements(l.server_list) AS srv
           JOIN sightings s ON s.name = srv ->> 'name'
          GROUP BY 1, s.first_seen, s.last_seen
          ORDER BY users DESC, name ASC`,
        [days]
      ),
      db.query(
        `${LATEST_CTE}
         SELECT
           (SELECT COUNT(DISTINCT srv ->> 'name')
              FROM latest l, LATERAL jsonb_array_elements(l.server_list) AS srv) AS servers,
           (SELECT COUNT(DISTINCT host_ref) FROM latest) AS hosts_reporting,
           (SELECT COUNT(*)
              FROM sightings si
             WHERE si.first_seen >= now() - interval '7 days'
               AND EXISTS (SELECT 1
                             FROM latest l, LATERAL jsonb_array_elements(l.server_list) AS srv
                            WHERE srv ->> 'name' = si.name)) AS new_last_7d`,
        [days]
      ),
      db.query(DISCOVERED_SQL, [days]),
    ]);

    const servers = mergeServerMaps(configured.rows, discovered.rows, meta);
    return {
      rangeDays: days,
      server: null,
      note: NOTE,
      policy: {
        contentHash: meta.contentHash,
        discoveryMode: meta.discoveryMode,
        // Count only — do not echo the full allowlist in every response when
        // it grows; empty vs non-empty is what the UI needs for the badge.
        approvedServerCount: meta.approvedMcpServers.length,
      },
      summary: summarize(servers, summary.rows[0]),
      servers,
    };
  });

  // ---- AIM-665 / AIM-627: session chain tracing (metadata only) ----------
  // Reconstruct request→tool→result timeline for one session_id from
  // tool_use events. Optional chain fields + agent_handoffs surface when
  // collectors emit schema v1.10. Never prompt bodies, args, or results.
  fastify.get('/api/mcp-sessions/:sessionId', async (req, reply) => {
    if (!userLevel(req, reply)) return reply;
    const sessionId = String(req.params?.sessionId || '').trim();
    if (!sessionId || sessionId.length > 128) {
      return reply.code(400).send({ error: 'invalid_session_id' });
    }
    const days = parseDays(req.query, 7, 90);
    const { rows } = await db.query(
      `SELECT e.event_id, e.ts, e.tool, e.host_ref, e.user_ref,
              e.user_pseudonym, e.team, e.repo_ref,
              COALESCE(e.tool_calls, e.payload -> 'tool_calls') AS tool_calls,
              e.payload -> 'agent_handoffs' AS agent_handoffs,
              e.payload -> 'enforcement' AS enforcement
         FROM events e
        WHERE e.event_type = 'tool_use'
          AND e.session_id = $1
          AND e.ts >= now() - ($2 || ' days')::interval
        ORDER BY e.ts ASC
        LIMIT 500`,
      [sessionId, days],
    );

    const calls = [];
    const handoffs = [];
    for (const r of rows) {
      const tcs = Array.isArray(r.tool_calls) ? r.tool_calls : [];
      for (const tc of tcs) {
        if (!tc || typeof tc !== 'object') continue;
        calls.push({
          eventId: r.event_id,
          ts: r.ts,
          tool: r.tool,
          toolName: tc.tool_name ?? null,
          mcpServer: tc.mcp_server ?? null,
          actionClass: tc.action_class ?? null,
          count: tc.count ?? null,
          durationMs: tc.duration_ms ?? null,
          callId: tc.call_id ?? null,
          parentCallId: tc.parent_call_id ?? null,
          resultStatus: tc.result_status ?? null,
          seq: tc.seq ?? null,
        });
      }
      const ahs = Array.isArray(r.agent_handoffs) ? r.agent_handoffs : [];
      for (const ah of ahs) {
        if (!ah || typeof ah !== 'object') continue;
        handoffs.push({
          eventId: r.event_id,
          ts: r.ts,
          tool: r.tool,
          handoffKind: ah.handoff_kind ?? null,
          status: ah.status ?? null,
          childSessionId: ah.child_session_id ?? null,
          toolName: ah.tool_name ?? null,
          parentCallId: ah.parent_call_id ?? null,
        });
      }
    }

    calls.sort((a, b) => {
      if (a.seq != null && b.seq != null && a.seq !== b.seq) return a.seq - b.seq;
      return String(a.ts).localeCompare(String(b.ts));
    });

    return {
      sessionId,
      rangeDays: days,
      note:
        'MCP session chain (AIM-665): tool_calls + agent_handoffs metadata only. ' +
        'Never arguments, results, prompts, or command lines. Chain edges require ' +
        'schema v1.10 call_id/parent_call_id when collectors emit them.',
      eventCount: rows.length,
      toolCallCount: calls.length,
      handoffCount: handoffs.length,
      chainCompleteness: {
        withCallId: calls.filter((c) => c.callId).length,
        withParent: calls.filter((c) => c.parentCallId).length,
        withResultStatus: calls.filter((c) => c.resultStatus).length,
      },
      toolCalls: calls,
      agentHandoffs: handoffs,
      events: rows.map((r) => ({
        eventId: r.event_id,
        ts: r.ts,
        tool: r.tool,
        host: r.host_ref,
        user: r.user_pseudonym ?? r.user_ref ?? null,
        team: r.team ?? null,
        enforcement: r.enforcement ?? null,
      })),
    };
  });

  // ---- AIM-627 / AIM-668: threat catalogue + allowlist recommendations --
  function loadThreatCatalogue() {
    const candidates = [
      resolve(process.cwd(), 'policies/mcp/threat-catalogue.yaml'),
      resolve(process.cwd(), '../../policies/mcp/threat-catalogue.yaml'),
      resolve(process.cwd(), '../policies/mcp/threat-catalogue.yaml'),
    ];
    for (const c of candidates) {
      try {
        const raw = readFileSync(c, 'utf8');
        return { pathUsed: c, parsed: yaml.load(raw) };
      } catch {
        /* try next */
      }
    }
    return null;
  }

  function buildAllowlistRecommendations(parsed, meta) {
    const rec = parsed?.allowlist_recommendations && typeof parsed.allowlist_recommendations === 'object'
      ? parsed.allowlist_recommendations
      : {};
    const approved = Array.isArray(meta?.approvedMcpServers) ? meta.approvedMcpServers : [];
    const serverSubs = Array.isArray(rec.never_approve_server_substrings)
      ? rec.never_approve_server_substrings.filter((x) => x && typeof x.substring === 'string')
      : [];
    const toolSubs = Array.isArray(rec.never_approve_tool_substrings)
      ? rec.never_approve_tool_substrings.filter((x) => x && typeof x.substring === 'string')
      : [];
    const neverServers = Array.isArray(rec.never_approve_servers)
      ? rec.never_approve_servers.filter(
        (x) => x && typeof x.name === 'string' && x.enabled !== false && x.name !== '*',
      )
      : [];
    const pilotSeed = Array.isArray(rec.pilot_seed_servers)
      ? rec.pilot_seed_servers.filter((s) => typeof s === 'string' && s.trim())
      : [];

    const conflicts = [];
    for (const name of approved) {
      const lower = name.toLowerCase();
      for (const entry of neverServers) {
        if (entry.name.toLowerCase() === lower) {
          conflicts.push({
            server: name,
            kind: 'never_approve_server',
            reason: entry.reason ?? null,
          });
        }
      }
      for (const entry of serverSubs) {
        if (lower.includes(String(entry.substring).toLowerCase())) {
          conflicts.push({
            server: name,
            kind: 'never_approve_server_substring',
            substring: entry.substring,
            reason: entry.reason ?? null,
          });
        }
      }
    }

    const pilotNotYetApproved = pilotSeed.filter((s) => !approved.includes(s));
    const residualGaps = (Array.isArray(parsed?.threats) ? parsed.threats : [])
      .filter((t) => t && t.residual_gap)
      .map((t) => ({
        threatId: t.id ?? null,
        severity: t.severity ?? null,
        detectorOrRail: t.detector_or_rail ?? null,
        residualGap: t.residual_gap,
      }));

    return {
      neverApproveServers: neverServers.map((x) => ({
        name: x.name,
        reason: x.reason ?? null,
      })),
      neverApproveServerSubstrings: serverSubs.map((x) => ({
        substring: x.substring,
        reason: x.reason ?? null,
      })),
      neverApproveToolSubstrings: toolSubs.map((x) => ({
        substring: x.substring,
        reason: x.reason ?? null,
      })),
      pilotSeedServers: pilotSeed,
      pilotNotYetApproved,
      conflictsWithLiveAllowlist: conflicts,
      residualGaps,
      reviewSlaDays: rec.review_sla_days ?? null,
      cveResponseBusinessDays: rec.cve_response_business_days ?? null,
      liveApprovedServerCount: approved.length,
      note:
        'Recommendations only (AIM-668). Apply via policy PR or PUT /api/mcp-allowlist; ' +
        'this endpoint never mutates the live allowlist.',
    };
  }

  fastify.get('/api/mcp-threats', async (req, reply) => {
    if (!anyRole(req, reply)) return reply;
    const loaded = loadThreatCatalogue();
    if (!loaded) {
      return reply.code(503).send({
        error: 'threat_catalogue_unavailable',
        detail: 'policies/mcp/threat-catalogue.yaml not found on disk',
      });
    }
    const { pathUsed, parsed } = loaded;
    if (parsed == null || typeof parsed !== 'object') {
      return reply.code(500).send({ error: 'threat_catalogue_parse_error' });
    }
    const meta = approvalMeta(policyLoader);
    return {
      note:
        'MCP threat catalogue (AIM-627/668): continuous-update threat classes for ' +
        'MCP/tool-call governance + allowlist recommendations. Metadata-only — no customer payloads.',
      path: pathUsed,
      version: parsed?.version ?? null,
      lastReviewed: parsed?.last_reviewed ?? null,
      updateCadence: parsed?.update_cadence ?? null,
      owners: parsed?.owners ?? null,
      threats: Array.isArray(parsed?.threats) ? parsed.threats : [],
      recommendations: buildAllowlistRecommendations(parsed, meta),
    };
  });
}

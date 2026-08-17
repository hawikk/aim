// Guardrail rules transparency + tuning API.
//
// GET /api/guardrail/rules — the rules the guardrail engine has loaded right
// now, read from the same YAML policy files on every request (no drift), plus
// firing counts and last-fired timestamps computed from stored findings (the
// persisted record of rule firings — engine audit records are streamed, not
// stored, so the findings table is the durable firing history).
//
// PATCH /api/guardrail/rules/:id — UI-tunable threshold rules.
// Overrides (gt/gte/window_seconds/severity only) are written to the
// machine-owned ui-overrides.yaml in the policy dir; match rules and every
// other rule aspect stay PR-managed in the core policy files.
//
// GET/PUT /api/guardrail/alerts
// non-secret alert destination config (webhook / Sentinel / Google Chat /
// optional Slack / email / PagerDuty), machine-owned alerts.yaml. Secrets stay
// env-managed (ALERT_WEBHOOK_SECRET, SENTINEL_SHARED_KEY,
// ALERT_GOOGLE_CHAT_WEBHOOK_URL, ALERT_EMAIL_SMTP_*, ALERT_SLACK_WEBHOOK_URL,
// ALERT_PAGERDUTY_ROUTING_KEY) and are only ever reported as presence
// booleans — never values. Slack is further gated by ALERT_SLACK_ENABLED
// (default off; SOC opt-in — see docs/security/slack-alert-destination.md).
// escalation_policies are policy-as-code (read on GET; not written
// by the dashboard form — stages with timers live in alerts.yaml / core).
//
// POST /api/guardrail/alerts/test — admin-only synthetic delivery
// proof for a destination. Today only `email` is supported (mirrors CLI
// `python -m guardrail.cli notify-test --email` / EmailNotifier.deliver_test).
// SMTP secrets stay env-managed; recipients come from alerts.yaml. Response
// and audit detail never include host/password/from values.
//
// All endpoints are gated to the security group, same as /api/findings:
// active rule internals (thresholds, allowlists) and alert routing are
// security posture, not org-wide telemetry. All mutations are audited.
import { writeFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import yaml from 'js-yaml';
import { query } from '../db.js';
import { requireRoles } from '../auth.js';
import { audit } from '../audit.js';
import { loadPolicy, policyPath, describeRule, rulePosture } from '../guardrail-policy.js';
import { deliverTestEmail, emailSmtpConfigured as smtpConfiguredFromEnv } from '../email-test.js';

const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const WINDOW_MIN_SECONDS = 60;
const WINDOW_MAX_SECONDS = 604800; // 7 days

const OVERRIDES_HEADER =
  '# Managed by the dashboard rule-tuning UI. Do not edit by hand —\n' +
  '# changes here are written by PATCH /api/guardrail/rules/:id and audited.\n';
const ALERTS_HEADER =
  '# Managed by the dashboard alert config UI. Do not edit by hand.\n' +
  '# Secrets stay env-managed (ALERT_WEBHOOK_SECRET, SENTINEL_SHARED_KEY,\n' +
  '# ALERT_GOOGLE_CHAT_WEBHOOK_URL, ALERT_EMAIL_SMTP_*, ALERT_SLACK_WEBHOOK_URL,\n' +
  '# ALERT_PAGERDUTY_ROUTING_KEY) and are never written here.\n' +
  '# Slack also requires ALERT_SLACK_ENABLED (SOC opt-in).\n' +
  '# escalation_policies (multi-stage timers) are policy-as-code —\n' +
  '# edit under settings.alerts.escalation_policies; the UI does not rewrite them.\n' +
  '# The guardrail engine merges settings.alerts from this file.\n';

const WEBHOOK_DEFAULTS = { enabled: false, url: '', min_severity: 'high' };
const SENTINEL_DEFAULTS = { enabled: false, workspace_id: '', log_type: 'AIGuardrailFinding' };
// Google Chat webhook URL is env-only (the URL itself is the secret).
const GOOGLE_CHAT_DEFAULTS = { enabled: false, min_severity: 'high' };
// Slack is feature-flagged off by default (ALERT_SLACK_ENABLED).
const SLACK_DEFAULTS = { enabled: false, min_severity: 'high' };
// PagerDuty Events API v2 — routing key is env-only.
const PAGERDUTY_DEFAULTS = { enabled: false, min_severity: 'critical' };
// recipients are non-secret; SMTP host/from/credentials stay env.
const EMAIL_DEFAULTS = { enabled: false, to: '', min_severity: 'high' };
// Syntactic email check only — directory membership is identity-sync's job.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const EMAIL_MAX_RECIPIENTS = 20;

function normalizeEmailTo(value) {
  if (typeof value !== 'string') return null;
  const parts = value.split(/[,;]/).map((s) => s.trim()).filter(Boolean);
  if (parts.length > EMAIL_MAX_RECIPIENTS) return null;
  const seen = new Set();
  const out = [];
  for (const p of parts) {
    if (!EMAIL_RE.test(p) || p.length > 254) return null;
    const key = p.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
  }
  return out.join(', ');
}

function emailSmtpConfigured() {
  // Presence only — never surface host/from values to the UI.
  return smtpConfiguredFromEnv(process.env);
}

function envFlagTruthy(name) {
  const raw = (process.env[name] || '').trim().toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

// Atomic write for the machine-owned policy files: tmp file in the same
// directory + rename, so a crash mid-write can never leave a truncated YAML
// the engine would then fail to load.
function writeYamlAtomic(file, header, data) {
  const tmp = `${file}.tmp-${process.pid}`;
  writeFileSync(tmp, header + yaml.dump(data));
  renameSync(tmp, file);
}

function ruleItem(rule, policy, stats) {
  const s = stats.get(rule.id);
  const text = describeRule(rule, policy.settings);
  // surface active / inert / discovery so operators never mistake a
  // permanently silent control for "all clear".
  const posture = rulePosture(rule, policy.settings);
  return {
    id: rule.id,
    type: rule.type,
    severity: rule.severity ?? 'medium',
    title: rule.title ?? rule.id,
    description: rule.description ?? '',
    condition: rule.when ?? rule.filter ?? null,
    conditionText: text.conditionText,
    threshold: rule.type === 'threshold'
      ? { groupBy: rule.group_by, windowSeconds: rule.window_seconds, metric: rule.metric, gt: rule.gt ?? null, gte: rule.gte ?? null }
      : null,
    thresholdText: text.thresholdText,
    overridden: rule.overridden === true,
    overrides: policy.ruleOverrides[rule.id] ?? null,
    posture: posture.status,
    postureLabel: posture.label,
    postureReasons: posture.reasons,
    inertUntil: Array.isArray(rule.inert_until) ? rule.inert_until : [],
    firedCount: s ? Number(s.fired_count) : 0,
    lastFiredAt: s?.last_fired_at ?? null,
  };
}

async function firingStats(db) {
  const { rows } = await db.query(
    `SELECT rule_id, COUNT(*) AS fired_count, MAX(detected_at) AS last_fired_at
       FROM findings GROUP BY rule_id`
  );
  return new Map(rows.map((r) => [r.rule_id, r]));
}

// Alerts config in wire (camelCase) shape, with defaults for unset sections.
function alertsPayload(policy) {
  const alerts = policy.settings.alerts ?? {};
  const webhook = { ...WEBHOOK_DEFAULTS, ...(alerts.webhook ?? {}) };
  const sentinel = { ...SENTINEL_DEFAULTS, ...(alerts.sentinel ?? {}) };
  const googleChat = { ...GOOGLE_CHAT_DEFAULTS, ...(alerts.google_chat ?? {}) };
  const slack = { ...SLACK_DEFAULTS, ...(alerts.slack ?? {}) };
  const pagerduty = { ...PAGERDUTY_DEFAULTS, ...(alerts.pagerduty ?? {}) };
  const email = { ...EMAIL_DEFAULTS, ...(alerts.email ?? {}) };
  const slackFeature = envFlagTruthy('ALERT_SLACK_ENABLED');
  // surface policy-as-code escalation stages (read-only wire shape).
  const escalationPolicies = Array.isArray(alerts.escalation_policies)
    ? alerts.escalation_policies.map((p) => ({
        id: p.id,
        minSeverity: p.min_severity ?? 'low',
        ruleIds: Array.isArray(p.rule_ids) ? p.rule_ids : [],
        stages: Array.isArray(p.stages)
          ? p.stages.map((s) => ({
              afterSeconds: s.after_seconds ?? 0,
              destinations: Array.isArray(s.destinations) ? s.destinations : [],
            }))
          : [],
      }))
    : [];
  return {
    alerts: {
      webhook: { enabled: webhook.enabled, url: webhook.url, minSeverity: webhook.min_severity },
      sentinel: { enabled: sentinel.enabled, workspaceId: sentinel.workspace_id, logType: sentinel.log_type },
      // no URL field — the Google Chat incoming-webhook URL is env-only.
      googleChat: { enabled: googleChat.enabled, minSeverity: googleChat.min_severity },
      // recipients are UI-managed; SMTP is env-only.
      email: { enabled: email.enabled, to: email.to, minSeverity: email.min_severity },
      // no URL field — Slack incoming-webhook URL is env-only. The UI
      // only renders this card when features.slack is true.
      slack: { enabled: slack.enabled, minSeverity: slack.min_severity },
      // PagerDuty routing key is env-only (ALERT_PAGERDUTY_ROUTING_KEY).
      pagerduty: { enabled: pagerduty.enabled, minSeverity: pagerduty.min_severity },
      escalationPolicies,
    },
    // Presence only — secret VALUES are never exposed through the API.
    secrets: {
      webhookSecret: Boolean(process.env.ALERT_WEBHOOK_SECRET),
      sentinelSharedKey: Boolean(process.env.SENTINEL_SHARED_KEY),
      googleChatWebhook: Boolean(process.env.ALERT_GOOGLE_CHAT_WEBHOOK_URL),
      emailSmtp: emailSmtpConfigured(),
      slackWebhook: Boolean(process.env.ALERT_SLACK_WEBHOOK_URL),
      pagerdutyRoutingKey: Boolean(process.env.ALERT_PAGERDUTY_ROUTING_KEY),
    },
    // Feature flags the UI uses to hide SOC-opt-in destinations.
    features: {
      slack: slackFeature,
      email: true,
      pagerduty: true,
      escalationPolicies: true,
    },
  };
}

// opts.db, opts.policyPath, and opts.deliverTestEmail are injectable for tests.
export async function guardrailRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const path = opts?.policyPath ?? policyPath();
  const runDeliverTestEmail = opts?.deliverTestEmail ?? deliverTestEmail;
  // Rule internals and alert routing are security posture: admin
  // only.
  const adminOnly = requireRoles('admin');

  function loadPolicyOr500(req, reply) {
    try {
      return loadPolicy(path);
    } catch (err) {
      req.log.error(err, 'failed to load guardrail policy');
      reply.code(500).send({ error: 'policy_unavailable', detail: `could not load guardrail policy: ${err.message}` });
      return null;
    }
  }

  fastify.get('/api/guardrail/rules', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;

    const policy = loadPolicyOr500(req, reply);
    if (!policy) return reply;
    const stats = await firingStats(db);

    const rules = policy.rules.map((rule) => ruleItem(rule, policy, stats));
    const postureCounts = rules.reduce(
      (acc, r) => {
        acc[r.posture] = (acc[r.posture] ?? 0) + 1;
        return acc;
      },
      { active: 0, inert: 0, discovery: 0 },
    );
    return {
      policyPath: path,
      version: policy.version,
      contentHash: policy.contentHash,
      sources: policy.sources,
      settings: policy.settings,
      // mcp_allowlist_mode is deny_unlisted after discovery closed.
      mcpAllowlistMode: policy.settings.mcp_allowlist_mode ?? 'deny_unlisted',
      postureCounts,
      rules,
    };
  });

  // ---- UI-tunable threshold rules. Overrides land in the
  // machine-owned ui-overrides.yaml; the core policy files are never touched.
  fastify.patch('/api/guardrail/rules/:id', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;

    const policy = loadPolicyOr500(req, reply);
    if (!policy) return reply;
    const rule = policy.rules.find((r) => r.id === req.params.id);
    if (!rule) {
      return reply.code(404).send({ error: 'not_found', detail: `no rule ${req.params.id}` });
    }
    // Match rules stay PR-managed — only threshold rules are UI-tunable.
    if (rule.type !== 'threshold') {
      return reply.code(400).send({ error: 'bad_request', detail: `rule '${rule.id}' is type '${rule.type}'; only threshold rules can be tuned from the UI` });
    }

    const body = req.body ?? {};
    const allowed = ['gt', 'gte', 'windowSeconds', 'severity', 'reset'];
    const unknown = Object.keys(body).filter((k) => !allowed.includes(k));
    if (unknown.length > 0) {
      return reply.code(400).send({ error: 'bad_request', detail: `unknown field(s): ${unknown.join(', ')} (allowed: ${allowed.join(', ')})` });
    }
    if ('reset' in body && body.reset !== true) {
      return reply.code(400).send({ error: 'bad_request', detail: 'reset must be true when present' });
    }

    // Existing override map (missing file = no overrides; never created on read).
    const overrides = structuredClone(policy.ruleOverrides);
    const current = { ...(overrides[rule.id] ?? {}) };
    let changes;

    if (body.reset === true) {
      delete overrides[rule.id];
      changes = { reset: true };
    } else {
      if (body.gt !== undefined && body.gte !== undefined) {
        return reply.code(400).send({ error: 'bad_request', detail: 'set gt or gte, not both' });
      }
      for (const key of ['gt', 'gte']) {
        if (body[key] !== undefined && (typeof body[key] !== 'number' || !Number.isFinite(body[key]) || body[key] <= 0)) {
          return reply.code(400).send({ error: 'bad_request', detail: `${key} must be a positive finite number` });
        }
      }
      if (body.windowSeconds !== undefined &&
          (!Number.isInteger(body.windowSeconds) || body.windowSeconds < WINDOW_MIN_SECONDS || body.windowSeconds > WINDOW_MAX_SECONDS)) {
        return reply.code(400).send({ error: 'bad_request', detail: `windowSeconds must be an integer ${WINDOW_MIN_SECONDS}..${WINDOW_MAX_SECONDS}` });
      }
      if (body.severity !== undefined && !SEVERITIES.includes(body.severity)) {
        return reply.code(400).send({ error: 'bad_request', detail: `severity must be one of ${SEVERITIES.join(', ')}` });
      }
      const patch = {};
      if (body.gt !== undefined) patch.gt = body.gt;
      if (body.gte !== undefined) patch.gte = body.gte;
      if (body.windowSeconds !== undefined) patch.window_seconds = body.windowSeconds;
      if (body.severity !== undefined) patch.severity = body.severity;
      if (Object.keys(patch).length === 0) {
        return reply.code(400).send({ error: 'bad_request', detail: 'empty patch — provide gt, gte, windowSeconds, severity, or reset' });
      }
      Object.assign(current, patch);
      if (current.gt !== undefined && current.gte !== undefined) {
        return reply.code(400).send({ error: 'bad_request', detail: 'a rule cannot override both gt and gte — reset first, then set one' });
      }
      overrides[rule.id] = current;
      changes = patch;
    }

    try {
      writeYamlAtomic(join(path, 'ui-overrides.yaml'), OVERRIDES_HEADER, { version: 1, rule_overrides: overrides });
    } catch (err) {
      req.log.error(err, 'failed to write ui-overrides.yaml');
      return reply.code(500).send({ error: 'policy_write_failed', detail: `could not write ui-overrides.yaml: ${err.message}` });
    }

    const actor = req.identity?.email ?? 'unknown';
    audit(actor, 'guardrail.rule_override', `guardrail/rules/${rule.id}`, { changes });

    // Re-read from disk so the response is the effective rule, drift-free.
    const effective = loadPolicyOr500(req, reply);
    if (!effective) return reply;
    const stats = await firingStats(db);
    return ruleItem(effective.rules.find((r) => r.id === rule.id), effective, stats);
  });

  // ---- alert destination config. Non-secret settings only, in the
  // machine-owned alerts.yaml; the engine merges settings.alerts from it. ----
  fastify.get('/api/guardrail/alerts', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const policy = loadPolicyOr500(req, reply);
    if (!policy) return reply;
    return alertsPayload(policy);
  });

  fastify.put('/api/guardrail/alerts', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const policy = loadPolicyOr500(req, reply);
    if (!policy) return reply;

    const body = req.body ?? {};
    const unknown = Object.keys(body).filter((k) => k !== 'webhook' && k !== 'sentinel' && k !== 'googleChat' && k !== 'email' && k !== 'slack' && k !== 'pagerduty');
    if (unknown.length > 0) {
      return reply.code(400).send({ error: 'bad_request', detail: `unknown field(s): ${unknown.join(', ')} (allowed: webhook, sentinel, googleChat, email, slack, pagerduty)` });
    }

    // Merge the partial body onto the current effective config (defaults when unset).
    const current = policy.settings.alerts ?? {};
    const webhook = { ...WEBHOOK_DEFAULTS, ...(current.webhook ?? {}) };
    const sentinel = { ...SENTINEL_DEFAULTS, ...(current.sentinel ?? {}) };
    const googleChat = { ...GOOGLE_CHAT_DEFAULTS, ...(current.google_chat ?? {}) };
    const slack = { ...SLACK_DEFAULTS, ...(current.slack ?? {}) };
    const pagerduty = { ...PAGERDUTY_DEFAULTS, ...(current.pagerduty ?? {}) };
    const email = { ...EMAIL_DEFAULTS, ...(current.email ?? {}) };

    if (body.webhook !== undefined) {
      const w = body.webhook;
      if (!w || typeof w !== 'object' || Array.isArray(w)) {
        return reply.code(400).send({ error: 'bad_request', detail: 'webhook must be an object' });
      }
      const badKeys = Object.keys(w).filter((k) => !['enabled', 'url', 'minSeverity'].includes(k));
      if (badKeys.length > 0) {
        return reply.code(400).send({ error: 'bad_request', detail: `unknown webhook field(s): ${badKeys.join(', ')}` });
      }
      if (w.enabled !== undefined) {
        if (typeof w.enabled !== 'boolean') return reply.code(400).send({ error: 'bad_request', detail: 'webhook.enabled must be a boolean' });
        webhook.enabled = w.enabled;
      }
      if (w.url !== undefined) {
        if (typeof w.url !== 'string') return reply.code(400).send({ error: 'bad_request', detail: 'webhook.url must be a string' });
        if (w.url !== '') {
          let parsed;
          try {
            parsed = new URL(w.url);
          } catch {
            return reply.code(400).send({ error: 'bad_request', detail: 'webhook.url must be a valid https:// URL (or empty to disable)' });
          }
          if (parsed.protocol !== 'https:') {
            return reply.code(400).send({ error: 'bad_request', detail: 'webhook.url must be a valid https:// URL (or empty to disable)' });
          }
        }
        webhook.url = w.url;
      }
      if (w.minSeverity !== undefined) {
        if (!SEVERITIES.includes(w.minSeverity)) {
          return reply.code(400).send({ error: 'bad_request', detail: `webhook.minSeverity must be one of ${SEVERITIES.join(', ')}` });
        }
        webhook.min_severity = w.minSeverity;
      }
    }

    if (body.sentinel !== undefined) {
      const s = body.sentinel;
      if (!s || typeof s !== 'object' || Array.isArray(s)) {
        return reply.code(400).send({ error: 'bad_request', detail: 'sentinel must be an object' });
      }
      const badKeys = Object.keys(s).filter((k) => !['enabled', 'workspaceId', 'logType'].includes(k));
      if (badKeys.length > 0) {
        return reply.code(400).send({ error: 'bad_request', detail: `unknown sentinel field(s): ${badKeys.join(', ')}` });
      }
      if (s.enabled !== undefined) {
        if (typeof s.enabled !== 'boolean') return reply.code(400).send({ error: 'bad_request', detail: 'sentinel.enabled must be a boolean' });
        sentinel.enabled = s.enabled;
      }
      if (s.workspaceId !== undefined) {
        if (typeof s.workspaceId !== 'string' || (s.workspaceId !== '' && !/^[0-9a-fA-F-]{32,36}$/.test(s.workspaceId))) {
          return reply.code(400).send({ error: 'bad_request', detail: 'sentinel.workspaceId must be a GUID (or empty)' });
        }
        sentinel.workspace_id = s.workspaceId;
      }
      if (s.logType !== undefined) {
        if (typeof s.logType !== 'string' || !/^[A-Za-z0-9_]{1,64}$/.test(s.logType)) {
          return reply.code(400).send({ error: 'bad_request', detail: 'sentinel.logType must match /^[A-Za-z0-9_]{1,64}$/' });
        }
        sentinel.log_type = s.logType;
      }
    }

    if (body.googleChat !== undefined) {
      const g = body.googleChat;
      if (!g || typeof g !== 'object' || Array.isArray(g)) {
        return reply.code(400).send({ error: 'bad_request', detail: 'googleChat must be an object' });
      }
      // No URL field — the incoming-webhook URL is ALERT_GOOGLE_CHAT_WEBHOOK_URL.
      const badKeys = Object.keys(g).filter((k) => !['enabled', 'minSeverity'].includes(k));
      if (badKeys.length > 0) {
        return reply.code(400).send({ error: 'bad_request', detail: `unknown googleChat field(s): ${badKeys.join(', ')}` });
      }
      if (g.enabled !== undefined) {
        if (typeof g.enabled !== 'boolean') return reply.code(400).send({ error: 'bad_request', detail: 'googleChat.enabled must be a boolean' });
        googleChat.enabled = g.enabled;
      }
      if (g.minSeverity !== undefined) {
        if (!SEVERITIES.includes(g.minSeverity)) {
          return reply.code(400).send({ error: 'bad_request', detail: `googleChat.minSeverity must be one of ${SEVERITIES.join(', ')}` });
        }
        googleChat.min_severity = g.minSeverity;
      }
    }

    if (body.email !== undefined) {
      const e = body.email;
      if (!e || typeof e !== 'object' || Array.isArray(e)) {
        return reply.code(400).send({ error: 'bad_request', detail: 'email must be an object' });
      }
      // No SMTP fields — host/from/password are ALERT_EMAIL_* env vars only.
      const badKeys = Object.keys(e).filter((k) => !['enabled', 'to', 'minSeverity'].includes(k));
      if (badKeys.length > 0) {
        return reply.code(400).send({ error: 'bad_request', detail: `unknown email field(s): ${badKeys.join(', ')}` });
      }
      if (e.enabled !== undefined) {
        if (typeof e.enabled !== 'boolean') return reply.code(400).send({ error: 'bad_request', detail: 'email.enabled must be a boolean' });
        email.enabled = e.enabled;
      }
      if (e.to !== undefined) {
        if (typeof e.to !== 'string') return reply.code(400).send({ error: 'bad_request', detail: 'email.to must be a string' });
        const normalized = normalizeEmailTo(e.to);
        if (normalized === null) {
          return reply.code(400).send({ error: 'bad_request', detail: 'email.to must be a comma-separated list of email addresses (or empty)' });
        }
        email.to = normalized;
      }
      if (e.minSeverity !== undefined) {
        if (!SEVERITIES.includes(e.minSeverity)) {
          return reply.code(400).send({ error: 'bad_request', detail: `email.minSeverity must be one of ${SEVERITIES.join(', ')}` });
        }
        email.min_severity = e.minSeverity;
      }
    }

    if (body.slack !== undefined) {
      // Slack is SOC opt-in. Refuse config writes while the feature
      // flag is off so a dashboard toggle cannot arm a destination that the
      // engine will ignore (and so operators learn about ALERT_SLACK_ENABLED).
      if (!envFlagTruthy('ALERT_SLACK_ENABLED')) {
        return reply.code(400).send({
          error: 'bad_request',
          detail: 'slack destination is feature-flagged off (set ALERT_SLACK_ENABLED=1 after SOC opt-in; see docs/security/slack-alert-destination.md)',
        });
      }
      const s = body.slack;
      if (!s || typeof s !== 'object' || Array.isArray(s)) {
        return reply.code(400).send({ error: 'bad_request', detail: 'slack must be an object' });
      }
      // No URL field — the incoming-webhook URL is ALERT_SLACK_WEBHOOK_URL.
      const badKeys = Object.keys(s).filter((k) => !['enabled', 'minSeverity'].includes(k));
      if (badKeys.length > 0) {
        return reply.code(400).send({ error: 'bad_request', detail: `unknown slack field(s): ${badKeys.join(', ')}` });
      }
      if (s.enabled !== undefined) {
        if (typeof s.enabled !== 'boolean') return reply.code(400).send({ error: 'bad_request', detail: 'slack.enabled must be a boolean' });
        slack.enabled = s.enabled;
      }
      if (s.minSeverity !== undefined) {
        if (!SEVERITIES.includes(s.minSeverity)) {
          return reply.code(400).send({ error: 'bad_request', detail: `slack.minSeverity must be one of ${SEVERITIES.join(', ')}` });
        }
        slack.min_severity = s.minSeverity;
      }
    }


    if (body.pagerduty !== undefined) {
      // PagerDuty Events API v2. Routing key is env-only.
      const p = body.pagerduty;
      if (!p || typeof p !== 'object' || Array.isArray(p)) {
        return reply.code(400).send({ error: 'bad_request', detail: 'pagerduty must be an object' });
      }
      const badKeys = Object.keys(p).filter((k) => !['enabled', 'minSeverity'].includes(k));
      if (badKeys.length > 0) {
        return reply.code(400).send({ error: 'bad_request', detail: `unknown pagerduty field(s): ${badKeys.join(', ')}` });
      }
      if (p.enabled !== undefined) {
        if (typeof p.enabled !== 'boolean') return reply.code(400).send({ error: 'bad_request', detail: 'pagerduty.enabled must be a boolean' });
        pagerduty.enabled = p.enabled;
      }
      if (p.minSeverity !== undefined) {
        if (!SEVERITIES.includes(p.minSeverity)) {
          return reply.code(400).send({ error: 'bad_request', detail: `pagerduty.minSeverity must be one of ${SEVERITIES.join(', ')}` });
        }
        pagerduty.min_severity = p.minSeverity;
      }
    }

    if (webhook.enabled && webhook.url === '') {
      return reply.code(400).send({ error: 'bad_request', detail: 'webhook.enabled requires a non-empty webhook.url' });
    }
    if (email.enabled && email.to === '') {
      return reply.code(400).send({ error: 'bad_request', detail: 'email.enabled requires a non-empty email.to' });
    }

    try {
      // preserve policy-as-code escalation_policies when rewriting destinations.
      const alertsOut = { webhook, sentinel, google_chat: googleChat, email, slack, pagerduty };
      if (Array.isArray(current.escalation_policies) && current.escalation_policies.length > 0) {
        alertsOut.escalation_policies = current.escalation_policies;
      }
      writeYamlAtomic(join(path, 'alerts.yaml'), ALERTS_HEADER, {
        version: 1,
        settings: { alerts: alertsOut },
      });
    } catch (err) {
      req.log.error(err, 'failed to write alerts.yaml');
      return reply.code(500).send({ error: 'policy_write_failed', detail: `could not write alerts.yaml: ${err.message}` });
    }

    const actor = req.identity?.email ?? 'unknown';
    audit(actor, 'guardrail.alerts_update', 'guardrail/alerts', {
      webhookEnabled: webhook.enabled,
      sentinelEnabled: sentinel.enabled,
      googleChatEnabled: googleChat.enabled,
      emailEnabled: email.enabled,
      slackEnabled: slack.enabled,
      pagerdutyEnabled: pagerduty.enabled,
      minSeverity: webhook.min_severity,
      googleChatMinSeverity: googleChat.min_severity,
      emailMinSeverity: email.min_severity,
      slackMinSeverity: slack.min_severity,
      pagerdutyMinSeverity: pagerduty.min_severity,
    });

    // Re-read from disk so the response is the effective config, drift-free.
    const effective = loadPolicyOr500(req, reply);
    if (!effective) return reply;
    return alertsPayload(effective);
  });

  // ---- synthetic delivery proof for alert destinations.
  // UI "Test send" on Rules → Alert destinations. Admin-only; secrets stay
  // env-managed and are never accepted in the request body or returned.
  fastify.post('/api/guardrail/alerts/test', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;

    const body = req.body ?? {};
    if (body && typeof body === 'object' && !Array.isArray(body)) {
      const unknown = Object.keys(body).filter((k) => k !== 'destination');
      if (unknown.length > 0) {
        return reply.code(400).send({
          error: 'bad_request',
          detail: `unknown field(s): ${unknown.join(', ')} (allowed: destination)`,
        });
      }
    } else if (body != null && typeof body !== 'object') {
      return reply.code(400).send({ error: 'bad_request', detail: 'body must be a JSON object' });
    }

    const destination = body?.destination;
    if (destination !== 'email') {
      return reply.code(400).send({
        error: 'bad_request',
        detail: destination == null || destination === ''
          ? 'destination is required (supported: email)'
          : `unsupported destination '${destination}' (supported: email)`,
      });
    }

    // Refuse SMTP credentials / hosts in the body — env-only (non-goal).
    // (Already covered by unknown-field check; keep the intent explicit.)
    for (const banned of ['smtpHost', 'smtpPassword', 'password', 'host', 'from', 'to', 'smtp']) {
      if (body && Object.prototype.hasOwnProperty.call(body, banned)) {
        return reply.code(400).send({
          error: 'bad_request',
          detail: 'SMTP credentials and recipients are not accepted in the request body',
        });
      }
    }

    const policy = loadPolicyOr500(req, reply);
    if (!policy) return reply;
    const emailCfg = { ...EMAIL_DEFAULTS, ...((policy.settings.alerts ?? {}).email ?? {}) };
    const actor = req.identity?.email ?? 'unknown';

    try {
      const result = await runDeliverTestEmail({
        to: emailCfg.to,
        env: process.env,
      });
      audit(actor, 'guardrail.alerts_test', 'guardrail/alerts/test', {
        destination: 'email',
        ok: true,
        attempts: result.attempts,
        recipientCount: result.recipientCount,
        // Secrets (host/from/password) intentionally omitted.
      });
      return {
        ok: true,
        destination: 'email',
        message: 'Test email sent',
        attempts: result.attempts,
      };
    } catch (err) {
      const status = Number.isInteger(err?.statusCode) ? err.statusCode : 502;
      const error = err?.code || (status === 400 ? 'bad_request' : 'delivery_failed');
      const detail = typeof err?.message === 'string' && err.message
        ? err.message
        : 'test email delivery failed';
      const attempts = Number.isInteger(err?.attempts) ? err.attempts : undefined;
      audit(actor, 'guardrail.alerts_test', 'guardrail/alerts/test', {
        destination: 'email',
        ok: false,
        error,
        // Scrubbed detail only — deliverTestEmail already redacts secrets.
        detail,
        ...(attempts != null ? { attempts } : {}),
      });
      req.log.warn({ err: error, detail }, 'guardrail alerts test failed');
      return reply.code(status).send({
        error,
        detail,
        destination: 'email',
        ...(attempts != null ? { attempts } : {}),
      });
    }
  });
}


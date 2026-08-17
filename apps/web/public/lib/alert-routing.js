/* — multi-destination alert routing helpers.
 *
 * Guardrail findings fan out to every enabled destination whose severity floor
 * is at or below the finding. Destinations are configured globally on the Rules
 * view (GET/PUT /api/guardrail/alerts); this module is the pure shape used by
 * the UI for validation, empty states, and "where does this rule go?" chips.
 *
 * PagerDuty is always a first-class card (routing key env-only).
 * Slack is feature-flagged (features.slack / ALERT_SLACK_ENABLED) — the card
 * only appears when the flag is on. Escalation ladders live in
 * lib/escalation-policies.js (dashboard-editable ladders).
 *
 * No secrets live here — only presence booleans from the API.
 */

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];

/** Lower number = more severe. Matches packages/alerting severity floor math. */
export const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

/** Always-rendered destinations (forms on Rules → Alert destinations). */
export const DESTINATIONS = [
  {
    id: 'webhook',
    title: 'Webhook',
    hasMinSeverity: true,
    secretKey: 'webhookSecret',
    fields: ['enabled', 'url', 'minSeverity'],
  },
  {
    id: 'sentinel',
    title: 'Microsoft Sentinel',
    hasMinSeverity: false,
    secretKey: 'sentinelSharedKey',
    fields: ['enabled', 'workspaceId', 'logType'],
  },
  {
    id: 'googleChat',
    title: 'Google Chat',
    hasMinSeverity: true,
    secretKey: 'googleChatWebhook',
    fields: ['enabled', 'minSeverity'],
  },
  {
    id: 'email',
    title: 'Email',
    hasMinSeverity: true,
    secretKey: 'emailSmtp',
    fields: ['enabled', 'to', 'minSeverity'],
  },
  {
    id: 'pagerduty',
    title: 'PagerDuty',
    hasMinSeverity: true,
    secretKey: 'pagerdutyRoutingKey',
    fields: ['enabled', 'minSeverity'],
  },
];

/** SOC opt-in destinations gated by features.* from GET /api/guardrail/alerts. */
export const OPTIONAL_DESTINATIONS = [
  {
    id: 'slack',
    title: 'Slack',
    hasMinSeverity: true,
    secretKey: 'slackWebhook',
    featureKey: 'slack',
    fields: ['enabled', 'minSeverity'],
  },
];

const DEST_BY_ID = Object.fromEntries(
  [...DESTINATIONS, ...OPTIONAL_DESTINATIONS].map((d) => [d.id, d]),
);

export function destMeta(id) {
  return DEST_BY_ID[id] ?? null;
}

/**
 * Destinations that should render cards for this payload.
 * Slack is omitted unless features.slack is true.
 *
 * @param {{ features?: object } | null | undefined} payload
 */
export function visibleDestinations(payload) {
  const features = payload?.features ?? {};
  const optional = OPTIONAL_DESTINATIONS.filter((d) => features[d.featureKey] === true);
  return [...DESTINATIONS, ...optional];
}

/**
 * Normalize a GET /api/guardrail/alerts payload into a stable row list.
 * Missing sections default to disabled so a partial response never blanks the panel.
 * Optional destinations (Slack) only appear when their feature flag is on.
 *
 * @param {{ alerts?: object, secrets?: object, features?: object } | null | undefined} payload
 * @returns {Array<object>}
 */
export function destinationRows(payload) {
  const alerts = payload?.alerts ?? {};
  const secrets = payload?.secrets ?? {};
  const features = payload?.features ?? {};
  const w = alerts.webhook ?? {};
  const s = alerts.sentinel ?? {};
  const g = alerts.googleChat ?? {};
  const e = alerts.email ?? {};
  const p = alerts.pagerduty ?? {};
  const sl = alerts.slack ?? {};

  const rows = [
    {
      id: 'webhook',
      title: 'Webhook',
      enabled: Boolean(w.enabled),
      minSeverity: SEVERITIES.includes(w.minSeverity) ? w.minSeverity : 'high',
      secretConfigured: Boolean(secrets.webhookSecret),
      url: typeof w.url === 'string' ? w.url : '',
      hasMinSeverity: true,
    },
    {
      id: 'sentinel',
      title: 'Microsoft Sentinel',
      enabled: Boolean(s.enabled),
      minSeverity: null, // Sentinel takes every severity when enabled
      secretConfigured: Boolean(secrets.sentinelSharedKey),
      workspaceId: typeof s.workspaceId === 'string' ? s.workspaceId : '',
      logType: typeof s.logType === 'string' && s.logType ? s.logType : 'AIGuardrailFinding',
      hasMinSeverity: false,
    },
    {
      id: 'googleChat',
      title: 'Google Chat',
      enabled: Boolean(g.enabled),
      minSeverity: SEVERITIES.includes(g.minSeverity) ? g.minSeverity : 'high',
      secretConfigured: Boolean(secrets.googleChatWebhook),
      hasMinSeverity: true,
    },
    {
      id: 'email',
      title: 'Email',
      enabled: Boolean(e.enabled),
      minSeverity: SEVERITIES.includes(e.minSeverity) ? e.minSeverity : 'high',
      secretConfigured: Boolean(secrets.emailSmtp),
      to: typeof e.to === 'string' ? e.to : '',
      hasMinSeverity: true,
    },
    {
      id: 'pagerduty',
      title: 'PagerDuty',
      enabled: Boolean(p.enabled),
      minSeverity: SEVERITIES.includes(p.minSeverity) ? p.minSeverity : 'critical',
      secretConfigured: Boolean(secrets.pagerdutyRoutingKey),
      hasMinSeverity: true,
    },
  ];

  // Slack card only when SOC opted in via ALERT_SLACK_ENABLED.
  if (features.slack === true) {
    rows.push({
      id: 'slack',
      title: 'Slack',
      enabled: Boolean(sl.enabled),
      minSeverity: SEVERITIES.includes(sl.minSeverity) ? sl.minSeverity : 'high',
      secretConfigured: Boolean(secrets.slackWebhook),
      hasMinSeverity: true,
    });
  }

  return rows;
}

/** Destinations currently toggled on (regardless of secret readiness). */
export function activeRoutes(payload) {
  return destinationRows(payload).filter((r) => r.enabled);
}

/**
 * Destinations that would receive a finding of the given severity.
 * A missing/unknown severity is treated as too low to route (fail closed).
 *
 * @param {{ alerts?: object, secrets?: object }} payload
 * @param {string} severity
 * @returns {Array<object>}
 */
export function routesForSeverity(payload, severity) {
  const rank = SEVERITY_RANK[severity];
  if (rank === undefined) return [];
  return activeRoutes(payload).filter((r) => {
    if (r.minSeverity == null) return true; // no floor → all severities
    const floor = SEVERITY_RANK[r.minSeverity];
    if (floor === undefined) return false;
    return rank <= floor; // finding is at least as severe as the floor
  });
}

/**
 * Panel-level summary used for empty / partial states.
 *
 * @param {{ alerts?: object, secrets?: object }} payload
 */
export function routingSummary(payload) {
  const routes = destinationRows(payload);
  const enabled = routes.filter((r) => r.enabled);
  const missingSecrets = enabled.filter((r) => !r.secretConfigured);
  const ready = enabled.filter((r) => r.secretConfigured);
  return {
    enabledCount: enabled.length,
    readyCount: ready.length,
    noneEnabled: enabled.length === 0,
    missingSecrets,
    routes,
  };
}

/** Human label for a route chip: "Webhook (≥ high)" or "Microsoft Sentinel". */
export function routeLabel(row) {
  if (row.minSeverity) return `${row.title} (≥ ${row.minSeverity})`;
  return row.title;
}

/**
 * Client-side validation mirrors PUT /api/guardrail/alerts (apps/api guardrail.js).
 * Returns { ok: true } or { ok: false, field, message } where field is a CSS class
 * selector key the form can focus (e.g. 'ac-url').
 *
 * @param {'webhook'|'sentinel'|'googleChat'|'email'|'pagerduty'|'slack'} dest
 * @param {object} fields
 */
export function validateDestination(dest, fields) {
  if (dest === 'webhook') return validateWebhook(fields);
  if (dest === 'sentinel') return validateSentinel(fields);
  if (dest === 'googleChat') return validateGoogleChat(fields);
  if (dest === 'email') return validateEmail(fields);
  if (dest === 'pagerduty') return validatePagerDuty(fields);
  if (dest === 'slack') return validateSlack(fields);
  return { ok: false, field: null, message: `Unknown destination: ${dest}` };
}

export function validateWebhook({ enabled, url, minSeverity } = {}) {
  if (typeof enabled !== 'boolean') {
    return { ok: false, field: 'ac-enabled', message: 'Enabled must be on or off.' };
  }
  if (minSeverity !== undefined && !SEVERITIES.includes(minSeverity)) {
    return { ok: false, field: 'ac-minsev', message: `Min severity must be one of ${SEVERITIES.join(', ')}.` };
  }
  const u = typeof url === 'string' ? url.trim() : '';
  if (enabled && !u) {
    return { ok: false, field: 'ac-url', message: 'Enabled webhook requires a non-empty https:// URL.' };
  }
  if (u) {
    let parsed;
    try {
      parsed = new URL(u);
    } catch {
      return { ok: false, field: 'ac-url', message: 'Webhook URL must be a valid https:// URL (or empty to clear).' };
    }
    if (parsed.protocol !== 'https:') {
      return { ok: false, field: 'ac-url', message: 'Webhook URL must use https://.' };
    }
  }
  return { ok: true };
}

export function validateSentinel({ enabled, workspaceId, logType } = {}) {
  if (typeof enabled !== 'boolean') {
    return { ok: false, field: 'ac-enabled', message: 'Enabled must be on or off.' };
  }
  const ws = typeof workspaceId === 'string' ? workspaceId.trim() : '';
  if (ws && !/^[0-9a-fA-F-]{32,36}$/.test(ws)) {
    return { ok: false, field: 'ac-workspace', message: 'Workspace ID must be a GUID (or empty).' };
  }
  if (enabled && !ws) {
    return { ok: false, field: 'ac-workspace', message: 'Enabled Sentinel requires a workspace ID.' };
  }
  const lt = typeof logType === 'string' ? logType.trim() : '';
  if (lt && !/^[A-Za-z0-9_]{1,64}$/.test(lt)) {
    return { ok: false, field: 'ac-logtype', message: 'Log type must be 1–64 letters, digits, or underscores.' };
  }
  return { ok: true };
}

export function validateGoogleChat({ enabled, minSeverity } = {}) {
  if (typeof enabled !== 'boolean') {
    return { ok: false, field: 'ac-enabled', message: 'Enabled must be on or off.' };
  }
  if (minSeverity !== undefined && !SEVERITIES.includes(minSeverity)) {
    return { ok: false, field: 'ac-minsev', message: `Min severity must be one of ${SEVERITIES.join(', ')}.` };
  }
  return { ok: true };
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const EMAIL_MAX_RECIPIENTS = 20;

export function validateEmail({ enabled, to, minSeverity } = {}) {
  if (typeof enabled !== 'boolean') {
    return { ok: false, field: 'ac-enabled', message: 'Enabled must be on or off.' };
  }
  if (minSeverity !== undefined && !SEVERITIES.includes(minSeverity)) {
    return { ok: false, field: 'ac-minsev', message: `Min severity must be one of ${SEVERITIES.join(', ')}.` };
  }
  const raw = typeof to === 'string' ? to.trim() : '';
  if (enabled && !raw) {
    return { ok: false, field: 'ac-email-to', message: 'Enabled email requires at least one recipient.' };
  }
  if (raw) {
    const parts = raw.split(/[,;]/).map((s) => s.trim()).filter(Boolean);
    if (parts.length > EMAIL_MAX_RECIPIENTS) {
      return { ok: false, field: 'ac-email-to', message: `At most ${EMAIL_MAX_RECIPIENTS} recipients.` };
    }
    for (const p of parts) {
      if (!EMAIL_RE.test(p) || p.length > 254) {
        return { ok: false, field: 'ac-email-to', message: `Invalid email address: ${p}` };
      }
    }
  }
  return { ok: true };
}

/**: enable + floor only; routing key is env-only. */
export function validatePagerDuty({ enabled, minSeverity } = {}) {
  if (typeof enabled !== 'boolean') {
    return { ok: false, field: 'ac-enabled', message: 'Enabled must be on or off.' };
  }
  if (minSeverity !== undefined && !SEVERITIES.includes(minSeverity)) {
    return { ok: false, field: 'ac-minsev', message: `Min severity must be one of ${SEVERITIES.join(', ')}.` };
  }
  return { ok: true };
}

/**: enable + floor only; webhook URL is env-only. */
export function validateSlack({ enabled, minSeverity } = {}) {
  if (typeof enabled !== 'boolean') {
    return { ok: false, field: 'ac-enabled', message: 'Enabled must be on or off.' };
  }
  if (minSeverity !== undefined && !SEVERITIES.includes(minSeverity)) {
    return { ok: false, field: 'ac-minsev', message: `Min severity must be one of ${SEVERITIES.join(', ')}.` };
  }
  return { ok: true };
}

/**
 * Collect field values from a destination card DOM element.
 * Pure enough to unit-test with a minimal object that has .querySelector.
 */
export function readCardFields(dest, cardEl) {
  if (!cardEl) return {};
  const enabled = Boolean(cardEl.querySelector('.ac-enabled')?.checked);
  if (dest === 'webhook') {
    return {
      enabled,
      url: cardEl.querySelector('.ac-url')?.value ?? '',
      minSeverity: cardEl.querySelector('.ac-minsev')?.value ?? 'high',
    };
  }
  if (dest === 'sentinel') {
    return {
      enabled,
      workspaceId: cardEl.querySelector('.ac-workspace')?.value ?? '',
      logType: cardEl.querySelector('.ac-logtype')?.value ?? 'AIGuardrailFinding',
    };
  }
  if (dest === 'googleChat') {
    return {
      enabled,
      minSeverity: cardEl.querySelector('.ac-minsev')?.value ?? 'high',
    };
  }
  if (dest === 'email') {
    return {
      enabled,
      to: cardEl.querySelector('.ac-email-to')?.value ?? '',
      minSeverity: cardEl.querySelector('.ac-minsev')?.value ?? 'high',
    };
  }
  if (dest === 'pagerduty') {
    return {
      enabled,
      minSeverity: cardEl.querySelector('.ac-minsev')?.value ?? 'critical',
    };
  }
  if (dest === 'slack') {
    return {
      enabled,
      minSeverity: cardEl.querySelector('.ac-minsev')?.value ?? 'high',
    };
  }
  return { enabled };
}

/** Build the PUT body section for one destination from form fields. */
export function payloadForDestination(dest, fields) {
  if (dest === 'webhook') {
    return {
      webhook: {
        enabled: fields.enabled,
        url: (fields.url ?? '').trim(),
        minSeverity: fields.minSeverity,
      },
    };
  }
  if (dest === 'sentinel') {
    return {
      sentinel: {
        enabled: fields.enabled,
        workspaceId: (fields.workspaceId ?? '').trim(),
        logType: (fields.logType ?? '').trim() || 'AIGuardrailFinding',
      },
    };
  }
  if (dest === 'googleChat') {
    return {
      googleChat: {
        enabled: fields.enabled,
        minSeverity: fields.minSeverity,
      },
    };
  }
  if (dest === 'email') {
    return {
      email: {
        enabled: fields.enabled,
        to: (fields.to ?? '').trim(),
        minSeverity: fields.minSeverity,
      },
    };
  }
  if (dest === 'pagerduty') {
    return {
      pagerduty: {
        enabled: fields.enabled,
        minSeverity: fields.minSeverity,
      },
    };
  }
  if (dest === 'slack') {
    return {
      slack: {
        enabled: fields.enabled,
        minSeverity: fields.minSeverity,
      },
    };
  }
  return {};
}

/**
 * Merge every destination card present on the panel into one PUT body.
 * Used by "Save all destinations". Does not include escalationPolicies —
 * those are saved separately via the escalation editor (partial PUT merge).
 */
export function payloadFromPanel(panelEl) {
  if (!panelEl) return {};
  const body = {};
  // Walk cards that are actually rendered (Slack may be feature-gated off).
  for (const card of panelEl.querySelectorAll('[data-dest]')) {
    const id = card.getAttribute('data-dest');
    if (!id || !DEST_BY_ID[id]) continue;
    Object.assign(body, payloadForDestination(id, readCardFields(id, card)));
  }
  return body;
}

/**
 * Validate every card on the panel. Returns first failure with dest id, or { ok: true }.
 */
export function validatePanel(panelEl) {
  if (!panelEl) return { ok: false, dest: null, field: null, message: 'No destinations panel.' };
  for (const card of panelEl.querySelectorAll('[data-dest]')) {
    const id = card.getAttribute('data-dest');
    if (!id || !DEST_BY_ID[id]) continue;
    const fields = readCardFields(id, card);
    const result = validateDestination(id, fields);
    if (!result.ok) return { ...result, dest: id };
  }
  return { ok: true };
}

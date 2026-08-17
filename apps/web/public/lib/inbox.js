/* AIM-160 — pure logic for the unified alert inbox (public/inbox.js).
 * DOM-free by design, same split as lib/triage.js: inbox.js renders and
 * fetches, this module decides — so the security-sensitive parts (evidence
 * URL resolution above all) are unit-testable under node:test. */
import { shortRef } from './format.js';

import { SEVERITY_FILTER_BANDS, severityBandOf } from './severity.js';

/* scheme -> gateway subdomain. MUST mirror SCHEME_HOSTS in
 * services/sentinel/src/sentinel/render.py: the sentinel and the inbox both
 * resolve the contract's source_uri, and the two disagreeing about where
 * `gatehouse:/pr/12` points is the open-redirect hole D3.1 §3.4 closes.
 * `guardrail` alerts are AI-Monitoring findings, so they resolve to aim. */

export const SCHEME_HOSTS = {
  cnapp: 'cnapp',
  cloudsentry: 'cnapp',
  aim: 'aim',
  guardrail: 'aim',
  gatehouse: 'gatehouse',
  sentinel: 'sentinel',
};

/* The contract's source_uri pattern (security-alert.schema.json), kept whole:
 * scheme-relative refs only — no absolute or protocol-relative URIs, no
 * traversal, no fragments, no ':' '/' '<' '>' in query values. An alert that
 * passed the API's consumer profile already matches this; re-checking here
 * means a hand-crafted API response still cannot turn into a URL. */
const SOURCE_URI_RE = /^([a-z][a-z0-9-]{0,31}):((?:\/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+(?:\?[a-z][a-z0-9_]*=[A-Za-z0-9._~%-]*(?:&[a-z][a-z0-9_]*=[A-Za-z0-9._~%-]*){0,7})?)$/;

/* host[:port] — what AIM_GATEWAY_HOST is documented to be. Anything else
 * (a URL, whitespace, userinfo) refuses resolution rather than breaking out
 * of the <subdomain>.<host> shape. */
const GATEWAY_HOST_RE = /^[a-z0-9][a-z0-9.-]*(:[0-9]{1,5})?$/i;

/* Resolve a source_uri to an absolute gateway URL, or null when unresolvable.
 * Null is a real answer: the caller renders the raw ref as inert TEXT, never
 * as an href. An unknown scheme becoming `https://<scheme>...` is exactly the
 * `javascript:`-shaped link this function exists to prevent. */
export function resolveEvidenceUrl(sourceUri, gatewayHost) {
  const match = SOURCE_URI_RE.exec(String(sourceUri ?? ''));
  if (!match) return null;
  const subdomain = SCHEME_HOSTS[match[1]];
  if (!subdomain) return null;
  const host = String(gatewayHost ?? '');
  if (!GATEWAY_HOST_RE.test(host)) return null;
  return `https://${subdomain}.${host}${match[2]}`;
}

/* The four bands the inbox filter bar offers, in display order. The API
 * matches on the band as well as the label (§7.4 rev 6), so an
 * out-of-vocabulary severity label is still caught by these filters.
 * AIM-524: the vocabulary is lib/severity.js's — the inbox no longer keeps
 * its own copy of the bands, the ordering or the severity_id mapping. */
export const SEVERITIES = SEVERITY_FILTER_BANDS;

/* The contract's pillar enum, in display order (cloud posture, AI usage,
 * PR security, secrets hygiene, the sentinel itself). Wire values stay
 * snake_case for the bus; UI labels are in PILLAR_LABELS (AIM-482). */
export const PILLARS = ['cloud_posture', 'ai_usage', 'pr_security', 'secrets_hygiene', 'sentinel'];

/* Friendly filter labels — never render raw pillar enums as card chrome. */
export const PILLAR_LABELS = {
  cloud_posture: 'cloud posture',
  ai_usage: 'AI tool usage',
  pr_security: 'PR security',
  secrets_hygiene: 'secrets hygiene',
  sentinel: 'platform',
};

/* Snooze presets offered on each row, [label, minutes]. The 7d ceiling is
 * well under the API's 30-day cap, so the UI can never 400 itself. */
export const SNOOZE_PRESETS = [['1h', 60], ['8h', 480], ['24h', 1440], ['7d', 10080]];

/* Band for an alert's row class. Out-of-vocabulary labels (corpus line 6:
 * severity "catastrophic", severity_id 5) must still render in their band's
 * colour — burying a critical-band alert visually is the same failure as
 * ranking it wrong. The severity_id -> band mapping now lives in
 * lib/severity.js with the rest of the scale; this stays as the inbox's name
 * for it. */
export function severityBandClass(alert) {
  return severityBandOf(alert);
}

/* Query string for GET /api/alerts from the filter bar state. Both filters
 * are passed THROUGH to the API — filtering re-queries, it never filters a
 * full local copy (the whole point of cursor paging). */
export function buildFilterParams({ severities, pillars } = {}) {
  const params = new URLSearchParams();
  const sev = [...(severities ?? [])].filter((s) => SEVERITIES.includes(s));
  const pil = [...(pillars ?? [])].filter((p) => PILLARS.includes(p));
  if (sev.length) params.set('severity', sev.join(','));
  if (pil.length) params.set('pillar', pil.join(','));
  return params;
}

/* AIM-482: map a bus alert onto AI-tool-governance presentation fields.
 * The contract still carries CNAPP-era pillars/resource shapes for wire
 * compatibility; the Alerts surface must not render those as the primary
 * card vocabulary. Prefer labels/subject, fall back carefully, never invent
 * cloud ARNs as the headline. */
const EXPOSURE_BY_NAMESPACE = {
  secret: 'secret_exposure',
  secrets: 'secret_exposure',
  secrets_hygiene: 'secret_exposure',
  pii: 'pii_exposure',
  policy: 'policy_violation',
  unapproved: 'tool_governance',
  ai_usage: 'tool_governance',
  pr_security: 'pr_security',
  cloud_posture: 'cloud_posture',
  cloud: 'cloud_posture',
  sentinel: 'platform',
  supply_chain: 'supply_chain',
};

export function exposureClassOf(alert) {
  const ft = String(alert?.finding_type ?? '');
  const ns = ft.includes('.') ? ft.split('.')[0] : ft;
  if (EXPOSURE_BY_NAMESPACE[ns]) return EXPOSURE_BY_NAMESPACE[ns];
  const leaf = ft.includes('.') ? ft.split('.').slice(1).join('.') : ft;
  if (/secret|credential|token|key/.test(leaf)) return 'secret_exposure';
  if (/pii|email|phone|ssn/.test(leaf)) return 'pii_exposure';
  if (/unapproved|tool/.test(leaf)) return 'tool_governance';
  return ns || 'unknown';
}

function labelOf(alert, ...keys) {
  const labels = alert?.labels && typeof alert.labels === 'object' ? alert.labels : {};
  for (const k of keys) {
    const v = labels[k];
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return null;
}

/** Domain fields for AI-native alert cards (tool / session / rule / exposure / user / repo). */
export function alertDomainFields(alert) {
  const labels = alert?.labels && typeof alert.labels === 'object' ? alert.labels : {};
  const resource = alert?.resource && typeof alert.resource === 'object' ? alert.resource : {};
  const subject = alert?.subject_ref && typeof alert.subject_ref === 'object' ? alert.subject_ref : {};

  const tool = labelOf(alert, 'tool_raw', 'tool', 'tool_name')
    || (resource.kind === 'ai_session' && resource.display && !/arn:|s3:|gcp:|azure:/i.test(resource.display)
      ? resource.display
      : null);

  let session = labelOf(alert, 'session_id', 'session')
    || (resource.kind === 'ai_session' ? (resource.ref || resource.display) : null);
  if (session && String(session).startsWith('aim:session:')) {
    session = String(session).slice('aim:session:'.length);
  }

  const rule = labelOf(alert, 'rule_id', 'rule', 'detector')
    || (typeof alert?.finding_type === 'string' && alert.finding_type.includes('.')
      ? alert.finding_type.split('.').slice(1).join('.')
      : alert?.finding_type)
    || null;

  const user = subject.user_ref
    || labelOf(alert, 'user_ref', 'user')
    || null;

  let repo = labelOf(alert, 'repo_ref', 'repo')
    || (resource.kind === 'repo' || resource.kind === 'pull_request'
      ? (resource.display || resource.ref)
      : null);
  // Do not surface cloud ARNs as "repo" — that reintroduces CNAPP card shape.
  if (repo && /arn:aws:|\/\/|s3:\/\//i.test(String(repo)) && resource.kind === 'cloud_resource') {
    repo = null;
  }

  /* AIM-702: optional policy_hash label for auto-triage keying (metadata only). */
  const policyHash = labelOf(alert, 'policy_hash', 'policyHash');

  return {
    tool,
    session: session ? shortRef(session, 14) : null,
    sessionFull: session,
    rule,
    policyHash,
    exposureClass: exposureClassOf(alert),
    user: user ? shortRef(user) : null,
    userFull: user,
    repo: repo ? shortRef(repo) : null,
    repoFull: repo,
    /* Keep raw finding_type for text search only — not for primary card chrome. */
    findingType: alert?.finding_type ?? null,
    /* Labels bag for text search (tool_raw etc.). */
    labelValues: Object.values(labels).filter((v) => typeof v === 'string'),
  };
}

/* The free-text filter. Deliberately client-side over the LOADED page only
 * (the UI labels it that way): the bus API has no text filter, and loading
 * every alert to filter locally would defeat cursor paging. Matches the
 * fields an analyst actually scans: title plus AI-domain fields. */
export function matchesText(alert, query) {
  const q = String(query ?? '').trim().toLowerCase();
  if (!q) return true;
  const d = alertDomainFields(alert);
  const hay = [
    alert?.title,
    d.findingType,
    d.tool,
    d.sessionFull,
    d.rule,
    d.exposureClass,
    d.userFull,
    d.repoFull,
    ...d.labelValues,
  ];
  return hay.some((v) => typeof v === 'string' && v.toLowerCase().includes(q));
}

/* What the state badge says for one alert. `states` is the map from
 * GET /api/alerts/state; absent means open (an expired snooze is excluded
 * server-side, so it arrives as absent too). */
export function inboxStateOf(states, alertId) {
  return states?.[alertId]?.state ?? 'open';
}

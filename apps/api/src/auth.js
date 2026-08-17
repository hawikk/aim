// Authn/z (unified role model, fine-grained RBAC
// + optional ABAC, multi-IdP OIDC). In-app OIDC and/or
// SAML 2.0 SP single sign-on with a four-role model that expands
// into a permission matrix:
//
//   admin     full access (user-level data, guardrail, labels, admin)
//   analyst   dashboards, findings console, user-level rows, fleet
//   auditor   dashboards, compliance evidence, audit trail (read-only)
//   viewer    org/team aggregates + dashboards only (no per-engineer rows)
//
// Permissions (authz.js) are the unit of authorization beyond coarse roles.
// requirePermission() gates on the matrix; requireRoles() remains for
// existing routes. Optional ABAC attribute conditions attach to permission
// checks without changing the default pure-RBAC path.
//
// The `reveal` grant (de-pseudonymization, PII-flagged content) is NOT a
// role: it is a separate capability bit derived from membership in
// AIM_REVEAL_GROUPS (default ai-monitoring-revealers), surfaced on
// GET /api/me and mirrored server-side where reveal paths exist.
//
// Modes:
//   sso       — one or more complete OIDC providers: authorization code
//               flow with PKCE, sessions in an HMAC-signed cookie.
//               Legacy single-IdP: AIM_OIDC_ISSUER + CLIENT_ID + CLIENT_SECRET.
// Multi-IdP: AIM_OIDC_PROVIDERS=google,entra,okta with
//               AIM_OIDC_<ID>_{ISSUER,CLIENT_ID,CLIENT_SECRET} per entry.
//               Concurrent providers share one redirect URI; login picks via
//               ?provider= or the HTML picker when multiple are configured.
//   personal  — no auth config: standalone/personal use, every request runs
//               as a local admin. AIM_AUTH_DEV=1 adds /auth/dev/*
//               role-switch endpoints (built-in secret, localhost only).
//
// Pilot / production graduation:
//   AIM_REQUIRE_SSO=1 refuses personal mode and refuses AIM_AUTH_DEV. Partial
//   AIM_OIDC_* (any of issuer/id/secret without all three, or incomplete
//   multi-provider entry) always fails closed at boot — never silently
//   degrades to local-admin.
//
// Client-supplied identity headers (x-forwarded-*) are NEVER trusted; the
// session cookie is the only identity source in SSO mode.
//
// Fail closed: an authenticated user whose groups map to no configured role
// gets role null — zero capabilities, every gated route 403s.
//
// server-side session revoke. HMAC cookies stay stateless,
// but each request also checks an email revoke watermark
// (session-revocation.js). Sessions with iat <= watermark are treated as
// unauthenticated — leaver force-deny without waiting for
// AIM_SESSION_TTL_HOURS. Watermarks come from admin playbook or identity-sync
// deprovision automation (designated service token).
// server-side session revoke. HMAC cookies stay stateless, but each
// request also checks an email revoke watermark (session-revocation.js).
// Sessions with iat <= watermark are treated as unauthenticated — leaver
// force-deny without waiting for AIM_SESSION_TTL_HOURS or secret rotation.
import { createHmac, timingSafeEqual } from 'node:crypto';
import * as oidc from 'openid-client';
import fastifyCookie from '@fastify/cookie';
import { audit } from './audit.js';
import { ServiceTokens, bearerFrom } from './servicetoken.js';
import { sessionRevocations } from './session-revocation.js';
import { scimDirectory } from './scim-store.js';
import {
  isJitEnabled,
  jitFailureBlocksLogin,
  jitProvisionOnLogin,
} from './jit-provision.js';
import { loginErrorPresentation } from './login-errors.js';
import * as db from './db.js';
import {
  attributesFromIdentity,
  evaluateAccess,
  hasPermission as identityHasPermission,
  normalizeAttributes,
  permissionList,
} from './authz.js';
import {
  readSamlEnv,
  createSamlSp,
  identityFromSamlProfile,
} from './saml-sp.js';

// Re-export AuthZ model entry points so route modules can import from auth.js.
export {
  PERMISSIONS,
  ROLE_PERMISSIONS,
  evaluateAccess,
  hasPermission as hasPermissionId,
  matchAttributes,
  permissionList,
  permissionsFor,
  rolePermissionMatrix,
} from './authz.js';

function splitCsv(value) {
  return String(value ?? '')
    .split(',')
    .map((g) => g.trim())
    .filter(Boolean);
}

// Pilot Google Workspace group inventory. Exact claim strings must
// match the IdP `groups` claim — short names below are the pilot defaults;
// operators override via AIM_ROLE_GROUPS_* / AIM_REVEAL_GROUPS when the IdP
// emits email-form group ids (e.g. ai-monitoring-analysts@examplecorp.com).
// See docs/security/group-role-matrix.md.
export const DEFAULT_ROLE_GROUPS = Object.freeze({
  admin: Object.freeze(['ai-monitoring-security']),
  analyst: Object.freeze(['ai-monitoring-analysts']),
  auditor: Object.freeze(['ai-monitoring-auditors']),
  viewer: Object.freeze(['ai-monitoring-viewers']),
});
export const DEFAULT_REVEAL_GROUPS = Object.freeze(['ai-monitoring-revealers']);
// Highest rank wins when a principal is in several AIM groups.
export const ROLE_PRECEDENCE = Object.freeze(['admin', 'analyst', 'auditor', 'viewer']);

/* ---------- Multi-IdP OIDC providers ----------
 *
 * Production-ready Google Workspace + Microsoft Entra ID + Okta, either
 * concurrently (login picker / ?provider=) or as a single-IdP switch
 * (AIM_OIDC_PROVIDERS=<one id>). Legacy AIM_OIDC_ISSUER/CLIENT_* remains
 * a single anonymous provider id "default".
 *
 * All providers share AIM_OIDC_REDIRECT_URI (register the same callback
 * URL on every IdP app). Role mapping stays global (AIM_ROLE_GROUPS_*).
 */
export const IDP_PRESETS = Object.freeze({
  google: Object.freeze({
    label: 'Google Workspace',
    defaultIssuer: 'https://accounts.google.com',
    defaultScopes: 'openid profile email',
    defaultGroupsClaim: 'groups',
  }),
  entra: Object.freeze({
    label: 'Microsoft Entra ID',
    // Tenant-specific: https://login.microsoftonline.com/{tenant}/v2.0
    defaultIssuer: null,
    defaultScopes: 'openid profile email',
    defaultGroupsClaim: 'groups',
  }),
  okta: Object.freeze({
    label: 'Okta',
    // Org-specific: https://{org}.okta.com or .../oauth2/default
    defaultIssuer: null,
    defaultScopes: 'openid profile email groups',
    defaultGroupsClaim: 'groups',
  }),
});

const PROVIDER_ID_RE = /^[a-z][a-z0-9_-]{0,31}$/;

function oidcProviderEnvKey(id, field) {
  return `AIM_OIDC_${String(id).toUpperCase().replace(/[^A-Z0-9]/g, '_')}_${field}`;
}

/**
 * Parse configured OIDC providers from env.
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {Array<{id:string,label:string,issuer:string,clientId:string,clientSecret:string,scopes:string,groupsClaim:string,complete:boolean,partial:boolean}>}
 */
export function parseOidcProviders(env = process.env) {
  const redirectUri =
    env.AIM_OIDC_REDIRECT_URI ?? `${env.AIM_BASE_URL ?? 'http://localhost:8080'}/auth/callback`;
  const globalScopes = env.AIM_OIDC_SCOPES ?? 'openid profile email';
  const globalGroupsClaim = env.AIM_OIDC_GROUPS_CLAIM ?? 'groups';
  const listRaw = env.AIM_OIDC_PROVIDERS;
  const out = [];

  if (listRaw && String(listRaw).trim()) {
    for (const rawId of splitCsv(listRaw)) {
      const id = String(rawId).toLowerCase();
      if (!PROVIDER_ID_RE.test(id)) {
        throw new Error(
          `invalid AIM_OIDC_PROVIDERS id "${rawId}": use lowercase [a-z][a-z0-9_-]{0,31}`,
        );
      }
      const preset = IDP_PRESETS[id] ?? {};
      const issuer = env[oidcProviderEnvKey(id, 'ISSUER')] || preset.defaultIssuer || '';
      const clientId = env[oidcProviderEnvKey(id, 'CLIENT_ID')] || '';
      const clientSecret = env[oidcProviderEnvKey(id, 'CLIENT_SECRET')] || '';
      const scopes = env[oidcProviderEnvKey(id, 'SCOPES')] || globalScopes || preset.defaultScopes || 'openid profile email';
      const groupsClaim =
        env[oidcProviderEnvKey(id, 'GROUPS_CLAIM')] || globalGroupsClaim || preset.defaultGroupsClaim || 'groups';
      const label = env[oidcProviderEnvKey(id, 'LABEL')] || preset.label || id;
      const complete = Boolean(issuer && clientId && clientSecret);
      // Listed in AIM_OIDC_PROVIDERS but incomplete → fail closed at boot.
      const partial = !complete;
      out.push({
        id,
        label,
        issuer,
        clientId,
        clientSecret,
        scopes,
        groupsClaim,
        redirectUri,
        complete,
        partial,
      });
    }
    return out;
  }

  // Legacy single-provider (earlier).
  const issuer = env.AIM_OIDC_ISSUER || '';
  const clientId = env.AIM_OIDC_CLIENT_ID || '';
  const clientSecret = env.AIM_OIDC_CLIENT_SECRET || '';
  if (issuer || clientId || clientSecret) {
    const complete = Boolean(issuer && clientId && clientSecret);
    out.push({
      id: 'default',
      label: 'SSO',
      issuer,
      clientId,
      clientSecret,
      scopes: globalScopes,
      groupsClaim: globalGroupsClaim,
      redirectUri,
      complete,
      partial: !complete,
    });
  }
  return out;
}


function parseScimGroupRoleMap(raw) {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    const out = {};
    for (const [k, v] of Object.entries(parsed)) {
      const role = String(v).toLowerCase();
      if (['admin', 'analyst', 'auditor', 'viewer'].includes(role)) {
        out[String(k).trim().toLowerCase()] = role;
      }
    }
    return out;
  } catch {
    return {};
  }
}
const oidcProviders = parseOidcProviders();

const config = {
  // ordered provider list (empty = personal mode).
  oidcProviders,
  baseUrl: process.env.AIM_BASE_URL ?? 'http://localhost:8080',
  redirectUri:
    process.env.AIM_OIDC_REDIRECT_URI ?? `${process.env.AIM_BASE_URL ?? 'http://localhost:8080'}/auth/callback`,
  // Global defaults still used for role mapping docs / single-provider legacy.
  scopes: process.env.AIM_OIDC_SCOPES ?? 'openid profile email',
  groupsClaim: process.env.AIM_OIDC_GROUPS_CLAIM ?? 'groups',
  // Group -> role mapping. Precedence: admin > analyst > auditor > viewer.
  // Empty override (AIM_ROLE_GROUPS_X="") means that role has no IdP group —
  // fail closed for that tier; there is no implicit fallback to "everyone".
  roleGroups: {
    admin: splitCsv(process.env.AIM_ROLE_GROUPS_ADMIN ?? DEFAULT_ROLE_GROUPS.admin.join(',')),
    analyst: splitCsv(process.env.AIM_ROLE_GROUPS_ANALYST ?? DEFAULT_ROLE_GROUPS.analyst.join(',')),
    auditor: splitCsv(process.env.AIM_ROLE_GROUPS_AUDITOR ?? DEFAULT_ROLE_GROUPS.auditor.join(',')),
    viewer: splitCsv(process.env.AIM_ROLE_GROUPS_VIEWER ?? DEFAULT_ROLE_GROUPS.viewer.join(',')),
  },
  // The reveal grant (§1): a separate capability, not a role and not
  // bundled into admin. Membership in one of these IdP groups sets the
  // `reveal` bit on the session; identity-sync gates POST /reveal on the same
  // group name (services/identity-sync config.py reveal_role).
  revealGroups: splitCsv(process.env.AIM_REVEAL_GROUPS ?? DEFAULT_REVEAL_GROUPS.join(',')),
  sessionSecret: process.env.AIM_SESSION_SECRET,
  sessionTtlHours: Number(process.env.AIM_SESSION_TTL_HOURS ?? 8) || 8,
  dev: process.env.AIM_AUTH_DEV === '1',
  // pilot and values-standard set this so a missing OIDC
  // secret never silently reopens personal-mode local-admin.
  requireSso: process.env.AIM_REQUIRE_SSO === '1',
  // Machine credentials for headless consumers (the sentinel). A
  // file rather than an env var: env vars are visible in `docker inspect` and
  // are inherited by child processes, and this one gates the alert inbox.
  serviceTokensFile: process.env.AIM_SERVICE_TOKENS_FILE,
  // SCIM: when a bearer token is configured, the directory is live.
  // Soft mode (default): provisioned users with active=false are denied on
  // every request. Enforce mode (AIM_SCIM_ENFORCE=1): only active SCIM users
  // may hold an SSO session (unknown emails denied).
  scimEnabled: Boolean(
    process.env.AIM_SCIM_BEARER_TOKEN && String(process.env.AIM_SCIM_BEARER_TOKEN).length >= 16,
  ),
  scimEnforce: process.env.AIM_SCIM_ENFORCE === '1',
  // JIT provision into SCIM directory on first SSO login (default on
  // when SCIM is configured; AIM_JIT_PROVISIONING=0 disables).
  jitProvisioning: isJitEnabled({
    scimEnabled: Boolean(
      process.env.AIM_SCIM_BEARER_TOKEN && String(process.env.AIM_SCIM_BEARER_TOKEN).length >= 16,
    ),
  }),
  // Optional JSON map of SCIM group displayName → AIM role, merged with
  // AIM_ROLE_GROUPS_* (display names that match role groups still work).
  scimGroupRoleMap: parseScimGroupRoleMap(process.env.AIM_SCIM_GROUP_ROLE_MAP),
  // optional OIDC claim names whose values become principal ABAC
  // attributes (CSV of claim keys). Empty = only derived attrs (teams from
  // groups, email, role). Example: AIM_OIDC_ATTR_CLAIMS=department,cost_center
  attrClaims: splitCsv(process.env.AIM_OIDC_ATTR_CLAIMS ?? ''),
  // SAML 2.0 SP — parallel to OIDC; see docs/deployment/saml-sso-runbook.md
  saml: readSamlEnv(process.env),
};

const OIDC_ENABLED =
  config.oidcProviders.length > 0 && config.oidcProviders.every((p) => p.complete);
const ANY_OIDC = config.oidcProviders.length > 0;
const SAML_ENABLED = Boolean(config.saml?.enabled);
const ANY_SAML = Boolean(config.saml?.any);
const SSO_ENABLED = OIDC_ENABLED || SAML_ENABLED;

// Loaded once at import. Tests override via setServiceTokens().
let serviceTokens = ServiceTokens.fromFile(config.serviceTokensFile);

/** Test seam; also lets server.js re-point the verifier after a reload. */
export function setServiceTokens(tokens) {
  serviceTokens = tokens;
}

/** Test seam: expose the process-wide revoke store (same instance auth uses). */
export function getSessionRevocations() {
  return sessionRevocations;
}

/**
 * Boot probe: non-null when AIM_SERVICE_TOKENS_FILE was set but unusable.
 * server.js turns this into a fatal startup error — a service-auth deployment
 * whose token file failed to parse must not come up looking healthy while
 * every consumer 401s.
 */
export function serviceTokenLoadError() {
  return serviceTokens.loadError();
}

export function serviceTokenNames() {
  return serviceTokens.names();
}

const SESSION_COOKIE = 'aim_session';
const OIDC_STATE_COOKIE = 'aim_oidc_state';
const OIDC_STATE_TTL_SECONDS = 600;
// Dev role-switching signs sessions with a well-known secret — acceptable
// only because AIM_AUTH_DEV is for local development (warned at startup).
const DEV_SESSION_SECRET = 'aim-dev-session-secret-not-for-production-use';

const PERSONAL_IDENTITY = {
  email: 'local-admin@localhost',
  name: 'Local Admin',
  groups: [],
  role: 'admin',
  // Personal mode is a single local operator; the reveal grant is theirs.
  reveal: true,
  // empty attributes — personal mode has no team scope.
  attributes: {},
  permissionGrants: [],
  mode: 'personal',
};

const NO_CAPS = {
  dashboard: false, findingsConsole: false, userLevel: false, fleet: false,
  guardrail: false, compliance: false, auditTrail: false, admin: false,
  coverage: false, reveal: false,
};
// Server-computed capabilities per role; the UI must gate privileged
// surfaces on these, never on client-side group-name sniffing. The
// findingsConsole/userLevel flags keep their old privacy-gate semantics.
// `coverage` is analyst+ like fleet: coverage gaps are an
// attacker's roadmap, so the screen is not in the all-roles dashboard tier.
// `viewer` is the aggregate-only tier: dashboards and compliance evidence,
// no per-engineer rows, no findings, no audit trail. `reveal` is NOT set
// here — it comes from the session's reveal grant, not the role.
const ROLE_CAPS = {
  admin: { ...NO_CAPS, dashboard: true, findingsConsole: true, userLevel: true, fleet: true, guardrail: true, compliance: true, auditTrail: true, admin: true, coverage: true },
  analyst: { ...NO_CAPS, dashboard: true, findingsConsole: true, userLevel: true, fleet: true, compliance: true, coverage: true },
  auditor: { ...NO_CAPS, dashboard: true, compliance: true, auditTrail: true },
  viewer: { ...NO_CAPS, dashboard: true, compliance: true },
};

const COOKIE_OPTS = {
  httpOnly: true,
  sameSite: 'lax',
  path: '/',
  secure: config.baseUrl.startsWith('https://'),
};

/* ---------- public host guard ----------
 *
 * OIDC state/PKCE live in a host-only Secure cookie. If /auth/login is hit on
 * a side-channel host (direct container port :8085, bare localhost, etc.) the
 * cookie is bound to that host, Authelia still redirects to AIM_BASE_URL, and
 * /auth/callback returns invalid_state because the cookie never arrives.
 * Reject wrong-host login starts and render browser-friendly errors so the
 * operator is steered to the configured public URL.
 */
function publicHostFromUrl(url) {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return null;
  }
}

function splitHostPort(hostport) {
  const raw = String(hostport || '').trim().toLowerCase();
  if (!raw) return { hostname: '', port: '' };
  // IPv6 literals are out of scope for the pilot stack hosts.
  const idx = raw.lastIndexOf(':');
  if (idx > 0 && /^\d+$/.test(raw.slice(idx + 1))) {
    return { hostname: raw.slice(0, idx), port: raw.slice(idx + 1) };
  }
  return { hostname: raw, port: '' };
}

function requestPublicHost(req) {
  // Cookie host binding follows the browser's Host header (what the client
  // connected as). Prefer Host over X-Forwarded-Host: the stack Caddyfile
  // uses `{host}`, which omits the port, and would false-reject
  // AIM_BASE_URL hosts that include :8443.
  const raw = req.headers.host || req.headers['x-forwarded-host'] || '';
  return String(raw).split(',')[0].trim().toLowerCase();
}

function expectedPublicHost() {
  return publicHostFromUrl(config.baseUrl);
}

function hostsMatch(got, expected) {
  if (!expected) return true;
  if (!got) return false;
  if (got === expected) return true;
  const g = splitHostPort(got);
  const e = splitHostPort(expected);
  if (g.hostname !== e.hostname) return false;
  // Port-tolerant when either side omitted the port (proxy placeholders).
  if (!g.port || !e.port) return true;
  return g.port === e.port;
}

function isPublicHost(req) {
  return hostsMatch(requestPublicHost(req), expectedPublicHost());
}

function wantsHtml(req) {
  const accept = String(req.headers.accept || '');
  // Prefer HTML for top-level browser navigations (Accept lists text/html).
  // API tests / curl with no Accept or application/json stay on JSON.
  if (!accept || accept === '*/*') return false;
  const html = accept.indexOf('text/html');
  if (html < 0) return false;
  const json = accept.indexOf('application/json');
  return json < 0 || html < json;
}

function authErrorPage({
  title,
  error,
  detail,
  actionHref,
  actionLabel,
  runbookHref,
  runbookLabel,
  runbookPath,
}) {
  const esc = (s) =>
    String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  const runbookBlock =
    runbookHref || runbookPath
      ? `<p class="runbook">Operator runbook${
          runbookHref
            ? `: <a href="${esc(runbookHref)}" rel="noopener noreferrer">${esc(runbookLabel || runbookPath || 'Open runbook')}</a>`
            : ''
        }${runbookPath ? ` <code>${esc(runbookPath)}</code>` : ''}</p>`
      : '';
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${esc(title)}</title>
<style>
  body{font:15px/1.5 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1.25rem;color:#111;background:#fafafa}
  h1{font-size:1.25rem;margin:0 0 .5rem}
  p{margin:.5rem 0;color:#333}
  code{background:#eee;padding:.1rem .35rem;border-radius:3px;font-size:.9em}
  a.btn{display:inline-block;margin-top:1rem;padding:.55rem 1rem;background:#111;color:#fff;text-decoration:none;border-radius:6px}
  a.btn:hover{background:#333}
  a{color:#0b57d0}
  .err{color:#666;font-size:.85rem;margin-top:1.5rem}
  .runbook{font-size:.9rem;color:#444}
</style>
</head><body>
  <h1>${esc(title)}</h1>
  <p>${esc(detail)}</p>
  ${actionHref ? `<p><a class="btn" href="${esc(actionHref)}">${esc(actionLabel || 'Try again')}</a></p>` : ''}
  ${runbookBlock}
  <p class="err">Error code: <code>${esc(error)}</code></p>
</body></html>`;
}

/*: signed-out landing. Clearing the app session then immediately
 * redirecting to /auth/login re-triggers OIDC against a still-valid IdP
 * session and lands the user back on `/` — a sign-out loop. This page
 * ends the app session and waits for an explicit re-login click. */
function signedOutPage({ loginHref }) {
  const esc = (s) =>
    String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta name="robots" content="noindex"/>
<title>Signed out — AI Monitoring</title>
<style>
  body{font:15px/1.5 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1.25rem;color:#111;background:#fafafa}
  h1{font-size:1.25rem;margin:0 0 .5rem}
  p{margin:.5rem 0;color:#333}
  a.btn{display:inline-block;margin-top:1rem;padding:.55rem 1rem;background:#111;color:#fff;text-decoration:none;border-radius:6px}
  a.btn:hover{background:#333}
  .muted{color:#666;font-size:.9rem;margin-top:1.5rem}
</style>
</head><body>
  <h1>Signed out</h1>
  <p>Your AI Monitoring session has ended. This browser will not reopen the dashboard until you sign in again.</p>
  <p>If you share this workstation, also sign out of your company identity provider to fully end single sign-on.</p>
  ${loginHref ? `<p><a class="btn" href="${esc(loginHref)}">Sign in again</a></p>` : ''}
  <p class="muted">You are on the signed-out landing on purpose — automatic return to login would re-authenticate via SSO.</p>
</body></html>`;
}


/**: multi-IdP chooser when concurrent providers are configured. */
function providerPickerPage({ providers, baseUrl }) {
  const esc = (s) =>
    String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  const base = String(baseUrl || '').replace(/\/$/, '');
  const buttons = providers
    .map(
      (p) =>
        `<p><a class="btn" href="${esc(`${base}/auth/login?provider=${encodeURIComponent(p.id)}`)}">${esc(p.label)}</a></p>`,
    )
    .join('\n  ');
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta name="robots" content="noindex"/>
<title>Sign in — AI Monitoring</title>
<style>
  body{font:15px/1.5 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1.25rem;color:#111;background:#fafafa}
  h1{font-size:1.25rem;margin:0 0 .5rem}
  p{margin:.5rem 0;color:#333}
  a.btn{display:inline-block;margin-top:.35rem;padding:.55rem 1rem;background:#111;color:#fff;text-decoration:none;border-radius:6px;min-width:12rem;text-align:center}
  a.btn:hover{background:#333}
  .muted{color:#666;font-size:.9rem;margin-top:1.5rem}
</style>
</head><body>
  <h1>Sign in to AI Monitoring</h1>
  <p>Choose your company identity provider:</p>
  ${buttons}
  <p class="muted">Operators can deep-link with <code>/auth/login?provider=&lt;id&gt;</code>.</p>
</body></html>`;
}

function clearSessionCookie(reply) {
  // clearCookie must match the attributes used when the cookie was set
  // (path/sameSite/secure), or browsers keep the session cookie.
  reply.clearCookie(SESSION_COOKIE, { ...COOKIE_OPTS });
  reply.clearCookie(OIDC_STATE_COOKIE, { ...COOKIE_OPTS });
}

/* ---------- stateless HMAC-signed session tokens ---------- */

function sign(value, secret) {
  return createHmac('sha256', secret).update(value).digest('base64url');
}

function encodeToken(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return `${body}.${sign(body, secret)}`;
}

// Returns the payload, or null when missing/tampered/expired.
function decodeToken(token, secret) {
  if (typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const body = token.slice(0, dot);
  const expected = Buffer.from(sign(body, secret));
  const got = Buffer.from(token.slice(dot + 1));
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!payload || typeof payload.exp !== 'number' || payload.exp * 1000 <= Date.now()) return null;
  return payload;
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const eq = part.indexOf('=');
    if (eq < 1) continue;
    out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}

/* ---------- CSRF protection for cookie sessions ----------
 *
 * Applies only to cookie-authenticated sessions. Bearer-authenticated
 * requests already return before this check is reached. Personal mode
 * with no session cookie also bypasses (no cookie = nothing to steal).
 *
 * Strategy: Origin + Sec-Fetch-Site. Both are browser-controlled and
 * cannot be set by arbitrary JS from another origin. Curl/service callers
 * that send neither header are allowed through; they cannot carry the
 * session cookie cross-site anyway.
 */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function csrfAllowed(req) {
  if (SAFE_METHODS.has(req.method)) return true;

  const fetchSite = req.headers['sec-fetch-site'];
  if (fetchSite) {
    // same-origin and none (top-level navigation with no referrer) are fine.
    return fetchSite === 'same-origin' || fetchSite === 'none';
  }

  const origin = req.headers['origin'];
  if (origin) {
    try {
      return new URL(origin).origin === new URL(config.baseUrl).origin;
    } catch {
      return false;
    }
  }

  // No Origin and no Sec-Fetch-Site → non-browser caller, allow.
  return true;
}

/* ---------- group -> role mapping ----------
 *
 * Fail closed. Exact string match against configured IdP group names only.
 * Unknown / company-wide groups (engineering, all-staff, …) never grant a
 * role. Viewer is an explicit grant (membership in AIM_ROLE_GROUPS_VIEWER),
 * not an implicit default for every authenticated user. Reveal is orthogonal
 * to role and never upgrades rank.
 */

/** Coerce the OIDC groups claim (array or CSV string) to a string[]. */
export function normalizeGroups(claim) {
  if (Array.isArray(claim)) return claim.filter((g) => typeof g === 'string' && g.length > 0);
  if (typeof claim === 'string') return splitCsv(claim);
  return [];
}

/**
 * Map IdP groups → AIM role. Highest rank wins; no match → null (fail closed).
 * Combines AIM_ROLE_GROUPS_* (injectable for tests) with AIM_SCIM_GROUP_ROLE_MAP.
 *
 * @param {string[]} groups
 * @param {Record<string, string[]>} [roleGroups]
 * @returns {'admin'|'analyst'|'auditor'|'viewer'|null}
 */
export function mapGroupsToRole(groups, roleGroups = config.roleGroups) {
  const have = new Set(Array.isArray(groups) ? groups : []);
  const rank = { admin: 4, analyst: 3, auditor: 2, viewer: 1 };
  let best = null;
  // AIM_SCIM_GROUP_ROLE_MAP: case-insensitive displayName → role.
  for (const g of have) {
    const role = config.scimGroupRoleMap[String(g).trim().toLowerCase()];
    if (role && (!best || rank[role] > rank[best])) best = role;
  }
  for (const role of ROLE_PRECEDENCE) {
    const mapped = roleGroups[role] ?? [];
    if (mapped.some((g) => have.has(g))) {
      if (!best || rank[role] > rank[best]) best = role;
      break; // ROLE_PRECEDENCE is highest-first
    }
  }
  return best; // SCIM-mapped / OIDC-mapped role, or null — fail closed
}

/**
 * Merge OIDC groups with SCIM directory membership for an email.
 * SCIM group displayNames are appended so AIM_ROLE_GROUPS_* and
 * AIM_SCIM_GROUP_ROLE_MAP both apply after provisioning.
 */
function mergeScimGroups(email, oidcGroups) {
  if (!config.scimEnabled) return oidcGroups;
  const scimGroups = scimDirectory.groupsForUser(email);
  if (!scimGroups.length) return oidcGroups;
  return [...new Set([...oidcGroups, ...scimGroups])];
}

/**
 * Soft: deny if SCIM knows the user and active=false.
 * Enforce: deny unless an active SCIM user exists.
 * When SCIM is not configured, always allow (no directory).
 */
function scimBlocksIdentity(email) {
  if (!config.scimEnabled || !email) return false;
  return scimDirectory.isEnforceDenied(email, { enforce: config.scimEnforce });
}

/**
 * after SCIM deprovision gate, JIT-upsert the principal so first
 * login provisions within SLA and enforce mode works without pre-push.
 * Returns a fail descriptor when enforce mode must deny; otherwise null/ok.
 */
async function runJitProvision(req, {
  email,
  displayName = null,
  externalId = null,
  idp = null,
  source,
}) {
  if (!config.jitProvisioning) return null;
  const jit = await jitProvisionOnLogin({
    email,
    displayName,
    externalId,
    idp,
    source,
    directory: scimDirectory,
    db,
    log: req?.log,
    enforce: config.scimEnforce,
  });
  if (jitFailureBlocksLogin(jit, { enforce: config.scimEnforce })) {
    return {
      error: jit.reason === 'scim_deprovisioned' ? 'scim_deprovisioned' : 'jit_provision_failed',
      detail: jit.error || jit.reason || 'JIT provisioning failed under SCIM enforce mode',
      jit,
    };
  }
  return { jit };
}

/**
 * Reveal grant is orthogonal to role: any mapped role (or none) can hold it,
 * it comes from its own IdP group list, and it is audited per use. Holding
 * the reveal group alone never grants analyst/admin APIs.
 *
 * @param {string[]} groups
 * @param {string[]} [revealGroups]
 */
export function hasRevealGrant(groups, revealGroups = config.revealGroups) {
  const have = new Set(Array.isArray(groups) ? groups : []);
  return (revealGroups ?? []).some((g) => have.has(g));
}

/** Boot-time fail-closed checks. Exported for unit tests. */
export function assertAuthBootPolicy({
  ssoEnabled = SSO_ENABLED,
  anyOidc = ANY_OIDC,
  anySaml = ANY_SAML,
  oidcEnabled = OIDC_ENABLED,
  samlEnabled = SAML_ENABLED,
  requireSso = config.requireSso,
  dev = config.dev,
  providers = config.oidcProviders,
} = {}) {
  // Partial OIDC: any declared provider without a complete set (even if SAML is complete).
  if (anyOidc && !oidcEnabled) {
    const partialIds = (providers ?? [])
      .filter((p) => p.partial || !p.complete)
      .map((p) => p.id);
    const hint = partialIds.length
      ? ` incomplete provider(s): ${partialIds.join(', ')}`
      : '';
    throw new Error(
      'partial AIM_OIDC_* configuration: set complete credentials for every provider ' +
        '(legacy AIM_OIDC_ISSUER + CLIENT_ID + CLIENT_SECRET, or AIM_OIDC_PROVIDERS with ' +
        'AIM_OIDC_<ID>_{ISSUER,CLIENT_ID,CLIENT_SECRET}), or leave all unset for personal mode.' +
        hint,
    );
  }
  // Partial SAML: any of entry/issuer/cert without the full set.
  if (anySaml && !samlEnabled) {
    throw new Error(
      'partial AIM_SAML_* configuration: set AIM_SAML_IDP_ENTRY_POINT, AIM_SAML_IDP_ISSUER, and AIM_SAML_IDP_CERT (or AIM_SAML_IDP_CERT_FILE) together, or leave all unset',
    );
  }
  if (requireSso && !ssoEnabled) {
    throw new Error(
      'AIM_REQUIRE_SSO=1 refuses personal mode: configure complete AIM_OIDC_* credentials ' +
        '(single IdP or AIM_OIDC_PROVIDERS multi-IdP) and/or complete AIM_SAML_* SP settings',
    );
  }
  if (requireSso && dev) {
    throw new Error(
      'AIM_AUTH_DEV=1 is incompatible with AIM_REQUIRE_SSO=1 (dev role-switch is not a pilot auth path)',
    );
  }
}

/* ---------- authorization helpers ---------- */

// Product docs/routes sometimes say "security-admin"; the session role id is
// `admin`. Alias so requireRoles('security-admin') matches an admin session
// and dev-login can accept either label (gate unblock).
const ROLE_ALIASES = Object.freeze({ 'security-admin': 'admin' });
function normalizeRole(role) {
  if (role == null) return role;
  return ROLE_ALIASES[role] ?? role;
}

export function hasRole(req, ...roles) {
  const have = normalizeRole(req.identity?.role);
  if (!have) return false;
  return roles.map(normalizeRole).includes(have);
}

function deny(req, reply, code, detail) {
  audit(req.identity?.email ?? 'unauthenticated', 'authz.deny', req.url.split('?')[0], {
    requiredRoles: detail.requiredRoles ?? null,
    requiredPermission: detail.requiredPermission ?? null,
    reason: detail.reason ?? null,
    role: req.identity?.role ?? null,
  });
  if (code === 401) {
    reply.code(401).send({ error: 'unauthenticated' });
  } else if (detail.requiredPermission) {
    reply.code(403).send({
      error: 'forbidden',
      detail: `requires permission: ${detail.requiredPermission}`,
      reason: detail.reason ?? 'missing_permission',
    });
  } else {
    reply.code(403).send({
      error: 'forbidden',
      detail: `requires role: ${(detail.requiredRoles || []).join(' or ')}`,
    });
  }
}

// Gate factory: usable inline (`if (!gate(req, reply)) return reply;`) or as
// a route preHandler. 401 when unauthenticated, 403 for the wrong role; both
// are recorded in the immutable audit trail as authz.deny.
export function requireRoles(...roles) {
  return (req, reply) => {
    if (!req.identity) {
      deny(req, reply, 401, { requiredRoles: roles });
      return false;
    }
    if (!hasRole(req, ...roles)) {
      deny(req, reply, 403, { requiredRoles: roles });
      return false;
    }
    return true;
  };
}

/**
 * Fine-grained permission gate. Prefer this over requireRoles for
 * new routes. Optional ABAC conditions are pure-RBAC when omitted.
 *
 *   requirePermission('findings.read')
 *   requirePermission('users.read', {
 *     conditions: { attr: 'teams', op: 'contains', value: 'secops' },
 *   })
 *   requirePermission('users.read', {
 *     conditions: { attr: 'teams', op: 'resource_eq', resourceAttr: 'team' },
 *     resourceFrom: (req) => ({ team: req.query.team }),
 *   })
 *
 * @param {string} permission
 * @param {{ conditions?: object, resourceFrom?: (req: object) => object }} [opts]
 */
export function requirePermission(permission, opts = {}) {
  return (req, reply) => {
    if (!req.identity) {
      deny(req, reply, 401, { requiredPermission: permission, reason: 'unauthenticated' });
      return false;
    }
    const resource = typeof opts.resourceFrom === 'function' ? opts.resourceFrom(req) : opts.resource;
    const decision = evaluateAccess({
      identity: req.identity,
      permission,
      conditions: opts.conditions,
      resource,
    });
    if (!decision.allow) {
      deny(req, reply, 403, {
        requiredPermission: permission,
        reason: decision.reason,
      });
      return false;
    }
    return true;
  };
}

/** Convenience: identity already holds the named permission (no ABAC). */
export function hasPermission(req, permission) {
  return identityHasPermission(req.identity, permission);
}

// User-level rows (pseudonym drill-downs) stay analyst+ — the same privacy
// gate as before, now role-based. Also used for conditional data shaping
// (repo label joins), not just gating.
export function canSeeUsers(req) {
  return hasRole(req, 'analyst', 'admin') || identityHasPermission(req.identity, 'users.read');
}

// /api/me payload — exact contract the web app gates its surfaces on.
// capabilities.reveal comes from the session's reveal grant, not the role.
// adds permissions[] (fine-grained matrix) and attributes (ABAC).
export function mePayload(req) {
  const id = req.identity;
  return {
    email: id?.email ?? null,
    name: id?.name ?? null,
    role: id?.role ?? null,
    mode: id?.mode ?? null,
    // present when session was minted via emergency break-glass admin.
    breakGlass: id?.breakGlass ?? null,
    // which OIDC provider issued the session (null in personal mode).
    idp: id?.idp ?? null,
    capabilities: { ...(ROLE_CAPS[id?.role] ?? { ...NO_CAPS }), reveal: Boolean(id?.reveal) },
    permissions: permissionList(id),
    attributes: attributesFromIdentity(id ?? {}),
  };
}

/**
 * mint a short-lived emergency admin session cookie.
 * role is always admin; reveal is always false (least privilege for outage path).
 * mode is `break_glass` so UI/audit can distinguish from normal SSO.
 *
 * @param {import('fastify').FastifyReply} reply
 * @param {{ email: string, name?: string|null, ttlSeconds: number, grantId: string, method: 'dual_control'|'webauthn' }} opts
 */
export function issueBreakGlassAdminSession(reply, {
  email,
  name = null,
  ttlSeconds,
  grantId,
  method,
}) {
  const secret = SSO_ENABLED
    ? config.sessionSecret
    : (config.dev ? DEV_SESSION_SECRET : config.sessionSecret);
  if (!secret || (SSO_ENABLED && String(secret).length < 32)) {
    throw new Error('session secret unavailable for break-glass admin session');
  }
  const ttl = Math.max(60, Math.min(480 * 60, Number(ttlSeconds) || 3600));
  const now = Math.floor(Date.now() / 1000);
  const watermark = sessionRevocations.get(email);
  const iat = watermark && now <= watermark.revokedAtSec
    ? watermark.revokedAtSec + 1
    : now;
  const session = {
    email,
    name,
    groups: [],
    role: 'admin',
    reveal: false,
    mode: 'break_glass',
    breakGlass: { grantId, method },
    iat,
    exp: iat + ttl,
  };
  reply.setCookie(SESSION_COOKIE, encodeToken(session, secret), {
    ...COOKIE_OPTS,
    maxAge: ttl,
  });
  return session;
}

/**
 * Pull optional ABAC attributes from OIDC claims (AIM_OIDC_ATTR_CLAIMS).
 * @param {Record<string, unknown>} claims
 * @returns {Record<string, string|string[]|null>}
 */
export function attributesFromClaims(claims) {
  if (!claims || typeof claims !== 'object') return {};
  /** @type {Record<string, unknown>} */
  const raw = {};
  for (const key of config.attrClaims) {
    if (Object.prototype.hasOwnProperty.call(claims, key)) {
      raw[key] = claims[key];
    }
  }
  return normalizeAttributes(raw);
}

/* ---------- the plugin ---------- */

// Map provider id → openid-client Configuration (filled at boot when SSO on).
const oidcConfigs = new Map();


async function issueSsoSession(reply, {
  email,
  name,
  groups,
  auditPath,
  attributes = {},
  idp = null,
  externalId = null,
  req = null,
}) {
  // JIT before group merge so SCIM membership (if any) is visible.
  const jitGate = await runJitProvision(req, {
    email,
    displayName: name,
    externalId,
    idp,
    source: auditPath || 'sso',
  });
  if (jitGate?.error) {
    return { error: jitGate.error, detail: jitGate.detail, jit: jitGate.jit };
  }
  const mergedGroups = mergeScimGroups(email, groups);
  const role = mapGroupsToRole(mergedGroups);
  const now = Math.floor(Date.now() / 1000);
  const watermark = sessionRevocations.get(email);
  const iat = watermark && now <= watermark.revokedAtSec
    ? watermark.revokedAtSec + 1
    : now;
  const session = {
    email,
    name: name ?? null,
    groups: mergedGroups,
    role,
    reveal: hasRevealGrant(mergedGroups),
    attributes: attributes && typeof attributes === 'object' ? attributes : {},
    ...(idp ? { idp } : {}),
    iat,
    exp: iat + config.sessionTtlHours * 3600,
  };
  reply.setCookie(SESSION_COOKIE, encodeToken(session, config.sessionSecret), {
    ...COOKIE_OPTS,
    maxAge: config.sessionTtlHours * 3600,
  });
  audit(email, 'auth.login', auditPath, {
    role,
    mode: 'sso',
    ...(idp ? { idp } : {}),
    ...(jitGate?.jit
      ? {
          jit: {
            status: jitGate.jit.status,
            created: Boolean(jitGate.jit.created),
            durationMs: jitGate.jit.durationMs,
            slaBreached: Boolean(jitGate.jit.slaBreached),
          },
        }
      : {}),
  });
  return { session, jit: jitGate?.jit ?? null };
}

function wrongHostLoginReply(req, reply, path) {
  const expected = expectedPublicHost();
  const got = requestPublicHost(req) || '(missing)';
  audit('unauthenticated', 'auth.login.failed', path, {
    error: 'wrong_host',
    expectedHost: expected,
    requestHost: got,
  });
  const actionHref = `${config.baseUrl.replace(/\/$/, '')}/auth/login`;
  if (wantsHtml(req)) {
    return reply
      .code(400)
      .type('text/html; charset=utf-8')
      .send(
        authErrorPage({
          title: 'Wrong host for login',
          error: 'wrong_host',
          detail: `Login must start on ${expected} (got ${got}). Open the public dashboard URL and try again.`,
          actionHref,
          actionLabel: 'Go to login',
        }),
      );
  }
  return reply.code(400).send({
    error: 'wrong_host',
    expectedHost: expected,
    requestHost: got,
    loginUrl: actionHref,
  });
}

/** @type {import('@node-saml/node-saml').SAML | null} */
let samlSp = null;

export async function authPlugin(fastify) {
  // Fail closed before any request path can open.
  assertAuthBootPolicy();

  if (OIDC_ENABLED) {
    if (!config.sessionSecret || config.sessionSecret.length < 32) {
      throw new Error('AIM_SESSION_SECRET (min 32 chars) is required when AIM_OIDC_* SSO is configured');
    }
    for (const provider of config.oidcProviders) {
      const issuer = new URL(provider.issuer);
      // http issuers only ever occur against a local/mock IdP; https stays enforced.
      const execute = issuer.protocol === 'http:' ? [oidc.allowInsecureRequests] : [];
      const discovered = await oidc.discovery(
        issuer,
        provider.clientId,
        provider.clientSecret,
        undefined,
        { execute },
      );
      oidcConfigs.set(provider.id, { provider, config: discovered });
      fastify.log.info(
        { provider: provider.id, issuer: provider.issuer },
        'OIDC SSO provider enabled',
      );
    }
    fastify.log.info(
      {
        providers: config.oidcProviders.map((p) => p.id),
        multi: config.oidcProviders.length > 1,
      },
      'OIDC SSO enabled',
    );
    if (config.dev) {
      // assertAuthBootPolicy already rejects requireSso+dev; with SSO alone we
      // refuse to register /auth/dev/* but surface the misconfiguration.
      fastify.log.warn('AIM_AUTH_DEV=1 is ignored when OIDC SSO is enabled; /auth/dev/* not registered');
    }
  } else if (config.dev) {
    fastify.log.warn('AIM_AUTH_DEV=1 — dev role-switch endpoints enabled with a built-in session secret; do not use outside local development');
  } else {
    fastify.log.warn('no auth configured — personal/standalone mode, all requests run as a local admin');
  }
  if (SAML_ENABLED) {
    if (!config.sessionSecret || String(config.sessionSecret).length < 32) {
      throw new Error('AIM_SESSION_SECRET (min 32 chars) is required when AIM_SAML_* SSO is configured');
    }
  }

  fastify.decorateRequest('identity', null);

  if (SAML_ENABLED) {
    samlSp = createSamlSp(config.saml);
    fastify.log.info(
      { idpIssuer: config.saml.idpIssuer, callbackUrl: config.saml.callbackUrl },
      'SAML SP enabled',
    );
  }

  // Cookie support at root so OIDC routes *and* break-glass admin ceremony
  // (registered outside this scope) can set aim_session.
  await fastify.register(fastifyCookie);

  /* ----- auth endpoints ----- */
  await fastify.register(async (scope) => {
    // SAML ACS is application/x-www-form-urlencoded (SAMLResponse POST).
    scope.addContentTypeParser(
      'application/x-www-form-urlencoded',
      { parseAs: 'string' },
      (req, body, done) => {
        try {
          done(null, Object.fromEntries(new URLSearchParams(body)));
        } catch (err) {
          done(err);
        }
      },
    );

    if (SSO_ENABLED) {
      // Start the authorization-code flow: redirect to the IdP with PKCE;
      // state/nonce/verifier ride along in a short-lived signed cookie.
      scope.get('/auth/login', async (req, reply) => {
        // refuse login starts on the wrong host so the state cookie
        // cannot be bound to :8085 / bare localhost while Authelia returns to
        // AIM_BASE_URL.
        if (!isPublicHost(req)) {
          const expected = expectedPublicHost();
          const got = requestPublicHost(req) || '(missing)';
          audit('unauthenticated', 'auth.login.failed', 'auth/login', {
            error: 'wrong_host',
            expectedHost: expected,
            requestHost: got,
          });
          const actionHref = `${config.baseUrl.replace(/\/$/, '')}/auth/login`;
          const detail =
            `SSO login must start at ${config.baseUrl} (got host ${got}). ` +
            'Opening the API on a direct port sets the login cookie on the wrong host, ' +
            'so the Authelia callback fails with invalid_state.';
          if (wantsHtml(req)) {
            return reply
              .code(400)
              .type('text/html; charset=utf-8')
              .send(
                authErrorPage({
                  title: 'Use the public dashboard URL',
                  error: 'wrong_host',
                  detail,
                  actionHref,
                  actionLabel: 'Continue to correct login',
                }),
              );
          }
          return reply.code(400).send({
            error: 'wrong_host',
            detail,
            loginUrl: actionHref,
          });
        }

        // SAML-only installs use /auth/login as the canonical entry.
        // Multi-IdP OIDC picker below only applies when OIDC is configured;
        // without this branch, zero oidcProviders falls through to a 200
        // provider_required JSON body (regression multi-IdP).
        if (SAML_ENABLED && !OIDC_ENABLED) {
          const authorizeUrl = await samlSp.getAuthorizeUrlAsync('', undefined, {});
          return reply.redirect(authorizeUrl);
        }

        // pick provider. Single-IdP auto-selects; multi requires
        // ?provider= or shows the HTML picker / JSON provider list.
        const requested = typeof req.query?.provider === 'string' ? req.query.provider.trim().toLowerCase() : '';
        let providerId = requested;
        if (!providerId) {
          if (config.oidcProviders.length === 1) {
            providerId = config.oidcProviders[0].id;
          } else if (config.oidcProviders.length === 0) {
            // SSO_ENABLED with neither usable OIDC nor SAML-only is a boot bug;
            // refuse rather than advertising a multi-provider picker.
            return reply.code(503).send({
              error: 'sso_misconfigured',
              detail: 'No OIDC providers and SAML is not enabled.',
            });
          } else {
            const summary = config.oidcProviders.map((p) => ({
              id: p.id,
              label: p.label,
              loginUrl: `${config.baseUrl.replace(/\/$/, '')}/auth/login?provider=${encodeURIComponent(p.id)}`,
            }));
            if (wantsHtml(req)) {
              return reply
                .type('text/html; charset=utf-8')
                .header('Cache-Control', 'no-store')
                .send(providerPickerPage({ providers: config.oidcProviders, baseUrl: config.baseUrl }));
            }
            return reply.code(200).send({
              error: 'provider_required',
              detail: 'Multiple OIDC providers configured; pass ?provider=<id>',
              providers: summary,
            });
          }
        }
        const entry = oidcConfigs.get(providerId);
        if (!entry) {
          const known = config.oidcProviders.map((p) => p.id);
          audit('unauthenticated', 'auth.login.failed', 'auth/login', {
            error: 'unknown_provider',
            provider: providerId,
          });
          const detail = `Unknown OIDC provider "${providerId}". Known: ${known.join(', ') || '(none)'}.`;
          if (wantsHtml(req)) {
            return reply
              .code(400)
              .type('text/html; charset=utf-8')
              .send(
                authErrorPage({
                  title: 'Unknown identity provider',
                  error: 'unknown_provider',
                  detail,
                  actionHref: `${config.baseUrl.replace(/\/$/, '')}/auth/login`,
                  actionLabel: 'Choose a provider',
                }),
              );
          }
          return reply.code(400).send({ error: 'unknown_provider', detail, providers: known });
        }

        const verifier = oidc.randomPKCECodeVerifier();
        const challenge = await oidc.calculatePKCECodeChallenge(verifier);
        const now = Math.floor(Date.now() / 1000);
        const flow = {
          state: oidc.randomState(),
          nonce: oidc.randomNonce(),
          verifier,
          provider: entry.provider.id,
          iat: now,
          exp: now + OIDC_STATE_TTL_SECONDS,
        };
        const url = oidc.buildAuthorizationUrl(entry.config, {
          redirect_uri: entry.provider.redirectUri || config.redirectUri,
          scope: entry.provider.scopes,
          state: flow.state,
          nonce: flow.nonce,
          code_challenge: challenge,
          code_challenge_method: 'S256',
        });
        reply.setCookie(OIDC_STATE_COOKIE, encodeToken(flow, config.sessionSecret), {
          ...COOKIE_OPTS,
          maxAge: OIDC_STATE_TTL_SECONDS,
        });
        return reply.redirect(url.href);
      });

      // public provider inventory for SPA / ops (no secrets).
      scope.get('/auth/providers', async (_req, reply) => {
        const providers = config.oidcProviders.map((p) => ({
          id: p.id,
          label: p.label,
          loginUrl: `${config.baseUrl.replace(/\/$/, '')}/auth/login?provider=${encodeURIComponent(p.id)}`,
        }));
        return reply.send({
          mode: providers.length > 1 ? 'multi' : providers.length === 1 ? 'single' : 'none',
          providers,
        });
      });

      // IdP redirect target: exchange the code, validate the ID token
      // (signature/iss/aud/exp via openid-client, nonce via expectedNonce),
      // map groups to a role, and open the session. OIDC-only (SAML uses ACS).
      if (OIDC_ENABLED) scope.get('/auth/callback', async (req, reply) => {
        const rawStateCookie = parseCookies(req.headers.cookie)[OIDC_STATE_COOKIE];
        const flow = decodeToken(rawStateCookie, config.sessionSecret);
        reply.clearCookie(OIDC_STATE_COOKIE, { path: '/', ...COOKIE_OPTS });
        const loginHref = `${config.baseUrl.replace(/\/$/, '')}/auth/login`;
        const fail = (code, error, detail) => {
          audit('unauthenticated', 'auth.login.failed', 'auth/callback', {
            error,
            requestHost: requestPublicHost(req) || null,
            hasStateCookie: Boolean(rawStateCookie),
          });
          // operator-visible titles + runbook for JIT / SCIM failures.
          const presented = loginErrorPresentation(error, detail);
          const resolvedDetail =
            presented.detail ||
            detail ||
            (error === 'invalid_state'
              ? 'The login cookie was missing when Authelia returned. Start login from the public dashboard URL (not a direct API port), then try again.'
              : 'The identity provider accepted the login, but AI Monitoring could not open a session. Try again from the public dashboard URL.');
          const resolvedTitle =
            presented.title ||
            (error === 'invalid_state' ? 'Login session expired or incomplete' : 'Sign-in failed');
          if (wantsHtml(req)) {
            return reply
              .code(code)
              .type('text/html; charset=utf-8')
              .send(
                authErrorPage({
                  title: resolvedTitle,
                  error,
                  detail: resolvedDetail,
                  actionHref: loginHref,
                  actionLabel: presented.actionLabel || 'Restart login',
                  runbookHref: presented.runbookHref,
                  runbookLabel: presented.runbookLabel,
                  runbookPath: presented.runbookPath,
                }),
              );
          }
          return reply.code(code).send({
            error,
            detail: resolvedDetail,
            loginUrl: loginHref,
            ...(presented.runbookPath ? { runbook: presented.runbookPath } : {}),
          });
        };
        if (!flow?.state) {
          return fail(
            400,
            'invalid_state',
            'Missing or expired login cookie (aim_oidc_state). This usually means login started on a different host/port than ' +
              config.baseUrl +
              ' (for example http://localhost:8085). Use the public URL, then restart login.',
          );
        }
        try {
          const providerId = flow.provider || config.oidcProviders[0]?.id;
          const entry = oidcConfigs.get(providerId);
          if (!entry) {
            return fail(
              400,
              'unknown_provider',
              `Login state referenced unknown OIDC provider "${providerId || ''}". Restart login.`,
            );
          }
          const redirectUri = entry.provider.redirectUri || config.redirectUri;
          const currentUrl = new URL(redirectUri);
          currentUrl.search = new URL(req.url, config.baseUrl).search;
          const tokens = await oidc.authorizationCodeGrant(entry.config, currentUrl, {
            pkceCodeVerifier: flow.verifier,
            expectedState: flow.state,
            expectedNonce: flow.nonce,
          });
          const claims = tokens.claims();
          if (!claims?.email) return fail(401, 'login_failed', 'Identity provider did not return an email claim.');
          // soft deprovision deny before JIT (never revive).
          // Enforce unknown-user deny runs *after* JIT so first login can provision.
          if (scimDirectory.isDeprovisioned(claims.email)) {
            audit(claims.email, 'auth.login.failed', 'auth/callback', {
              error: 'scim_deprovisioned',
              scimEnforce: config.scimEnforce,
              idp: entry.provider.id,
            });
            return fail(
              403,
              'scim_deprovisioned',
              'SCIM has deprovisioned this user (active=false).',
            );
          }
          // first login provisions into SCIM directory within SLA.
          const jitGate = await runJitProvision(req, {
            email: claims.email,
            displayName: claims.name ?? null,
            externalId: claims.sub != null ? String(claims.sub) : null,
            idp: entry.provider.id,
            source: 'auth/callback',
          });
          if (jitGate?.error) {
            audit(claims.email, 'auth.login.failed', 'auth/callback', {
              error: jitGate.error,
              scimEnforce: config.scimEnforce,
              idp: entry.provider.id,
              jit: jitGate.jit
                ? { status: jitGate.jit.status, durationMs: jitGate.jit.durationMs }
                : undefined,
            });
            return fail(403, jitGate.error, jitGate.detail);
          }
          // Enforce mode after JIT: still no active row → deny.
          if (scimBlocksIdentity(claims.email)) {
            audit(claims.email, 'auth.login.failed', 'auth/callback', {
              error: 'scim_deprovisioned',
              scimEnforce: config.scimEnforce,
              idp: entry.provider.id,
            });
            return fail(
              403,
              'scim_deprovisioned',
              config.scimEnforce
                ? 'SCIM enforce mode: user is not an active provisioned user.'
                : 'SCIM has deprovisioned this user (active=false).',
            );
          }
          const groupsClaim = entry.provider.groupsClaim || config.groupsClaim;
          const groups = mergeScimGroups(claims.email, normalizeGroups(claims[groupsClaim]));
          const role = mapGroupsToRole(groups);
          const now = Math.floor(Date.now() / 1000);
          // if this email was force-revoked in the same second, bump
          // iat past the watermark so a legitimate re-login (re-hire / group
          // restore) is not immediately denied while older cookies still fail.
          const watermark = sessionRevocations.get(claims.email);
          const iat = watermark && now <= watermark.revokedAtSec
            ? watermark.revokedAtSec + 1
            : now;
          const session = {
            email: claims.email,
            name: claims.name ?? null,
            groups,
            role,
            reveal: hasRevealGrant(groups),
            // optional ABAC attributes from configured OIDC claims.
            attributes: attributesFromClaims(claims),
            idp: entry.provider.id,
            iat,
            exp: iat + config.sessionTtlHours * 3600,
          };
          reply.setCookie(SESSION_COOKIE, encodeToken(session, config.sessionSecret), {
            ...COOKIE_OPTS,
            maxAge: config.sessionTtlHours * 3600,
          });
          audit(claims.email, 'auth.login', 'auth/callback', {
            role,
            idp: entry.provider.id,
            ...(jitGate?.jit
              ? {
                  jit: {
                    status: jitGate.jit.status,
                    created: Boolean(jitGate.jit.created),
                    durationMs: jitGate.jit.durationMs,
                    slaBreached: Boolean(jitGate.jit.slaBreached),
                  },
                }
              : {}),
          });
          // post-login always lands on Overview. A bare `/` left the
          // SPA free to re-claim the hash for Findings or a stale
          // client-side destination; `#/overview` is the guaranteed front page.
          return reply.redirect('/#/overview');
        } catch (err) {
          req.log.warn(err, 'OIDC callback failed');
          return fail(401, 'login_failed');
        }
      });
    }

      if (SAML_ENABLED) {
        // Explicit SAML entry (also used when OIDC + SAML coexist).
        scope.get('/auth/saml/login', async (req, reply) => {
          if (!isPublicHost(req)) {
            return wrongHostLoginReply(req, reply, 'auth/saml/login');
          }
          const authorizeUrl = await samlSp.getAuthorizeUrlAsync('', undefined, {});
          return reply.redirect(authorizeUrl);
        });

        // SP metadata for IdP app registration (public — no secrets).
        scope.get('/auth/saml/metadata', async (req, reply) => {
          const xml = samlSp.generateServiceProviderMetadata(null, null);
          return reply
            .type('application/samlmetadata+xml; charset=utf-8')
            .header('Cache-Control', 'no-store')
            .send(xml);
        });

        // Assertion Consumer Service (HTTP-POST binding).
        scope.post('/auth/saml/acs', async (req, reply) => {
          const loginHref = SAML_ENABLED && !OIDC_ENABLED
            ? `${config.baseUrl.replace(/\/$/, '')}/auth/saml/login`
            : `${config.baseUrl.replace(/\/$/, '')}/auth/login`;
          const fail = (code, error, detail) => {
            audit('unauthenticated', 'auth.login.failed', 'auth/saml/acs', {
              error,
              requestHost: requestPublicHost(req) || null,
            });
            // operator-visible titles + runbook for JIT / SCIM failures.
            const presented = loginErrorPresentation(error, detail);
            const resolvedDetail =
              presented.detail ||
              detail ||
              'The identity provider posted an assertion, but AI Monitoring could not open a session. Check SP metadata, ACS URL, and IdP signing cert.';
            const resolvedTitle = presented.title || 'SAML sign-in failed';
            if (wantsHtml(req)) {
              return reply
                .code(code)
                .type('text/html; charset=utf-8')
                .send(
                  authErrorPage({
                    title: resolvedTitle,
                    error,
                    detail: resolvedDetail,
                    actionHref: loginHref,
                    actionLabel: presented.actionLabel || 'Restart login',
                    runbookHref: presented.runbookHref,
                    runbookLabel: presented.runbookLabel,
                    runbookPath: presented.runbookPath,
                  }),
                );
            }
            return reply.code(code).send({
              error,
              detail: resolvedDetail,
              loginUrl: loginHref,
              ...(presented.runbookPath ? { runbook: presented.runbookPath } : {}),
            });
          };

          const body = req.body && typeof req.body === 'object' ? req.body : {};
          const samlResponse = body.SAMLResponse;
          if (!samlResponse || typeof samlResponse !== 'string') {
            return fail(400, 'missing_saml_response', 'POST body must include SAMLResponse.');
          }

          try {
            const { profile, loggedOut } = await samlSp.validatePostResponseAsync({
              SAMLResponse: samlResponse,
              ...(typeof body.RelayState === 'string' ? { RelayState: body.RelayState } : {}),
            });
            if (loggedOut) {
              clearSessionCookie(reply);
              return reply.redirect('/auth/logout');
            }
            const id = identityFromSamlProfile(profile, {
              groupsAttribute: config.saml.groupsAttribute,
              emailAttribute: config.saml.emailAttribute,
              nameAttribute: config.saml.nameAttribute,
            });
            if (!id.email) {
              return fail(401, 'login_failed', 'SAML assertion did not include an email NameID or email attribute.');
            }
            // Soft deprovision deny before JIT (never revive leavers).
            if (scimDirectory.isDeprovisioned(id.email)) {
              audit(id.email, 'auth.login.failed', 'auth/saml/acs', {
                error: 'scim_deprovisioned',
                scimEnforce: config.scimEnforce,
              });
              return fail(
                403,
                'scim_deprovisioned',
                'SCIM has deprovisioned this user (active=false).',
              );
            }
            const issued = await issueSsoSession(reply, {
              email: id.email,
              name: id.name,
              groups: id.groups,
              auditPath: 'auth/saml/acs',
              externalId:
                typeof profile?.nameID === 'string' && profile.nameID
                  ? profile.nameID
                  : null,
              req,
            });
            if (issued?.error) {
              audit(id.email, 'auth.login.failed', 'auth/saml/acs', {
                error: issued.error,
                scimEnforce: config.scimEnforce,
              });
              return fail(403, issued.error, issued.detail);
            }
            if (scimBlocksIdentity(id.email)) {
              audit(id.email, 'auth.login.failed', 'auth/saml/acs', {
                error: 'scim_deprovisioned',
                scimEnforce: config.scimEnforce,
              });
              return fail(
                403,
                'scim_deprovisioned',
                config.scimEnforce
                  ? 'SCIM enforce mode: user is not an active provisioned user.'
                  : 'SCIM has deprovisioned this user (active=false).',
              );
            }
            return reply.redirect('/#/overview');
          } catch (err) {
            req.log.warn(err, 'SAML ACS validation failed');
            return fail(401, 'login_failed', err?.message ? String(err.message).slice(0, 200) : undefined);
          }
        });
      }

    /*: logout ends the app session and stops. GET serves a signed-out
     * HTML page (browser "Sign out" link); POST keeps the JSON shape for API
     * clients. Neither path auto-redirects to /auth/login — that was the
     * SSO re-auth loop. */
    const finishLogout = (req, reply, { html }) => {
      const secret = SSO_ENABLED ? config.sessionSecret : DEV_SESSION_SECRET;
      const session = decodeToken(parseCookies(req.headers.cookie)[SESSION_COOKIE], secret);
      clearSessionCookie(reply);
      audit(session?.email ?? PERSONAL_IDENTITY.email, 'auth.logout', 'auth/logout', {});
      if (html) {
        const loginHref = SSO_ENABLED ? `${config.baseUrl.replace(/\/$/, '')}/auth/login` : '/';
        return reply
          .type('text/html; charset=utf-8')
          .header('Cache-Control', 'no-store')
          .send(signedOutPage({ loginHref: SSO_ENABLED ? loginHref : null }));
      }
      return { ok: true };
    };

    scope.get('/auth/logout', async (req, reply) => finishLogout(req, reply, {
      // Prefer HTML for browser navigations; curl/API callers without Accept
      // still get the signed-out page on GET (the link target).
      html: wantsHtml(req) || !String(req.headers.accept || '').includes('application/json'),
    }));
    scope.post('/auth/logout', async (req, reply) => finishLogout(req, reply, { html: false }));

    // Dev-only role switching for local UI work (never in SSO mode).
    if (!SSO_ENABLED && config.dev) {
      // Accept product alias security-admin; session role is always canonical.
      const DEV_ROLES = ['admin', 'security-admin', 'analyst', 'auditor', 'viewer', 'none'];
      scope.get('/auth/dev/login', async (req, reply) => {
        const role = req.query?.role;
        if (!DEV_ROLES.includes(role)) {
          return reply.code(400).send({ error: 'bad_request', detail: `role must be one of ${DEV_ROLES.join(', ')}` });
        }
        const canonical = role === 'none' ? null : normalizeRole(role);
        // Optional email/name so tests and local UI work can pose as
        // distinct users (per-user resources like saved views key on email).
        const email = typeof req.query?.email === 'string' && req.query.email.length > 0 && req.query.email.length <= 254
          ? req.query.email
          : `${canonical ?? 'none'}@dev.local`;
        const now = Math.floor(Date.now() / 1000);
        const watermark = sessionRevocations.get(email);
        const iat = watermark && now <= watermark.revokedAtSec
          ? watermark.revokedAtSec + 1
          : now;
        // optional ABAC attrs for local tests.
        //   &attrs={"teams":["secops"],"department":"security"}
        //   &teams=secops,platform   (shorthand list → attributes.teams)
        let attributes = {};
        if (typeof req.query?.attrs === 'string' && req.query.attrs.length > 0 && req.query.attrs.length <= 2048) {
          try {
            attributes = normalizeAttributes(JSON.parse(req.query.attrs));
          } catch {
            return reply.code(400).send({ error: 'bad_request', detail: 'attrs must be JSON object' });
          }
        }
        if (typeof req.query?.teams === 'string' && req.query.teams.length > 0) {
          attributes = {
            ...attributes,
            teams: req.query.teams.split(',').map((s) => s.trim()).filter(Boolean),
          };
        }
        // Optional extra permission grants (comma-separated permission ids).
        let permissionGrants = [];
        if (typeof req.query?.grants === 'string' && req.query.grants.length > 0) {
          permissionGrants = req.query.grants.split(',').map((s) => s.trim()).filter(Boolean);
        }
        // Optional IdP groups for team-derived attributes.
        let groups = [];
        if (typeof req.query?.groups === 'string' && req.query.groups.length > 0) {
          groups = req.query.groups.split(',').map((s) => s.trim()).filter(Boolean);
        }
        const session = {
          email,
          name: typeof req.query?.name === 'string' && req.query.name.length > 0 ? req.query.name : `Dev ${canonical ?? 'none'}`,
          groups,
          role: canonical,
          // &reveal=1 poses as a reveal-grant holder (dev/test only).
          reveal: req.query?.reveal === '1',
          attributes,
          permissionGrants,
          iat,
          exp: iat + 12 * 3600,
        };
        reply.setCookie(SESSION_COOKIE, encodeToken(session, DEV_SESSION_SECRET), { ...COOKIE_OPTS, maxAge: 12 * 3600 });
        // every dev/break-glass role switch is auditable.
        audit(session.email, 'auth.dev.login', 'auth/dev/login', {
          role: session.role,
          reveal: session.reveal,
          permissionGrants: session.permissionGrants,
        });
        return { ok: true, role: session.role };
      });
      scope.get('/auth/dev/logout', async (req, reply) => {
        clearSessionCookie(reply);
        audit('dev', 'auth.dev.logout', 'auth/dev/logout', {});
        return { ok: true };
      });
    }
  });

  /* ----- identity resolution for everything else ----- */
  fastify.addHook('onRequest', async (req, reply) => {
    const path = req.url.split('?')[0];
    // Liveness, OIDC flow, and SCIM provisioning stay open here.
    // /scim/* authenticates with AIM_SCIM_BEARER_TOKEN inside scim routes —
    // must not be treated as a service token (Bearer would 401 here).
    if (path === '/api/health' || path.startsWith('/auth/') || path.startsWith('/scim/')) return;

    // ----- machine credentials -----
    // An Authorization: Bearer header is an explicit claim of service
    // identity, so it is AUTHORITATIVE: resolve it or 401. It deliberately
    // does not fall through to the cookie/personal paths below.
    //
    // That matters most in personal mode, where the tail of this hook hands
    // every request an admin identity. Falling through would make a
    // typo'd or unconfigured sentinel token appear to work perfectly — right
    // up until SSO is switched on, at which point the same deployment starts
    // 401ing with nothing changed on the consumer side. Rejecting here moves
    // that discovery to install time, where it is a five-minute fix.
    const bearer = bearerFrom(req.headers.authorization);
    if (bearer !== null) {
      const result = serviceTokens.verify(bearer);
      if (result.ok) {
        req.identity = result.identity;
        return;
      }
      audit(result.name ? `svc:${result.name}` : 'unauthenticated', 'authz.deny', path, {
        requiredRoles: ['service'],
        role: null,
        reason: result.reason,
      });
      return reply.code(401).send({
        error: 'unauthenticated',
        detail: result.reason === 'not-configured'
          ? 'this install accepts no service tokens; set AIM_SERVICE_TOKENS_FILE to enable them'
          : `service token ${result.reason}`,
      });
    }

    if (SSO_ENABLED) {
      const session = decodeToken(parseCookies(req.headers.cookie)[SESSION_COOKIE], config.sessionSecret);
      if (!session) {
        // The SPA drives the login redirect; APIs answer 401, static assets stay public.
        if (path.startsWith('/api/')) {
          audit('unauthenticated', 'authz.deny', path, { requiredRoles: ['authenticated'], role: null });
          return reply.code(401).send({ error: 'unauthenticated' });
        }
        return;
      }
      // email revoke watermark force-denies mid-TTL sessions.
      if (sessionRevocations.isSessionRevoked(session)) {
        if (path.startsWith('/api/')) {
          audit(session.email, 'authz.deny', path, {
            requiredRoles: ['authenticated'],
            role: session.role ?? null,
            reason: 'session_revoked',
          });
          return reply.code(401).send({ error: 'unauthenticated', detail: 'session_revoked' });
        }
        return;
      }
      if (!csrfAllowed(req)) {
        audit(session.email, 'authz.deny', path, { requiredRoles: ['authenticated'], role: session.role ?? null, reason: 'csrf' });
        return reply.code(403).send({ error: 'forbidden', detail: 'cross-origin request rejected' });
      }
      // mid-session SCIM deprovision (active=false) or enforce deny.
      // Immediate — does not wait for cookie exp revoke watermark.
      if (scimBlocksIdentity(session.email)) {
        audit(session.email, 'authz.deny', path, {
          requiredRoles: ['authenticated'],
          role: session.role ?? null,
          reason: 'scim_deprovisioned',
        });
        return reply.code(401).send({
          error: 'scim_deprovisioned',
          detail: 'user deprovisioned via SCIM',
        });
      }
      // emergency admin sessions keep fixed admin role + no reveal;
      // do not re-map from IdP groups (IdP may be the outage).
      if (session.mode === 'break_glass') {
        req.identity = {
          email: session.email,
          name: session.name ?? null,
          groups: session.groups ?? [],
          role: 'admin',
          reveal: false,
          mode: 'break_glass',
          breakGlass: session.breakGlass ?? null,
        };
        return;
      }
      // Recompute role from live SCIM membership + session groups so group
      // PATCH propagates without forcing re-login (role elevation/demotion).
      const groups = mergeScimGroups(session.email, session.groups ?? []);
      const role = mapGroupsToRole(groups);
      req.identity = {
        email: session.email,
        name: session.name ?? null,
        groups,
        role,
        reveal: session.reveal === true || hasRevealGrant(groups),
        attributes: normalizeAttributes(session.attributes),
        permissionGrants: Array.isArray(session.permissionGrants) ? session.permissionGrants : [],
        idp: session.idp ?? null,
        mode: 'sso',
      };
      return;
    }
    if (config.dev) {
      const dev = decodeToken(parseCookies(req.headers.cookie)[SESSION_COOKIE], DEV_SESSION_SECRET);
      if (dev) {
        if (sessionRevocations.isSessionRevoked(dev)) {
          if (path.startsWith('/api/')) {
            audit(dev.email, 'authz.deny', path, {
              requiredRoles: ['authenticated'],
              role: dev.role ?? null,
              reason: 'session_revoked',
            });
            return reply.code(401).send({ error: 'unauthenticated', detail: 'session_revoked' });
          }
          return;
        }
        if (!csrfAllowed(req)) {
          audit(dev.email, 'authz.deny', path, { requiredRoles: ['authenticated'], role: dev.role ?? null, reason: 'csrf' });
          return reply.code(403).send({ error: 'forbidden', detail: 'cross-origin request rejected' });
        }
        // break-glass sessions in local/dev also use DEV_SESSION_SECRET.
        if (dev.mode === 'break_glass') {
          req.identity = {
            email: dev.email,
            name: dev.name ?? null,
            groups: dev.groups ?? [],
            role: 'admin',
            reveal: false,
            mode: 'break_glass',
            breakGlass: dev.breakGlass ?? null,
          };
          return;
        }
        req.identity = {
          email: dev.email,
          name: dev.name ?? null,
          groups: dev.groups ?? [],
          role: dev.role ?? null,
          reveal: dev.reveal === true,
          attributes: normalizeAttributes(dev.attributes),
          permissionGrants: Array.isArray(dev.permissionGrants) ? dev.permissionGrants : [],
          mode: 'personal',
        };
        return;
      }
    }
    req.identity = PERSONAL_IDENTITY;
  });
}

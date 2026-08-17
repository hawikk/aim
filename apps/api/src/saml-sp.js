// SAML 2.0 Service Provider helpers (AIM-715).
//
// Builds a @node-saml/node-saml SP against env config and extracts identity
// claims for the same fail-closed group→role path used by OIDC (auth.js).
// Unsigned AuthnRequests (HTTP-Redirect); assertions must be signed by the IdP.
import { readFileSync } from 'node:fs';
import { SAML, ValidateInResponseTo } from '@node-saml/node-saml';

/**
 * Load a PEM cert/key from env: inline PEM (with literal `\n`), or `file:/path`.
 * Returns null when unset.
 *
 * @param {string|undefined} value
 * @param {string|undefined} filePathEnv optional dedicated *_FILE path
 */
export function loadPemMaterial(value, filePathEnv) {
  if (filePathEnv && String(filePathEnv).trim()) {
    return readFileSync(String(filePathEnv).trim(), 'utf8');
  }
  if (!value) return null;
  const raw = String(value).trim();
  if (!raw) return null;
  if (raw.startsWith('file:')) {
    return readFileSync(raw.slice('file:'.length), 'utf8');
  }
  // Operators often paste multi-line PEMs as single-line with \n escapes.
  return raw.includes('BEGIN ') ? raw : raw.replace(/\\n/g, '\n');
}

/**
 * Parse SAML env into a normalized config object (does not construct SAML yet).
 * Full config requires entryPoint + idpIssuer + idpCert.
 *
 * @param {NodeJS.ProcessEnv} [env]
 */
export function readSamlEnv(env = process.env) {
  const baseUrl = env.AIM_BASE_URL ?? 'http://localhost:8080';
  const entryPoint = (env.AIM_SAML_IDP_ENTRY_POINT ?? '').trim();
  const idpIssuer = (env.AIM_SAML_IDP_ISSUER ?? '').trim();
  const idpCert = loadPemMaterial(env.AIM_SAML_IDP_CERT, env.AIM_SAML_IDP_CERT_FILE);
  const spEntityId = (env.AIM_SAML_SP_ENTITY_ID ?? baseUrl).trim();
  const callbackUrl = (
    env.AIM_SAML_CALLBACK_URL ?? `${baseUrl.replace(/\/$/, '')}/auth/saml/acs`
  ).trim();
  const groupsAttribute = (env.AIM_SAML_GROUPS_ATTRIBUTE ?? 'groups').trim() || 'groups';
  const emailAttribute = (env.AIM_SAML_EMAIL_ATTRIBUTE ?? 'email').trim() || 'email';
  const nameAttribute = (env.AIM_SAML_NAME_ATTRIBUTE ?? 'displayName').trim() || 'displayName';
  // Default: require signed assertions (IdP must sign). Response signature optional
  // so Okta/Entra assertion-only signing works without dual-sign.
  const wantAssertionsSigned = env.AIM_SAML_WANT_ASSERTIONS_SIGNED !== '0';
  const wantAuthnResponseSigned = env.AIM_SAML_WANT_RESPONSE_SIGNED === '1';
  // always = best for single-process / sticky sessions; never = multi-pod without
  // shared request cache (still signature + audience + time bounds).
  const validateRaw = (env.AIM_SAML_VALIDATE_IN_RESPONSE_TO ?? 'always').toLowerCase();
  const validateInResponseTo =
    validateRaw === 'never'
      ? ValidateInResponseTo.never
      : validateRaw === 'ifpresent'
        ? ValidateInResponseTo.ifPresent
        : ValidateInResponseTo.always;

  const any = Boolean(entryPoint || idpIssuer || idpCert);
  const enabled = Boolean(entryPoint && idpIssuer && idpCert);
  return {
    any,
    enabled,
    entryPoint,
    idpIssuer,
    idpCert,
    spEntityId,
    callbackUrl,
    groupsAttribute,
    emailAttribute,
    nameAttribute,
    wantAssertionsSigned,
    wantAuthnResponseSigned,
    validateInResponseTo,
  };
}

/**
 * Construct the SAML SP. Throws if not fully configured.
 *
 * @param {ReturnType<typeof readSamlEnv>} cfg
 */
export function createSamlSp(cfg) {
  if (!cfg?.enabled) {
    throw new Error('SAML SP requires AIM_SAML_IDP_ENTRY_POINT, AIM_SAML_IDP_ISSUER, and AIM_SAML_IDP_CERT');
  }
  return new SAML({
    callbackUrl: cfg.callbackUrl,
    entryPoint: cfg.entryPoint,
    idpIssuer: cfg.idpIssuer,
    issuer: cfg.spEntityId,
    idpCert: cfg.idpCert,
    audience: cfg.spEntityId,
    wantAssertionsSigned: cfg.wantAssertionsSigned,
    wantAuthnResponseSigned: cfg.wantAuthnResponseSigned,
    validateInResponseTo: cfg.validateInResponseTo,
    // Email NameID is the enterprise default; attribute map still preferred when present.
    identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    acceptedClockSkewMs: 5 * 60 * 1000,
  });
}

/**
 * Coerce a SAML attribute value (string | string[]) to string[].
 * @param {unknown} value
 * @returns {string[]}
 */
export function attributeValues(value) {
  if (value == null) return [];
  if (Array.isArray(value)) {
    return value
      .flatMap((v) => attributeValues(v))
      .filter((s) => typeof s === 'string' && s.length > 0);
  }
  if (typeof value === 'string') {
    // Some IdPs send a single multi-value CSV; split conservatively when commas present
    // and the value does not look like a URI.
    if (value.includes(',') && !value.includes('://') && !value.includes('@')) {
      return value.split(',').map((s) => s.trim()).filter(Boolean);
    }
    return value.length > 0 ? [value] : [];
  }
  return [];
}

/**
 * Extract email, display name, and groups from a validated node-saml profile.
 * Fail closed: missing email → null email (caller rejects login).
 *
 * @param {Record<string, unknown>} profile
 * @param {{ groupsAttribute?: string, emailAttribute?: string, nameAttribute?: string }} [opts]
 */
export function identityFromSamlProfile(profile, opts = {}) {
  const groupsAttribute = opts.groupsAttribute ?? 'groups';
  const emailAttribute = opts.emailAttribute ?? 'email';
  const nameAttribute = opts.nameAttribute ?? 'displayName';

  const attrs = (profile?.attributes && typeof profile.attributes === 'object')
    ? profile.attributes
    : {};

  const pick = (name) => {
    if (profile && profile[name] != null) return profile[name];
    if (attrs[name] != null) return attrs[name];
    return null;
  };

  // Common IdP attribute URIs as fallbacks when the configured short name is empty.
  const emailFallbacks = [
    emailAttribute,
    'email',
    'mail',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
  ];
  let email = null;
  for (const key of emailFallbacks) {
    const vals = attributeValues(pick(key));
    if (vals[0] && vals[0].includes('@')) {
      email = vals[0];
      break;
    }
  }
  if (!email && typeof profile?.nameID === 'string' && profile.nameID.includes('@')) {
    email = profile.nameID;
  }

  const nameFallbacks = [
    nameAttribute,
    'displayName',
    'name',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
    'http://schemas.microsoft.com/identity/claims/displayname',
  ];
  let name = null;
  for (const key of nameFallbacks) {
    const vals = attributeValues(pick(key));
    if (vals[0]) {
      name = vals[0];
      break;
    }
  }

  const groupFallbacks = [
    groupsAttribute,
    'groups',
    'memberOf',
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
    'http://schemas.xmlsoap.org/claims/Group',
  ];
  let groups = [];
  for (const key of groupFallbacks) {
    const vals = attributeValues(pick(key));
    if (vals.length) {
      groups = vals;
      break;
    }
  }
  // Deduplicate while preserving order.
  groups = [...new Set(groups)];

  return { email, name, groups };
}

/* Lightweight i18n for the no-build ES-module dashboard (AIM-761).
 *
 * Constraints (from product policy + Agents.md):
 *  - No third-party runtime deps. Chart.js is the only vendored exception; i18n
 *    is not worth becoming a supply-chain surface.
 *  - English is the source of truth and the fail-closed fallback. A missing key
 *    or missing locale never blanks a security panel.
 *  - Security names which additional locales ship. Do not invent translations of
 *    severity / enforcement / works-council copy without that input.
 *
 * Shape:
 *  - Dot keys: t('severity.band.critical')
 *  - Named interpolation: t('chrome.hostsMissing', { count: 42 })
 *  - Nested catalogs (objects), flattened at register time for O(1) lookup
 *  - Locale event so chrome can re-paint when Security enables more locales
 *
 * This module is pure enough for node:test. It never imports the DOM at load;
 * applyDocumentLang is the only path that touches document.
 */

import { en as enCatalog } from '../locales/en.js';

export const LOCALE_KEY = 'aim.locale';
export const LOCALE_EVENT = 'aim:localechange';
export const DEFAULT_LOCALE = 'en';

/** BCP-47 tags Security has not yet authorized for shipping. Kept as a code
 *  constant so the follow-up translation issue and the issue comment stay in
 *  sync — do not register catalogs for these until Security names them.
 *
 *  v1 ship set (AIM-916 / docs/security/admin-ui-locales-v1.md): en + de + fr + nl.
 *  de/fr/nl left this list when AIM-917 registered catalogs (severity/enforcement
 *  copy still needs Founding Engineer — Security & Platform acceptance on the PR). */
export const LOCALES_AWAITING_SECURITY = Object.freeze([
  'es', // Spain / LATAM ops — reopen on customer contract or pack expansion
  'pl', // Poland / CEE ops
  'sv', // Nordics
  'it', // Italy / EU ops
]);

/** Locales registered at boot for the admin/analyst console (AIM-917). */
export const SHIPPED_LOCALES = Object.freeze(['en', 'de', 'fr', 'nl']);

const catalogs = new Map(); // locale → flat Map(key → string template)
let activeLocale = DEFAULT_LOCALE;

/** Flatten nested message objects into "a.b.c" keys. Arrays are rejected so a
 *  catalog typo fails closed at register time rather than producing garbage. */
export function flattenMessages(input, prefix = '', out = new Map()) {
  if (input == null || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError(`i18n catalog at "${prefix || '(root)'}" must be a plain object`);
  }
  for (const [k, v] of Object.entries(input)) {
    if (!k || k.includes('.')) {
      throw new TypeError(`i18n key segment must be non-empty and dot-free: "${k}" under "${prefix}"`);
    }
    const path = prefix ? `${prefix}.${k}` : k;
    if (v != null && typeof v === 'object' && !Array.isArray(v)) {
      flattenMessages(v, path, out);
    } else if (typeof v === 'string') {
      out.set(path, v);
    } else if (typeof v === 'number' || typeof v === 'boolean') {
      out.set(path, String(v));
    } else {
      const kind = Array.isArray(v) ? 'array' : v === null ? 'null' : typeof v;
      throw new TypeError(`i18n value at "${path}" must be a string (got ${kind})`);
    }
  }
  return out;
}

/**
 * Register (or replace) a locale catalog.
 * @param {string} locale BCP-47 tag, e.g. 'en', 'de'
 * @param {object} messages nested message object
 * @returns {number} number of leaf keys registered
 */
export function registerCatalog(locale, messages) {
  const tag = normalizeLocale(locale);
  if (!tag) throw new TypeError('registerCatalog: locale is required');
  const flat = flattenMessages(messages);
  catalogs.set(tag, flat);
  return flat.size;
}

export function availableLocales() {
  return [...catalogs.keys()].sort();
}

export function hasLocale(locale) {
  return catalogs.has(normalizeLocale(locale));
}

export function hasKey(key, locale = activeLocale) {
  const flat = catalogs.get(normalizeLocale(locale));
  return Boolean(flat && flat.has(key));
}

export function currentLocale() {
  return activeLocale;
}

/**
 * Pick the best available locale from stored preference, then navigator, then
 * DEFAULT_LOCALE. Never returns a tag that has no registered catalog.
 */
export function resolveLocale({
  stored = null,
  navigatorLocales = [],
  available = availableLocales(),
} = {}) {
  const have = new Set(available.map(normalizeLocale).filter(Boolean));
  if (!have.size) return DEFAULT_LOCALE;

  const candidates = [];
  if (stored) candidates.push(stored);
  for (const n of navigatorLocales || []) candidates.push(n);

  for (const c of candidates) {
    const tag = normalizeLocale(c);
    if (!tag) continue;
    if (have.has(tag)) return tag;
    // language-only fallback: 'de-DE' → 'de'
    const lang = tag.split('-')[0];
    if (lang && have.has(lang)) return lang;
  }
  if (have.has(DEFAULT_LOCALE)) return DEFAULT_LOCALE;
  return available[0] || DEFAULT_LOCALE;
}

/**
 * Activate a locale. Unknown tags fall back via resolveLocale so a bad
 * localStorage value cannot blank the dashboard.
 * @returns {string} the locale actually applied
 */
export function setLocale(locale, { persist = true, announce = true } = {}) {
  const next = resolveLocale({
    stored: locale,
    available: availableLocales(),
  });
  const prev = activeLocale;
  activeLocale = next;

  if (persist) writeStored(next);
  if (announce && prev !== next) {
    try {
      if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
        window.dispatchEvent(new CustomEvent(LOCALE_EVENT, { detail: { locale: next, previous: prev } }));
      }
    } catch {
      /* event delivery is best-effort */
    }
  }
  return next;
}

/** Read the operator preference, or null if unset/unreadable. */
export function storedLocale() {
  try {
    const value = storage()?.getItem(LOCALE_KEY);
    return value ? normalizeLocale(value) : null;
  } catch {
    return null;
  }
}

/**
 * Look up a message and interpolate {name} placeholders.
 * Missing key → English → the key itself (never empty, never throws).
 *
 * @param {string} key
 * @param {Record<string, string|number>|null} [params]
 * @param {{ locale?: string }} [opts]
 * @returns {string}
 */
export function t(key, params, opts = {}) {
  if (typeof key !== 'string' || !key) return '';
  const locale = normalizeLocale(opts.locale) || activeLocale;
  const template = lookup(key, locale) ?? lookup(key, DEFAULT_LOCALE) ?? key;
  return interpolate(template, params);
}

/** True when the active catalog (or English fallback) owns the key. */
export function hasMessage(key, locale = activeLocale) {
  return lookup(key, locale) != null || lookup(key, DEFAULT_LOCALE) != null;
}

/**
 * Set <html lang="…"> so AT and browser heuristics match the active catalog.
 * Safe to call without a document (tests).
 */
export function applyDocumentLang(doc = typeof document !== 'undefined' ? document : null) {
  if (!doc?.documentElement) return activeLocale;
  doc.documentElement.setAttribute('lang', activeLocale);
  return activeLocale;
}

/**
 * Boot helper: register catalogs, pick locale, stamp document lang.
 * English must already be registered (or passed in catalogs.en).
 *
 * @param {object} [opts]
 * @param {Record<string, object>} [opts.catalogs]
 * @param {string|null} [opts.locale] force a locale (tests)
 * @param {boolean} [opts.persist]
 * @param {Document|null} [opts.document]
 * @returns {string} active locale
 */
export function initI18n({
  catalogs: extra = null,
  locale = null,
  persist = true,
  document: doc = typeof document !== 'undefined' ? document : null,
} = {}) {
  if (extra && typeof extra === 'object') {
    for (const [tag, messages] of Object.entries(extra)) {
      registerCatalog(tag, messages);
    }
  }
  if (!catalogs.has(DEFAULT_LOCALE)) {
    throw new Error('initI18n: English (en) catalog is required before boot');
  }

  const nav = (() => {
    try {
      if (typeof navigator === 'undefined') return [];
      if (Array.isArray(navigator.languages) && navigator.languages.length) {
        return [...navigator.languages];
      }
      return navigator.language ? [navigator.language] : [];
    } catch {
      return [];
    }
  })();

  const chosen = resolveLocale({
    stored: locale ?? storedLocale(),
    navigatorLocales: locale ? [] : nav,
  });
  setLocale(chosen, { persist, announce: false });
  applyDocumentLang(doc);
  return activeLocale;
}

/* ---------- internals ---------- */

function lookup(key, locale) {
  const flat = catalogs.get(normalizeLocale(locale));
  if (!flat) return null;
  return flat.has(key) ? flat.get(key) : null;
}

/** {name} interpolation. Unknown placeholders are left intact so a typo is
 *  visible in the UI rather than silently deleted. */
export function interpolate(template, params) {
  if (params == null || typeof params !== 'object') return String(template);
  return String(template).replace(/\{([a-zA-Z_][a-zA-Z0-9_]*)\}/g, (match, name) => {
    if (!Object.prototype.hasOwnProperty.call(params, name)) return match;
    const v = params[name];
    return v == null ? '' : String(v);
  });
}

/** Lowercase BCP-47-ish tag; strips whitespace; rejects empty/garbage. */
export function normalizeLocale(tag) {
  if (tag == null) return '';
  const s = String(tag).trim().replace(/_/g, '-').toLowerCase();
  if (!s || !/^[a-z]{2,3}(-[a-z0-9]{2,8})*$/i.test(s)) return '';
  return s;
}

function storage() {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

function writeStored(locale) {
  try {
    storage()?.setItem(LOCALE_KEY, locale);
  } catch {
    /* preference is best-effort */
  }
}

/** Test helper — wipe catalogs and reset active locale. Not for production.
 *  Callers that clear must re-register English before asserting product copy. */
export function _resetI18nForTests() {
  catalogs.clear();
  activeLocale = DEFAULT_LOCALE;
}

/* English is always present. Registering at module load means severityBadge /
 * emptyState work in unit tests without every suite calling initI18n(). */
registerCatalog(DEFAULT_LOCALE, enCatalog);

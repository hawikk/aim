/* Locale picker for admin/analyst chrome.
 *
 * Lists only registered catalogs (never LOCALES_AWAITING_SECURITY tags).
 * Preference path matches the scaffold: localStorage aim.locale → navigator → en.
 * Policy: docs/security/admin-ui-locales-v1.md (picker + navigator, not navigator-only).
 */

import {
  availableLocales,
  currentLocale,
  setLocale,
  applyDocumentLang,
  t,
  LOCALE_EVENT,
  hasKey,
} from './i18n.js';
import { esc } from './dom.js';

export const LOCALE_PICKER_ID = 'locale-picker';

/**
 * Human label for a registered locale. Prefer the catalog's meta.name so the
 * option reads "Deutsch" rather than a BCP-47 tag; fall back to the tag.
 */
export function localeLabel(tag) {
  const key = 'meta.name';
  if (hasKey(key, tag)) {
    // Look up in that catalog without switching active locale.
    return t(key, null, { locale: tag });
  }
  return tag;
}

/**
 * Populate #locale-picker options from availableLocales() and sync selection.
 * Safe when the select is missing (unit tests without full chrome).
 *
 * @param {Document|null} [doc]
 * @returns {HTMLSelectElement|null}
 */
export function syncLocalePicker(doc = typeof document !== 'undefined' ? document : null) {
  const select = doc?.getElementById?.(LOCALE_PICKER_ID);
  if (!select) return null;

  const tags = availableLocales();
  const active = currentLocale();
  const optionsHtml = tags
    .map((tag) => {
      const label = localeLabel(tag);
      const selected = tag === active ? ' selected' : '';
      return `<option value="${tag}"${selected}>${esc(label)}</option>`;
    })
    .join('');
  select.innerHTML = optionsHtml;
  if (tags.includes(active)) select.value = active;

  select.setAttribute('aria-label', t('chrome.locale'));
  select.title = t('chrome.localeHint');
  const wrap = select.closest('label.locale-picker');
  if (wrap) {
    const visible = wrap.querySelector('.locale-picker-label');
    if (visible) visible.textContent = t('chrome.locale');
  }
  return select;
}

/**
 * Wire the top-bar locale select. Call after initI18n has registered catalogs.
 *
 * @param {object} [opts]
 * @param {Document|null} [opts.document]
 * @param {() => void} [opts.onChange] optional re-paint hook (e.g. refresh route)
 * @returns {HTMLSelectElement|null}
 */
export function initLocalePicker({
  document: doc = typeof document !== 'undefined' ? document : null,
  onChange = null,
} = {}) {
  const select = syncLocalePicker(doc);
  if (!select) return null;

  if (select.dataset.localePickerBound === '1') return select;
  select.dataset.localePickerBound = '1';

  select.addEventListener('change', () => {
    const next = setLocale(select.value, { persist: true, announce: true });
    applyDocumentLang(doc);
    syncLocalePicker(doc);
    const status = doc?.getElementById?.('sr-status');
    if (status) {
      status.textContent = `${t('chrome.locale')}: ${localeLabel(next)}`;
    }
    if (typeof onChange === 'function') {
      try {
        onChange(next);
      } catch {
        /* re-paint is best-effort */
      }
    }
  });

  /* Another tab (or code path) changing aim.locale should keep this control honest. */
  if (typeof window !== 'undefined') {
    window.addEventListener(LOCALE_EVENT, () => {
      syncLocalePicker(doc);
      applyDocumentLang(doc);
    });
    window.addEventListener('storage', (e) => {
      if (e.key !== 'aim.locale') return;
      if (e.newValue) setLocale(e.newValue, { persist: false, announce: true });
      else setLocale(currentLocale(), { persist: false, announce: true });
      syncLocalePicker(doc);
      applyDocumentLang(doc);
    });
  }

  return select;
}

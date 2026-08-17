/* Runtime theme control (AIM-514).
 *
 * Dark is the product default and light is an opt-in override block in
 * styles.css keyed on `<html data-theme="light">` (decision: AIM-69, see
 * docs/frontend-design-system.md). This module owns the *runtime* half of that
 * decision: read the operator's stored choice, put it on the root element, and
 * tell the rest of the app that the tokens moved.
 *
 * Two things deliberately live outside this module:
 *
 *  - The *pre-paint* application is an inline script in index.html. Module
 *    scripts are deferred by definition, so anything here runs after the first
 *    paint — which is exactly the flash of the wrong theme we are avoiding.
 *    That snippet must keep using THEME_KEY and this value vocabulary;
 *    test/theme.test.js asserts the two stay in sync.
 *  - Chart re-coloring. Charts are app.js's; it listens for THEME_EVENT and
 *    re-resolves its tokens. Anything else that caches a computed token value
 *    should do the same rather than growing a hook here.
 */

export const THEME_KEY = 'aim.theme';
export const THEME_EVENT = 'aim:themechange';
export const DEFAULT_THEME = 'dark';

const THEMES = new Set(['dark', 'light']);

/* localStorage throws (not returns null) in a partitioned or storage-disabled
 * context, and the dashboard is embedded in wikis where that happens. A theme
 * preference is never worth taking the app down for, so every access is
 * best-effort and the failure mode is "you get dark". */
function storage() {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

/** The operator's stored choice, or null if unset/unreadable/garbage. */
export function storedTheme() {
  try {
    const value = storage()?.getItem(THEME_KEY);
    return THEMES.has(value) ? value : null;
  } catch {
    return null;
  }
}

/** The theme currently on the document. Anything but "light" is dark. */
export function currentTheme(doc = document) {
  return doc.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

/**
 * Put `theme` on the document, persist it, and announce the change.
 *
 * @param {string} theme            'dark' | 'light'; anything else → DEFAULT_THEME
 * @param {object} [opts]
 * @param {boolean} [opts.persist]  false when echoing another tab's change
 * @returns {string} the theme actually applied
 */
export function applyTheme(theme, { persist = true } = {}) {
  const next = THEMES.has(theme) ? theme : DEFAULT_THEME;
  // Dark is the attribute-less default: light is set, dark is removed. Writing
  // data-theme="dark" would work today but would make :root and the override
  // block two competing definitions of the default.
  if (next === 'light') document.documentElement.setAttribute('data-theme', 'light');
  else document.documentElement.removeAttribute('data-theme');

  if (persist) {
    try {
      storage()?.setItem(THEME_KEY, next);
    } catch {
      /* preference is best-effort; the applied theme still holds for this session */
    }
  }

  syncToggles(next);
  window.dispatchEvent(new CustomEvent(THEME_EVENT, { detail: { theme: next } }));
  return next;
}

/** Flip dark ↔ light. Returns the theme now in effect. */
export function toggleTheme() {
  return applyTheme(currentTheme() === 'light' ? 'dark' : 'light');
}

/* The button is a toggle, not a menu: aria-pressed carries the state and the
 * accessible name stays put, so a screen reader announces "Light theme,
 * pressed" rather than a label that changes out from under the user. The
 * title is the sighted equivalent and says what the click will do. */
function syncToggles(theme) {
  for (const btn of document.querySelectorAll('[data-theme-toggle]')) {
    btn.setAttribute('aria-pressed', theme === 'light' ? 'true' : 'false');
    btn.title = theme === 'light' ? 'Switch to the dark theme' : 'Switch to the light theme';
  }
}

/**
 * Wire every [data-theme-toggle] control in the chrome.
 *
 * Called at app boot, before the session fetch: an analyst staring at the
 * "couldn't load your session" banner in the wrong theme should still be able
 * to fix the theme.
 */
export function initThemeToggle() {
  const applied = applyTheme(storedTheme() ?? DEFAULT_THEME);

  for (const btn of document.querySelectorAll('[data-theme-toggle]')) {
    btn.addEventListener('click', () => {
      const theme = toggleTheme();
      const status = document.getElementById('sr-status');
      if (status) status.textContent = `${theme === 'light' ? 'Light' : 'Dark'} theme applied`;
    });
  }

  /* A second tab changing the preference should not leave this one wrong;
   * `storage` only fires in the *other* documents, so this cannot loop. */
  window.addEventListener('storage', (e) => {
    if (e.key !== THEME_KEY) return;
    applyTheme(THEMES.has(e.newValue) ? e.newValue : DEFAULT_THEME, { persist: false });
  });

  return applied;
}

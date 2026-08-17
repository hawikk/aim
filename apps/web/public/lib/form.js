/* Shared form primitives for the mutation module UIs (
 * Phase 3).
 *
 * findings.js, rules.js and inbox.js each grew the same three patterns by
 * hand, and the copies had already drifted — rules.js and inbox.js hand-rolled
 * the 401 path (`err.status === 401` + `window.location.assign`) that
 * findings.js routed through the kernel, and every submit handler re-derived
 * its own disable/re-enable dance (one of them re-enables on success, one
 * only on error, one only if the button survived the re-render). Drift in
 * these paths is not cosmetic: a gate that forgets the 401 redirect strands
 * a logged-out analyst on a dead view, and a busy state that re-enables too
 * early allows a double-submitted triage write.
 *
 * The three primitives:
 *
 *   requireCapability  — module bootstrap gate on /api/me capabilities
 *   withBusy           — optimistic disable around an async mutation
 *   showFieldError / clearFieldError — inline validation error + focus
 *
 * The `no-local-form-gate` test in test/form.test.js fails the build if a
 * mutation module reintroduces a hand-rolled /api/me gate.
 */

import { api, isUnauthorized, redirectToLogin } from './api.js';

/**
 * Capability-gated module bootstrap.
 *
 * Fetches /api/me once; invokes `start` only when the session's capabilities
 * include `capability`. Registration *is* the gate for module views — a
 * module whose start never runs registers nothing, so its route falls back
 * to Overview and no DOM is built. Returns true when the module started.
 *
 * A 401 means SSO mode with no session: full-page redirect to the login
 * flow. Any other failure (network, 5xx) leaves the module inert — it must
 * never take the shell down. `start`'s own errors are logged with `label`,
 * never thrown, for the same reason.
 *
 * @param {string} capability key of /api/me capabilities, e.g. 'findingsConsole'
 * @param {(me: object) => unknown} start module init, called with the /api/me
 *   payload (may be async; errors are logged)
 * @param {string} [label] log prefix, e.g. 'findings console'
 * @returns {Promise<boolean>} whether the module started
 */
export async function requireCapability(capability, start, label = capability) {
  const me = await api('/api/me').catch((err) => {
    if (isUnauthorized(err)) redirectToLogin();
    return null;
  });
  if (!me?.capabilities?.[capability]) return false;
  Promise.resolve()
    .then(() => start(me))
    .catch((err) => console.error(`${label} failed to start:`, err));
  return true;
}

/**
 * Run an async mutation with its triggering control(s) disabled.
 *
 * Disables before `task` runs so a double-click (or a repeat keyboard
 * activation) cannot fire a second write; an invocation that arrives while
 * the control is already disabled is swallowed. The task's error is
 * rethrown so the caller keeps its own error surface (inline error element,
 * toast).
 *
 * `reenable` controls when the control comes back:
 *   - 'error' (default) — only when the task threw. For submit buttons whose
 *     success path re-renders and destroys the form (rules.js): the stale
 *     disabled node is discarded, and a failure must hand the button back.
 *   - 'always' — unconditionally (exports, paging, bulk bars that persist).
 *   - 'connected' — only when the control is still in the document (findings
 *     triage: success may re-render the row away; a validation blocker leaves
 *     it in place and the operator needs the button back to retry).
 *   - (error) => boolean — bespoke predicate (rules test-send keeps the
 *     button disabled while the destination secret is unconfigured).
 *
 * @param {Element | Element[]} controls
 * @param {() => Promise<unknown>} task
 * @param {{ reenable?: 'error' | 'always' | 'connected' | ((error: unknown) => boolean) }} [opts]
 */
export async function withBusy(controls, task, { reenable = 'error' } = {}) {
  const list = (Array.isArray(controls) ? controls : [controls]).filter(Boolean);
  if (!list.length) return task();
  if (list[0].disabled) return undefined; // a write is already in flight
  list.forEach((c) => { c.disabled = true; });
  let error = null;
  try {
    return await task();
  } catch (err) {
    error = err;
    throw err;
  } finally {
    const enable = typeof reenable === 'function'
      ? Boolean(reenable(error))
      : reenable === 'always'
        ? true
        : reenable === 'connected'
          ? list[0].isConnected
          : error !== null;
    if (enable) list.forEach((c) => { c.disabled = false; });
  }
}

/**
 * Show an inline form error and move focus to the offending field.
 *
 * the error element carries role="alert" so screen readers speak
 * the message, but without the focus move the operator has to hunt for which
 * input the message is about. Pass `field` whenever the error names one.
 *
 * @param {Element | null} errEl the form's error element (role="alert")
 * @param {string} message
 * @param {Element | null} [field] input/select to focus
 */
export function showFieldError(errEl, message, field = null) {
  if (!errEl) return;
  errEl.textContent = message;
  field?.focus?.();
}

/** Clear one or more inline error elements before (re)validating. */
export function clearFieldError(...errEls) {
  errEls.forEach((el) => { if (el) el.textContent = ''; });
}

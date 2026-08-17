/* The fetch boundary for the dashboard (AIM-1089, AIM-453 Phase 1).
 *
 * Every view talks to the API through `api()` here. It used to be
 * reimplemented in sixteen view modules and the copies had diverged —
 * some read `body.error`, some did not; some handled 204, some would
 * throw trying to parse an empty body. Sixteen copies is sixteen things
 * to audit, same lesson as the esc extraction in AIM-523. This module is the
 * one copy.
 * The `no-local-api` guard in test/api.test.js fails the build if a view
 * reintroduces a local definition.
 *
 * Canonical semantics (union of the sixteen copies):
 *   - non-2xx   → throw Error with `err.status` set; message is
 *                 `body.detail || body.error || "<status> <statusText>"`
 *   - 204       → null (never attempt to parse an empty body)
 *   - otherwise → parsed JSON
 */

export async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const err = new Error(body.detail || body.error || `${res.status} ${res.statusText}`);
    err.status = res.status;
    throw err;
  }
  return res.status === 204 ? null : res.json();
}

/** POST/PUT/PATCH/DELETE with a JSON body. */
export function apiJson(path, method, body) {
  return api(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** Text endpoints (CSV exports) with the same error shape as api(). */
export async function apiText(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const err = new Error(body.detail || body.error || `${res.status} ${res.statusText}`);
    err.status = res.status;
    throw err;
  }
  return res.text();
}

/* 401 handling. The kernel throws like any other error — it does NOT
 * redirect on its own, because a view-level retry banner is the right
 * response to a transient failure and only the caller knows which. The
 * session bootstrap in app.js is the one place that treats 401 as
 * "session expired, back to login". */
export const isUnauthorized = (err) => err?.status === 401;

export function redirectToLogin() {
  window.location.assign('/auth/login');
}

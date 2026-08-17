// Smoke test acceptance criteria:
//  1. overview answers "who uses which AI tools and how much"
//  2. unapproved view surfaces tool + first-seen + count
//  3. all endpoints respond < 2s on pilot-scale data
//  4. user-level endpoint is gated for the auditor role (checked when the API
//     runs with AIM_AUTH_DEV=1, via the dev role-login; in SSO mode a
//     cookieless request must 401 instead)
const base = process.env.API_URL ?? 'http://localhost:8080';

// Dev role login: returns the aim_session cookie for a role, or null
// when the API has no dev endpoints (SSO mode).
async function devLogin(role) {
  const res = await fetch(`${base}/auth/dev/login?role=${role}`);
  if (!res.ok) return null;
  const setCookie = res.headers.get('set-cookie') ?? '';
  const match = setCookie.match(/aim_session=[^;]+/);
  return match ? match[0] : null;
}
const adminCookie = await devLogin('admin');
const headers = adminCookie ? { cookie: adminCookie } : {};

let failures = 0;
async function check(name, path, { maxMs = 2000, expectStatus = 200, validate } = {}) {
  const t0 = performance.now();
  const res = await fetch(base + path, { headers });
  const ms = performance.now() - t0;
  const body = await res.json().catch(() => null);
  const problems = [];
  if (res.status !== expectStatus) problems.push(`status ${res.status}, expected ${expectStatus}`);
  if (expectStatus === 200 && ms > maxMs) problems.push(`${ms.toFixed(0)}ms > ${maxMs}ms`);
  if (expectStatus === 200 && validate) {
    const msg = validate(body);
    if (msg) problems.push(msg);
  }
  const ok = problems.length === 0;
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name} — ${ms.toFixed(0)}ms${problems.length ? ' — ' + problems.join('; ') : ''}`);
  return body;
}

await check('health', '/api/health');
const ov = await check('overview 30d', '/api/overview?days=30', {
  validate: (b) =>
    b?.totals?.activeUsers > 0 && b?.tools?.length > 0 && b?.trend?.length > 0
      ? null
      : 'missing activeUsers/tools/trend',
});
await check('overview 90d', '/api/overview?days=90');
await check('teams', '/api/teams?days=30', {
  validate: (b) => (b?.teams?.length >= 10 ? null : 'expected all 12 teams'),
});
if (ov?.tools?.length) {
  await check('tool detail', `/api/tools/${encodeURIComponent(ov.tools[0].tool)}?days=30`, {
    validate: (b) => (b?.models?.length > 0 && b?.sessions > 0 ? null : 'missing models/sessions'),
  });
}
await check('unapproved discovery', '/api/unapproved?days=90', {
  validate: (b) => {
    if (!b?.unapproved?.length) return 'no unapproved tools found';
    const r = b.unapproved[0];
    return r.tool && r.firstSeen && r.events > 0 ? null : 'missing tool/firstSeen/count';
  },
});
await check('users (security)', '/api/users?days=30', {
  validate: (b) => (b?.users?.length > 0 ? null : 'no user rows'),
});

// Authz negative test: auditor role must not reach user-level rows. Only
// meaningful when dev role-login is available (AIM_AUTH_DEV=1); in SSO mode a
// cookieless request must 401 instead.
if (adminCookie) {
  const auditorCookie = await devLogin('auditor');
  const t0 = performance.now();
  const res = await fetch(base + '/api/users?days=30', { headers: { cookie: auditorCookie } });
  const ok = res.status === 403;
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'} users gated for auditor role — status ${res.status} (${(performance.now() - t0).toFixed(0)}ms)`);
  const res2 = await fetch(base + '/api/audit/events', { headers: { cookie: auditorCookie } });
  const ok2 = res2.status === 200;
  if (!ok2) failures++;
  console.log(`${ok2 ? 'PASS' : 'FAIL'} auditor can read audit trail — status ${res2.status}`);
} else {
  // Distinguish SSO mode (cookieless must 401) from local personal mode
  // (no IdP configured — the API intentionally serves a local admin identity).
  const login = await fetch(base + '/auth/login', { redirect: 'manual' });
  const ssoMode = login.status >= 300 && login.status < 400;
  const res2 = await fetch(base + '/api/overview?days=7', { headers: {} });
  const expected = ssoMode ? 401 : 200;
  const ok2 = res2.status === expected;
  if (!ok2) failures++;
  console.log(`${ok2 ? 'PASS' : 'FAIL'} unauthenticated request ${ssoMode ? 'rejected (SSO mode)' : 'serves local personal identity'} — status ${res2.status}`);
}

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);

// Browser-driven route check for the dashboard. Dev-only.
//
// apps/web has no DOM test harness: lib/router.js is unit-tested under
// node:test, but "does the URL actually put the right view on screen" needs a
// real browser. This is that check. It drives headless Chrome over CDP against
// the preview server and asserts the properties exists to guarantee
// module views (findings/rules/compliance/mcp/onboarding) are addressable,
// survive a reload, take part in history, and stay invisible to a session
// whose capabilities don't include them.
//
// Not in CI: it needs a running stack and a Chrome binary. Run it when you
// touch routing.
//
//   node scripts/preview-web.mjs --port 8123 --upstream http://localhost:8085 &
//   chrome-headless-shell --remote-debugging-port=9222 --no-sandbox about:blank &
//   node scripts/verify-web-routes.mjs
//
//   [--base http://localhost:8123] [--cdp http://localhost:9222]

const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i].replace(/^--/, ''), process.argv[i + 1]);
const BASE = args.get('base') ?? 'http://localhost:8123';
const CDP = args.get('cdp') ?? 'http://localhost:9222';

const MODULES = ['findings', 'rules', 'compliance', 'mcp', 'onboarding'];

/* A session with the dashboard and nothing else. Stubbed over CDP so the gate
 * can be exercised without minting a second role in the API. */
const UNPRIVILEGED_ME = JSON.stringify({
  email: 'viewer@localhost', name: 'Viewer', role: 'viewer', mode: 'sso',
  capabilities: {
    dashboard: true, findingsConsole: false, userLevel: false, fleet: false,
    guardrail: false, compliance: false, auditTrail: false, admin: false,
  },
});

async function openTab({ stubMe = null } = {}) {
  const target = await (await fetch(`${CDP}/json/new?about:blank`, { method: 'PUT' })).json();
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener('open', r, { once: true }));

  let id = 0;
  const pending = new Map();
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const n = ++id;
      pending.set(n, { resolve, reject });
      ws.send(JSON.stringify({ id: n, method, params }));
    });

  ws.addEventListener('message', (e) => {
    const m = JSON.parse(e.data);
    if (m.method === 'Fetch.requestPaused') {
      if (stubMe && m.params.request.url.endsWith('/api/me')) {
        send('Fetch.fulfillRequest', {
          requestId: m.params.requestId,
          responseCode: 200,
          responseHeaders: [{ name: 'content-type', value: 'application/json' }],
          body: Buffer.from(stubMe).toString('base64'),
        });
      } else {
        send('Fetch.continueRequest', { requestId: m.params.requestId });
      }
      return;
    }
    if (m.id && pending.has(m.id)) {
      const { resolve, reject } = pending.get(m.id);
      pending.delete(m.id);
      if (m.error) reject(new Error(JSON.stringify(m.error)));
      else resolve(m.result);
    }
  });

  await send('Page.enable');
  await send('Runtime.enable');
  if (stubMe) await send('Fetch.enable', { patterns: [{ urlPattern: '*' }] });

  const evaluate = async (expression) => {
    const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text);
    return r.result.value;
  };

  /* What is on screen, and does the URL agree? Feature modules register only
   * once their capability fetch settles, so poll for the expected view rather
   * than betting on a fixed delay. `want` null just waits for any view. */
  const state = (want = null) => evaluate(`(async () => {
    for (let i = 0; i < 120; i++) {
      const v = document.querySelector('.view.active');
      if (v && (${want === null} || v.id === 'view-${want}')) break;
      await new Promise(r => setTimeout(r, 50));
    }
    const v = document.querySelector('.view.active');
    const tab = document.querySelector('#tabs button.active');
    return { view: v ? v.id.replace(/^view-/, '') : null, hash: location.hash, tab: tab ? tab.dataset.view : null };
  })()`);

  const goto = async (url, want = null) => {
    await send('Page.navigate', { url });
    return state(want);
  };

  return { send, evaluate, state, goto, close: () => ws.close() };
}

const results = [];
function check(name, ok, detail) {
  results.push(ok);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `\n        ${JSON.stringify(detail)}` : ''}`);
}
// A module view is "on screen and addressable" only when the DOM, the nav and
// the URL all name it. Those three disagreeing is the defect removes.
const agrees = (s, view) => s.view === view && s.hash === `#/${view}` && s.tab === view;

/* ---------- privileged session: the views exist and route ---------- */
{
  const t = await openTab();

  check('a shared #/findings link opens the findings inbox', agrees(await t.goto(`${BASE}/#/findings`, 'findings'), 'findings'));
  check('#/mcp survives a fresh load instead of dropping to Overview', agrees(await t.goto(`${BASE}/#/mcp`, 'mcp'), 'mcp'));

  await t.evaluate(`document.querySelector('#tab-rules').click()`);
  check('a module tab click writes the URL like any static tab', agrees(await t.state('rules'), 'rules'));

  await t.evaluate('history.back()');
  check('Back returns to the previous module view', agrees(await t.state('mcp'), 'mcp'));
  await t.evaluate('history.forward()');
  check('Forward replays it', agrees(await t.state('rules'), 'rules'));

  await t.evaluate(`document.querySelector('#tabs button[data-view="overview"]').click()`);
  check('leaving a module view for a static tab works', agrees(await t.state('overview'), 'overview'));

  // a tab click whose hash already matches must still re-render.
  await t.evaluate(`document.querySelector('#tab-compliance').click()`);
  await t.state('compliance');
  await t.evaluate(`document.querySelector('#tab-compliance').click()`);
  check('re-clicking the active module tab keeps it', agrees(await t.state('compliance'), 'compliance'));

  const junk = await t.goto(`${BASE}/#/not-a-module`, 'overview');
  check('an unknown view name falls back to Overview', junk.view === 'overview', junk);

  // first-run onboarding / the findings landing may claim a BARE
  // landing, and must now say so in the URL — but may never take an explicit one.
  await t.goto(`${BASE}/`);
  await new Promise((r) => setTimeout(r, 2500));
  const landing = await t.state();
  check('a bare landing resolves to an addressable URL', agrees(landing, landing.view), landing);

  await t.goto(`${BASE}/#/fleet`, 'fleet');
  await new Promise((r) => setTimeout(r, 2500));
  const explicit = await t.state();
  check('an explicit URL is never stolen by a landing module', agrees(explicit, 'fleet'), explicit);

  t.close();
}

/* ---------- unprivileged session: the views are not merely hidden ---------- */
{
  const t = await openTab({ stubMe: UNPRIVILEGED_ME });
  for (const name of MODULES) {
    await t.goto(`${BASE}/#/${name}`);
    // Give every module's gate a full chance to (not) register before looking.
    await new Promise((r) => setTimeout(r, 3000));
    const s = await t.evaluate(`(() => {
      const v = document.querySelector('.view.active');
      return { view: v ? v.id.replace(/^view-/, '') : null, hash: location.hash,
               built: !!document.querySelector('#view-${name}'), tab: !!document.querySelector('#tab-${name}') };
    })()`);
    // Falling back is not enough: capability gating is the ABSENCE of a
    // registration, so the section and tab must never have been created.
    check(`#/${name} without the capability falls back to Overview, unbuilt`,
      s.view === 'overview' && !s.built && !s.tab, s);
  }
  t.close();
}

const failed = results.filter((ok) => !ok).length;
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);

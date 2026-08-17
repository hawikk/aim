# How to add a dashboard view

Companion to the frontend assessment and the shared kernel.
This is the checklist the next view author follows so the wiring is mechanical
instead of re-derived from a 2,000-line file. The enforceable subset is guarded
by `apps/web/test/view-registration.test.js` — a static view that misses a
touch point fails CI.

There are two kinds of view. Pick first, then follow that path.

- **Static view** — always routable, lives in `index.html`, registered in the
  router's `VALID_VIEWS`. Examples: Overview, Teams, Security, Audit. Use when
  every authenticated session may route to it (individual tabs may still be
  hidden per capability).
- **Module view** — routable only after its module registers it at runtime,
  which happens only when the session's capabilities allow it. Examples:
  Status, Findings, Rules, Compliance, MCP, Dashboards. Use when the view is
  capability-gated end to end: in a session without the capability the route
  never exists and falls back to Overview.

## Rule zero: import the kernel, do not reimplement it

The kernel owns the primitives every view needs. **Never** copy a
local `api`, `esc`, or `fmtTs` into a new view — the copies are what diverged
in the first place, and CI guards fail the build:

- `lib/api.js` — the only fetch boundary: `api()`, `apiJson()`, `apiText()`,
  `isUnauthorized()`, `redirectToLogin()`. 204 → `null`; non-2xx → `Error`
  with `err.status`. Guard: `no module under public/ defines a local api`
  in `apps/web/test/api.test.js`.
- `lib/dom.js` — the only HTML-escaping boundary: `esc()`, `$()`, and a
  re-export of all of `lib/format.js` (`fmtTs`, `fmtInt`, `fmtTok`, …).
  Guard: `no module under public/ defines a local esc` in
  `apps/web/test/dom.test.js`; timestamp drift guard in
  `apps/web/test/smoke.test.js`.
- `lib/components.js` — `table()`, `card()`, `emptyState()`, `skeletonCards()`.
  Loading/empty/error states come from here, not hand-rolled markup.
- `lib/entity-detail.js` — `entityDetailShell()` / `entityDetailError()` /
  `hideEntityDetail()`: the one skeleton for `#/view/<entity>` drill-down
  panels (guard/hide, back-linked heading, cards strip, failure state). A new
  drill-down consumes it; the per-view part is only the cards list and the
  `body` markup after them.
- `lib/severity.js` — severity/criticality badges and pills. One scale
  everywhere; a critical looks identical on every view.
- `lib/charts.js` / `lib/chart-series.js` — Chart.js integration. Read the
  dataviz standards before writing chart code.
- `lib/runtime.js` — shared router-owned `state`, `hashFor()`, error surfaces.
  Re-exports `api`/`apiJson`, so `from '../lib/runtime.js'` is also a kernel
  import for view modules.
- `lib/form.js` — the mutation-UI primitives: `requireCapability()`
  for the module bootstrap gate, `withBusy()` for submit busy state, and
  `showFieldError()` / `clearFieldError()` for inline validation errors.
  Guard: `no-local-form-gate` in `apps/web/test/form.test.js`.

Design the **empty, loading, partial, and failure states first** — a blank
security dashboard is an incident. Every new view ships with a
DOM test covering: mounts, renders with data, renders empty, renders on API
error.

## Static view checklist

Touch points, in order (example name: `widgets`):

1. **Router registration** — `apps/web/public/lib/router.js`
   - Add `'widgets'` to `VALID_VIEWS`.
   - If the view deep-links an entity (`#/widgets/<id>`), also add it to
     `DRILL_VIEWS`. Otherwise a stray second segment is dropped, which is the
     safe default.

2. **View module** — `apps/web/public/views/widgets.js`
   - Export `export async function loadWidgets()` (camelCase of the view name).
   - Import from the kernel: `../lib/dom.js`, `../lib/format.js`,
     `../lib/components.js`, `../lib/charts.js`, `../lib/runtime.js` as needed
     (see rule zero). Views import from `../lib/…` (one directory deeper than
     top-level modules).
   - Fetch via `api(\`/api/widgets?days=${state.days}\`)`. If the API doesn't
     return what the view needs, file an issue against the API owner — do not
     build a client-side workaround.
   - Independent panels load independently (see `views/teams.js`): one failed
     aggregate must not blank the whole view.
   - Exception — the streaming pattern: a static tab whose rendering is owned
     by a top-level module (Activity: `activity.js` watches the section
     and owns the trail) registers a deliberate no-op shim
     (`views/activity.js`) so `refresh()` has a loader. Don't add a second one
     without the same justification; a no-op loader is a silent blank view
     waiting to happen.

3. **Loader wiring** — `apps/web/public/app.js`
   - `import { loadWidgets } from './views/widgets.js';`
   - Add `widgets: loadWidgets,` to the `loaders` map.
   - Optional: a CSV export link in `updateExports()` if the endpoint supports
     `format=csv`.
   - Optional: capability-gated tab — in the bootstrap, unhide on
     `capabilities?.yourCap` with `$('#tab-widgets').hidden = false`, matching
     the audit/users/fleet pattern. The tab ships `hidden` in HTML; the
     **section never does** (next step).

4. **HTML shell** — `apps/web/public/index.html`
   - Tab button, placed in the right nav group (`data-nav-group`:
     `analysis` / `ops` / `control` / `restricted`, or the primary slot):
     ```html
     <button data-view="widgets" id="tab-widgets" role="tab" aria-selected="false" aria-controls="view-widgets">
       <svg class="ico" … aria-hidden="true">…</svg>
       Widgets
     </button>
     ```
     Add `hidden` to the button only if the tab is capability-gated.
   - Section, with the exact ARIA pairing:
     ```html
     <section id="view-widgets" class="view" role="tabpanel" aria-labelledby="tab-widgets" tabindex="0">
     ```
     **Never** put the HTML `hidden` attribute on the section. The view
     switcher toggles `.active`; a static `hidden` is never cleared and the
     view renders blank (— this exact bug shipped once on Audit).
   - Give the view's dynamic containers stable ids (`widgets-table`, …) —
     smoke tests assert them.

5. **Smoke ids + tests** — `apps/web/test/`
   - `view-registration.test.js` enforces steps 1–4 mechanically; it picks the
     new view up automatically from `VALID_VIEWS`.
   - Add view-specific structural assertions to `smoke.test.js` (ids the view
     wires up, capability gate regex, API path) following the existing
     per-AIM blocks.
   - Add a DOM-level test (jsdom) for the four states: mounts, data, empty,
     API error.

## Module view checklist

1. **Module file** — `apps/web/public/widgets.js` (top level, next to
   `findings.js` / `status.js`).
2. **Script tag** — add `<script type="module" src="/widgets.js"></script>`
   with the other module tags at the bottom of `index.html`.
3. **Capability gate first** — `await requireCapability('yourCap', init, 'your module label')`
   from `lib/form.js`. Do not hand-roll the `/api/me` fetch or the 401
   redirect. If the capability is absent, `init` never runs and the module
   **registers nothing**. Registration *is* the gate: an unregistered name is
   not routable, so `#/widgets` falls back to Overview without ever building
   the view.
4. **Build tab + section via the helpers** — `moduleTab({ view, label, icon })`
   and `moduleSection({ view, html })` from `lib/a11y.js` (they create the
   same `data-view`/`role=tab`/`tabpanel` pairing static views declare in
   HTML; nav placement is handled by `placeNavTab` in `lib/nav-ia.js`).
5. **Register** —
   ```js
   registerModuleView('widgets', { onActivate: loadWidgets /*, drill: true */ });
   ```
   `onActivate(state)` is called by `route()` on every activation; it must be
   idempotent. Pass `drill: true` only if the view deep-links an entity.
6. **Kernel imports** — same rule zero (`./lib/…` paths at top level). Pure
   logic worth testing goes in `lib/widgets.js`; the module file stays thin
   (the `dashboards.js` + `lib/dashboards.js` split is the pattern).
7. **Mutation UIs use the form primitives** — if the module writes
   (POST/PUT/PATCH/DELETE), run every submit through `withBusy(control, task,
   { reenable })` so a double-click cannot fire a second write:
   `reenable: 'error'` (default) when success re-renders and destroys the
   control, `'always'` for controls that persist (exports, paging, bulk
   bars), `'connected'` when success may re-render the row away but a
   validation blocker leaves it in place. Show validation failures with
   `showFieldError(errEl, message, field)` — it sets the `role="alert"`
   message *and* moves focus to the offending field; clear with
   `clearFieldError(...)` before re-validating. `findings.js` (triage, bulk
   bar, saved views) and `rules.js` (threshold editor, alert destinations)
   are the reference consumers.
8. **Smoke test** — assert the script tag, the `registerModuleView('widgets'`
   call, and the `requireCapability('yourCap'` gate in `smoke.test.js` (see
   the dashboards block for the shape).

## When a module outgrows one file: the sibling split

Proven five times now — `views/security.js` → `views/security/*`,
`findings.js` → `findings/*`, `mcp.js` → `mcp/*`,
`activity.js` → `activity/*`, and `compliance.js` → `compliance/*`
. When a module view crosses ~800 LOC:

1. Keep the top-level file (`findings.js`) as the **thin orchestrator** —
   capability gate, tab/section injection, fetches, and panel wiring only.
2. Extract cohesive panels into a sibling directory named after the module
   (`public/findings/state.js`, `row.js`, `triage.js`, …). Shared
   view-private state lives in a `state.js` `fctx` object the orchestrator
   populates and siblings import — never re-created locally, reset at the top
   of `init()`.
3. The external contract must not move: same `registerModuleView` name, same
   capability gate, same DOM ids and deep-links. No product change.
4. Update source-grep tests to read the **aggregate** (orchestrator + every
   sibling, sorted) so a later split cannot silently drop a guard — see
   `readFindingsView`/`readSecurityView` in `smoke.test.js`,
   `deeplinks.test.js`, and `form.test.js`.

## Verify before claiming done

- `npm --prefix apps/web test` is green, including `view-registration.test.js`.
- Run the app, route to the view directly via its hash (`#/widgets`), reload,
  exercise empty/error/data states, and attach a screenshot to the issue.
- Check keyboard nav: arrow keys across tabs, focus lands on the section,
  filters and tables are operable without a mouse.

## References

- Design system tokens/components: `docs/frontend-design-system.md`
- app.js split + shared-module map: `docs/frontend-app-js-split-map.md`
- Router contracts (module views, capability gating): header comments in
  `apps/web/public/lib/router.js`
- Kernel rationale: `apps/web/public/lib/api.js`, `lib/dom.js` headers

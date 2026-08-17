/* The shared component vocabulary (AIM-526).
 *
 * AIM-527 pure-moved table/card/emptyState out of app.js so views/*.js could
 * import them. That stopped the *structural* trapping; this file is the
 * *contract* that stops the drift those copies introduced:
 *
 *  - emptyState is a first-class API that distinguishes no-data / no-collector /
 *    filtered / error / loading. A security analyst must not read a coverage gap
 *    as a clean result (AIM-475 / AIM-476 class of bug).
 *  - table carries the a11y contract by construction: caption, scoped headers,
 *    keyboard-reachable sort, drill-down rows with role/tabindex/name.
 *  - card is one tile with tone + optional href; clones that drop tone are how
 *    a bad number rendered neutral on five screens.
 *
 * The rule: a view describes *what* it is showing and never *how* the markup is
 * built. If a view can't say something through this API, extend the API.
 *
 * Import path uses `../lib/dom.js` (even though we live under lib/) so the
 * AIM-523 import guard, which matches the substring `lib/dom.js`, still passes.
 */
import { esc, $ } from '../lib/dom.js';
import { installEmpty, installBannerCopy } from './install-state.js';
import { t } from './i18n.js';

/** Canonical setup-doc paths (AIM-591). Repo-relative so empty states and
 * install-state rewrites cannot drift. Operators open them from the deployment
 * checkout or internal docs host — the console never fetches them itself. */
export const SETUP_DOCS = {
  enrollment: 'docs/deployment/enrollment-and-heartbeat.md',
  otelGenai: 'docs/otel-genai-integration-guide.md',
  vendorAdmin: 'docs/ops/vendor-admin-telemetry.md',
  guardrail: 'docs/guardrail-engine-v1.md',
  pipeline: 'docs/deployment/pipeline-liveness.md',
};

/** Only hash routes and same-origin absolute paths. Blocks javascript: and //evil. */
export function safeEmptyHref(href) {
  if (typeof href !== 'string' || !href) return '';
  if (href.startsWith('#/')) return href;
  if (href.startsWith('/') && !href.startsWith('//')) return href;
  return '';
}

/** Repo-relative setup doc path only (docs/… or policies/…). */
export function safeDocPath(doc) {
  if (typeof doc !== 'string' || !doc) return '';
  if (/^(docs|policies)\/[A-Za-z0-9_./-]+$/.test(doc)) return doc;
  return '';
}

/* Designed empty-state copy for the views/* modules that still share a
 * vocabulary of "why this panel might be empty". needsEvents: true means the
 * copy is about the selected range and may be rewritten by install state. */
export const EMPTY = {
  overviewTools: {
    needsEvents: true,
    title: 'No AI tool usage yet',
    body: 'No events were collected in this time range. Widen the range or check collector status on Fleet. Vendor admin feeds (Claude Code OTel, Cursor Analytics, Copilot Metrics) stay dark until a credential or exporter is configured — see docs/ops/vendor-admin-telemetry.md.',
    doc: SETUP_DOCS.enrollment,
    href: '#/fleet',
    linkLabel: 'Open Fleet',
  },
  overviewTrend: {
    needsEvents: true,
    title: 'No activity in this range',
    body: 'Daily active users and sessions will appear here once events arrive.',
    doc: SETUP_DOCS.enrollment,
  },
  providers: {
    needsEvents: true,
    title: 'No provider traffic',
    body: 'No AI provider traffic seen via proxy or endpoint collectors in this range.',
    doc: SETUP_DOCS.enrollment,
  },
  appLlm: {
    needsEvents: true,
    title: 'No application-LLM traffic',
    body: 'No provider-API calls (OpenAI, Anthropic, OpenRouter) observed at the proxy in this range.',
    doc: SETUP_DOCS.enrollment,
  },
  appLlmNew: { needsEvents: true, title: 'No new sources', body: 'No source made its first-ever LLM API call inside this window — nothing new is talking to a provider.' },
  apps: {
    needsEvents: true,
    title: 'No instrumented apps yet',
    body: 'No first-party app OTel GenAI telemetry (tool=genai_app) in this range — see docs/otel-genai-integration-guide.md. Claude Code OTel is a coding-tool feed and lives on Tools / Overview, not here.',
    doc: SETUP_DOCS.otelGenai,
  },
  appsModels: { needsEvents: true, title: 'No model data', body: 'This service made no model calls in the selected range.' },
  appsModelsFleet: {
    needsEvents: true,
    title: 'No model distribution yet',
    body: 'Model and token totals appear here once an instrumented service emits OTel GenAI spans — see docs/otel-genai-integration-guide.md.',
  },
  appsTrend: { needsEvents: true, title: 'No traffic in this range', body: 'Daily requests and tokens for this app will appear here once telemetry arrives.' },
  provTrend: { needsEvents: true, title: 'No provider activity', body: 'Daily provider volumes will appear here once traffic is observed.' },
  teamsModels: { needsEvents: true, title: 'No model usage by team', body: 'No model-level token or cost data could be attributed to teams in this range.' },
  teams: {
    needsEvents: true,
    title: 'No team usage',
    body: 'No usage could be attributed to teams in this range.',
    doc: SETUP_DOCS.enrollment,
    href: '#/fleet',
    linkLabel: 'Open Fleet',
  },
  teamsMatrix: {
    needsEvents: true,
    title: 'No usage data yet',
    body: 'Connect a collector from the Fleet view to start seeing team × tool usage.',
    doc: SETUP_DOCS.enrollment,
    href: '#/fleet',
    linkLabel: 'Open Fleet',
  },
  models: { needsEvents: true, title: 'No model data', body: 'No model-level usage for this tool in the selected range.' },
  toolTrend: { needsEvents: true, title: 'No usage in this range', body: 'Daily usage for this tool will appear here once events arrive.' },
  flags: { needsEvents: true, title: 'No guardrail matches', body: 'Nothing triggered the policy detectors in this range — that is the good outcome.' },
  flagsTrend: { needsEvents: true, title: 'No detection volume', body: 'Guardrail matches per day will appear here when detectors fire in this range.' },
  /* AIM-588: endpoint enforcement dispositions (blocked / would-block / override). */
  blocksTrend: {
    needsEvents: true,
    title: 'No enforce-block history',
    body: 'Blocked, would-block (shadow), and override counts per day appear when endpoints report enforcement dispositions in this range.',
  },
  unapproved: { needsEvents: true, title: 'No unapproved tools discovered', body: 'Every observed tool is on the sanctioned list for this range.' },
  mcpServers: { needsEvents: true, title: 'No MCP server calls', body: 'No mcp_call tool invocations recorded in this range — tool_use events arrive from collectors on schema v1.1.' },
  breakGlass: { needsEvents: true, title: 'No break-glass overrides in this range', body: 'No secret-pattern resubmit overrides (enforcement.action=confirmed) in the selected pilot window — blocks may still have fired without an override.' },
  breakGlassGrants: { title: 'No break-glass grants', body: 'No manager-approval grants in this window. Request a time-boxed grant when secret_override_requires_manager is on, or for pre-approved IR windows.' },
  repos: { needsEvents: true, title: 'No repository data', body: 'No events carried a repo reference in this range — only endpoint collectors resolve repos.' },
  users: { needsEvents: true, title: 'No user activity', body: 'No user-level usage recorded in this range.' },
  fleet: {
    reason: 'no-collector',
    title: 'No enrolled devices',
    body: 'No collectors have enrolled yet. Run the join command on a device with an enrollment token; it appears here after its first heartbeat.',
    action: 'aim join --token <enrollment-token>',
    doc: SETUP_DOCS.enrollment,
    href: '#/onboarding',
    linkLabel: 'Open Onboarding',
  },
  /* AIM-588: daily healthy-% / gaps; snapshot bar above still answers "right now". */
  fleetCoverageTrend: {
    title: 'No coverage history yet',
    body: 'Daily healthy percentage and coverage-gap counts appear once fleet history is rolled up. The snapshot bar above is the current truth.',
  },
  audit: { title: 'No audit events', body: 'No audit events match these filters.' },
  userTools: { needsEvents: true, title: 'No tools in range', body: 'This user has no tool usage in the selected range.' },
  userToolCalls: { needsEvents: true, title: 'No tool calls in range', body: 'No tool_use events for this user in the selected range — only collectors on schema v1.1 report them.' },
  userSessions: { needsEvents: true, title: 'No sessions in range', body: 'Sessions will appear here once this user is active.' },
  userFlags: { needsEvents: true, title: 'No flag hits', body: 'Nothing this user did triggered the policy detectors in this range — that is the good outcome.' },
  userFindings: { needsEvents: true, title: 'No linked findings', body: 'No guardrail findings are linked to this user in this range.' },
  noTools: {
    needsEvents: true,
    title: 'No tools to show',
    body: 'No tools observed yet — the picker will populate once usage arrives from enrolled collectors. Dark vendor feeds (Claude Code OTel, Cursor Analytics, Copilot Metrics) are listed above when a credential or exporter is missing.',
    doc: SETUP_DOCS.enrollment,
    href: '#/fleet',
    linkLabel: 'Open Fleet',
  },
  rules: {
    reason: 'no-collector',
    title: 'No rules in the loaded policy',
    body: 'No guardrail rules are loaded, so no prompt or tool use is being evaluated against policy at all. Policy lives as code under policies/guardrail/v1/.',
    doc: SETUP_DOCS.guardrail,
  },
  findingsOpen: {
    needsEvents: true,
    title: 'Inbox zero — no open findings',
    body: 'No open findings in triage. New critical findings will badge this tab once collectors report and detectors fire.',
    doc: SETUP_DOCS.enrollment,
    href: '#/fleet',
    linkLabel: 'Open Fleet',
  },
  findingsFiltered: {
    reason: 'filtered',
    title: 'No findings match this filter',
    body: 'Findings exist outside the current filters.',
  },
  activity: {
    needsEvents: true,
    title: 'No events in the trail yet',
    body: 'No collector has reported an event. Enroll a device and the trail populates within one heartbeat.',
    action: 'aim join --token <enrollment-token>',
    doc: SETUP_DOCS.enrollment,
    href: '#/fleet',
    linkLabel: 'Open Fleet',
  },
  onboardingTokens: {
    title: 'No enrollment tokens yet',
    body: 'Mint one above to onboard your first collector. Until a collector enrols, nothing is being monitored.',
    action: 'aim join --token <enrollment-token>',
    doc: SETUP_DOCS.enrollment,
  },
};

/* Install state (GET /api/onboarding/status) is published once at bootstrap.
 * Null until it resolves, and null forever if it fails — empty states then fall
 * back to their designed range copy and never invent a claim about the install. */
let install = null;
export function setInstallState(st) { install = st ?? null; }
export function getInstallState() { return install; }

/* ------------------------------------------------------------ empty state ---
 *
 * 'no-data'      Pipeline is fine; this slice genuinely has nothing. Only this
 *                reason is rewritten by install state.
 * 'no-collector' Coverage is missing. Never softened. role="alert".
 * 'filtered'     Unfiltered data exists; current filters excluded it all.
 * 'error'        The fetch failed. Unknown, not empty. role="alert".
 * 'loading'      In flight.
 */
export const EMPTY_REASONS = ['no-data', 'no-collector', 'filtered', 'error', 'loading'];
const LOUD = new Set(['no-collector', 'error']);

/** Default empty-state copy, resolved through i18n so a future locale does not
 *  re-hardcode the five reasons. English strings live in locales/en.js. */
function defaultEmptyCopy(reason) {
  const title = t(`empty.reason.${reason}.title`);
  const bodyKey = `empty.reason.${reason}.body`;
  const body = t(bodyKey);
  /* t() returns the key when missing; treat that as "no body" so loading /
   * no-data stay title-only, matching the pre-i18n DEFAULT_COPY shape. */
  const resolvedBody = body === bodyKey ? '' : body;
  return resolvedBody ? { title, body: resolvedBody } : { title };
}

/**
 * @param {object} [spec]
 * @param {string} [spec.reason='no-data']
 * @param {string} [spec.title]
 * @param {string} [spec.body]
 * @param {string} [spec.action]
 * @param {string[]} [spec.filters]
 * @param {string} [spec.clearHref]
 * @param {string} [spec.retryLabel]
 * @param {string} [spec.retryKey]
 * @param {boolean} [spec.needsEvents]
 * @param {string} [spec.doc] repo-relative setup path (docs/… or policies/…)
 * @param {string} [spec.href] in-app next step (#/… or same-origin /…)
 * @param {string} [spec.linkLabel] label for href CTA
 * @returns {string}
 */
export function emptyState(spec = {}) {
  const reason = EMPTY_REASONS.includes(spec.reason) ? spec.reason : 'no-data';

  /* Only 'no-data' defers to install state. Other reasons are claims the caller
   * has evidence for; overwriting a filtered or error state would put a false
   * explanation on screen. */
  const resolved = reason === 'no-data' ? (installEmpty(spec, install) ?? spec) : spec;

  const d = defaultEmptyCopy(reason);
  const title = resolved.title || d.title;
  const body = resolved.body ?? d.body ?? '';
  const action = resolved.action || '';
  const doc = safeDocPath(resolved.doc || spec.doc || '');
  const href = safeEmptyHref(resolved.href || spec.href || '');
  const linkLabel = resolved.linkLabel || spec.linkLabel || '';
  const loud = LOUD.has(reason);

  let html = `<div class="empty-state empty-${reason}" role="${loud ? 'alert' : 'status'}"`
    + (reason === 'loading' ? ' aria-busy="true"' : '')
    + `><div class="empty-title">${esc(title)}</div>`;
  if (body) html += `<div class="empty-body">${esc(body)}</div>`;

  if (reason === 'filtered' && Array.isArray(spec.filters) && spec.filters.length) {
    html += `<div class="empty-filters">${esc(t('empty.activeFilters'))} ${spec.filters.map((f) => `<code>${esc(f)}</code>`).join(' ')}</div>`;
  }
  if (reason === 'filtered' && spec.clearHref) {
    html += `<div class="empty-action"><a class="empty-clear" href="${esc(spec.clearHref)}">${esc(t('empty.clearFilters'))}</a></div>`;
  }
  if (action) html += `<div class="empty-action"><code>${esc(action)}</code></div>`;
  if (doc) html += `<div class="empty-doc">${esc(t('empty.setup'))} <code>${esc(doc)}</code></div>`;
  if (href && linkLabel) {
    html += `<div class="empty-cta"><a class="empty-link" href="${esc(href)}">${esc(linkLabel)}</a></div>`;
  }
  if (reason === 'error' && spec.retryKey) {
    html += `<div class="empty-action"><button type="button" class="btn-retry" data-empty-retry="${esc(spec.retryKey)}">${esc(spec.retryLabel || t('empty.retry'))}</button></div>`;
  }
  return `${html}</div>`;
}

/* ------------------------------------------------------------------ card ----
 * Accepts positional args (legacy, still used widely) or a single options
 * object. `valueHtml` is the only markup escape hatch and is opt-in by name.
 */
export function card(label, value, tone, delta, href) {
  const o = (label && typeof label === 'object') ? label : { label, value, tone, delta, href };
  const valueHtml = o.valueHtml ?? esc(o.value);
  const body = `<div class="label">${esc(o.label)}</div>`
    + `<div class="value${o.tone ? ` tone-${esc(o.tone)}` : ''}">${valueHtml}</div>`
    + (o.delta ?? '');
  const roleAttr = o.role ? ` role="${esc(o.role)}"` : '';
  return o.href
    ? `<a class="card card-link" href="${esc(o.href)}"${roleAttr}>${body}</a>`
    : `<div class="card"${roleAttr}>${body}</div>`;
}

export const skeletonCards = (n = 6) => Array.from({ length: n }, () => '<div class="skel"></div>').join('');

/* ----------------------------------------------------------------- table ----
 *
 * Caption is mandatory (degrades to a generated one rather than throw — a
 * thrown exception here blanks the view, which is AIM-475). Headers get
 * scope="col"; first non-numeric cell is scope="row". Sortable columns use a
 * real <button>. Drill-down via opts.drilldown sets role/tabindex/aria-label.
 *
 * Callers that already set role/tabindex via rowAttrs (Security drill-down)
 * keep working — drilldown is additive, not exclusive.
 */
export function table(el, cols, rows, opts = {}) {
  if (!el) return;
  el.innerHTML = tableHtml(cols, rows, opts);
  wireSort(el, opts);
}

/** String form for composers / unit tests without a DOM. */
export function tableHtml(cols, rows, opts = {}) {
  const caption = `<caption class="sr-only">${esc(opts.caption || fallbackCaption(cols))}</caption>`;
  if (!rows || rows.length === 0) {
    return caption + headHtml(cols, opts)
      + `<tbody><tr class="empty-row"><td colspan="${cols.length}">${emptyState(opts.empty)}</td></tr></tbody>`;
  }
  const body = rows.map((r) => rowHtml(r, cols, opts) + (opts.rowAfter ? opts.rowAfter(r) : '')).join('');
  return caption + headHtml(cols, opts) + `<tbody>${body}</tbody>`;
}

export function tableRowHtml(cols, row, opts = {}) {
  return rowHtml(row, cols, opts);
}

function fallbackCaption(cols) {
  const labels = (cols || []).map((c) => c.label).filter(Boolean).join(', ');
  return labels ? `Data table: ${labels}` : 'Data table';
}

function headHtml(cols, opts) {
  const sort = opts.sort || {};
  const cells = cols.map((c) => {
    const cls = c.num ? ' class="num"' : '';
    if (!c.sortable) return `<th scope="col"${cls}>${esc(c.label)}</th>`;
    const active = sort.key === c.key;
    const dir = active ? (sort.dir === 'desc' ? 'descending' : 'ascending') : 'none';
    return `<th scope="col" aria-sort="${dir}"${cls}>`
      + `<button type="button" class="th-sort${active ? ' is-sorted' : ''}" data-sort-key="${esc(c.key)}"`
      + ` aria-label="${esc(c.label)}, sort ${active && sort.dir !== 'desc' ? 'descending' : 'ascending'}">`
      + `${esc(c.label)}<span class="th-sort-caret" aria-hidden="true">${active ? (sort.dir === 'desc' ? '▾' : '▴') : '⇅'}</span>`
      + '</button></th>';
  }).join('');
  return `<thead><tr>${cells}</tr></thead>`;
}

function rowHtml(r, cols, opts) {
  const attrs = { ...(opts.rowAttrs ? opts.rowAttrs(r) : null) };
  let cls = opts.rowClass ? opts.rowClass(r) : '';

  if (opts.drilldown) {
    cls = `${cls} is-clickable`.trim();
    Object.assign(attrs, opts.drilldown.attrs ? opts.drilldown.attrs(r) : null, {
      role: 'button',
      tabindex: '0',
      'aria-label': opts.drilldown.label ? opts.drilldown.label(r) : 'Open detail',
    });
  }

  const attrStr = Object.entries(attrs)
    .filter(([, v]) => v != null && v !== '')
    .map(([k, v]) => `${k}="${esc(v)}"`)
    .join(' ');

  const cells = cols.map((c, i) => {
    const content = c.render ? c.render(r) : esc(r[c.key] ?? '');
    const numCls = c.num ? ' class="num"' : '';
    return i === 0 && !c.num
      ? `<th scope="row" class="rowhead">${content}</th>`
      : `<td${numCls}>${content}</td>`;
  }).join('');

  return `<tr${cls ? ` class="${esc(cls)}"` : ''}${attrStr ? ` ${attrStr}` : ''}>${cells}</tr>`;
}

const sortWired = new WeakSet();
function wireSort(el, opts) {
  if (!opts.onSort || sortWired.has(el)) return;
  sortWired.add(el);
  el.addEventListener('click', (e) => {
    const btn = e.target.closest?.('.th-sort');
    if (btn && el.contains(btn)) opts.onSort(btn.dataset.sortKey);
  });
}

/* Underscore aliases for views/* pre-rename imports (AIM-527 → AIM-782). */
export {
  card as _card,
  emptyState as _emptyState,
  skeletonCards as _skeletonCards,
};

export function installBanner(st) {
  const copy = installBannerCopy(st);
  const main = $('#main');
  if (!copy || !main || main.querySelector('.install-banner')) return;
  const el = document.createElement('div');
  el.className = 'banner warn install-banner';
  el.setAttribute('role', 'alert');
  const strong = document.createElement('strong');
  strong.textContent = copy.lead;
  const detail = document.createElement('span');
  detail.textContent = copy.detail;
  el.append(strong, detail);
  // AIM-591: same setup vocabulary as empty panels — doc path + in-app CTA.
  const doc = safeDocPath(copy.doc);
  if (doc) {
    const docEl = document.createElement('div');
    docEl.className = 'empty-doc';
    docEl.append('Setup: ');
    const code = document.createElement('code');
    code.textContent = doc;
    docEl.append(code);
    el.append(docEl);
  }
  const href = safeEmptyHref(copy.href);
  if (href && copy.linkLabel) {
    const wrap = document.createElement('div');
    wrap.className = 'empty-cta';
    const link = document.createElement('a');
    link.className = 'empty-link';
    link.href = href;
    link.textContent = copy.linkLabel;
    wrap.append(link);
    el.append(wrap);
  }
  main.prepend(el);
}

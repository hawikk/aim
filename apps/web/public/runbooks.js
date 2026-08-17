/* AIM-703 — SOC runbook pages for every alert class.
 *
 * Self-contained module (findings/rules pattern): injects nav tab, section,
 * stylesheet. Routable as `#/runbooks` and `#/runbooks/<slug>`.
 *
 * Gate: capabilities.findingsConsole (analyst+) — same tier as Findings and
 * the Alerts inbox. Runbooks are operational security content.
 *
 * Catalog + gap logic live in lib/runbooks.js (unit-tested, no DOM). This
 * module only renders and deep-links.
 */

import { registerModuleView, parseHash } from './lib/router.js';
import {
  listRunbooks,
  listRunbookGaps,
  resolveRunbook,
  runbookHash,
  FALLBACK_RUNBOOK,
} from './lib/runbooks.js';
import { esc } from './lib/dom.js';
import { moduleTab, moduleSection, announce } from './lib/a11y.js';
import { card, emptyState } from './lib/components.js';
import { severityBadge } from './lib/severity.js';
import { api } from './lib/api.js';

const me = await api('/api/me').catch((err) => {
  if (err.status === 401) window.location.assign('/auth/login');
  return null;
});
if (me?.capabilities?.findingsConsole) {
  init().catch((err) => console.error('runbooks viewer failed to start:', err));
}

function severityPill(sev) {
  return severityBadge(sev || 'low');
}

function gapsHtml(gaps) {
  const all = [...gaps.catalogGaps, ...gaps.liveGaps];
  if (!all.length) {
    return `<div class="rb-gaps ok" role="status">
      <strong>No runbook gaps</strong>
      <p>Every catalog entry has content, and every live guardrail rule maps to a page.</p>
    </div>`;
  }
  const rows = all
    .map(
      (g) => `<tr>
      <td>${severityBadge('medium', { label: g.kind, srLabel: false })}</td>
      <td><code>${esc(g.id)}</code></td>
      <td>${esc(g.detail)}</td>
      <td><a href="${esc(runbookHash(FALLBACK_RUNBOOK))}">fallback runbook →</a></td>
    </tr>`
    )
    .join('');
  return `<div class="rb-gaps bad" role="alert">
    <strong>${all.length} runbook gap${all.length === 1 ? '' : 's'}</strong>
    <p>Missing or unmapped alert classes fall back to <code>${esc(FALLBACK_RUNBOOK)}</code> until content is added. Do not treat these as “no runbook needed”.</p>
    <div class="table-wrap" tabindex="0" role="region" aria-label="Runbook gaps, scrollable">
      <table class="rb-table">
        <caption class="sr-only">Runbook coverage gaps by kind and id</caption>
        <thead><tr><th scope="col">Kind</th><th scope="col">Id</th><th scope="col">Detail</th><th scope="col">Link</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </div>`;
}

function indexHtml(gaps) {
  const items = listRunbooks()
    .map(
      (rb) => `<li>
      <a class="rb-card" href="${esc(runbookHash(rb.slug))}">
        <span class="rb-card-head">
          ${severityPill(rb.severity)}
          <span class="rb-card-title">${esc(rb.title)}</span>
          <code class="rb-slug">${esc(rb.slug)}</code>
        </span>
        <span class="rb-card-sum">${esc(rb.summary)}</span>
      </a>
    </li>`
    )
    .join('');
  return `
    <div class="cards" role="list" aria-label="Runbook coverage summary">
      ${card({ label: 'Runbook pages', value: String(listRunbooks().length), role: 'listitem' })}
      ${card({
        label: 'Gaps',
        value: String(gaps.catalogGaps.length + gaps.liveGaps.length),
        tone: gaps.ok ? 'good' : 'bad',
        role: 'listitem',
      })}
    </div>
    <div class="panel">
      <h2 id="rb-gaps-h">Coverage gaps</h2>
      <div id="rb-gaps-body" aria-labelledby="rb-gaps-h">${gapsHtml(gaps)}</div>
    </div>
    <div class="panel">
      <h2 id="rb-index-h">Alert-class runbooks <span class="hint">one page per taxonomy slug — deep-link from Findings, Rules, Alerts</span></h2>
      <ul class="rb-index" aria-labelledby="rb-index-h">${items}</ul>
    </div>`;
}

function detailHtml(slug) {
  const { runbook, known } = resolveRunbook(slug);
  const page = runbook;
  const resolvedSlug = resolveRunbook(slug).slug;
  const steps = (page.steps || [])
    .map((s, i) => `<li><span class="rb-step-n">${i + 1}</span><span>${esc(s)}</span></li>`)
    .join('');
  const rules = (page.relatedRules || [])
    .map((r) => `<li><code>${esc(r)}</code></li>`)
    .join('') || '<li class="faint">No engine rule ids mapped to this page</li>';
  const types = (page.relatedFindingTypes || [])
    .map((t) => `<li><code>${esc(t)}</code></li>`)
    .join('') || '<li class="faint">No finding types mapped to this page</li>';
  const unknownNote =
    !known || resolvedSlug === FALLBACK_RUNBOOK
      ? `<div class="banner warn" role="status">This is the fallback runbook. The requested class <code>${esc(slug || '—')}</code> is not a dedicated page — treat as a catalog gap and extend the taxonomy.</div>`
      : '';
  return `
    <p class="rb-back"><a href="${esc(runbookHash())}">← All runbooks</a></p>
    ${unknownNote}
    <article class="rb-detail" aria-labelledby="rb-detail-title">
      <header class="rb-detail-head">
        ${severityPill(page.severity)}
        <h2 id="rb-detail-title">${esc(page.title)}</h2>
        <code class="rb-slug">${esc(resolvedSlug)}</code>
      </header>
      <p class="rb-summary">${esc(page.summary)}</p>
      <div class="rb-when"><span class="rb-label">When it applies</span><p>${esc(page.when)}</p></div>
      <div class="rb-steps">
        <h3>Triage steps</h3>
        <ol>${steps}</ol>
      </div>
      <div class="rb-related">
        <div>
          <h3>Related rules</h3>
          <ul>${rules}</ul>
        </div>
        <div>
          <h3>Related finding types</h3>
          <ul>${types}</ul>
        </div>
      </div>
      <p class="rb-siem-hint">SIEM deep-link: set <code>RUNBOOK_BASE_URL</code> to this dashboard’s runbooks path so alert payloads open here — e.g. <code>https://&lt;host&gt;/#/runbooks/</code> + slug <code>${esc(resolvedSlug)}</code>.</p>
    </article>`;
}

async function init() {
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/runbooks.css';
  document.head.appendChild(link);

  moduleTab({
    view: 'runbooks',
    label: 'Runbooks',
    icon: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/><path d="M8 7h8"/><path d="M8 11h6"/></svg>',
  });

  const section = moduleSection({
    view: 'runbooks',
    html: `
    <div class="banner info">Operator runbooks for every guardrail alert class. Deep-link from Findings, Rules, and Alerts — missing mappings are listed as gaps, never as a silent blank page.</div>
    <div id="rb-body" aria-busy="true"></div>`,
  });
  document.querySelector('main').appendChild(section);
  const body = section.querySelector('#rb-body');

  async function load() {
    body.setAttribute('aria-busy', 'true');
    const { entity } = parseHash(location.hash);
    let liveRuleIds = null;
    try {
      const rulesPayload = await api('/api/guardrail/rules').catch(() => null);
      const rules = rulesPayload?.rules ?? rulesPayload;
      if (Array.isArray(rules)) liveRuleIds = rules.map((r) => r.id).filter(Boolean);
    } catch {
      /* gaps without live rules still show catalog integrity */
    }
    const gaps = listRunbookGaps(liveRuleIds);

    if (entity) {
      body.innerHTML = detailHtml(entity);
      const title = resolveRunbook(entity).runbook.title;
      announce(`Runbook: ${title}`);
    } else {
      body.innerHTML = indexHtml(gaps);
      announce(
        gaps.ok
          ? `Runbooks index — ${listRunbooks().length} pages, no gaps`
          : `Runbooks index — ${gaps.catalogGaps.length + gaps.liveGaps.length} gap(s)`
      );
    }
    body.setAttribute('aria-busy', 'false');
  }

  registerModuleView('runbooks', {
    onActivate: () =>
      load().catch((err) => {
        body.setAttribute('aria-busy', 'false');
        body.innerHTML =
          emptyState({
            reason: 'error',
            title: 'Runbooks failed to load',
            body: err.message,
          }) || `<div class="err" role="alert">${esc(err.message)}</div>`;
        announce(`Runbooks failed: ${err.message}`);
      }),
  });
}

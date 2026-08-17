/* Alerts inbox stack-health strip + pillar deep links (split).
 * Polls /api/stack/health, unlocks evidence links once gatewayHost is known,
 * and renders Related deep links from operator config. The strip reports
 * unreachability; it never takes the shell down. */

import { api } from '../lib/api.js';
import { esc } from '../lib/dom.js';
import { inboxCtx } from './state.js';
import { render } from './render.js';

const HEALTH_POLL_MS = 30_000;

function renderPillarLinks(services) {
  // Deep links only (D1): the shell points at related UIs, it does not
  // embed or rewrite them. Links come from operator config
  // (AIM_STACK_SERVICES ui fields); only https: URLs are rendered as hrefs.
  // label as "Related" rather than "Pillars" — CNAPP vocabulary.
  // shell deep-links only (D1). List destinations; entity hops live in lib/deeplinks.js.
  const links = ['<a href="#/overview">Dashboard</a>', '<a href="#/security">Security</a>', '<a href="#/findings">Findings</a>', '<a href="#/fleet">Fleet</a>'];
  for (const svc of services) {
    if (!svc.ui) continue;
    let url;
    try {
      url = new URL(svc.ui);
    } catch {
      continue;
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') continue;
    links.push(`<a href="${esc(url.href)}" target="_blank" rel="noopener noreferrer">${esc(svc.name)}</a>`);
  }
  inboxCtx.section.querySelector('#inbox-pillars').innerHTML =
    `<span class="hint">Related:</span> ${links.join(' · ')}`;
}

async function pollStackHealth(healthEl) {
  try {
    const h = await api('/api/stack/health');
    inboxCtx.gatewayHost = h.gatewayHost;
    healthEl.hidden = false;
    healthEl.innerHTML = h.services.map((s) => {
      const detail = s.status === 'ok' ? `${s.latencyMs}ms` : (s.detail ?? s.status);
      const dot = s.status === 'ok' ? 'ok' : (s.status === 'degraded' ? 'warn' : 'down');
      return `<span class="stack-svc" title="${esc(s.name)} — ${esc(s.status)} · ${esc(detail)}">` +
        `<span class="stack-dot ${dot}"></span>${esc(s.name)}</span>`;
    }).join('');
    healthEl.dataset.configured = String(h.configured);
    renderPillarLinks(h.services);
    render(); // evidence links unlock once gatewayHost is known
  } catch {
    // The strip reports unreachability; it never takes the shell down.
    healthEl.hidden = false;
    healthEl.innerHTML = '<span class="stack-svc" title="stack health endpoint unreachable"><span class="stack-dot down"></span>stack</span>';
  }
}

export function startStackHealth(healthEl) {
  pollStackHealth(healthEl);
  setInterval(() => {
    if (document.visibilityState === 'visible') pollStackHealth(healthEl);
  }, HEALTH_POLL_MS);
}

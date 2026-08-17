/* AIM-1168: first-party vendor admin feed strip + empty-state copy. */
import { esc } from './dom.js';

export function darkVendorFeeds(feeds) {
  return (feeds ?? []).filter((f) => f.status !== 'live');
}

export function liveVendorFeeds(feeds) {
  return (feeds ?? []).filter((f) => f.status === 'live');
}

export function vendorFeedEmpty(spec, feeds) {
  const dark = darkVendorFeeds(feeds);
  if (dark.length === 0) return spec;
  const names = dark.map((f) => f.label).join(', ');
  return {
    ...spec,
    body: `${spec.body} Dark vendor feeds: ${names}.`,
  };
}

export function vendorFeedBannerHtml(feeds) {
  const list = feeds ?? [];
  if (list.length === 0) return '';
  return list.map((f) => {
    const pill = f.status === 'live' ? 'ok' : 'warn';
    const extra = f.status === 'dark' && f.reason
      ? ` <span class="hint">${esc(f.reason)}</span>`
      : '';
    return `<span class="pill ${pill}">${esc(f.label)}: ${esc(f.status)}</span>${extra}`;
  }).join(' ');
}

export function renderVendorFeedBanner(el, feeds) {
  if (!el) return;
  const html = vendorFeedBannerHtml(feeds);
  if (!html) {
    el.hidden = true;
    el.innerHTML = '';
    return;
  }
  el.hidden = false;
  el.innerHTML = html;
}

/** Append Copilot org-daily rows that are not already in the tools inventory. */
export function mergeVendorTools(tools, feeds) {
  const have = new Set((tools ?? []).map((t) => t.tool));
  const extra = [];
  for (const f of liveVendorFeeds(feeds)) {
    if (f.id === 'copilot_metrics' && !have.has('github_copilot')) {
      extra.push({
        tool: 'github_copilot',
        sanctioned: false,
        users: f.activeUsers ?? 0,
        hosts: 0,
        sessions: f.sessions ?? 0,
        tokens: f.tokens ?? 0,
        costUsd: f.costUsd ?? 0,
        firstSeen: f.lastDay,
        lastSeen: f.lastDay,
        vendorAdmin: true,
      });
    }
  }
  return [...(tools ?? []), ...extra];
}

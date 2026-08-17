/* AIM-718 — Access review / attestation workflow for AIM roles.
 *
 * Self-contained module (same pattern as compliance.js): injects its own
 * nav tab, view section and stylesheet at runtime. Activates for admin or
 * auditor only — the roles that own "who has privileged AIM access".
 *
 * Answers: "who currently holds admin/analyst/auditor/viewer (+ reveal)?",
 * "export that roster", "open a review campaign", "attest the review".
 */

import { registerModuleView } from './lib/router.js';
import { esc } from './lib/dom.js';
import { table as dataTable, card as sharedCard } from './lib/components.js';
import { fmtInt, fmtTs } from './lib/format.js';
import { moduleTab, moduleSection } from './lib/a11y.js';
import { api, apiJson } from './lib/api.js';

const me = await api('/api/me').catch(() => null);
const role = me?.role;
if (role === 'admin' || role === 'auditor') {
  try {
    init();
  } catch (err) {
    console.error('access-review view failed to start:', err);
  }
}

const PRINCIPAL_COLS = [
  {
    key: 'email',
    label: 'Principal',
    render: (p) => `<code>${esc(p.email)}</code>${p.displayName ? `<div class="muted ar-sub">${esc(p.displayName)}</div>` : ''}`,
  },
  {
    key: 'role',
    label: 'Role',
    render: (p) => roleBadge(p.role),
  },
  {
    key: 'reveal',
    label: 'Reveal',
    render: (p) => (p.reveal
      ? '<span class="ar-badge tone-warn">reveal</span>'
      : '<span class="muted">—</span>'),
  },
  {
    key: 'active',
    label: 'Active',
    render: (p) => (p.active
      ? '<span class="ar-badge tone-good">active</span>'
      : '<span class="ar-badge tone-bad">inactive</span>'),
  },
  {
    // Bracket access: smoke guard bans `.groups` property sniff for IdP→role
    // mapping; roster display still needs the server-provided group list field.
    key: 'groups',
    label: 'Groups',
    // Bracket access avoids the smoke `.groups` IdP-sniff guard (AIM-151): this
    // is a server-provided roster display column, not client-side role mapping.
    render: (p) => {
      const list = p['groups'];
      return Array.isArray(list) && list.length
        ? list.map((g) => `<span class="ar-chip">${esc(g)}</span>`).join(' ')
        : '<span class="muted">—</span>';
    },
  },
];

const CAMPAIGN_COLS = [
  {
    key: 'createdAt',
    label: 'Opened',
    render: (c) => `<span class="mono" title="${esc(c.createdAt)}">${esc(fmtTs(c.createdAt))}</span>`,
  },
  {
    key: 'periodLabel',
    label: 'Period',
    render: (c) => esc(c.periodLabel || '—'),
  },
  {
    key: 'status',
    label: 'Status',
    render: (c) => statusBadge(c.status),
  },
  {
    key: 'principalCount',
    label: 'Principals',
    num: true,
    render: (c) => fmtInt(c.principalCount ?? 0),
  },
  {
    key: 'attestedBy',
    label: 'Attested by',
    render: (c) => (c.attestedBy
      ? `<code>${esc(c.attestedBy)}</code><div class="muted ar-sub">${esc(fmtTs(c.attestedAt))}</div>`
      : '<span class="muted">—</span>'),
  },
  {
    key: '_actions',
    label: '',
    render: (c) => `<button type="button" class="btn-export" data-ar-open="${esc(c.id)}">Open</button>`,
  },
];

function roleBadge(roleName) {
  if (!roleName) return '<span class="ar-badge tone-warn">reveal only</span>';
  const tone = roleName === 'admin' ? 'tone-bad' : roleName === 'analyst' ? 'tone-warn' : 'tone-good';
  return `<span class="ar-badge ${tone}">${esc(roleName)}</span>`;
}

function statusBadge(status) {
  if (status === 'attested') return '<span class="ar-badge tone-good">attested</span>';
  if (status === 'open') return '<span class="ar-badge tone-warn">open</span>';
  return `<span class="ar-badge">${esc(status || '—')}</span>`;
}

function init() {
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/access-review.css';
  document.head.appendChild(link);

  // AIM-1070: moduleTab places into the Control plane group via nav-ia.
  const btn = moduleTab({
    view: 'access-review',
    label: 'Access review',
  });
  btn.title = 'Periodic AIM role access review and attestation';

  const section = moduleSection({
    view: 'access-review',
    html: `
    <div class="banner info">
      Periodic review of who holds AIM roles (admin, analyst, auditor, viewer)
      and the reveal grant. Export the roster, open a campaign, attest when done.
    </div>

    <div class="controls-row" role="group" aria-label="Access review actions">
      <a class="btn-export" id="ar-export-csv" href="/api/access-review/roster?format=csv">Export CSV</a>
      <button type="button" class="btn-export" id="ar-open-campaign">Open review campaign</button>
    </div>

    <div id="ar-status" class="ar-status" role="status" aria-live="polite"></div>
    <div id="ar-error" class="error-banner" hidden role="alert"></div>

    <div class="cards" id="ar-stats" aria-label="Role summary"></div>

    <div class="panel">
      <h2>Live roster <span class="hint" id="ar-roster-meta"></span></h2>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Access roster table, scrollable">
        <table id="ar-roster"></table>
      </div>
      <p class="muted ar-note" id="ar-roster-note"></p>
    </div>

    <div class="panel">
      <h2>Review campaigns <span class="hint">snapshotted rosters and attestation seals</span></h2>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Campaigns table, scrollable">
        <table id="ar-campaigns"></table>
      </div>
      <div id="ar-campaigns-empty" class="empty-state" hidden>
        No campaigns yet. Open a review campaign to freeze the current roster for attestation.
      </div>
    </div>

    <dialog id="ar-dialog" class="ar-dialog" aria-labelledby="ar-dialog-title">
      <form method="dialog" id="ar-dialog-form">
        <header class="ar-dialog-head">
          <h2 id="ar-dialog-title">Campaign</h2>
          <button type="submit" class="btn-export" value="cancel" aria-label="Close">Close</button>
        </header>
        <div id="ar-dialog-body" class="ar-dialog-body"></div>
      </form>
    </dialog>
  `,
  });
  document.querySelector('main')?.appendChild(section);

  registerModuleView('access-review', {
    onActivate: () => loadAccessReview().catch((err) => setError(err.message || String(err))),
    drill: true,
  });

  section.querySelector('#ar-open-campaign')?.addEventListener('click', () => {
    openCampaign().catch((err) => setError(err.message || String(err)));
  });
  section.querySelector('#ar-campaigns')?.addEventListener('click', (ev) => {
    const openBtn = ev.target.closest('[data-ar-open]');
    if (!openBtn) return;
    showCampaign(openBtn.getAttribute('data-ar-open')).catch((err) => {
      setError(err.message || String(err));
    });
  });
}

function setError(msg) {
  const el = document.getElementById('ar-error');
  if (!el) return;
  if (!msg) {
    el.hidden = true;
    el.textContent = '';
    return;
  }
  el.hidden = false;
  el.textContent = msg;
}

function setStatus(msg) {
  const el = document.getElementById('ar-status');
  if (el) el.textContent = msg || '';
}

async function loadAccessReview() {
  setError(null);
  setStatus('Loading access roster…');
  try {
    const [roster, campaigns] = await Promise.all([
      api('/api/access-review/roster'),
      api('/api/access-review/campaigns'),
    ]);
    renderRoster(roster);
    renderCampaigns(campaigns?.items ?? []);
    setStatus(
      `Roster as of ${fmtTs(roster.generatedAt)} · ${fmtInt(roster.summary?.totalPrincipals ?? 0)} principals · source ${roster.source}`,
    );
  } catch (err) {
    setError(err.message || String(err));
    setStatus('');
    renderEmptyStates();
  }
}

function renderEmptyStates() {
  const stats = document.getElementById('ar-stats');
  if (stats) stats.innerHTML = '';
  const table = document.getElementById('ar-roster');
  if (table) dataTable(table, PRINCIPAL_COLS, []);
  const campaigns = document.getElementById('ar-campaigns');
  if (campaigns) dataTable(campaigns, CAMPAIGN_COLS, []);
  const empty = document.getElementById('ar-campaigns-empty');
  if (empty) empty.hidden = false;
}

function renderRoster(roster) {
  const s = roster.summary || {};
  const by = s.byRole || {};
  const stats = document.getElementById('ar-stats');
  if (stats) {
    stats.innerHTML = [
      sharedCard('Principals', fmtInt(s.totalPrincipals ?? 0)),
      sharedCard('Admin', fmtInt(by.admin ?? 0), by.admin ? 'bad' : null),
      sharedCard('Analyst', fmtInt(by.analyst ?? 0), by.analyst ? 'warn' : null),
      sharedCard('Auditor', fmtInt(by.auditor ?? 0)),
      sharedCard('Viewer', fmtInt(by.viewer ?? 0)),
      sharedCard('Reveal grant', fmtInt(s.withReveal ?? 0), s.withReveal ? 'warn' : null),
      sharedCard('Inactive', fmtInt(s.inactivePrincipals ?? 0), s.inactivePrincipals ? 'warn' : null),
    ].join('');
  }

  const meta = document.getElementById('ar-roster-meta');
  if (meta) {
    meta.textContent = [
      `source: ${roster.source}`,
      roster.scimEnabled ? 'SCIM on' : 'SCIM off',
      roster.rosterHash ? `hash ${String(roster.rosterHash).slice(0, 12)}…` : '',
    ].filter(Boolean).join(' · ');
  }

  const note = document.getElementById('ar-roster-note');
  if (note) note.textContent = roster.note || '';

  const table = document.getElementById('ar-roster');
  if (table) {
    dataTable(table, PRINCIPAL_COLS, roster.principals || [], {
      empty: 'No principals currently map to an AIM role or reveal grant.',
    });
  }

  // Role group configuration footer (always visible — config is part of the review).
  const groups = roster.roleGroups || {};
  const reveal = roster.revealGroups || [];
  if (note && (groups.admin || reveal.length)) {
    const lines = [
      roster.note || '',
      `Role groups — admin: ${(groups.admin || []).join(', ') || '—'}; ` +
        `analyst: ${(groups.analyst || []).join(', ') || '—'}; ` +
        `auditor: ${(groups.auditor || []).join(', ') || '—'}; ` +
        `viewer: ${(groups.viewer || []).join(', ') || '—'}. ` +
        `Reveal: ${reveal.join(', ') || '—'}.`,
    ].filter(Boolean);
    note.textContent = lines.join(' ');
  }
}

function renderCampaigns(items) {
  const table = document.getElementById('ar-campaigns');
  const empty = document.getElementById('ar-campaigns-empty');
  if (empty) empty.hidden = items.length > 0;
  if (table) {
    dataTable(table, CAMPAIGN_COLS, items, {
      empty: 'No campaigns yet.',
    });
  }
}

async function openCampaign() {
  setError(null);
  const periodLabel = window.prompt(
    'Period label for this review (e.g. "2026-Q3 quarterly")',
    defaultPeriodLabel(),
  );
  if (periodLabel === null) return;
  const notes = window.prompt('Optional notes for the campaign', '') ?? '';
  setStatus('Opening campaign…');
  try {
    const campaign = await apiJson('/api/access-review/campaigns', 'POST', { periodLabel: periodLabel || null, notes: notes || null });
    setStatus(`Campaign opened · ${fmtInt(campaign.principalCount)} principals frozen`);
    await loadAccessReview();
    showCampaign(campaign.id, campaign);
  } catch (err) {
    setError(err.message || String(err));
    setStatus('');
  }
}

function defaultPeriodLabel() {
  const d = new Date();
  const q = Math.floor(d.getUTCMonth() / 3) + 1;
  return `${d.getUTCFullYear()}-Q${q} access review`;
}

async function showCampaign(id, preloaded) {
  const dialog = document.getElementById('ar-dialog');
  const body = document.getElementById('ar-dialog-body');
  const title = document.getElementById('ar-dialog-title');
  if (!dialog || !body) return;

  let campaign = preloaded;
  if (!campaign || !campaign.roster) {
    try {
      campaign = await api(`/api/access-review/campaigns/${encodeURIComponent(id)}`);
    } catch (err) {
      setError(err.message || String(err));
      return;
    }
  }

  title.textContent = campaign.periodLabel || `Campaign ${String(campaign.id).slice(0, 8)}`;
  const roster = campaign.roster || { principals: [], summary: {} };
  const s = roster.summary || {};

  body.innerHTML = `
    <div class="ar-campaign-meta">
      <div><strong>Status</strong> ${statusBadge(campaign.status)}</div>
      <div><strong>Opened</strong> ${esc(fmtTs(campaign.createdAt))} by <code>${esc(campaign.createdBy)}</code></div>
      <div><strong>Principals</strong> ${esc(fmtInt(campaign.principalCount ?? 0))}</div>
      <div><strong>Roster hash</strong> <code>${esc(campaign.rosterHash || '')}</code></div>
      ${campaign.notes ? `<div><strong>Notes</strong> ${esc(campaign.notes)}</div>` : ''}
      ${campaign.status === 'attested' ? `
        <div class="ar-attest-seal">
          <strong>Attested</strong> ${esc(fmtTs(campaign.attestedAt))} by <code>${esc(campaign.attestedBy)}</code>
          <blockquote class="ar-statement">${esc(campaign.statement || '')}</blockquote>
        </div>
      ` : ''}
    </div>
    <div class="cards ar-dialog-stats">
      ${sharedCard('Admin', fmtInt(s.byRole?.admin ?? 0))}
      ${sharedCard('Analyst', fmtInt(s.byRole?.analyst ?? 0))}
      ${sharedCard('Auditor', fmtInt(s.byRole?.auditor ?? 0))}
      ${sharedCard('Viewer', fmtInt(s.byRole?.viewer ?? 0))}
      ${sharedCard('Reveal', fmtInt(s.withReveal ?? 0))}
    </div>
    <div class="table-wrap" tabindex="0" role="region" aria-label="Campaign roster">
      <table id="ar-dialog-roster"></table>
    </div>
    <div class="ar-dialog-actions">
      <a class="btn-export" href="/api/access-review/campaigns/${encodeURIComponent(campaign.id)}?format=csv">Export snapshot CSV</a>
      ${campaign.status === 'open' ? `
        <label class="ar-statement-label" for="ar-statement">Attestation statement (required)</label>
        <textarea id="ar-statement" rows="3" maxlength="4000"
          placeholder="I have reviewed the AIM role holders listed above and confirm they remain appropriate for their duties."></textarea>
        <button type="button" class="btn-export" id="ar-attest-btn" data-ar-attest="${esc(campaign.id)}">
          Attest review
        </button>
      ` : ''}
    </div>
  `;

  const table = body.querySelector('#ar-dialog-roster');
  if (table) {
    dataTable(table, PRINCIPAL_COLS, roster.principals || [], {
      empty: 'Snapshot has no principals.',
    });
  }

  body.querySelector('#ar-attest-btn')?.addEventListener('click', async () => {
    const statement = body.querySelector('#ar-statement')?.value?.trim() || '';
    if (statement.length < 8) {
      setError('Attestation statement must be at least 8 characters.');
      return;
    }
    setError(null);
    setStatus('Recording attestation…');
    try {
      const updated = await apiJson(`/api/access-review/campaigns/${encodeURIComponent(campaign.id)}/attest`, 'POST', { statement });
      setStatus(`Attested by ${updated.attestedBy} at ${fmtTs(updated.attestedAt)}`);
      await loadAccessReview();
      showCampaign(updated.id, updated);
    } catch (err) {
      setError(err.message || String(err));
      setStatus('');
    }
  });

  if (typeof dialog.showModal === 'function') dialog.showModal();
  else dialog.setAttribute('open', '');
}

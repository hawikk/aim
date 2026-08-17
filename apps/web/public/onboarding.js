/* — Server first-run onboarding + enrollment-token minting.
 *
 * Self-contained module, same pattern as rules.js: injects its own nav tab,
 * view section and stylesheet at runtime, and activates for the admin
 * role only (capabilities.admin) — the same gate the API enforces.
 *
 * The view mints scoped enrollment tokens (name, optional expiry, optional max
 * enrollments), shows the exact copy-paste join command for an engineer ONCE
 * at mint time (the cleartext token is never retrievable again), lists existing
 * tokens with lifecycle status, and revokes them. Every mint/revoke is audited
 * server-side.
 *
 * First-run: when the server has no events and no enrolled devices, an admin
 * lands here instead of on empty charts (GET /api/onboarding/status). This
 * module loads last, so its landing wins the initial one — but only when the
 * operator landed without asking for a view; an explicit or shared
 * URL is a destination, not a suggestion. When we stand down, the nav tab
 * carries the warning marker instead.
 */
import { landedWithoutView, landOnView, registerModuleView } from './lib/router.js';
import { fmtInt, fmtDay, relTime } from './lib/format.js';
import { esc } from './lib/dom.js';
import { moduleTab, moduleSection, announce } from './lib/a11y.js';
import { table as dataTable, EMPTY } from './lib/components.js';
import { api } from './lib/api.js';

/* ---------- Gate: server-computed capability (same gate as the API) ----------
 * capabilities.admin is the admin gate. Minting is a
 * security-sensitive action; do not reintroduce client-side group sniffing. */
const me = await api('/api/me').catch((err) => {
  if (err.status === 401) window.location.assign('/auth/login');
  return null;
});
if (me?.capabilities?.admin) {
  init().catch((err) => console.error('onboarding view failed to start:', err));
}

const STATUS_PILL = { active: 'ok', revoked: 'muted', expired: 'warn', exhausted: 'warn' };

const TOKEN_COLS = [
  {
    key: 'name',
    label: 'Token',
    render: (tok) => `<b>${esc(tok.name)}</b><div class="ob-sub">prefix <code>${esc(tok.tokenPrefix)}…</code> · by ${esc(tok.createdBy)}</div>`,
  },
  {
    key: 'status',
    label: 'Status',
    render: (tok) => `<span class="pill ${STATUS_PILL[tok.status] ?? 'muted'}"><span class="sr-only">Status: </span>${esc(tok.status)}</span>`,
  },
  {
    key: 'scope',
    label: 'Scope',
    render: (tok) => esc([
      tok.maxEnrollments === null ? 'unlimited' : `${fmtInt(tok.enrollmentCount)}/${fmtInt(tok.maxEnrollments)} enrolled`,
      tok.expiresAt ? `expires ${fmtDay(tok.expiresAt)}` : 'no expiry',
    ].join(' · ')),
  },
  { key: 'createdAt', label: 'Created', render: (tok) => esc(fmtDay(tok.createdAt)) },
  { key: 'lastUsedAt', label: 'Last used', render: (tok) => esc(relTime(tok.lastUsedAt)) },
  {
    key: '_actions',
    label: 'Actions',
    render: (tok) => `<span class="ob-actions">${tok.status !== 'revoked'
      ? `<button type="button" class="btn btn-danger btn-sm" data-revoke="${esc(tok.id)}" data-token-name="${esc(tok.name)}">Revoke<span class="sr-only"> enrollment token ${esc(tok.name)}</span></button>`
      : `<span class="ob-sub">revoked ${esc(relTime(tok.revokedAt))}</span>`}</span>`,
  },
];

async function init() {
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/onboarding.css';
  document.head.appendChild(link);

  // Onboarding lives under Ops & health (collapsible), not leftmost permanent tab.
  /*: the warning badge was a bare "!" carrying its meaning in a `title`
   * alone. Titles are not reliably announced and never surface on touch or
   * keyboard focus, so the one persistent, cross-view signal that the stack is
   * running an insecure default enrollment token was invisible to a screen
   * reader user. The glyph is now decorative and the meaning is real text, which
   * also folds it into the tab's accessible name — "Onboarding, insecure default
   * enrollment token in use" — so it is heard from any view, as intended. */
  const btn = moduleTab({
    view: 'onboarding',
    label: 'Onboarding ',
    icon: '<svg class="ico" viewBox="0 0 16 16"><path d="M8 1.5v9M4.5 7L8 10.5 11.5 7" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M2.5 13.5h11" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
    extra: '<span id="ob-badge" class="ob-badge" hidden><span aria-hidden="true">!</span>'
      + '<span class="sr-only">Insecure default enrollment token in use</span></span>',
  });

  const section = moduleSection({ view: 'onboarding', html: `
    <div class="banner info">Onboard a collector without editing any env file. Mint a scoped enrollment token, then hand the shown command to an engineer — running it enrolls their device and it appears in Fleet coverage. Tokens are <b>enrollment-only</b> (they cannot send events), hashed at rest, and shown in full <b>only once</b>. Minting and revoking are audited.</div>
    <div class="ob-firstrun" id="ob-firstrun" role="status" aria-live="polite" hidden></div>
    <div class="panel">
      <h2>Mint an enrollment token</h2>
      <form id="ob-mint" class="ob-form" autocomplete="off">
        <label>Name <span class="hint">how you'll recognize it (e.g. "ring0 pilot")</span>
          <input type="text" id="ob-name" maxlength="80" required placeholder="ring0 pilot" /></label>
        <label>Expires in (days) <span class="hint">optional — blank = no expiry</span>
          <input type="number" id="ob-expiry" min="1" max="365" placeholder="30" /></label>
        <label>Max enrollments <span class="hint">optional — blank = unlimited</span>
          <input type="number" id="ob-max" min="1" max="100000" placeholder="50" /></label>
        <div class="ob-form-actions">
          <button type="submit" class="btn btn-primary" id="ob-mint-btn">Mint token</button>
          <span class="ob-err" id="ob-mint-err" role="alert"></span>
        </div>
      </form>
      <div id="ob-minted" class="ob-minted" hidden></div>
    </div>
    <div class="panel">
      <h2>Enrollment tokens <span class="hint">revoke to block new enrollments immediately — already-enrolled devices are unaffected</span></h2>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Enrollment tokens table, scrollable">
        <table id="ob-table" aria-busy="true"><caption class="sr-only">Enrollment tokens, with status, scope and revoke controls</caption></table>
      </div>
    </div>` });
  document.querySelector('main').appendChild(section);

  const mintForm = section.querySelector('#ob-mint');
  const mintErr = section.querySelector('#ob-mint-err');
  const mintedBox = section.querySelector('#ob-minted');
  const table = section.querySelector('#ob-table');
  const firstRunBox = section.querySelector('#ob-firstrun');

  // `#/onboarding` is a real route — the tab is an ordinary data-view
  // button handled by app.js, and route() calls this to render.
  registerModuleView('onboarding', { onActivate: () => loadTokens() });

  // Re-written on every render, so it has to be re-emitted each time.

    async function loadTokens() {
    try {
      const d = await api('/api/onboarding/tokens');
      dataTable(table, TOKEN_COLS, d.tokens, {
        caption: 'Enrollment tokens, their status, scope, and when each was last used to enrol a collector',
        empty: {
          ...EMPTY.onboardingTokens,
          reason: 'no-data',
        },
        rowAttrs: (tok) => ({ 'data-id': tok.id }),
      });
    } catch (err) {
      dataTable(table, TOKEN_COLS, [], {
        caption: 'Enrollment tokens — failed to load',
        empty: { reason: 'error', body: `The token list could not be loaded: ${err.message}. Existing tokens may still be active.` },
      });
      announce(`Enrollment tokens failed to load: ${err.message}`);
    } finally {
      table.setAttribute('aria-busy', 'false');
    }
  }

  /* Prefer the platform the operator is looking at, so Windows admins land on
   * Windows first rather than having to discover a second tab. */
  function preferredPlatformId(platforms) {
    const ids = new Set((platforms || []).map((p) => p.id));
    const ua = (navigator.userAgent || navigator.platform || '').toLowerCase();
    if (/win/.test(ua) && ids.has('windows')) return 'windows';
    if (/mac|darwin/.test(ua) && ids.has('linux')) return 'linux'; // macOS shares the python path
    if (ids.has('linux')) return 'linux';
    return platforms?.[0]?.id ?? null;
  }

  /* Platforms from the mint response, with a back-compat fallback when an
   * older API only returns `command` (earlier). */
  function platformsFromMint(d) {
    if (Array.isArray(d.platforms) && d.platforms.length) return d.platforms;
    return [{
      id: 'linux',
      label: 'Linux / macOS',
      command: d.command,
      hint: 'Run on the engineer machine. Enrolls, writes the device token, sends the first heartbeat.',
    }];
  }

  /* Render the one-time secret + copy-paste command after a successful mint.
   *
   * this is the single most consequential surface in the view — the
   * cleartext token is displayed exactly once and can never be retrieved again.
   * It used to appear silently below the fold with focus left on the (now
   * re-enabled) Mint button, so a keyboard or screen-reader operator got no
   * signal that the thing they cannot get back was now on screen. Focus moves
   * to the box itself rather than to its Copy button: the operator needs the
   * warning and the command read to them, not just the control at the end.
   *
   * Windows is a first-class tab next to Linux, not a footnote. The
   * same mint shows both self-enroll and Intune fleet commands, plus a
   * measured time-to-first-evidence bound from the API. */
  function renderMinted(d) {
    const platforms = platformsFromMint(d);
    const initialId = preferredPlatformId(platforms);
    const fe = d.firstEvidence || {};
    const feMinutes = fe.expectedMaxMinutes ?? 5;
    const feNote = fe.note
      || `Device should appear in Fleet within ${feMinutes} minutes (one heartbeat). First AI tool event is first evidence.`;

    mintedBox.hidden = false;
    mintedBox.setAttribute('role', 'group');
    mintedBox.setAttribute('aria-labelledby', 'ob-minted-h');
    mintedBox.tabIndex = -1;
    mintedBox.innerHTML = `
      <div class="ob-minted-head">
        <span class="pill ok">token minted</span>
        <span class="hint" id="ob-minted-h">Copy this now — the full token is shown only once and cannot be retrieved again.</span>
      </div>
      <div class="ob-platforms" role="tablist" aria-label="Enrollment platform">
        ${platforms.map((p) => `
          <button type="button" class="ob-plat-tab${p.id === initialId ? ' is-active' : ''}"
            role="tab" id="ob-tab-${esc(p.id)}" data-plat="${esc(p.id)}"
            aria-selected="${p.id === initialId ? 'true' : 'false'}"
            aria-controls="ob-plat-panel">${esc(p.label)}</button>`).join('')}
      </div>
      <div class="ob-plat-panel" id="ob-plat-panel" role="tabpanel" aria-labelledby="ob-tab-${esc(initialId)}">
        <p class="ob-plat-hint" id="ob-plat-hint"></p>
        <label class="ob-cmd-label" id="ob-cmd-label">Run this on the target machine
          <div class="ob-cmd">
            <code id="ob-cmd-text"></code>
            <button type="button" class="btn btn-sm" id="ob-copy"><span id="ob-copy-label">Copy</span><span class="sr-only"> enrollment command</span></button>
          </div>
        </label>
      </div>
      <div class="ob-ttfe" id="ob-ttfe" role="status">
        <b>Time to first evidence:</b> ${esc(feNote)}
        <a class="pseudo-link" href="#/fleet" data-view="fleet">Open Fleet to verify</a>
      </div>
      <div class="ob-future hint">Unified installer (coming soon): <code>${esc(d.futureCommand || '')}</code></div>
      <span class="sr-only" id="ob-copy-status" role="status"></span>`;

    const byId = Object.fromEntries(platforms.map((p) => [p.id, p]));
    let activeId = initialId;
    const cmdText = mintedBox.querySelector('#ob-cmd-text');
    const platHint = mintedBox.querySelector('#ob-plat-hint');
    const panel = mintedBox.querySelector('#ob-plat-panel');
    const copyBtn = mintedBox.querySelector('#ob-copy');
    const copyLabel = mintedBox.querySelector('#ob-copy-label');
    const copyStatus = mintedBox.querySelector('#ob-copy-status');

    function showPlatform(id) {
      const p = byId[id] || platforms[0];
      if (!p) return;
      activeId = p.id;
      cmdText.textContent = p.command;
      platHint.textContent = p.hint || '';
      panel.setAttribute('aria-labelledby', `ob-tab-${p.id}`);
      mintedBox.querySelectorAll('.ob-plat-tab').forEach((btn) => {
        const on = btn.dataset.plat === p.id;
        btn.classList.toggle('is-active', on);
        btn.setAttribute('aria-selected', on ? 'true' : 'false');
        btn.tabIndex = on ? 0 : -1;
      });
    }
    showPlatform(activeId);

    mintedBox.querySelector('.ob-platforms').addEventListener('click', (e) => {
      const tab = e.target.closest('[data-plat]');
      if (!tab) return;
      showPlatform(tab.dataset.plat);
      announce(`${byId[tab.dataset.plat]?.label || tab.dataset.plat} enrollment command shown.`);
    });
    // Arrow keys between platform tabs (roving tabindex).
    mintedBox.querySelector('.ob-platforms').addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft' && e.key !== 'Home' && e.key !== 'End') return;
      const tabs = [...mintedBox.querySelectorAll('.ob-plat-tab')];
      const i = tabs.findIndex((t) => t.dataset.plat === activeId);
      let next = i;
      if (e.key === 'ArrowRight') next = (i + 1) % tabs.length;
      if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length;
      if (e.key === 'Home') next = 0;
      if (e.key === 'End') next = tabs.length - 1;
      e.preventDefault();
      showPlatform(tabs[next].dataset.plat);
      tabs[next].focus();
    });

    copyBtn.addEventListener('click', async () => {
      const text = byId[activeId]?.command || d.command;
      try {
        await navigator.clipboard.writeText(text);
        // Retitle only the visible half so the sr-only suffix survives.
        copyLabel.textContent = 'Copied';
        copyStatus.textContent = `${byId[activeId]?.label || 'Enrollment'} command copied to clipboard.`;
        setTimeout(() => { copyLabel.textContent = 'Copy'; }, 1500);
      } catch {
        // Clipboard blocked (non-secure context) — select the text as fallback.
        const range = document.createRange();
        range.selectNodeContents(cmdText);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        copyStatus.textContent = 'Clipboard unavailable — the command is selected, copy it manually.';
      }
    });
    mintedBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    mintedBox.focus();
  }

  mintForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    mintErr.textContent = '';
    const name = section.querySelector('#ob-name').value.trim();
    const expiry = section.querySelector('#ob-expiry').value;
    const max = section.querySelector('#ob-max').value;
    const payload = { name };
    if (expiry) payload.expiresInDays = Number(expiry);
    if (max) payload.maxEnrollments = Number(max);
    const mintBtn = section.querySelector('#ob-mint-btn');
    mintBtn.disabled = true;
    try {
      const d = await api('/api/onboarding/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      mintForm.reset();
      announce(`Enrollment token "${name}" minted. The full token is shown once — copy it now.`);
      renderMinted(d);
      loadTokens();
      // Re-fetch: drops the first-run nudge now that a token exists, but keeps
      // the insecure-default warning up until ENROLL_TOKENS is actually cleared.
      refreshStatus();
    } catch (err) {
      mintErr.textContent = err.message; // 400 detail from the API lands here
    } finally {
      mintBtn.disabled = false;
    }
  });

  /* Revoking is destructive, so it stays two-step — but as an inline arm/confirm
   * rather than a native confirm() dialog. Same deliberate second action, and it
   * keeps the consequence visible next to the row it applies to instead of in a
   * browser-chrome modal that cannot be styled or made consistent across the
   * fleet's platforms. The armed state disarms itself after 4 s. */
  /*: arm/disarm swaps the button's *markup*, not its text. The label
   * carries an sr-only suffix naming the token, and the original textContent
   * round-trip flattened that span into visible text on disarm — the button
   * would silently grow to "Revoke enrollment token ring0 pilot" on screen.
   *
   * The consequence of arming used to live only in `title`, which is neither
   * announced reliably nor reachable by keyboard. It is now sr-only text inside
   * the button (so it is part of the accessible name the moment focus lands)
   * and an announcement, because arming is the last step before a destructive,
   * audited action. The 4 s auto-disarm is announced too: a screen reader user
   * who armed and then paused otherwise has no way to know the button quietly
   * went back to being safe. */
  const REVOKE_CONSEQUENCE = 'New enrollments with this token are blocked immediately. Already-enrolled devices keep working.';
  let armed = null;
  function disarm({ announceIt = false } = {}) {
    if (!armed) return;
    clearTimeout(armed.timer);
    armed.btn.innerHTML = armed.html;
    armed.btn.classList.remove('ob-armed');
    armed.btn.removeAttribute('title');
    const name = armed.btn.dataset.tokenName;
    armed = null;
    if (announceIt) announce(`Revoke of "${name}" not confirmed — the button reset to Revoke.`);
  }

  table.addEventListener('click', async (e) => {
    const revokeBtn = e.target.closest('[data-revoke]');
    if (!revokeBtn) { disarm(); return; }
    const name = revokeBtn.dataset.tokenName ?? revokeBtn.dataset.revoke;
    if (armed?.btn !== revokeBtn) {
      disarm();
      armed = { btn: revokeBtn, html: revokeBtn.innerHTML, timer: null };
      revokeBtn.innerHTML =
        `Confirm revoke<span class="sr-only"> of enrollment token ${esc(name)}. ${esc(REVOKE_CONSEQUENCE)} Activate again within 4 seconds to confirm.</span>`;
      revokeBtn.classList.add('ob-armed');
      revokeBtn.title = REVOKE_CONSEQUENCE;
      armed.timer = setTimeout(() => disarm({ announceIt: true }), 4000);
      announce(`Confirm revoke of "${name}"? ${REVOKE_CONSEQUENCE} Activate the button again to confirm.`);
      return;
    }
    disarm();
    revokeBtn.disabled = true;
    try {
      await api(`/api/onboarding/tokens/${encodeURIComponent(revokeBtn.dataset.revoke)}/revoke`, { method: 'POST' });
      announce(`Enrollment token "${name}" revoked.`);
      /* The row survives the reload but its button does not — it becomes a
       * "revoked Xm ago" note. Park focus on the table's scroll region rather
       * than letting the re-render drop it to <body>. */
      const hadFocus = table.contains(document.activeElement);
      await loadTokens();
      if (hadFocus) table.closest('.table-wrap')?.focus();
    } catch (err) {
      revokeBtn.disabled = false;
      revokeBtn.insertAdjacentHTML('afterend', `<span class="ob-err" role="alert">${esc(err.message)}</span>`);
    }
  });

  // Status banners: first-run nudge + legacy/insecure-token posture. The
  // insecure-default warning must persist even after a mint — minting a scoped
  // token does not clear ENROLL_TOKENS from the env — so this is re-rendered
  // from a fresh /status fetch after each mint, not blanket-hidden.
  function renderStatusBanners(status) {
    const banners = [];
    if (status.insecureDefaultToken) {
      // AC: dev-enroll-token-change-me must trigger a visible warning.
      banners.push(
        '<div class="banner danger"><b>Insecure default enrollment token in use.</b> ' +
        'The stack is running with the shipped <code>ENROLL_TOKENS=dev-enroll-token-change-me</code> default — ' +
        'anyone who reads the public compose file can enroll a device. Mint a scoped token below, hand that to engineers, ' +
        'then clear <code>ENROLL_TOKENS</code> in your environment and restart ingest.</div>'
      );
    } else if (status.legacyTokensPresent) {
      banners.push(
        '<div class="banner warn"><b>Legacy env enrollment token active.</b> ' +
        'A static <code>ENROLL_TOKENS</code> value is still accepted (deprecated). Prefer scoped, revocable, ' +
        'audited tokens minted here, then clear <code>ENROLL_TOKENS</code>.</div>'
      );
    }
    if (status.firstRun && status.canMint) {
      banners.push(
        '<div class="banner warn"><b>No AI usage yet.</b> No events and no enrolled devices — mint a token below and run the command on a collector to see it here.</div>'
      );
    }
    firstRunBox.innerHTML = banners.join('');
    firstRunBox.hidden = banners.length === 0;
    /*: the insecure-default warning used to be delivered by hijacking
     * the main area. It no longer overrides an explicit destination, so mark
     * the tab — a live security warning must stay visible from every view. */
    const badge = btn.querySelector('#ob-badge');
    if (badge) badge.hidden = !status.insecureDefaultToken;
  }

  async function refreshStatus() {
    try {
      const status = await api('/api/onboarding/status');
      renderStatusBanners(status);
      return status;
    } catch {
      /* status is a nicety; failing it must not break the tab. */
      return null;
    }
  }

  // First-run: land the admin here instead of on empty charts. Also land here
  // whenever there's a security warning to act on (insecure default token) —
  // but only if no view was requested in the URL. Stealing the main area from
  // an explicit destination is what stranded operators.
  const status = await refreshStatus();
  if (status && landedWithoutView() && ((status.firstRun && status.canMint) || status.insecureDefaultToken)) {
    landOnView('onboarding');
  }

  loadTokens(); // pre-warm so the first tab open is instant
}

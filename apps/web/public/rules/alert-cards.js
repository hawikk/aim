/* Alert destination cards — pure-moved from rules.js.
 *
 * The alert destinations panel: routing summary, one form card per
 * destination (webhook, Sentinel, Google Chat, email, Slack, PagerDuty), the
 * save-all toolbar with its Audit deep-link, and the escalation
 * ladder editor below (./escalation.js). HTML builders only — the load/save
 * and test-send handlers live in ./alerts-panel.js.
 *
 * Secrets stay env-managed and are never entered in this UI.
 */
import { esc } from '../lib/dom.js';
import { SEVERITIES, destinationRows, routingSummary, routeLabel } from '../lib/alert-routing.js';
import { auditHash, GUARDRAIL_ALERTS_UPDATE_ACTION } from '../lib/audit-filters.js';
import { emptyState } from '../lib/components.js';
import { escalationHtml } from './escalation.js';

function secretBadge(configured) {
  return configured
    ? '<span class="secret-badge ok">secret configured</span>'
    : '<span class="secret-badge missing">secret not configured</span>';
}

/*: each destination is an independent form. Marking it `role="group"`
 * named by its heading is what lets a screen reader user tell which "Enabled"
 * checkbox and which "Min severity" select they are on — there are three of
 * each on this panel and, before this, all six were unnamed duplicates.
 * The badge stays inside the heading visually but outside the group's
 * accessible name, so heading navigation reads "Webhook", not
 * "Webhook secret not configured". */
/* `extraActions` slots non-save controls (e.g. email Test send) into
 * the same actions row without inventing a second footer. */
function alertCard({ dest, title, secretConfigured, minSeverity, body, enabled, extraActions = '' }) {
  const h = `ac-h-${dest}`;
  const stateClass = enabled ? (secretConfigured ? 'is-enabled' : 'is-enabled is-secret-missing') : 'is-disabled';
  return `<div class="alert-card ${stateClass}" data-dest="${dest}" role="group" aria-labelledby="${h}">
    <h3><span id="${h}">${esc(title)}</span> ${secretBadge(secretConfigured)}</h3>
    ${body}
    ${minSeverity === null ? '' : `<label>Min severity <select class="ac-minsev">
      ${SEVERITIES.map((v) => `<option value="${v}"${v === minSeverity ? ' selected' : ''}>${v}</option>`).join('')}
    </select></label>`}
    <div class="ac-actions">
      <button type="button" class="rbtn primary" data-save-alerts="${dest}">Save ${esc(title)}</button>
      ${extraActions}
      <span class="ac-err" role="alert"></span>
      <span class="ac-ok" role="status"></span>
    </div>
  </div>`;
}

const enabledToggle = (on) =>
  `<label class="ac-toggle"><input type="checkbox" class="ac-enabled"${on ? ' checked' : ''} /> Enabled</label>`;

/*: panel summary so multi-destination routing is answerable without
 * reading the cards. Empty state is first-class — zero enabled destinations
 * is not "all clear", it is "findings stay local". */
function routingSummaryHtml(d) {
  const summary = routingSummary(d);
  if (summary.noneEnabled) {
    return `<div id="alert-routing-summary" class="alert-routing-summary" data-routing-state="empty">
      ${emptyState({
        reason: 'no-data',
        title: 'No alert destinations enabled',
        body: 'Every rule still records findings, but nothing is paged out. Enable one or more destinations below — a single rule fans out to every destination whose severity floor includes it. No JSON required.',
      })}
    </div>`;
  }
  const chips = summary.routes.filter((r) => r.enabled).map((r) => {
    const warn = r.secretConfigured ? '' : ' route-chip-warn';
    const secretNote = r.secretConfigured ? '' : ' · secret missing';
    return `<span class="route-chip${warn}" data-route-chip="${esc(r.id)}">${esc(routeLabel(r))}${esc(secretNote)}</span>`;
  }).join('');
  const secretWarn = summary.missingSecrets.length
    ? `<p class="alert-routing-warn" role="status">Enabled but secret not configured (engine fails closed): ${esc(summary.missingSecrets.map((r) => r.title).join(', '))}</p>`
    : '';
  return `<div id="alert-routing-summary" class="alert-routing-summary" data-routing-state="active" role="status"
      aria-label="Active alert routing for every rule">
    <div class="alert-routing-label">Active routes <span class="hint">each rule fans out to every route whose floor includes its severity</span></div>
    <div class="alert-routing-chips">${chips}</div>
    ${secretWarn}
  </div>`;
}

function destinationCardHtml(row) {
  if (!row) return '';
  if (row.id === 'webhook') {
    return alertCard({
      dest: 'webhook',
      title: row.title,
      secretConfigured: row.secretConfigured,
      minSeverity: row.minSeverity,
      enabled: row.enabled,
      body: `${enabledToggle(row.enabled)}
        <label>URL <input type="url" class="ac-url" value="${esc(row.url)}" placeholder="https://example.org/hook" autocomplete="off" /></label>`,
    });
  }
  if (row.id === 'sentinel') {
    return alertCard({
      dest: 'sentinel',
      title: row.title,
      secretConfigured: row.secretConfigured,
      minSeverity: null,
      enabled: row.enabled,
      body: `${enabledToggle(row.enabled)}
        <label>Workspace ID <input type="text" class="ac-workspace" value="${esc(row.workspaceId)}" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" autocomplete="off" /></label>
        <label>Log type <input type="text" class="ac-logtype" value="${esc(row.logType)}" autocomplete="off" /></label>`,
    });
  }
  if (row.id === 'googleChat') {
    return alertCard({
      dest: 'googleChat',
      title: row.title,
      secretConfigured: row.secretConfigured,
      minSeverity: row.minSeverity,
      enabled: row.enabled,
      body: `<p class="ac-hint">Company channel. Incoming-webhook URL is set via deployment env (<code>ALERT_GOOGLE_CHAT_WEBHOOK_URL</code>) — never entered here.</p>
        ${enabledToggle(row.enabled)}`,
    });
  }
  if (row.id === 'email') {
    return alertCard({
      dest: 'email',
      title: row.title,
      secretConfigured: row.secretConfigured,
      minSeverity: row.minSeverity,
      enabled: row.enabled,
      body: `<p class="ac-hint">SMTP is set via deployment env (<code>ALERT_EMAIL_SMTP_HOST</code>, <code>ALERT_EMAIL_FROM</code>) — never entered here. Recipients are non-secret routing.</p>
        ${enabledToggle(row.enabled)}
        <label>To <input type="text" class="ac-email-to" value="${esc(row.to ?? '')}" placeholder="soc@example.com, oncall@example.com" autocomplete="off" /></label>`,
      // Test send proves delivery without leaving Rules (no secrets in the request).
      extraActions: `<button type="button" class="rbtn" data-test-send="email"${row.secretConfigured ? '' : ' disabled title="SMTP env not configured — set ALERT_EMAIL_SMTP_HOST and ALERT_EMAIL_FROM first"'}>Test send</button>`,
    });
  }
  if (row.id === 'slack') {
    return alertCard({
      dest: 'slack',
      title: row.title,
      secretConfigured: row.secretConfigured,
      minSeverity: row.minSeverity,
      enabled: row.enabled,
      body: `<p class="ac-hint">SOC opt-in. Incoming-webhook URL is <code>ALERT_SLACK_WEBHOOK_URL</code> — never entered here. Feature flag <code>ALERT_SLACK_ENABLED</code> is already on (this card is hidden when off).</p>
        ${enabledToggle(row.enabled)}`,
    });
  }
  if (row.id === 'pagerduty') {
    return alertCard({
      dest: 'pagerduty',
      title: row.title,
      secretConfigured: row.secretConfigured,
      minSeverity: row.minSeverity,
      enabled: row.enabled,
      body: `<p class="ac-hint">Events API v2. Routing key is <code>ALERT_PAGERDUTY_ROUTING_KEY</code> — never entered here. Typical ladder end-stage after Slack/chat.</p>
        ${enabledToggle(row.enabled)}`,
    });
  }
  return '';
}

export function alertsHtml(d) {
  const rows = destinationRows(d);
  const cards = rows.map(destinationCardHtml).join('');
  const auditHref = auditHash({ action: GUARDRAIL_ALERTS_UPDATE_ACTION });
  return `${routingSummaryHtml(d)}
    <div class="alert-cards-toolbar">
      <button type="button" class="rbtn primary" data-save-all-alerts>Save all destinations</button>
      <a class="alert-audit-link" href="${esc(auditHref)}" data-alerts-audit-link>Destination config audit trail</a>
      <span class="ac-all-err" role="alert"></span>
      <span class="ac-all-ok" role="status"></span>
    </div>
    <div class="alert-cards" id="alert-cards-grid" aria-label="Alert destination forms">${cards}</div>
    ${escalationHtml(d)}`;
}

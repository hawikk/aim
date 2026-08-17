/* Alert destinations panel: load + save interactions (AIM-1147) — pure-moved
 * from rules.js.
 *
 * Owns everything that mutates /api/guardrail/alerts: the destination cards
 * (AIM-94/584 — per-card save and one-click save-all), the email Test send
 * (AIM-988), and the multi-stage escalation ladder editor (AIM-990). Applying
 * a fresh payload re-renders the cards and re-stamps the per-rule route chips
 * on the rules list, since routing is derived from the same destinations.
 *
 * Secrets stay env-managed: nothing here ever accepts or sends one.
 */
import { api } from '../lib/api.js';
import { announce, preservingFocus } from '../lib/a11y.js';
import { withBusy, showFieldError, clearFieldError } from '../lib/form.js';
import { emptyState } from '../lib/components.js';
import {
  destinationRows,
  readCardFields,
  payloadForDestination,
  payloadFromPanel,
  validateDestination,
  validatePanel,
} from '../lib/alert-routing.js';
import {
  blankPolicy,
  validatePolicies,
  readPoliciesFromPanel,
  payloadForPolicies,
} from '../lib/escalation-policies.js';
import { alertsHtml } from './alert-cards.js';
import { escalationHtml } from './escalation.js';
import { renderRules } from './rule-list.js';
import { rulesState } from './state.js';

function applyAlertsPayload(d, { flashDest, flashAll, flashEscalation } = {}) {
  const alertCards = rulesState.alertCards;
  rulesState.lastAlerts = d;
  alertCards.innerHTML = alertsHtml(d);
  alertCards.setAttribute('aria-busy', 'false');
  // Re-stamp per-rule route chips when destinations change without a full rules reload.
  if (rulesState.lastRules.length) renderRules();
  if (flashAll) {
    const ok = alertCards.querySelector('.ac-all-ok');
    if (ok) ok.textContent = 'All destinations saved';
  } else if (flashDest) {
    const ok = alertCards.querySelector(`[data-dest="${flashDest}"] .ac-ok`);
    if (ok) ok.textContent = 'Saved';
  }
  if (flashEscalation) {
    const ok = alertCards.querySelector('.esc-all-ok');
    if (ok) ok.textContent = 'Escalation policies saved';
  }
}

function renderEscalationFromPolicies(policies) {
  const alertCards = rulesState.alertCards;
  const panel = alertCards.querySelector('#escalation-policies');
  if (!panel) return;
  const lastAlerts = rulesState.lastAlerts;
  panel.outerHTML = escalationHtml({
    ...(lastAlerts || {}),
    alerts: { ...(lastAlerts?.alerts || {}), escalationPolicies: policies },
    features: { ...(lastAlerts?.features || {}), escalationPolicies: true },
  });
}

function collectEscalationPoliciesFromDom() {
  return readPoliciesFromPanel(rulesState.alertCards.querySelector('#escalation-policies'));
}

export async function loadAlerts(opts) {
  const alertCards = rulesState.alertCards;
  try {
    const d = await api('/api/guardrail/alerts');
    applyAlertsPayload(d, opts);
  } catch (err) {
    rulesState.lastAlerts = null;
    alertCards.setAttribute('aria-busy', 'false');
    alertCards.innerHTML = emptyState({
      reason: 'error',
      title: 'Could not load alert destinations',
      body: err.message,
    });
    announce(`Alert destinations failed to load: ${err.message}`);
  }
}

/* Validation failures land in the card's .ac-err and focus moves to the
 * offending field — lib/form.js showFieldError (AIM-1113). */
function showCardError(cardEl, errEl, result) {
  showFieldError(errEl, result.message, result.field ? cardEl.querySelector(`.${result.field}`) : null);
}

export function bindAlertsPanel() {
  const alertCards = rulesState.alertCards;

  alertCards.addEventListener('click', async (e) => {
    /* AIM-990: escalation policy editor */
    const addPolicyBtn = e.target.closest('[data-add-policy]');
    if (addPolicyBtn) {
      const policies = collectEscalationPoliciesFromDom();
      const n = policies.length + 1;
      policies.push(blankPolicy({
        id: policies.some((p) => p.id === 'soc-oncall') ? `soc-oncall-${n}` : 'soc-oncall',
      }));
      renderEscalationFromPolicies(policies);
      alertCards.querySelector('#esc-policy-list .esc-policy:last-of-type .esc-id')?.focus();
      announce('New escalation policy added. Configure stages and save.');
      return;
    }
    const removePolicyBtn = e.target.closest('[data-remove-policy]');
    if (removePolicyBtn) {
      const pidx = Number(removePolicyBtn.dataset.removePolicy);
      renderEscalationFromPolicies(collectEscalationPoliciesFromDom().filter((_, i) => i !== pidx));
      announce('Escalation policy removed. Save to persist.');
      alertCards.querySelector('[data-add-policy]')?.focus();
      return;
    }
    const addStageBtn = e.target.closest('[data-add-stage]');
    if (addStageBtn) {
      const pidx = Number(addStageBtn.dataset.addStage);
      const policies = collectEscalationPoliciesFromDom();
      const p = policies[pidx];
      if (!p) return;
      p.stages = [...(p.stages || []), { afterSeconds: 900, destinations: ['pagerduty'] }];
      renderEscalationFromPolicies(policies);
      alertCards.querySelector(`.esc-policy[data-policy-index="${pidx}"] .esc-stage:last-of-type .esc-after`)?.focus();
      announce(`Stage added to policy ${p.id || pidx}.`);
      return;
    }
    const removeStageBtn = e.target.closest('[data-remove-stage]');
    if (removeStageBtn) {
      const stageEl = removeStageBtn.closest('.esc-stage');
      const card = removeStageBtn.closest('.esc-policy');
      const pidx = Number(card?.dataset.policyIndex);
      const sidx = Number(stageEl?.dataset.stageIndex);
      if (!Number.isInteger(pidx) || !Number.isInteger(sidx) || sidx === 0) return;
      const policies = collectEscalationPoliciesFromDom();
      const p = policies[pidx];
      if (!p) return;
      p.stages = (p.stages || []).filter((_, i) => i !== sidx);
      if (!p.stages.length) p.stages = blankPolicy().stages.slice(0, 1);
      renderEscalationFromPolicies(policies);
      announce(`Stage ${sidx} removed.`);
      alertCards.querySelector(`.esc-policy[data-policy-index="${pidx}"] [data-add-stage]`)?.focus();
      return;
    }
    const saveEscBtn = e.target.closest('[data-save-escalation]');
    if (saveEscBtn) {
      const errEl = alertCards.querySelector('.esc-all-err');
      const okEl = alertCards.querySelector('.esc-all-ok');
      clearFieldError(errEl, okEl);
      const policies = collectEscalationPoliciesFromDom();
      if (policies.length) {
        const check = validatePolicies(policies);
        if (!check.ok) {
          const first = check.validations.find((v) => !v.ok);
          const msg = first?.errors?.[0] || 'Invalid escalation policy.';
          const badIdx = check.validations.findIndex((v) => !v.ok);
          showFieldError(errEl, msg, alertCards.querySelector(`.esc-policy[data-policy-index="${badIdx}"] .esc-id`));
          announce(`Cannot save escalation policies: ${msg}`);
          return;
        }
      }
      try {
        await withBusy(saveEscBtn, () => preservingFocus(alertCards, '[data-save-escalation]', async () => {
          const d = await api('/api/guardrail/alerts', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payloadForPolicies(policies)),
          });
          applyAlertsPayload(d, { flashEscalation: true });
        }));
        announce(policies.length
          ? `${policies.length} escalation polic${policies.length === 1 ? 'y' : 'ies'} saved.`
          : 'Escalation policies cleared.');
      } catch (err) {
        showFieldError(errEl, err.message);
        announce(`Escalation save failed: ${err.message}`);
      }
      return;
    }

    /* AIM-988: prove email delivery without leaving Rules. Body is destination
     * only — SMTP secrets stay server/env-side; never send host/password. */
    const testBtn = e.target.closest('[data-test-send]');
    if (testBtn) {
      const dest = testBtn.dataset.testSend;
      const cardEl = testBtn.closest('.alert-card');
      const errEl = cardEl.querySelector('.ac-err');
      const okEl = cardEl.querySelector('.ac-ok');
      clearFieldError(errEl, okEl);
      // withBusy swallows the click when a send is already in flight.
      await withBusy(testBtn, async () => {
        try {
          const d = await api('/api/guardrail/alerts/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ destination: dest }),
          });
          const okMsg = d?.message || d?.detail || `Test ${dest} sent`;
          if (okEl) okEl.textContent = okMsg;
          announce(`Test send succeeded: ${okMsg}`);
        } catch (err) {
          errEl.textContent = err.message;
          announce(`Test send failed: ${err.message}`);
        }
      }, {
        // Keep the button disabled while the destination secret is
        // unconfigured (same condition as the initial render).
        reenable: () => !(rulesState.lastAlerts
          && !destinationRows(rulesState.lastAlerts).find((r) => r.id === dest)?.secretConfigured),
      });
      return;
    }

    /* AIM-584: one click commits every destination card — multi-destination
     * edits without hand-assembling JSON or three separate saves. */
    const saveAllBtn = e.target.closest('[data-save-all-alerts]');
    if (saveAllBtn) {
      const errEl = alertCards.querySelector('.ac-all-err');
      const okEl = alertCards.querySelector('.ac-all-ok');
      clearFieldError(errEl, okEl);
      const panelCheck = validatePanel(alertCards);
      if (!panelCheck.ok) {
        errEl.textContent = panelCheck.message;
        const badCard = alertCards.querySelector(`[data-dest="${panelCheck.dest}"]`);
        if (badCard) showCardError(badCard, badCard.querySelector('.ac-err'), panelCheck);
        announce(`Cannot save destinations: ${panelCheck.message}`);
        return;
      }
      const payload = payloadFromPanel(alertCards);
      try {
        await withBusy(saveAllBtn, () => preservingFocus(alertCards, '[data-save-all-alerts]', async () => {
          const d = await api('/api/guardrail/alerts', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
          applyAlertsPayload(d, { flashAll: true });
        }));
        announce('All alert destinations saved.');
      } catch (err) {
        errEl.textContent = err.message;
      }
      return;
    }

    const saveBtn = e.target.closest('[data-save-alerts]');
    if (!saveBtn) return;
    const dest = saveBtn.dataset.saveAlerts;
    const cardEl = saveBtn.closest('.alert-card');
    const errEl = cardEl.querySelector('.ac-err');
    clearFieldError(errEl);
    const fields = readCardFields(dest, cardEl);
    const check = validateDestination(dest, fields);
    if (!check.ok) {
      showCardError(cardEl, errEl, check);
      announce(`Cannot save ${dest}: ${check.message}`);
      return;
    }
    const payload = payloadForDestination(dest, fields);
    const title = cardEl.querySelector('h3 span[id]')?.textContent ?? dest;
    try {
      /* AIM-515: the PUT response re-renders all three cards, so the Save button
       * the operator just pressed is destroyed and focus falls to <body>.
       * Restore it to the same card's Save button, and announce — the "Saved"
       * chip is a visual-only confirmation otherwise. */
      await withBusy(saveBtn, () => preservingFocus(alertCards, `[data-save-alerts="${CSS.escape(dest)}"]`, async () => {
        const d = await api('/api/guardrail/alerts', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        applyAlertsPayload(d, { flashDest: dest });
      }));
      announce(`${title} alert destination saved.`);
    } catch (err) {
      errEl.textContent = err.message; // 400 detail from the API lands here
    }
  });
}

/* AIM-987 / AIM-990 — multi-stage escalation policy helpers.
 *
 * GET/PUT /api/guardrail/alerts surfaces ladders as alerts.escalationPolicies.
 * Stages use engine destination ids (slack, pagerduty, google_chat, …).
 * Secrets stay env-managed. Pure module (optional DOM form reading).
 */

import { SEVERITIES, SEVERITY_RANK } from './alert-routing.js';

export const KNOWN_STAGE_DESTINATIONS = Object.freeze([
  'webhook', 'sentinel', 'bus', 'splunk_hec', 'syslog_cef',
  'google_chat', 'slack', 'pagerduty', 'email',
]);

export const STAGE_DEST_LABELS = Object.freeze({
  webhook: 'Webhook',
  sentinel: 'Microsoft Sentinel',
  bus: 'Alert bus',
  splunk_hec: 'Splunk HEC',
  syslog_cef: 'Syslog CEF',
  google_chat: 'Google Chat',
  slack: 'Slack',
  pagerduty: 'PagerDuty',
  email: 'Email',
});

export const STAGE_DESTINATIONS = Object.freeze(
  KNOWN_STAGE_DESTINATIONS.map((id) => ({ id, title: STAGE_DEST_LABELS[id] || id })),
);

export const PRIMARY_STAGE_DESTINATIONS = Object.freeze([
  'slack', 'pagerduty', 'google_chat', 'email', 'webhook',
]);

const KNOWN_SET = new Set(KNOWN_STAGE_DESTINATIONS);
const POLICY_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;

function clampNonNegInt(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

export function stageDestLabel(destId) {
  if (typeof destId !== 'string') return '—';
  return STAGE_DEST_LABELS[destId] ?? destId;
}

export function formatStageDelay(afterSeconds) {
  const s = clampNonNegInt(afterSeconds);
  if (s === 0) return 'immediate';
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  if (m < 60) return rem ? `${m}m ${rem}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const mRem = m % 60;
  if (mRem === 0 && rem === 0) return `${h}h`;
  if (rem === 0) return `${h}h ${mRem}m`;
  return `${h}h ${mRem}m ${rem}s`;
}

export function cumulativeDelaySeconds(stages, index) {
  if (!Array.isArray(stages) || index < 0) return 0;
  let total = 0;
  for (let i = 0; i <= index && i < stages.length; i++) {
    total += clampNonNegInt(stages[i].afterSeconds);
  }
  return total;
}

function normalizeStage(raw, index) {
  const s = raw && typeof raw === 'object' ? raw : {};
  let after = clampNonNegInt(s.afterSeconds);
  if (index === 0) after = 0;
  const destinations = Array.isArray(s.destinations)
    ? [...new Set(s.destinations.filter((d) => typeof d === 'string' && d.trim()).map((d) => d.trim()))]
    : [];
  return { afterSeconds: after, destinations };
}

export function normalizePolicy(raw) {
  const p = raw && typeof raw === 'object' ? raw : {};
  const id = typeof p.id === 'string' ? p.id.trim() : '';
  const minSeverity = SEVERITIES.includes(p.minSeverity) ? p.minSeverity : 'low';
  const ruleIds = Array.isArray(p.ruleIds)
    ? p.ruleIds.filter((r) => typeof r === 'string' && r.trim()).map((r) => r.trim())
    : [];
  const stages = Array.isArray(p.stages) ? p.stages.map((s, i) => normalizeStage(s, i)) : [];
  return { id, minSeverity, ruleIds, stages };
}

export function normalizeEscalationPolicies(payload) {
  const raw = payload?.alerts?.escalationPolicies;
  if (!Array.isArray(raw)) return [];
  return raw.map((p, idx) => {
    const n = normalizePolicy(p);
    if (!n.id) n.id = `policy-${idx + 1}`;
    return n;
  });
}

export const policiesFromPayload = normalizeEscalationPolicies;

export function validatePolicy(policy, opts = {}) {
  const p = normalizePolicy(policy);
  const errors = [];
  const warnings = [];
  if (!p.id) errors.push('Policy id is required.');
  else if (!POLICY_ID_RE.test(p.id)) {
    errors.push('Policy id must be 1–64 chars: letters, digits, . _ - (start with letter/digit).');
  }
  const known = opts.knownIds instanceof Set
    ? opts.knownIds
    : new Set(Array.isArray(opts.knownIds) ? opts.knownIds : []);
  if (p.id && known.has(p.id)) errors.push(`Duplicate policy id "${p.id}".`);
  if (!SEVERITIES.includes(p.minSeverity)) {
    errors.push(`minSeverity must be one of ${SEVERITIES.join(', ')}.`);
  }
  if (!p.stages.length) errors.push('At least one stage is required.');
  p.stages.forEach((stage, i) => {
    const where = `Stage ${i}`;
    if (i === 0 && stage.afterSeconds !== 0) {
      errors.push(`${where}: afterSeconds must be 0 (fires with the finding).`);
    }
    if (i > 0 && stage.afterSeconds === 0) {
      errors.push(`${where}: later stages need delay > 0 (use stage 0 for immediate).`);
    }
    if (i > 0 && (!Number.isFinite(stage.afterSeconds) || stage.afterSeconds < 0)) {
      errors.push(`${where}: afterSeconds must be a non-negative integer.`);
    }
    if (!stage.destinations.length) {
      errors.push(`${where}: at least one destination is required.`);
    } else {
      for (const d of stage.destinations) {
        if (!KNOWN_SET.has(d)) errors.push(`${where}: unknown destination "${d}".`);
      }
    }
  });
  return { ok: errors.length === 0, errors, warnings, policy: p };
}

export function validateEscalationPolicy(policy) {
  const v = validatePolicy(policy);
  return { ok: v.ok, errors: v.errors, warnings: v.warnings };
}

export function validatePolicies(policies) {
  const list = Array.isArray(policies) ? policies : [];
  const ids = list.map((p) => (typeof p?.id === 'string' ? p.id.trim() : ''));
  const validations = list.map((p, i) => {
    const others = new Set(ids.filter((id, j) => j !== i && id));
    return validatePolicy(p, { knownIds: others });
  });
  return {
    ok: validations.every((v) => v.ok),
    validations,
    policies: validations.map((v) => v.policy),
  };
}

export function escalationSummary(payload) {
  const policies = normalizeEscalationPolicies(payload);
  const { validations } = validatePolicies(policies);
  const invalidCount = validations.filter((v) => !v.ok).length;
  return {
    policies,
    validations,
    count: policies.length,
    noneConfigured: policies.length === 0,
    invalidCount,
    allValid: policies.length > 0 && invalidCount === 0,
  };
}

export function blankPolicy(overrides = {}) {
  return normalizePolicy({
    id: overrides.id ?? 'soc-oncall',
    minSeverity: overrides.minSeverity ?? 'high',
    ruleIds: overrides.ruleIds ?? [],
    stages: overrides.stages ?? [
      { afterSeconds: 0, destinations: ['slack'] },
      { afterSeconds: 900, destinations: ['pagerduty'] },
    ],
  });
}

export function secondsToMinutesField(seconds) {
  const n = Number(seconds);
  if (!Number.isFinite(n) || n <= 0) return '';
  if (n % 60 === 0) return String(n / 60);
  return String(Math.round((n / 60) * 1000) / 1000);
}

export function minutesFieldToSeconds(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return null;
  return Math.round(n * 60);
}

export function readPolicyFromCard(cardEl) {
  if (!cardEl) return blankPolicy({ id: '', stages: [] });
  const id = cardEl.querySelector('.esc-id')?.value?.trim() ?? '';
  const minSeverity = cardEl.querySelector('.esc-minsev')?.value ?? 'high';
  const ruleRaw = cardEl.querySelector('.esc-rule-ids')?.value ?? '';
  const ruleIds = ruleRaw.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
  const stageEls = [...cardEl.querySelectorAll('.esc-stage[data-stage-index]')];
  const stages = stageEls.map((el, i) => {
    let afterSeconds = 0;
    if (i > 0) {
      const afterInput = el.querySelector('.esc-after');
      if (afterInput) {
        const unit = afterInput.getAttribute('data-esc-unit') || 'seconds';
        if (unit === 'minutes') {
          const sec = minutesFieldToSeconds(afterInput.value);
          afterSeconds = sec == null ? 0 : sec;
        } else {
          afterSeconds = clampNonNegInt(afterInput.value);
        }
      }
    }
    const multi = el.querySelector('select.esc-dests');
    let destinations = [];
    if (multi) destinations = [...multi.selectedOptions].map((o) => o.value).filter(Boolean);
    else destinations = [...el.querySelectorAll('input.esc-dest:checked')].map((c) => c.value);
    return { afterSeconds, destinations };
  });
  return normalizePolicy({ id, minSeverity, ruleIds, stages });
}

export function readPoliciesFromPanel(panelEl) {
  if (!panelEl) return [];
  return [...panelEl.querySelectorAll('.esc-policy[data-editing], .esc-policy[data-policy-id]')]
    .map(readPolicyFromCard);
}

export function payloadForPolicies(policies) {
  const list = Array.isArray(policies) ? policies : [];
  return {
    escalationPolicies: list.map((raw) => {
      const p = normalizePolicy(raw);
      return {
        id: p.id,
        minSeverity: p.minSeverity,
        ruleIds: p.ruleIds,
        stages: p.stages.map((s) => ({
          afterSeconds: s.afterSeconds,
          destinations: [...s.destinations],
        })),
      };
    }),
  };
}

export function policyCoversSeverity(policy, severity) {
  const floor = SEVERITY_RANK[policy?.minSeverity ?? 'low'];
  const rank = SEVERITY_RANK[severity];
  if (floor === undefined || rank === undefined) return false;
  return rank <= floor;
}

// AIM-989 — first-login / JIT failure presentation for SSO HTML + JSON replies.
// Pure map: no Fastify deps so unit tests and auth.js share one source of truth.

export const JIT_RUNBOOK_PATH = 'docs/security/jit-provisioning-sla.md';

/**
 * Operator-facing copy for login failure error codes (AIM-720 / AIM-989).
 * Returns null fields where the caller should keep its generic defaults.
 *
 * @param {string} error
 * @param {string} [detail]
 * @returns {{
 *   title: string | null,
 *   detail: string | null,
 *   actionLabel: string | null,
 *   runbookHref: string | null,
 *   runbookLabel: string | null,
 *   runbookPath: string | null,
 * }}
 */
export function loginErrorPresentation(error, detail) {
  const code = String(error || '');
  if (code === 'jit_provision_failed') {
    return {
      title: 'First-login provisioning failed',
      detail:
        detail ||
        'Your identity provider accepted the sign-in, but AI Monitoring could not create or refresh your directory record (JIT). Retry once. If it fails again, contact your security admin with this error code.',
      actionLabel: 'Retry sign-in',
      runbookHref: null,
      runbookLabel: 'JIT provisioning runbook',
      runbookPath: JIT_RUNBOOK_PATH,
    };
  }
  if (code === 'scim_deprovisioned') {
    return {
      title: 'Account deactivated',
      detail:
        detail ||
        'Your account is marked inactive in the SCIM directory. JIT provisioning never re-activates leavers. Contact your identity admin if this is wrong.',
      actionLabel: 'Back to sign-in',
      runbookHref: null,
      runbookLabel: 'JIT / SCIM runbook',
      runbookPath: JIT_RUNBOOK_PATH,
    };
  }
  return {
    title: null,
    detail: detail || null,
    actionLabel: null,
    runbookHref: null,
    runbookLabel: null,
    runbookPath: null,
  };
}

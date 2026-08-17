// Just-in-time (JIT) user provisioning on first SSO login.
//
// When SCIM is configured and JIT is enabled, a successful OIDC/SAML login
// upserts the principal into the SCIM directory so:
//   * AIM_SCIM_ENFORCE=1 works without pre-pushing every user from the IdP
//   * Access review / directory inventory sees login-only users
//   * Provision latency and failures are audited (SLA + observability)
//
// Hard rules:
//   * Never re-activate a SCIM deprovisioned user (active=false). Login already
//     fails closed via scimBlocksIdentity; this module double-checks.
//   * Memory upsert is the request-path source of truth; DB persist is
//     best-effort async (same tables as SCIM routes) so Postgres cannot
//     breach the first-login SLA.

import { audit } from './audit.js';
import {
  normalizeEmail,
  isValidEmail,
  persistUser,
  scimDirectory,
} from './scim-store.js';

/** Default AIM-side SLA for in-process JIT (memory path). Documented in runbook. */
export const JIT_SLA_MS_DEFAULT = 1000;

/**
 * JIT is live only when SCIM is configured. Default ON; set AIM_JIT_PROVISIONING=0
 * to disable (SCIM push-only mode).
 */
export function isJitEnabled({
  scimEnabled = Boolean(
    process.env.AIM_SCIM_BEARER_TOKEN && String(process.env.AIM_SCIM_BEARER_TOKEN).length >= 16,
  ),
  env = process.env,
} = {}) {
  if (!scimEnabled) return false;
  const raw = env.AIM_JIT_PROVISIONING;
  if (raw == null || raw === '') return true;
  return raw !== '0' && String(raw).toLowerCase() !== 'false';
}

export function jitSlaMs(env = process.env) {
  const n = Number(env.AIM_JIT_SLA_MS ?? JIT_SLA_MS_DEFAULT);
  return Number.isFinite(n) && n > 0 ? n : JIT_SLA_MS_DEFAULT;
}

/**
 * Provision (or refresh) a SCIM directory user from verified SSO claims.
 * Safe to call on every login. Returns quickly; never throws for expected paths.
 */
export async function jitProvisionOnLogin(opts) {
  const started = performance.now();
  const directory = opts.directory ?? scimDirectory;
  const slaMs = opts.slaMs ?? jitSlaMs();
  const source = opts.source || 'sso';
  const idp = opts.idp ?? null;
  const email = normalizeEmail(opts.email);

  const finish = (partial) => {
    const durationMs = Math.round(performance.now() - started);
    const slaBreached = durationMs > slaMs;
    return {
      durationMs,
      slaBreached,
      userId: null,
      created: false,
      error: null,
      reason: null,
      ...partial,
    };
  };

  if (!isJitEnabled()) {
    return finish({ status: 'disabled', reason: 'jit_disabled_or_scim_off' });
  }

  if (!isValidEmail(email)) {
    const result = finish({
      status: 'failed',
      error: 'invalid_email',
      reason: 'email_invalid',
    });
    audit('system', 'identity.jit_provision_failed', 'jit/login', {
      error: result.error,
      source,
      idp,
      durationMs: result.durationMs,
    });
    return result;
  }

  const existing = directory.getUserByName(email);
  if (existing && existing.active === false) {
    const result = finish({
      status: 'blocked',
      userId: existing.id,
      reason: 'scim_deprovisioned',
    });
    audit(email, 'identity.jit_provision_failed', `jit/Users/${existing.id}`, {
      error: 'scim_deprovisioned',
      source,
      idp,
      durationMs: result.durationMs,
    });
    return result;
  }

  try {
    const created = !existing;
    const user = directory.upsertUser({
      id: existing?.id,
      userName: email,
      externalId: opts.externalId ?? existing?.externalId ?? null,
      displayName:
        opts.displayName != null
          ? String(opts.displayName)
          : existing?.displayName ?? null,
      active: true,
    });

    if (opts.db?.query) {
      void Promise.resolve()
        .then(() => persistUser(opts.db, user))
        .catch((err) => {
          opts.log?.warn?.(
            { err: err?.message || String(err), email, userId: user.id },
            'JIT user persist failed (memory only)',
          );
          audit(email, 'identity.jit_provision_failed', `jit/Users/${user.id}`, {
            error: 'persist_failed',
            detail: err?.message ? String(err.message).slice(0, 200) : 'persist_failed',
            source,
            idp,
            created,
          });
        });
    }

    const result = finish({
      status: created ? 'created' : 'refreshed',
      userId: user.id,
      created,
    });

    audit(
      email,
      created ? 'identity.user_provisioned' : 'identity.user_updated',
      `jit/Users/${user.id}`,
      {
        source: 'jit',
        loginSource: source,
        idp,
        active: true,
        externalId: user.externalId,
        durationMs: result.durationMs,
        slaMs,
        slaBreached: result.slaBreached,
      },
    );

    if (result.slaBreached) {
      audit(email, 'identity.jit_sla_breach', `jit/Users/${user.id}`, {
        durationMs: result.durationMs,
        slaMs,
        source,
        idp,
      });
      opts.log?.warn?.(
        {
          email,
          userId: user.id,
          durationMs: result.durationMs,
          slaMs,
        },
        'JIT provision exceeded SLA',
      );
    }

    return result;
  } catch (err) {
    const result = finish({
      status: 'failed',
      error: err?.message ? String(err.message).slice(0, 200) : 'jit_failed',
      reason: 'upsert_failed',
    });
    audit(email, 'identity.jit_provision_failed', 'jit/login', {
      error: result.error,
      source,
      idp,
      durationMs: result.durationMs,
      enforce: Boolean(opts.enforce),
    });
    opts.log?.warn?.(
      { err: result.error, email, durationMs: result.durationMs },
      'JIT provision failed',
    );
    return result;
  }
}

export function jitFailureBlocksLogin(result, { enforce = false } = {}) {
  if (!enforce) return false;
  if (!result) return false;
  if (result.status === 'created' || result.status === 'refreshed') return false;
  if (result.status === 'disabled') return false;
  if (result.status === 'blocked') return true;
  if (result.status === 'failed') return true;
  if (result.status === 'skipped') return false;
  return false;
}

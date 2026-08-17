/* AIM-215 — what "nothing on screen" actually means.
 *
 * A first-run operator cannot tell an empty dashboard from a broken pipeline,
 * and the dashboard's own copy pushed them toward the wrong reading: every
 * event-dependent empty state was phrased about the selected *range* ("in this
 * range", "widen the range"), which silently asserts that collection works and
 * only the window was wrong. On a fresh unified-stack install nothing is being
 * collected at any range, so that copy is false — and for the guardrail panels
 * it is worse than false. "Nothing triggered the policy detectors — that is the
 * good outcome" reads as a security assurance while zero telemetry is being
 * monitored.
 *
 * GET /api/onboarding/status returns `installState`, computed server-side from
 * all-time (not range-scoped) data. The three values are three different
 * operator actions:
 *
 *   no-collectors  nothing has ever enrolled; the install is unfinished.
 *   no-events      devices ARE enrolled and not one event ever landed. The
 *                  pipeline is broken, not idle. This is the silent-drop case.
 *   live           events exist, so an empty view really is about the range.
 *
 * These functions are pure and DOM-free so they can be tested directly; app.js
 * owns the rendering. `install` is null until the status call resolves and
 * stays null if it fails — every function here then returns the unmodified
 * designed copy, so a failed status call degrades to the previous behaviour
 * and never invents a claim about the install.
 */
import { fmtInt } from './format.js';

const DOC_ENROLLMENT = 'docs/deployment/enrollment-and-heartbeat.md';
const DOC_PIPELINE = 'docs/deployment/pipeline-liveness.md';

/* Rewrite an event-dependent empty state to say why it is really empty.
 * Returns `spec` unchanged whenever the designed range copy is the honest copy:
 * when the spec is not event-dependent (audit events exist with no collector at
 * all; Fleet is already device-scoped), or when install state is unknown. */
export function installEmpty(spec, install) {
  if (!spec?.needsEvents || !install) return spec;

  if (install.installState === 'no-collectors') {
    /* Deliberately not "no data in this range": on a fresh install the range is
     * irrelevant — every one of these panels is empty at every range. */
    return {
      title: 'Nothing is being collected yet',
      body: install.canMint
        ? 'No collector has enrolled, so no AI tool usage is being monitored at all. Mint an enrollment token on the Onboarding tab, then run the join command on a device.'
        : 'No collector has enrolled, so no AI tool usage is being monitored at all. Ask a security admin to mint an enrollment token and onboard a device.',
      doc: DOC_ENROLLMENT,
      href: install.canMint ? '#/onboarding' : '#/fleet',
      linkLabel: install.canMint ? 'Open Onboarding' : 'Open Fleet',
    };
  }

  if (install.installState === 'no-events') {
    /* The install looks finished and is not working. This must never read like
     * an idle-but-healthy pipeline. */
    const n = Number(install.deviceCount) || 0;
    return {
      title: 'Collectors enrolled, but no events have ever arrived',
      body: `${fmtInt(n)} collector${n === 1 ? ' has' : 's have'} enrolled and not one event has reached this server. That is a broken pipeline, not a quiet one — check the collector logs and that the device can reach ${install.ingestUrl || 'the ingest endpoint'}.`,
      action: 'aim status',
      doc: DOC_PIPELINE,
      href: '#/fleet',
      linkLabel: 'Open Fleet',
    };
  }

  /* live: the range really is the reason this panel is empty. Name the most
   * recent event so "widen the range" is a fact the operator can act on rather
   * than a guess. */
  const when = install.lastEventAt ? new Date(install.lastEventAt) : null;
  if (when && !Number.isNaN(when.getTime())) {
    const days = Math.floor((Date.now() - when.getTime()) / 86400000);
    const ago = days <= 0 ? 'today' : days === 1 ? '1 day ago' : `${fmtInt(days)} days ago`;
    return {
      ...spec,
      body: `${spec.body} Most recent event on this server: ${when.toISOString().slice(0, 10)} (${ago}).`,
    };
  }
  return spec;
}

/* Copy for the persistent install banner, or null when there is nothing to say.
 *
 * Per-panel copy alone is not enough: a view whose panels happen to be non-empty
 * (Fleet listing a device, Audit listing logins) shows no warning at all, so an
 * operator can wander a stack that is monitoring nothing and never meet the
 * message. The banner sits above every view until events actually arrive. */
export function installBannerCopy(install) {
  if (!install || install.installState === 'live') return null;

  if (install.installState === 'no-collectors') {
    return {
      lead: 'This server is not monitoring anything yet. ',
      detail: install.canMint
        ? 'No collector has enrolled. Every chart below is empty because nothing is being collected — not because usage is low. Mint an enrollment token on the Onboarding tab and run the join command on a device.'
        : 'No collector has enrolled. Every chart below is empty because nothing is being collected — not because usage is low. Ask a security admin to onboard a device.',
      doc: DOC_ENROLLMENT,
      href: install.canMint ? '#/onboarding' : '#/fleet',
      linkLabel: install.canMint ? 'Open Onboarding' : 'Open Fleet',
    };
  }

  if (install.installState === 'no-events') {
    const n = Number(install.deviceCount) || 0;
    return {
      lead: 'Collectors are enrolled but no events have ever arrived. ',
      detail: `${fmtInt(n)} collector${n === 1 ? '' : 's'} enrolled and nothing has reached this server, so the ingest path is broken rather than idle. Check the collector logs and that the device can reach ${install.ingestUrl || 'the ingest endpoint'}.`,
      doc: DOC_PIPELINE,
      href: '#/fleet',
      linkLabel: 'Open Fleet',
    };
  }

  /* An installState this build does not know about. Saying nothing would let a
   * future server value silently restore the empty-dashboard reading, so fall
   * back to the one claim that is true for every non-`live` state. */
  return {
    lead: 'This server has not collected any AI tool usage. ',
    detail: 'Every chart below is empty because nothing has been collected — not because usage is low.',
    doc: DOC_ENROLLMENT,
  };
}

/**
 * Zero-touch / MDM enroll admin runbook + install-health copy.
 *
 * Pure, DOM-free catalog so unit tests can lock wording without mounting the
 * Install health view. Surfaces Intune (Windows) and Jamf (macOS) admin paths
 * as metadata-only operational content — no secrets, no prompt text, no
 * per-user investigation copy.
 *
 * Privacy / works-council bar:
 *   - Device identity is a random on-device UUID (host_id), not a hardware
 *     fingerprint; never suggest collecting serials or user prompts for verify.
 *   - Describe package assignment, enroll, heartbeat, and first-usage metadata
 *     only. Do not ask operators to paste prompt content or session transcripts.
 *   - EU/works-council safe: no performance monitoring of individuals; fleet
 *     health is about collector presence and time-to-first-evidence.
 */

/** Repo-relative docs the console links to (never fetched by the browser). */
export const MDM_DOCS = Object.freeze({
  zeroTouch: 'docs/deployment/zero-touch-mdm-enroll.md',
  enrollment: 'docs/deployment/enrollment-and-heartbeat.md',
  rollout: 'docs/deployment/rollout-plan.md',
  intune: 'deploy/windows/intunewin/README.md',
  jamf: 'docs/deployment/jamf-macos.md',
  pipeline: 'docs/deployment/pipeline-liveness.md',
});

/**
 * Platform parity cards shown on Install health.
 * @typedef {{ id: string, platform: string, mdm: string, title: string, summary: string, steps: string[], verify: string, docs: string[] }} MdmPath
 */

/** @type {readonly MdmPath[]} */
export const MDM_ADMIN_PATHS = Object.freeze([
  {
    id: 'windows-intune',
    platform: 'Windows',
    mdm: 'Intune',
    title: 'Windows · Intune Win32 (zero-touch)',
    summary:
      'Assign the AIM collector as a required Win32 app to a device group. SYSTEM install enrolls with a ring enrollment token and heartbeats without a user running a join command.',
    steps: [
      'Mint a scoped enrollment token on Onboarding (ring capacity, short expiry preferred). Do not bake personal tokens into packages.',
      'Build the .intunewin from deploy/windows (see Intune packaging README). Secrets stay out of the package — inject enroll-token and events token via remediation or a secrets broker.',
      'Create the Win32 app: System context, detection on registry Version, supersedence for updates. Assign Required to the ring device group.',
      'Confirm Install health: device row appears after enroll; first heartbeat is first evidence for the per-device SLO (default ≤5 minutes).',
    ],
    verify:
      'Intune shows the app installed; Install health lists the hostname under Recent enrollments with SLO met (or pending inside the window) after the first heartbeat. Package assigned alone is not first evidence.',
    docs: [MDM_DOCS.intune, MDM_DOCS.zeroTouch, MDM_DOCS.enrollment],
  },
  {
    id: 'macos-jamf',
    platform: 'macOS',
    mdm: 'Jamf',
    title: 'macOS · Jamf Pro (zero-touch)',
    summary:
      'Same security bar as Intune: no secrets in the package, system LaunchDaemons for scan + health, managed config under /etc/aim-collector/, version detection via Extension Attribute.',
    steps: [
      'Mint a ring enrollment token on Onboarding — same token model as Windows; platforms share enroll protocol and Fleet coverage.',
      'Build the pkg with deploy/macos/jamf tooling; upload package + configuration profile + Extension Attribute to Jamf. Inject secrets via policy, not the pkg payload.',
      'Scope a ring-0 smart group; deploy as required. Prefer system enroll + LaunchDaemon heartbeat over per-user self-serve for fleet machines.',
      'Confirm Install health within one heartbeat interval after first boot/policy run. EA version match ≠ AIM enroll — check this view for the device row.',
    ],
    verify:
      'EA reports package version; launchctl shows system daemons loaded; Install health lists the Mac with first evidence (heartbeat). Uninstall policy must leave residue check clean.',
    docs: [MDM_DOCS.jamf, MDM_DOCS.zeroTouch, MDM_DOCS.rollout],
  },
  {
    id: 'linux-self-or-cm',
    platform: 'Linux',
    mdm: 'Config management / self-enroll',
    title: 'Linux · config management or self-enroll',
    summary:
      'Parity with Windows enroll protocol: same /v1/enroll + heartbeat, different packaging. Engineers use the Linux tab on Onboarding; fleets use deploy/linux/install.sh or golden-image first-boot.',
    steps: [
      'Mint an enrollment token on Onboarding; copy the Linux / macOS command (or hand the token to config management).',
      'For fleet hosts: run deploy/linux/install.sh (or image prepare + seal-for-clone) with enroll-token injected at first boot — never ship host_id or device_token in a golden image.',
      'For laptop pilots: engineer runs the one-line install from Onboarding; device appears in Fleet after the first heartbeat.',
      'WSL is a separate endpoint from the Windows host — enroll inside WSL with the Linux path if that distro must report.',
    ],
    verify:
      'Device row in Install health / Fleet with healthy heartbeat. Image clones must each get a unique host_id (seal before capture).',
    docs: [MDM_DOCS.enrollment, MDM_DOCS.zeroTouch, MDM_DOCS.rollout],
  },
]);

/**
 * Health states operators hit after MDM assign or self-enroll.
 * Keys align with install-health overall / device SLO vocabulary where possible.
 * @typedef {{ id: string, title: string, severity: 'info'|'warn'|'bad', body: string, next: string, href?: string, linkLabel?: string, doc?: string }} HealthCopy
 */

/** @type {Readonly<Record<string, HealthCopy>>} */
export const HEALTH_COPY = Object.freeze({
  never_configured: {
    id: 'never_configured',
    title: 'No collectors enrolled yet',
    severity: 'info',
    body:
      'Nothing has enrolled on this server. MDM package assignment alone does not count — the collector must complete /v1/enroll and send a heartbeat. Mint a token on Onboarding, or confirm Intune/Jamf is injecting the enrollment token and the install actually ran.',
    next: 'Open Onboarding to mint a token, or follow the zero-touch admin path for your MDM below.',
    href: '#/onboarding',
    linkLabel: 'Open Onboarding',
    doc: MDM_DOCS.zeroTouch,
  },
  missing_collector: {
    id: 'missing_collector',
    title: 'Package may be assigned, collector not reporting',
    severity: 'warn',
    body:
      'Endpoint tooling can show the app installed while AIM still has no enroll row. Common causes: enrollment token missing or expired, install ran without network to ingest, or host_id reused from an unsealed golden image (clones collapse into one device).',
    next: 'Check MDM install/remediation logs, token validity, and reachability of the ingest URL. Re-enroll after seal if clones share identity.',
    href: '#/fleet',
    linkLabel: 'Open Fleet',
    doc: MDM_DOCS.pipeline,
  },
  delayed_first_evidence: {
    id: 'delayed_first_evidence',
    title: 'Enrolled — waiting for first evidence',
    severity: 'warn',
    body:
      'The device enrolled but the first heartbeat (per-device first evidence) has not arrived yet. Inside the SLO window this is normal; the heartbeat interval defaults to five minutes. This is metadata liveness only — not AI usage content.',
    next: 'Wait one heartbeat cycle, then refresh. If still pending past the SLO, treat as a breach: collector process, network path, or device token storage failed.',
    href: '#/install-health',
    linkLabel: 'Refresh Install health',
    doc: MDM_DOCS.enrollment,
  },
  breached_no_evidence: {
    id: 'breached_no_evidence',
    title: 'Past SLO with no first evidence',
    severity: 'bad',
    body:
      'Enrollment crossed the time-to-first-evidence SLO without a heartbeat. Treat as a broken install path, not quiet usage. Users may still use AI tools — this product simply has no collector liveness from that host.',
    next: 'On the host: collector service/task running, device_token present, outbound HTTPS to ingest. In MDM: remediation re-run, secrets present. Do not request prompt or chat content to “verify”.',
    href: '#/fleet',
    linkLabel: 'Open Fleet',
    doc: MDM_DOCS.pipeline,
  },
  no_events_after_enroll: {
    id: 'no_events_after_enroll',
    title: 'Heartbeat OK, no AI usage events yet',
    severity: 'info',
    body:
      'First evidence for the per-device SLO is the heartbeat. Fleet first-usage is a separate metric: enrolled devices may legitimately send no AI tool events if no sanctioned tools ran. That is idle telemetry, not a failed install — unless every host stays silent after known tool use.',
    next: 'If tools are in use and still silent, check collector scan/hooks and the events ingest token (separate from the enrollment token).',
    href: '#/activity',
    linkLabel: 'Open Activity',
    doc: MDM_DOCS.enrollment,
  },
});

/** Privacy footer shared by the in-product runbook surface. */
export const PRIVACY_FOOTER =
  'Metadata only: host identity is a random UUID generated on device (not a serial or TPM id). ' +
  'This view never shows prompts, completions, or file contents. EU / works-council posture: fleet ' +
  'install health measures collector presence and latency — not how much any person uses AI tools.';

/**
 * Map install-health API shape → health copy for the admin callout.
 * @param {{ overall?: string, summary?: { enrolled?: number, pending?: number, breached?: number, met?: number }, devices?: Array<{ state?: string }> }} data
 * @returns {HealthCopy}
 */
export function healthCopyForInstall(data) {
  const overall = data?.overall || '';
  const enrolled = Number(data?.summary?.enrolled) || 0;
  const devices = Array.isArray(data?.devices) ? data.devices : [];
  const breached = devices.filter((d) => d.state === 'breached').length
    || Number(data?.summary?.breached) || 0;
  const pending = devices.filter((d) => d.state === 'pending').length
    || Number(data?.summary?.pending) || 0;

  if (overall === 'never_configured' || enrolled === 0) {
    return HEALTH_COPY.never_configured;
  }
  if (breached > 0 || overall === 'broken') {
    return HEALTH_COPY.breached_no_evidence;
  }
  if (pending > 0 || overall === 'degraded') {
    return HEALTH_COPY.delayed_first_evidence;
  }
  // Enrolled and SLO green — still offer the “heartbeat ≠ usage events” nuance
  // so operators do not escalate idle fleets as install failures.
  return HEALTH_COPY.no_events_after_enroll;
}

/**
 * Empty-state body for the Recent enrollments table.
 * @param {{ enrolled?: number, lookbackDays?: number, canMint?: boolean }} opts
 */
export function enrollmentsEmptyCopy(opts = {}) {
  const lookback = opts.lookbackDays ?? 7;
  if (opts.enrolled) {
    return {
      reason: 'filtered',
      title: 'No enrollments in the lookback window',
      body:
        `Nothing enrolled in the last ${lookback} day${lookback === 1 ? '' : 's'}. ` +
        'Older devices still count toward fleet first-event latency above. ' +
        'New zero-touch devices appear here after MDM install completes enroll + first heartbeat.',
    };
  }
  return {
    reason: 'no-collector',
    title: 'No enrolled devices',
    body: opts.canMint !== false
      ? 'No collector has enrolled. For a single device, mint a token on Onboarding and use the Linux or Windows tab. For fleet zero-touch, assign the Intune Win32 or Jamf package with a ring enrollment token — then return here for first-evidence SLO.'
      : 'No collector has enrolled. Ask a security admin to mint an enrollment token or assign the Intune/Jamf collector package. This view stays empty until enroll succeeds.',
    href: opts.canMint !== false ? '#/onboarding' : '#/fleet',
    linkLabel: opts.canMint !== false ? 'Open Onboarding' : 'Open Fleet',
    doc: MDM_DOCS.zeroTouch,
  };
}

/** @returns {readonly MdmPath[]} */
export function listMdmAdminPaths() {
  return MDM_ADMIN_PATHS;
}

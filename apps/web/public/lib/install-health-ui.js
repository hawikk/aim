/* AIM-928 / AIM-933 — pure helpers for Install health UI
 * (cohorts + empty/recovery copy).
 *
 * Keeps enroll → first-evidence presentation consistent:
 *   - OS family for Windows / Linux / macOS parity cues
 *   - Cohort rollups with RAG SLO state (met / pending / breached)
 *   - Empty + recovery copy for missing collector, delayed first event,
 *     and zero-touch MDM (Intune / Jamf-ready) paths
 *
 * Admin step-by-step MDM paths live in mdm-enroll-runbook.js (AIM-933).
 * Metadata-only: no tokens, secrets, prompts, or event content.
 *
 * Doc paths are string constants (not components.js imports) so pure unit
 * tests stay free of the components module graph.
 */

const DOC_ENROLLMENT = 'docs/deployment/enrollment-and-heartbeat.md';
const DOC_PIPELINE = 'docs/deployment/pipeline-liveness.md';
const DOC_ZERO_TOUCH = 'docs/deployment/zero-touch-mdm-enroll.md';

export const OS_FAMILIES = Object.freeze(['windows', 'linux', 'darwin', 'other']);

export const OS_FAMILY_LABEL = Object.freeze({
  windows: 'Windows',
  linux: 'Linux',
  darwin: 'macOS',
  other: 'Other / unknown',
});

/** Map device.os strings from collectors / fixtures to a stable family key. */
export function osFamily(os) {
  const s = String(os ?? '').trim().toLowerCase();
  if (!s) return 'other';
  if (s === 'windows' || s.startsWith('win') || s.includes('windows')) return 'windows';
  if (s === 'darwin' || s === 'macos' || s === 'mac os' || s.includes('darwin') || s.includes('mac')) {
    return 'darwin';
  }
  if (
    s === 'linux'
    || s.includes('linux')
    || s.includes('ubuntu')
    || s.includes('debian')
    || s.includes('rhel')
    || s.includes('centos')
    || s.includes('fedora')
    || s.includes('amzn')
  ) {
    return 'linux';
  }
  return 'other';
}

/**
 * RAG tone for a device/cohort SLO state.
 * Text labels always accompany colour (met / pending / breached).
 * @returns {'ok'|'warn'|'bad'|'muted'}
 */
export function sloTone(state) {
  if (state === 'met' || state === 'ok') return 'ok';
  if (state === 'pending' || state === 'degraded') return 'warn';
  if (state === 'breached' || state === 'broken') return 'bad';
  if (state === 'never_configured') return 'muted';
  return 'muted';
}

/**
 * RAG tone for a measured latency vs SLO target.
 * null latency uses device state (pending=amber, breached=red).
 */
export function latencyTone(latencySec, sloSec, state) {
  if (state === 'breached' || state === 'broken') return 'bad';
  if (state === 'pending' || state === 'degraded') return 'warn';
  if (latencySec == null || sloSec == null || sloSec <= 0) {
    return state === 'met' || state === 'ok' ? 'ok' : 'muted';
  }
  if (latencySec > sloSec) return 'bad';
  // Amber band: over half the SLO but still inside target.
  if (latencySec > sloSec * 0.5) return 'warn';
  return 'ok';
}

function percentile(sorted, p) {
  if (!sorted.length) return null;
  if (sorted.length === 1) return sorted[0];
  const idx = (sorted.length - 1) * p;
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  if (lo === hi) return sorted[lo];
  const w = idx - lo;
  return Math.round(sorted[lo] * (1 - w) + sorted[hi] * w);
}

/**
 * Cohort time-to-first-evidence by OS family.
 * Worst device state wins for the cohort RAG badge.
 *
 * @param {Array<object>} devices  classified devices from GET /api/install-health
 * @param {number} [sloSec=300]
 * @returns {Array<object>} one row per family that has ≥1 device, Windows first
 */
export function cohortByOs(devices = [], sloSec = 300) {
  const buckets = Object.fromEntries(OS_FAMILIES.map((f) => [f, {
    family: f,
    label: OS_FAMILY_LABEL[f],
    enrolled: 0,
    met: 0,
    pending: 0,
    breached: 0,
    latencies: [],
  }]));

  for (const d of devices) {
    const f = osFamily(d.os);
    const b = buckets[f];
    b.enrolled += 1;
    if (d.state === 'met') {
      b.met += 1;
      if (d.latency_seconds != null) b.latencies.push(Number(d.latency_seconds));
    } else if (d.state === 'pending') {
      b.pending += 1;
    } else if (d.state === 'breached') {
      b.breached += 1;
    }
  }

  const rank = { breached: 0, pending: 1, met: 2, ok: 2 };
  const order = { windows: 0, linux: 1, darwin: 2, other: 3 };

  return OS_FAMILIES
    .map((f) => buckets[f])
    .filter((b) => b.enrolled > 0)
    .map((b) => {
      b.latencies.sort((a, c) => a - c);
      const p50 = percentile(b.latencies, 0.5);
      const p95 = percentile(b.latencies, 0.95);
      let state = 'met';
      if (b.breached > 0) state = 'breached';
      else if (b.pending > 0) state = 'pending';
      else if (p95 != null && p95 > sloSec) state = 'degraded';
      return {
        family: b.family,
        label: b.label,
        enrolled: b.enrolled,
        met: b.met,
        pending: b.pending,
        breached: b.breached,
        p50Seconds: p50,
        p95Seconds: p95,
        state,
        tone: sloTone(state),
        latencyTone: latencyTone(p95 ?? p50, sloSec, state),
      };
    })
    .sort((a, b) => {
      const ra = rank[a.state] ?? 9;
      const rb = rank[b.state] ?? 9;
      if (ra !== rb) return ra - rb;
      return (order[a.family] ?? 9) - (order[b.family] ?? 9);
    });
}

/**
 * Empty-state specs for the recent-enrollments table.
 * Distinguishes never-configured (MDM recovery) vs lookback filter.
 *
 * @param {{ enrolled?: number, lookbackDays?: number }} summary
 */
export function devicesEmptySpec(summary = {}) {
  const lookback = summary.lookbackDays ?? 7;
  if (summary.enrolled) {
    return {
      reason: 'filtered',
      title: 'No enrollments in the lookback window',
      body: `Nothing enrolled in the last ${lookback} day${lookback === 1 ? '' : 's'}. Older devices still count toward fleet first-event latency and OS cohorts above. Expand MDM waves or check that Intune/Jamf packages report enroll.`,
      href: '#/onboarding',
      linkLabel: 'Open Onboarding',
      doc: DOC_ZERO_TOUCH,
    };
  }
  return {
    reason: 'no-collector',
    title: 'No enrolled devices — first-evidence SLO is undefined',
    body: 'Zero-touch path: mint a token on Onboarding, then push the Linux join command or the Windows fleet (Intune) package. Jamf Pro uses the macOS system package path (see Zero-touch / MDM admin path on this page). Devices appear here after enroll; first heartbeat is first evidence (default ≤ 5 minutes). MDM “Installed” alone is not enroll.',
    action: 'aim join <ingest-url> --token <enrollment-token>',
    href: '#/onboarding',
    linkLabel: 'Open Onboarding (Linux · Windows · Intune)',
    doc: DOC_ZERO_TOUCH,
  };
}

/**
 * Empty-state for SLO breach alert candidates.
 */
export function alertsEmptySpec({ enrolled = 0 } = {}) {
  if (!enrolled) {
    return {
      reason: 'no-collector',
      title: 'No breach alerts — nothing enrolled yet',
      body: 'Alerts fire when a device is past the enroll → first-evidence SLO with no heartbeat. Enroll a collector first (self-enroll or Intune/Jamf fleet package).',
      href: '#/onboarding',
      linkLabel: 'Open Onboarding',
      doc: DOC_ENROLLMENT,
    };
  }
  return {
    reason: 'no-data',
    title: 'No breach alerts',
    body: 'Every recent enrollment is inside the SLO (or still waiting inside the window). Delayed first evidence shows as amber pending on the device row until the target is missed.',
  };
}

/**
 * Recovery / delayed-evidence panel copy (not an empty table — ops next steps).
 * Returns null when nothing needs recovery guidance.
 *
 * @param {{ overall?: string, summary?: object, slo?: object }} data
 */
export function recoveryCopy(data = {}) {
  const summary = data.summary || {};
  const sloText = data.slo?.text || 'enroll → first evidence ≤ 5m';
  const enrolled = summary.enrolled ?? 0;
  const pending = summary.pending ?? 0;
  const breached = summary.breached ?? 0;
  const fleet = summary.fleetFirstEvent || {};
  const hasFleetEvent = fleet.first_event_at != null;

  if (enrolled === 0 || data.overall === 'never_configured') {
    return {
      tone: 'info',
      title: 'Missing collector — enroll has not started',
      body: 'No device has joined this server. Use Onboarding for self-enroll (Linux / macOS / Windows) or zero-touch fleet packaging (Windows Intune Win32; Jamf Pro system package for Mac). Metadata only — tokens are shown once at mint and never here. See the Zero-touch / MDM admin path panel on this page.',
      steps: [
        'Mint an enrollment token on Onboarding (admin).',
        'Deploy via Intune (Windows fleet tab), Jamf (macOS system package), or Linux config-management / self-enroll one-liner.',
        `Expect first heartbeat within the SLO (${sloText}). This view turns green only when that evidence lands.`,
      ],
      href: '#/onboarding',
      linkLabel: 'Open Onboarding',
      doc: DOC_ZERO_TOUCH,
    };
  }

  if (breached > 0) {
    return {
      tone: 'bad',
      title: `${breached} device${breached === 1 ? '' : 's'} past SLO with no first evidence`,
      body: `Red = breached: enrolled past the target (${sloText}) and still no heartbeat. Check collector install on the host, outbound reachability to ingest, and that the MDM package actually ran (Intune app status / Jamf policy log). Do not request prompt or chat content to verify — metadata liveness only.`,
      steps: [
        'On the host: aim status (or Windows service / scheduled task health).',
        'Confirm MDM assignment succeeded and the enroll token was not revoked or exhausted.',
        'If heartbeats never arrive, re-run enroll or re-push the package; do not treat silence as a clean install.',
      ],
      href: '#/fleet',
      linkLabel: 'Open Fleet',
      doc: DOC_PIPELINE,
    };
  }

  if (pending > 0) {
    return {
      tone: 'warn',
      title: `${pending} enrollment${pending === 1 ? '' : 's'} waiting for first evidence`,
      body: `Amber = delayed / still inside the SLO window. First server evidence is the first heartbeat after enroll. If MDM just pushed the package, wait one heartbeat interval before treating this as a failure.`,
      steps: [
        `Still inside target (${sloText}) — refresh this view; it polls while open.`,
        'Windows fleet and Linux/macOS paths share the same SLO; OS cohorts above show which path is lagging.',
        'If the row flips to red, follow the breached recovery steps. Full admin matrix: ' + DOC_ZERO_TOUCH,
      ],
      href: '#/fleet',
      linkLabel: 'Open Fleet',
      doc: DOC_ENROLLMENT,
    };
  }

  if (!hasFleetEvent) {
    return {
      tone: 'warn',
      title: 'Collectors heartbeating — no usage events yet',
      body: 'Devices met the per-host heartbeat SLO, but the fleet has never received a usage event. That is a pipeline or tooling gap, not a clean "no AI in use" signal. Heartbeat first evidence ≠ AI usage events.',
      steps: [
        'Confirm an AI coding tool is installed and used once on a ring-0 host.',
        'Check collector hooks (aim status) and ingest connectivity (events token is separate from enroll token).',
        'Pipeline liveness docs cover silent-drop diagnosis.',
      ],
      href: '#/fleet',
      linkLabel: 'Open Fleet',
      doc: DOC_PIPELINE,
    };
  }

  return null;
}

/** Format seconds for operator-facing duration (matches install-health view). */
export function formatDur(sec) {
  const n = Math.max(0, Math.floor(Number(sec) || 0));
  if (n < 60) return `${n}s`;
  if (n < 3600) {
    const m = Math.floor(n / 60);
    const s = n % 60;
    return s ? `${m}m ${s}s` : `${m}m`;
  }
  const h = Math.floor(n / 3600);
  const m = Math.floor((n % 3600) / 60);
  return m ? `${h}h ${m}m` : `${h}h`;
}

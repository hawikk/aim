// Server first-run onboarding + enrollment-token minting.
//
// Replaces hand-edited ENROLL_TOKENS env surgery with an admin flow: a
// admin mints named, scoped (expiry / max enrollments), revocable
// enrollment tokens from the dashboard. Ingest redeems them at POST /v1/enroll
// (services/ingest/src/enroll-token-store.ts) alongside the legacy env path.
//
// Security bar (mirrors the migration 011 header):
//   * Tokens are enrollment-only — they authenticate /v1/enroll and nothing
//     else. They cannot post events (/v1/events uses INGEST_TOKENS).
//   * Hashed at rest (SHA-256); the cleartext token is returned exactly once,
//     at mint time, and never logged or persisted in full. The list endpoint
//     never exposes token_hash — only a short non-secret prefix.
//   * Minting and revocation are admin only (fail-closed; viewer /
//     auditor / analyst get 403) and are recorded in the immutable audit trail
// with actor identity.
//   * Revoking blocks new enrollments immediately; already-issued per-device
//     tokens are untouched (device blast radius unchanged).
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { query } from '../db.js';
import { requireRoles, hasRole } from '../auth.js';
import { audit } from '../audit.js';

// Public ingest endpoint an engineer's collector posts to. Shown in the
// copy-paste join command; defaults to the local pilot ingest port.
const INGEST_PUBLIC_URL = (process.env.AIM_INGEST_PUBLIC_URL ?? 'http://localhost:8080').replace(/\/+$/, '');

// Dashboard base URL that serves the public enroll.sh one-shot.
// Prefer AIM_BASE_URL (compose default http://localhost:8081 for the API
// container's public face); fall back to the local pilot dashboard port.
const DASHBOARD_PUBLIC_URL = (
  process.env.AIM_BASE_URL
  ?? process.env.AIM_DASHBOARD_PUBLIC_URL
  ?? 'http://localhost:8081'
).replace(/\/+$/, '');

const MAX_NAME_LEN = 80;
const MAX_EXPIRY_DAYS = 365;
const MAX_ENROLLMENTS_CAP = 100000;

// The insecure shipped default for the legacy ENROLL_TOKENS env var
// (docker-compose.yml). If a stack is still running with this value, anyone who
// reads the public compose file can enroll a device — the dashboard must warn
// about it loudly. Kept in sync with ingest's docker-compose default.
const INSECURE_DEFAULT_ENROLL_TOKEN = 'dev-enroll-token-change-me';

// Legacy env tokens the api process can see (same var ingest reads). Used only
// to detect the insecure default and whether any legacy token is still in play;
// the values themselves are never returned to the client.
function legacyEnrollTokens() {
  return (process.env.ENROLL_TOKENS ?? '')
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);
}

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

// SHA-256 of a 32-byte random token, hex — 64 chars, enrollment-only.
function newToken() {
  return randomBytes(32).toString('hex');
}

// Heartbeat cadence the fleet client posts on (enroll-client DEFAULT_INTERVAL).
// Surfaces in the mint response so the UI can state a real time-to-first-
// evidence bound rather than inventing one client-side.
const HEARTBEAT_INTERVAL_SEC = 300;
const FIRST_EVIDENCE_MAX_MINUTES = Math.ceil(HEARTBEAT_INTERVAL_SEC / 60);

// The exact commands an engineer (or fleet package) runs. Linux and Windows
// are first-class and equally specific — the dashboard used to only
// show the python one-liner, which made Windows fleet install look unsupported.
//
// Linux/macOS primary path is the dashboard-hosted enroll.sh
// one-shot (install aimonitoring-security → aim join → doctor --fix →
// token_file verify). Legacy `python -m aim_collector install` remains as
// `command` for older clients; `futureCommand` stays the bare `aim join`
// form once the CLI is already installed.
function joinCommands(token) {
  const url = INGEST_PUBLIC_URL;
  const dash = DASHBOARD_PUBLIC_URL;
  // One-shot device enroll (install + join + doctor). Token appears only in
  // the operator's copy buffer — enroll.sh never logs it.
  const linux =
    `curl -fsSL ${dash}/enroll.sh | bash -s -- --url ${url} --token ${token}`;
  // Python Launcher on Windows (py -3). Same enroll protocol as Linux.
  // (Windows curl|bash one-shot is a follow-up; self-enroll stays py -3.)
  const windows = `py -3 -m aim_collector install --ingest-url ${url} --enroll-token ${token}`;
  // Intune/SYSTEM package path — EnrollToken is this mint; Token is the ring's
  // events ingest bearer (not the enrollment secret).
  const windowsFleet =
    `powershell.exe -ExecutionPolicy Bypass -File Install-AIMCollector.ps1` +
    ` -IngestUrl "${url}" -EnrollToken "${token}" -Token <events-ingest-token>`;
  return {
    ingestUrl: url,
    dashboardUrl: dash,
    // Back-compat for older clients that only read `command`:
    command: `python -m aim_collector install --ingest-url ${url} --enroll-token ${token}`,
    // Bare join once aimonitoring-security is already on PATH:
    futureCommand: `aim join ${url} --token ${token}`,
    // primary engineer path (also printed by install-pilot):
    enrollCommand: linux,
    platforms: [
      {
        id: 'linux',
        label: 'Linux / macOS',
        command: linux,
        hint: 'One-shot on the engineer machine (Python 3.11+, pipx preferred). Installs aimonitoring-security, joins the fleet, runs doctor --fix, and verifies token_file so events can flush.',
      },
      {
        id: 'windows',
        label: 'Windows',
        command: windows,
        hint: 'PowerShell or cmd with the Python launcher (py). Same enroll protocol as Linux — device appears in Fleet after the first heartbeat.',
      },
      {
        id: 'windows-fleet',
        label: 'Windows fleet (Intune)',
        command: windowsFleet,
        hint: 'SYSTEM install via Intune Win32 (deploy/windows). -EnrollToken is this mint; -Token is the ring events bearer (not the enrollment secret).',
      },
    ],
    // Measured bound for "when will I see this device?" — one heartbeat cycle.
    firstEvidence: {
      heartbeatIntervalSec: HEARTBEAT_INTERVAL_SEC,
      expectedMaxMinutes: FIRST_EVIDENCE_MAX_MINUTES,
      verifyIn: 'fleet',
      note: `Device should appear in Fleet within ${FIRST_EVIDENCE_MAX_MINUTES} minutes (one heartbeat). First AI tool event is first evidence.`,
    },
  };
}

// Derived lifecycle state for the list view (never trusts the client).
function tokenStatus(row, now) {
  if (row.revoked_at) return 'revoked';
  if (row.expires_at && new Date(row.expires_at).getTime() <= now) return 'expired';
  if (row.max_enrollments !== null && Number(row.enrollment_count) >= Number(row.max_enrollments)) {
    return 'exhausted';
  }
  return 'active';
}

function toIso(v) {
  if (v === null || v === undefined) return null;
  return v instanceof Date ? v.toISOString() : String(v);
}

function tokenView(row, now) {
  return {
    id: String(row.id),
    name: row.name,
    tokenPrefix: row.token_prefix,
    expiresAt: toIso(row.expires_at),
    maxEnrollments: row.max_enrollments === null ? null : Number(row.max_enrollments),
    enrollmentCount: Number(row.enrollment_count),
    // directory human this token attributes enrolled devices to.
    // Never a secret, but it is personal data — only on the admin surface.
    boundEmail: row.bound_email ?? null,
    createdBy: row.created_by,
    createdAt: toIso(row.created_at),
    lastUsedAt: toIso(row.last_used_at),
    revokedAt: toIso(row.revoked_at),
    revokedBy: row.revoked_by ?? null,
    status: tokenStatus(row, now),
  };
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// opts.db is injectable for tests; defaults to the real pg pool.
export async function onboardingRoutes(fastify, opts) {
  const db = opts?.db ?? { query };
  const adminOnly = requireRoles('admin');

  // ---- Install state: what "nothing on screen" actually means ----
  //
  // Available to any authenticated role so the SPA can land the right user on
  // the onboarding view AND so every event-dependent empty state can say the
  // true reason it is empty. Resilient: if the ingest-owned tables don't exist
  // yet (ingest runs migrations; a race at cold boot), treat as first-run
  // rather than failing the landing page.
  //
  // `installState` is the field the dashboard reads. The three values are not
  // cosmetic — they are three different operator actions:
  //
  //   no-collectors  nothing has ever enrolled. The install is unfinished.
  //                  Action: mint a token and run the join command.
  //   no-events      devices ARE enrolled and not one event has ever landed.
  //                  The pipeline is broken, not idle. This is the silent-drop
  //                  case and gets the loudest treatment in the UI.
  //   live           events exist. An empty view is therefore a statement about
  //                  the selected range or filters, not about the install.
  //
  // A view that cannot tell these apart tells a brand-new operator their
  // guardrails are clean when in fact nothing is being monitored at all.
  //
  // deviceCount === 0 with events present is `live`: the data is real (revoked
  // device, or a legacy INGEST_TOKENS poster that never enrolled), so range
  // copy is the honest copy.
  fastify.get('/api/onboarding/status', async (req) => {
    // MAX(ts) answers "any events?" and "how recent?" in one index-only
    // backward scan on idx_events_ts, so this costs no more than the
    // SELECT 1 ... LIMIT 1 it replaces. NULL means the table is empty.
    let lastEventAt = null;
    try {
      const ev = await db.query('SELECT MAX(ts) AS last_event_at FROM events');
      lastEventAt = ev.rows[0]?.last_event_at ?? null;
    } catch {
      lastEventAt = null;
    }
    const hasEvents = lastEventAt !== null;
    let deviceCount = 0;
    try {
      const dv = await db.query('SELECT COUNT(*)::int AS n FROM devices WHERE revoked_at IS NULL');
      deviceCount = Number(dv.rows[0]?.n ?? 0);
    } catch {
      deviceCount = 0;
    }
    const canMint = hasRole(req, 'admin');
    const legacy = legacyEnrollTokens();
    return {
      firstRun: !hasEvents && deviceCount === 0,
      installState: hasEvents ? 'live' : deviceCount > 0 ? 'no-events' : 'no-collectors',
      lastEventAt: toIso(lastEventAt),
      hasEvents,
      deviceCount,
      canMint,
      ingestUrl: INGEST_PUBLIC_URL,
      // Legacy ENROLL_TOKENS posture. Booleans only — never the
      // token values. insecureDefaultToken drives a loud dashboard warning.
      legacyTokensPresent: legacy.length > 0,
      insecureDefaultToken: legacy.includes(INSECURE_DEFAULT_ENROLL_TOKEN),
    };
  });

  // ---- List minted tokens (admin) — never exposes token_hash ----
  fastify.get('/api/onboarding/tokens', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const { rows } = await db.query(
      `SELECT id, name, token_prefix, expires_at, max_enrollments, enrollment_count,
              bound_email, created_by, created_at, last_used_at, revoked_at, revoked_by
         FROM enroll_tokens
        ORDER BY created_at DESC`
    );
    const now = Date.now();
    return { tokens: rows.map((r) => tokenView(r, now)), ingestUrl: INGEST_PUBLIC_URL };
  });

  // ---- Mint a token (admin). Returns the cleartext token ONCE. ----
  fastify.post('/api/onboarding/tokens', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const body = req.body ?? {};
    const allowed = ['name', 'expiresInDays', 'maxEnrollments', 'boundEmail'];
    const unknown = Object.keys(body).filter((k) => !allowed.includes(k));
    if (unknown.length > 0) {
      return reply.code(400).send({ error: 'bad_request', detail: `unknown field(s): ${unknown.join(', ')} (allowed: ${allowed.join(', ')})` });
    }

    const name = typeof body.name === 'string' ? body.name.trim() : '';
    if (!name || name.length > MAX_NAME_LEN) {
      return reply.code(400).send({ error: 'bad_request', detail: `name is required (1..${MAX_NAME_LEN} chars)` });
    }

    let expiresAt = null;
    if (body.expiresInDays !== undefined && body.expiresInDays !== null) {
      const days = Number(body.expiresInDays);
      if (!Number.isInteger(days) || days < 1 || days > MAX_EXPIRY_DAYS) {
        return reply.code(400).send({ error: 'bad_request', detail: `expiresInDays must be an integer 1..${MAX_EXPIRY_DAYS}` });
      }
      expiresAt = new Date(Date.now() + days * 86400_000).toISOString();
    }

    let maxEnrollments = null;
    if (body.maxEnrollments !== undefined && body.maxEnrollments !== null) {
      const n = Number(body.maxEnrollments);
      if (!Number.isInteger(n) || n < 1 || n > MAX_ENROLLMENTS_CAP) {
        return reply.code(400).send({ error: 'bad_request', detail: `maxEnrollments must be an integer 1..${MAX_ENROLLMENTS_CAP}` });
      }
      maxEnrollments = n;
    }

    // optional directory email this token attributes devices to.
    // Validation is syntactic only — identity-sync refuses emails not in
    // dir_users at enroll time (fail-open: enroll still succeeds).
    let boundEmail = null;
    if (body.boundEmail !== undefined && body.boundEmail !== null && body.boundEmail !== '') {
      if (typeof body.boundEmail !== 'string' || !EMAIL_RE.test(body.boundEmail.trim())) {
        return reply.code(400).send({ error: 'bad_request', detail: 'boundEmail must be a valid email address' });
      }
      boundEmail = body.boundEmail.trim().toLowerCase();
    }

    const token = newToken();
    const id = randomUUID();
    const actor = req.identity?.email ?? 'unknown';
    const { rows } = await db.query(
      `INSERT INTO enroll_tokens
         (id, name, token_hash, token_prefix, expires_at, max_enrollments, bound_email, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id, name, token_prefix, expires_at, max_enrollments, enrollment_count,
                 bound_email, created_by, created_at, last_used_at, revoked_at, revoked_by`,
      [id, name, hashToken(token), token.slice(0, 8), expiresAt, maxEnrollments, boundEmail, actor]
    );

    // Audit the mint — actor + scope, never the token or its hash.
    audit(actor, 'enroll_token.mint', `onboarding/tokens/${id}`, {
      name,
      expiresAt,
      maxEnrollments,
      boundEmail,
      tokenPrefix: token.slice(0, 8),
    });

    // The cleartext token is returned here and NOWHERE else.
    return reply.code(201).send({
      token: tokenView(rows[0], Date.now()),
      secret: token,
      ...joinCommands(token),
    });
  });

  // ---- Revoke a token (admin). Idempotent-safe; audited. ----
  fastify.post('/api/onboarding/tokens/:id/revoke', async (req, reply) => {
    if (!adminOnly(req, reply)) return reply;
    const actor = req.identity?.email ?? 'unknown';
    const { rows } = await db.query(
      `UPDATE enroll_tokens
          SET revoked_at = COALESCE(revoked_at, now()),
              revoked_by = COALESCE(revoked_by, $2)
        WHERE id = $1
        RETURNING id, name, token_prefix, expires_at, max_enrollments, enrollment_count,
                  bound_email, created_by, created_at, last_used_at, revoked_at, revoked_by`,
      [req.params.id, actor]
    );
    if (rows.length === 0) {
      return reply.code(404).send({ error: 'not_found', detail: `no enrollment token ${req.params.id}` });
    }
    audit(actor, 'enroll_token.revoke', `onboarding/tokens/${req.params.id}`, {
      name: rows[0].name,
      tokenPrefix: rows[0].token_prefix,
    });
    return tokenView(rows[0], Date.now());
  });
}

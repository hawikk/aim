// AIM-994 / AIM-582: synthetic test email for POST /api/guardrail/alerts/test.
//
// Mirrors guardrail `EmailNotifier.deliver_test` (services/guardrail):
//   - SMTP host/from/user/password stay env-only (ALERT_EMAIL_*)
//   - recipients come from alerts.yaml (non-secret policy)
//   - metadata-only body — no prompt/response content
//   - retry with exponential backoff on SMTP/network errors
//
// Secrets must never appear in HTTP responses or audit detail. Error text is
// scrubbed before it leaves this module. Transports are injectable so unit
// tests never open a real socket.
import net from 'node:net';
import tls from 'node:tls';

export const MAX_RETRIES = 3;
export const BACKOFF_BASE_SECONDS = 0.5;
export const DEFAULT_TIMEOUT_MS = 10_000;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function envFlagTruthy(raw) {
  const v = String(raw ?? '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

/**
 * Read SMTP connection settings from env. Never log or return these as an
 * API payload — only pass them into a transport.
 */
export function emailSmtpFromEnv(env = process.env) {
  const useSsl = envFlagTruthy(env.ALERT_EMAIL_SMTP_SSL);
  const useTlsFlag = env.ALERT_EMAIL_SMTP_TLS == null || env.ALERT_EMAIL_SMTP_TLS === ''
    ? true
    : envFlagTruthy(env.ALERT_EMAIL_SMTP_TLS);
  const portRaw = env.ALERT_EMAIL_SMTP_PORT;
  let port;
  if (portRaw == null || portRaw === '') {
    port = useSsl ? 465 : 587;
  } else {
    port = Number(portRaw);
  }
  return {
    host: String(env.ALERT_EMAIL_SMTP_HOST || '').trim(),
    port,
    user: String(env.ALERT_EMAIL_SMTP_USER || ''),
    password: String(env.ALERT_EMAIL_SMTP_PASSWORD || ''),
    from: String(env.ALERT_EMAIL_FROM || '').trim(),
    useTls: useTlsFlag && !useSsl,
    useSsl,
    triageBaseUrl: String(env.AIM_BASE_URL || '').trim(),
  };
}

/** Presence-only gate used by GET /api/guardrail/alerts and the test route. */
export function emailSmtpConfigured(env = process.env) {
  return Boolean(
    String(env.ALERT_EMAIL_SMTP_HOST || '').trim()
    && String(env.ALERT_EMAIL_FROM || '').trim(),
  );
}

/**
 * Parse recipients from policy/UI (comma/semicolon string or list).
 * Returns [] when empty; throws ValueError-style Error on invalid input.
 */
export function parseRecipients(raw) {
  if (raw == null || raw === '') return [];
  let parts;
  if (typeof raw === 'string') {
    parts = raw.split(/[,;]/).map((s) => s.trim()).filter(Boolean);
  } else if (Array.isArray(raw)) {
    parts = raw.map((s) => String(s).trim()).filter(Boolean);
  } else {
    throw new Error('email.to must be a list of addresses or a comma-separated string');
  }
  const out = [];
  const seen = new Set();
  for (const p of parts) {
    if (!EMAIL_RE.test(p) || p.length > 254) {
      throw new Error('email.to contains an invalid address');
    }
    const key = p.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
  }
  if (out.length > 20) {
    throw new Error('email.to may list at most 20 recipients');
  }
  return out;
}

/**
 * Build the plain-text test message (same synthetic finding as Python
 * `build_test_email_finding` / `deliver_test`).
 */
export function buildTestEmailMessage({ from, to, triageBaseUrl = '' }) {
  const toList = Array.isArray(to) ? to : parseRecipients(to);
  if (!from || !EMAIL_RE.test(from)) {
    throw new Error('ALERT_EMAIL_FROM is not a valid address');
  }
  if (toList.length === 0) {
    throw new Error('email.to must list at least one recipient');
  }
  const subject = '[AIM TEST] [HIGH] AIM email alert destination test message';
  const link = triageBaseUrl
    ? `${triageBaseUrl.replace(/\/$/, '')}/#/findings`
    : '(configure AIM_BASE_URL for triage deep links)';
  const body = [
    'AI Monitoring guardrail alert',
    '=============================',
    '',
    'Metadata only — no prompt/response content is included.',
    '',
    '--- AIM email alert destination test message',
    'Severity:  HIGH',
    'Rule:      email-destination-test',
    'Tool:      guardrail-test',
    'Subject:   cccccccccccc (pseudonym)',
    'Finding:   00000000-0000-4000-8000-00000000test',
    `Triage:    ${link}`,
    '',
    '— AI Monitoring guardrail engine',
    '',
  ].join('\n');

  // RFC 5322 simple message. CRLF line endings for SMTP DATA.
  const headers = [
    `From: ${from}`,
    `To: ${toList.join(', ')}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
  ];
  const raw = `${headers.join('\r\n')}\r\n\r\n${body.replace(/\r?\n/g, '\r\n')}`;
  return { from, to: toList, subject, body, raw };
}

/**
 * Strip SMTP secrets / hosts from error text so nothing sensitive reaches
 * HTTP responses or audit detail.
 */
export function sanitizeSmtpError(err, smtp = {}) {
  let msg = err && typeof err === 'object' && 'message' in err
    ? String(err.message)
    : String(err ?? 'smtp error');
  const secrets = [smtp.password, smtp.user, smtp.host, smtp.from]
    .filter((s) => typeof s === 'string' && s.length > 0);
  for (const s of secrets) {
    if (!s) continue;
    // Escape regex metacharacters in secret material.
    const re = new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
    msg = msg.replace(re, '[redacted]');
  }
  // Generic host:port patterns that might still leak.
  msg = msg.replace(/\b[\w.-]+\.(?:local|internal|corp|example)(?::\d+)?\b/gi, '[redacted-host]');
  msg = msg.replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g, '[redacted-host]');
  // Cap length so a chatty SMTP banner cannot flood the response.
  if (msg.length > 240) msg = `${msg.slice(0, 237)}...`;
  return msg;
}

function sleepMs(ms, sleep = (n) => new Promise((r) => setTimeout(r, n))) {
  return sleep(ms);
}

/**
 * Minimal SMTP client (AUTH LOGIN, STARTTLS / implicit SSL). No extra deps.
 * Rejects on non-2xx/3xx reply codes. Never includes credentials in thrown
 * messages (password is only written as base64 AUTH payload on the wire).
 */
export function defaultSmtpTransport(smtp) {
  return async function send(message) {
    const timeout = smtp.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const socket = await connectSocket(smtp, timeout);
    try {
      await smtpDialog(socket, smtp, message, timeout);
    } finally {
      try { socket.end(); } catch { /* ignore */ }
      socket.destroy();
    }
  };
}

function connectSocket(smtp, timeout) {
  return new Promise((resolve, reject) => {
    const onErr = (err) => reject(err);
    if (smtp.useSsl) {
      const s = tls.connect({ host: smtp.host, port: smtp.port, servername: smtp.host, timeout }, () => {
        s.setTimeout(timeout);
        resolve(s);
      });
      s.once('error', onErr);
      s.once('timeout', () => {
        s.destroy();
        reject(new Error('SMTP connection timed out'));
      });
      return;
    }
    const s = net.connect({ host: smtp.host, port: smtp.port }, () => {
      s.setTimeout(timeout);
      resolve(s);
    });
    s.once('error', onErr);
    s.once('timeout', () => {
      s.destroy();
      reject(new Error('SMTP connection timed out'));
    });
  });
}

function upgradeToTls(socket, smtp, timeout) {
  return new Promise((resolve, reject) => {
    const secure = tls.connect({
      socket,
      host: smtp.host,
      servername: smtp.host,
      timeout,
    }, () => {
      secure.setTimeout(timeout);
      resolve(secure);
    });
    secure.once('error', reject);
  });
}

/**
 * Read one multi-line SMTP reply. Resolves with { code, text }.
 */
function readReply(socket) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const onData = (chunk) => {
      buf += chunk.toString('utf8');
      // SMTP multi-line: "250-…" then final "250 …"
      const lines = buf.split(/\r?\n/);
      // Need at least one complete line ending.
      if (!buf.includes('\n')) return;
      // Walk complete lines; last fragment may be partial.
      let complete = '';
      for (let i = 0; i < lines.length - 1; i++) {
        complete += `${lines[i]}\n`;
        const line = lines[i];
        if (/^\d{3}[ \t]/.test(line)) {
          socket.off('data', onData);
          socket.off('error', onErr);
          socket.off('close', onClose);
          const code = Number(line.slice(0, 3));
          resolve({ code, text: complete.trim() });
          return;
        }
      }
      // Keep partial trailing fragment.
      buf = lines[lines.length - 1];
    };
    const onErr = (err) => {
      socket.off('data', onData);
      socket.off('close', onClose);
      reject(err);
    };
    const onClose = () => {
      socket.off('data', onData);
      socket.off('error', onErr);
      reject(new Error('SMTP connection closed before reply'));
    };
    socket.on('data', onData);
    socket.once('error', onErr);
    socket.once('close', onClose);
  });
}

function writeLine(socket, line) {
  return new Promise((resolve, reject) => {
    socket.write(`${line}\r\n`, (err) => (err ? reject(err) : resolve()));
  });
}

async function expect(socket, okCodes) {
  const reply = await readReply(socket);
  if (!okCodes.includes(reply.code)) {
    // Never echo full banner (may include hostname).
    throw new Error(`SMTP ${reply.code}`);
  }
  return reply;
}

async function smtpDialog(plainSocket, smtp, message, timeout) {
  let socket = plainSocket;
  await expect(socket, [220]);
  await writeLine(socket, `EHLO aim-guardrail`);
  await expect(socket, [250]);

  if (smtp.useTls && !smtp.useSsl) {
    await writeLine(socket, 'STARTTLS');
    await expect(socket, [220]);
    socket = await upgradeToTls(socket, smtp, timeout);
    await writeLine(socket, `EHLO aim-guardrail`);
    await expect(socket, [250]);
  }

  if (smtp.user) {
    if (!smtp.password) {
      throw new Error('ALERT_EMAIL_SMTP_PASSWORD is required when ALERT_EMAIL_SMTP_USER is set');
    }
    await writeLine(socket, 'AUTH LOGIN');
    await expect(socket, [334]);
    await writeLine(socket, Buffer.from(smtp.user, 'utf8').toString('base64'));
    await expect(socket, [334]);
    await writeLine(socket, Buffer.from(smtp.password, 'utf8').toString('base64'));
    await expect(socket, [235, 250]);
  }

  await writeLine(socket, `MAIL FROM:<${message.from}>`);
  await expect(socket, [250]);
  for (const rcpt of message.to) {
    await writeLine(socket, `RCPT TO:<${rcpt}>`);
    await expect(socket, [250, 251]);
  }
  await writeLine(socket, 'DATA');
  await expect(socket, [354]);
  // Dot-stuff lines starting with '.'
  const data = message.raw
    .replace(/\r?\n/g, '\r\n')
    .replace(/^\./gm, '..');
  await new Promise((resolve, reject) => {
    socket.write(`${data}\r\n.\r\n`, (err) => (err ? reject(err) : resolve()));
  });
  await expect(socket, [250]);
  try {
    await writeLine(socket, 'QUIT');
  } catch {
    /* ignore quit failures */
  }
}

/**
 * Deliver a synthetic test email. Returns { ok, attempts } or throws a
 * sanitized Error (`error.code` is a stable token for the route).
 *
 * opts:
 *   - env: env object (default process.env)
 *   - to: recipients string/list from alerts.yaml
 *   - transport: async (message) => void  (default real SMTP)
 *   - sleep: async (ms) => void
 *   - maxRetries: number (default MAX_RETRIES)
 */
export async function deliverTestEmail(opts = {}) {
  const env = opts.env ?? process.env;
  const smtp = emailSmtpFromEnv(env);

  if (!smtp.host || !smtp.from) {
    const err = new Error(
      'SMTP is not configured (set ALERT_EMAIL_SMTP_HOST and ALERT_EMAIL_FROM)',
    );
    err.code = 'smtp_not_configured';
    err.statusCode = 400;
    throw err;
  }
  if (!Number.isInteger(smtp.port) || smtp.port < 1 || smtp.port > 65535) {
    const err = new Error('ALERT_EMAIL_SMTP_PORT is invalid');
    err.code = 'smtp_not_configured';
    err.statusCode = 400;
    throw err;
  }
  if (smtp.user && !smtp.password) {
    const err = new Error(
      'ALERT_EMAIL_SMTP_PASSWORD is required when ALERT_EMAIL_SMTP_USER is set',
    );
    err.code = 'smtp_not_configured';
    err.statusCode = 400;
    throw err;
  }

  let toList;
  try {
    toList = parseRecipients(opts.to);
  } catch (e) {
    const err = new Error(e.message || 'invalid recipients');
    err.code = 'recipients_invalid';
    err.statusCode = 400;
    throw err;
  }
  if (toList.length === 0) {
    const err = new Error(
      'email.to has no recipients — configure recipients in Alert destinations before Test send',
    );
    err.code = 'recipients_missing';
    err.statusCode = 400;
    throw err;
  }

  let message;
  try {
    message = buildTestEmailMessage({
      from: smtp.from,
      to: toList,
      triageBaseUrl: smtp.triageBaseUrl,
    });
  } catch (e) {
    const err = new Error(sanitizeSmtpError(e, smtp));
    err.code = 'message_build_failed';
    err.statusCode = 400;
    throw err;
  }

  const transport = opts.transport ?? defaultSmtpTransport(smtp);
  const sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  const maxRetries = opts.maxRetries ?? MAX_RETRIES;

  let lastErr;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      await transport(message);
      return { ok: true, attempts: attempt + 1, recipientCount: toList.length };
    } catch (e) {
      lastErr = e;
      if (attempt < maxRetries) {
        await sleepMs(BACKOFF_BASE_SECONDS * (2 ** attempt) * 1000, sleep);
      }
    }
  }
  const err = new Error(sanitizeSmtpError(lastErr, smtp));
  err.code = 'delivery_failed';
  err.statusCode = 502;
  err.attempts = maxRetries + 1;
  throw err;
}

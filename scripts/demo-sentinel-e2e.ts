#!/usr/bin/env node
/**
 * End-to-end demo for AIM-27:
 *   guardrail finding -> SentinelForwarder -> mock Log Analytics endpoint
 *   + immutable audit trail records (finding lifecycle + alert forwarded)
 *   + chain verification + audit queries.
 *
 * The mock endpoint independently verifies the SharedKey HMAC signature, so
 * this exercises the exact wire format Sentinel expects — only the URL and
 * real credentials differ in production.
 *
 * Run: npm run demo:sentinel
 */
import { createServer } from 'node:http';
import { createHmac, randomBytes } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SentinelForwarder } from '../packages/alerting/src/sentinel.ts';
import { AuditLog } from '../packages/audit/src/audit-log.ts';

const WORKSPACE_ID = 'demo-workspace-0001';
const SHARED_KEY = randomBytes(32).toString('base64');
const AUDIT_KEY = randomBytes(32).toString('hex');

function verifySignature(req, body) {
  const m = /^SharedKey ([^:]+):(.+)$/.exec(req.headers.authorization ?? '');
  if (!m || m[1] !== WORKSPACE_ID) return false;
  const stringToSign = `POST\n${body.length}\napplication/json\nx-ms-date:${req.headers['x-ms-date']}\n/api/logs`;
  const expected = createHmac('sha256', Buffer.from(SHARED_KEY, 'base64')).update(stringToSign, 'utf8').digest('base64');
  return m[2] === expected;
}

const received = [];
const server = createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    if (!verifySignature(req, body)) {
      res.writeHead(403).end('invalid signature');
      return;
    }
    received.push(...JSON.parse(body.toString('utf8')));
    res.writeHead(200, { 'Content-Type': 'application/json' }).end('{}');
  });
});

await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;
console.log(`mock Log Analytics endpoint listening on 127.0.0.1:${port}\n`);

const auditPath = join(mkdtempSync(join(tmpdir(), 'aim-audit-')), 'audit.jsonl');
const audit = new AuditLog({ path: auditPath, key: AUDIT_KEY });

const forwarder = new SentinelForwarder({
  workspaceId: WORKSPACE_ID,
  sharedKey: SHARED_KEY,
  endpoint: `http://127.0.0.1:${port}/api/logs?api-version=2016-04-01`,
  runbookBaseUrl: 'https://wiki.corp/runbooks/',
  onForward: (e) => audit.append({ actor: 'pipeline/guardrail-engine', action: 'alert.forwarded', resource: 'sentinel/AIGuardrailFinding', detail: e }),
});

// 1) Guardrail engine raises a finding (metadata-only) -> lifecycle audited.
const finding = {
  findingId: 'f-2026-0001',
  findingType: 'secret_pattern_detected',
  title: 'AWS access key pattern detected in prompt metadata',
  timestamp: new Date().toISOString(),
  userId: 'jdoe@corp',
  team: 'payments',
  tool: 'claude-code',
  model: 'claude-opus-4',
  repo: 'github.com/corp/payments',
  matchFlags: 'aws-access-key',
};
audit.append({ actor: 'pipeline/guardrail-engine', action: 'finding.open', resource: `finding/${finding.findingId}`, detail: { findingType: finding.findingType } });

// 2) Forward to Sentinel and measure latency.
const t0 = performance.now();
await forwarder.forward([finding]);
const latencyMs = (performance.now() - t0).toFixed(0);
console.log(`[1] finding forwarded + acknowledged by mock Sentinel in ${latencyMs} ms (AC: "within minutes" — actual is seconds)`);
console.log('    record in Sentinel custom log AIGuardrailFinding_CL:');
console.log(JSON.stringify(received[0], null, 2).replace(/^/gm, '    '));

// 3) SOC analyst works the finding; dashboard access + lifecycle are audited.
audit.append({ actor: 'analyst@corp', action: 'dashboard.view', resource: 'dashboard/findings', detail: { view: 'findings', filter: 'severity:High' } });
audit.append({ actor: 'analyst@corp', action: 'finding.ack', resource: `finding/${finding.findingId}` });
audit.append({ actor: 'security-lead@corp', action: 'policy.update', resource: 'policy/secret-patterns', detail: { addedPattern: 'aws-session-token', version: 4 } });
audit.append({ actor: 'analyst@corp', action: 'finding.resolve', resource: `finding/${finding.findingId}`, detail: { resolution: 'credential rotated, user coached' } });

// 4) Verify chain integrity + run the AC queries.
const verification = AuditLog.verify({ path: auditPath, key: AUDIT_KEY });
console.log(`\n[2] audit chain verified: ${verification.count} records, ok=${verification.ok}`);

const policyChanges = AuditLog.query({ path: auditPath, action: ['policy.create', 'policy.update', 'policy.delete'] });
const dashboardAccess = AuditLog.query({ path: auditPath, action: 'dashboard.view' });
const lifecycle = AuditLog.query({ path: auditPath, resource: `finding/${finding.findingId}` });
console.log(`[3] audit queries -> dashboard access: ${dashboardAccess.length}, policy changes: ${policyChanges.length}, finding f-2026-0001 lifecycle: ${lifecycle.map((r) => r.action).join(' -> ')}`);

// 5) Tamper demonstration.
const { readFileSync, writeFileSync } = await import('node:fs');
const lines = readFileSync(auditPath, 'utf8').split('\n').filter(Boolean);
const tampered = JSON.parse(lines[3]);
tampered.actor = 'attacker@corp';
lines[3] = JSON.stringify(tampered);
writeFileSync(auditPath, lines.join('\n') + '\n');
const after = AuditLog.verify({ path: auditPath, key: AUDIT_KEY });
console.log(`[4] after tampering with record seq ${after.failedSeq}: verify ok=${after.ok} (${after.reason})`);

server.close();
console.log('\ndemo complete.');

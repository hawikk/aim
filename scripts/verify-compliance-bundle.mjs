#!/usr/bin/env node
// Offline verifier compliance evidence bundles.
//
// An auditor (or CI) runs this against an exported bundle to prove:
//   1. the bundle's content hash matches its report + chain anchor,
//   2. the HMAC signature is valid (same key family as the audit trail),
//   3. the audit hash chain itself verifies end-to-end, and
//   4. a `compliance.export` record sealing THIS bundle's hash exists in
//      that verified chain at the seq/seal the bundle claims.
//
// Usage:
//   AUDIT_LOG_PATH=/var/lib/aim/audit.jsonl AUDIT_HMAC_KEY=... \
//     node scripts/verify-compliance-bundle.mjs aim-compliance-bundle.json
//
// Exit code 0 = every check passed; 1 = at least one failed.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyBundle } from '../apps/api/src/compliance-bundle.js';

const file = process.argv[2];
if (!file) {
  console.error('usage: verify-compliance-bundle.mjs <bundle.json>');
  process.exit(2);
}

const path = process.env.AUDIT_LOG_PATH;
const key = process.env.AUDIT_HMAC_KEY;
if (!path || !key) {
  console.error('AUDIT_LOG_PATH and AUDIT_HMAC_KEY are required (same values as the API service).');
  process.exit(2);
}

const bundle = JSON.parse(readFileSync(join(process.cwd(), file), 'utf8'));
const { ok, checks } = verifyBundle(bundle, { path, key });

for (const c of checks) {
  console.log(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name} — ${c.detail}`);
}
console.log(ok ? '\nBundle verified against the audit hash chain.' : '\nBundle verification FAILED.');
process.exit(ok ? 0 : 1);

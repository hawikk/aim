#!/usr/bin/env node
// Mint a service token for a headless consumer of the AIM API (AIM-165).
//
//   node scripts/mint-service-token.mjs sentinel --role analyst
//
// Prints the secret ONCE (give it to the consumer) and the file entry to add
// to AIM_SERVICE_TOKENS_FILE. The secret is never written to disk by this
// script: only its digest goes in the token file, so the plaintext exists
// exactly where you paste it and nowhere else.
//
// This exists because the alternative is operators hand-rolling sha256 in a
// shell, where `echo secret | sha256sum` silently hashes a trailing newline
// and produces a token that will never authenticate.
import { randomBytes, createHash } from 'node:crypto';

const ALLOWED_ROLES = ['analyst', 'auditor'];

const args = process.argv.slice(2);
const name = args.find((a) => !a.startsWith('-'));
const roleIdx = args.indexOf('--role');
const role = roleIdx === -1 ? 'analyst' : args[roleIdx + 1];
const expIdx = args.indexOf('--expires');
const expires = expIdx === -1 ? null : args[expIdx + 1];

function die(msg) {
  console.error(`error: ${msg}`);
  console.error('\nusage: node scripts/mint-service-token.mjs <name> [--role analyst|auditor] [--expires 2027-01-01T00:00:00Z]');
  process.exit(1);
}

if (!name) die('a consumer name is required (e.g. "sentinel")');
if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(name)) die(`invalid name ${JSON.stringify(name)}: lowercase alphanumeric and dashes, 1-40 chars`);
if (!ALLOWED_ROLES.includes(role)) {
  // Mirrors the loader's refusal, so you find out here rather than at boot.
  die(`role ${JSON.stringify(role)} is not permitted for a service token; allowed: ${ALLOWED_ROLES.join(', ')}`);
}
if (expires !== null && Number.isNaN(Date.parse(expires))) die(`--expires ${JSON.stringify(expires)} is not an ISO-8601 timestamp`);

// 32 bytes of CSPRNG output, base64url. Long enough that the digest-compare
// in servicetoken.js is the only realistic attack surface.
const secret = `aimsvc_${randomBytes(32).toString('base64url')}`;
const entry = { name, role, sha256: createHash('sha256').update(secret, 'utf8').digest('hex') };
if (expires) entry.expires_at = expires;

console.log(`\n  secret (shown once — copy it to ${name} now):\n\n    ${secret}\n`);
console.log(`  add to AIM_SERVICE_TOKENS_FILE under "tokens":\n`);
console.log(`${JSON.stringify(entry, null, 2).split('\n').map((l) => `    ${l}`).join('\n')}\n`);
console.log('  the consumer sends it as:  Authorization: Bearer <secret>\n');

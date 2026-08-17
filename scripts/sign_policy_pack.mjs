#!/usr/bin/env node
/**
 * Offline / CI signer for AIM-688 policy packs.
 *
 * Usage:
 *   node scripts/sign_policy_pack.mjs \
 *     --policy-dir policies/guardrail/v1 \
 *     --out /tmp/policy-pack.json \
 *     --key-id aim-policy-prod-2026
 *
 * Env:
 *   POLICY_PACK_PRIVATE_KEY  base64 raw 32-byte Ed25519 seed (required)
 *   POLICY_PACK_KEY_ID       default key id when --key-id omitted
 *
 * Generate a test keypair:
 *   node scripts/sign_policy_pack.mjs --gen-keys
 */
import { writeFileSync, readFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const apiRoot = join(here, '..', 'apps', 'api', 'src');

const {
  generatePolicyKeyPair,
  buildPayloadFromDir,
  signPayload,
  verifyPack,
  loadPublicKeyFromEnv,
} = await import(join(apiRoot, 'policy-pack.js'));

function usage() {
  console.error(`Usage:
  node scripts/sign_policy_pack.mjs --policy-dir <dir> [--out <file>] [--key-id <id>] [--pack-id <id>]
  node scripts/sign_policy_pack.mjs --gen-keys
  node scripts/sign_policy_pack.mjs --verify <pack.json>
`);
  process.exit(2);
}

const args = process.argv.slice(2);
if (args.includes('--gen-keys')) {
  const kp = generatePolicyKeyPair();
  console.log(JSON.stringify({
    POLICY_PACK_PRIVATE_KEY: kp.privateKeyB64,
    POLICY_PACK_PUBLIC_KEY: kp.publicKeyB64,
    note: 'Store the private key in CI/secrets; deploy only the public key to the API.',
  }, null, 2));
  process.exit(0);
}

const verifyIdx = args.indexOf('--verify');
if (verifyIdx >= 0) {
  const path = args[verifyIdx + 1];
  if (!path) usage();
  const pack = JSON.parse(readFileSync(path, 'utf8'));
  const pub = process.env.POLICY_PACK_PUBLIC_KEY;
  if (!pub) {
    console.error('POLICY_PACK_PUBLIC_KEY required for --verify');
    process.exit(1);
  }
  const r = verifyPack(pack, pub, {
    expectedKeyId: process.env.POLICY_PACK_KEY_ID || null,
  });
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.ok ? 0 : 1);
}

function flag(name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
}

const policyDir = flag('--policy-dir');
if (!policyDir) usage();
const out = flag('--out');
const keyId = flag('--key-id') || process.env.POLICY_PACK_KEY_ID || 'aim-policy-default';
const packId = flag('--pack-id') || undefined;
const priv = process.env.POLICY_PACK_PRIVATE_KEY;
if (!priv) {
  console.error('POLICY_PACK_PRIVATE_KEY is required (base64 raw 32-byte Ed25519 seed)');
  process.exit(1);
}

const payload = buildPayloadFromDir(resolve(policyDir));
const pack = signPayload(payload, priv, { keyId, packId });

// Self-check if public key is available.
const pub = loadPublicKeyFromEnv();
if (pub) {
  const r = verifyPack(pack, pub);
  if (!r.ok) {
    console.error('self-verify failed:', r.reason, r.checks);
    process.exit(1);
  }
}

const json = `${JSON.stringify(pack, null, 2)}\n`;
if (out) {
  writeFileSync(out, json);
  console.error(`wrote ${out}`);
  console.error(`policy_hash=${pack.payload.policyHash} packId=${pack.packId} keyId=${pack.keyId}`);
} else {
  process.stdout.write(json);
}

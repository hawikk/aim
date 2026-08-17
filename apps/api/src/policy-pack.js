// Versioned signed policy packs with provenance (AIM-688).
//
// Extends the existing policy_hash / contentHash work: every pack carries the
// same sha256-over-sorted-YAML-bytes that findings.policy_hash and
// GET /api/guardrail/rules use, then seals that artifact with Ed25519 so the
// server can refuse unsigned or tampered promotions.
//
// Envelope (schema aim.policy-pack/v1):
//   {
//     schema, alg, keyId, signedAt, packId,
//     payload: { policyVersion, policyHash, files: [{name, sha256, size, contentB64}] },
//     signature   // base64 raw Ed25519 over canonicalJSON(payload)
//   }
//
// Keys (raw 32-byte Ed25519, base64):
//   POLICY_PACK_PRIVATE_KEY  — sign (CI/ops; never required on the API for verify-only)
//   POLICY_PACK_PUBLIC_KEY   — verify (required for promote in enforce mode)
//   POLICY_PACK_KEY_ID       — labels which key signed the pack
//   POLICY_PACK_DIR          — pack registry + active pointer
//   POLICY_PACK_MODE         — enforce (default when pubkey set) | observe
//
// Promote path: verify signature → recompute policy_hash from files → store
// pack → write active pointer → append audit `policy.promote` with actor + hash.

import {
  createHash,
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
  statSync,
} from 'node:fs';
import { join } from 'node:path';

export const PACK_SCHEMA = 'aim.policy-pack/v1';
export const PACK_ALG = 'Ed25519';
export const ACTIVE_POINTER = 'active.json';

/** Deterministic JSON — same semantics as compliance-bundle/audit. */
export function canonical(value) {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}

function b64e(buf) {
  return Buffer.from(buf).toString('base64');
}

function b64d(text) {
  return Buffer.from(String(text).trim(), 'base64');
}

export function generatePolicyKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const privRaw = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
  const pubRaw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  return {
    privateKeyB64: b64e(privRaw),
    publicKeyB64: b64e(pubRaw),
  };
}

function privateKeyFromRaw(rawOrB64) {
  const raw = Buffer.isBuffer(rawOrB64) ? rawOrB64 : b64d(rawOrB64);
  if (raw.length !== 32) throw new Error(`Ed25519 private key must be 32 bytes, got ${raw.length}`);
  const pkcs8 = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    raw,
  ]);
  return createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

function publicKeyFromRaw(rawOrB64) {
  const raw = Buffer.isBuffer(rawOrB64) ? rawOrB64 : b64d(rawOrB64);
  if (raw.length !== 32) throw new Error(`Ed25519 public key must be 32 bytes, got ${raw.length}`);
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    raw,
  ]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

export function loadPublicKeyFromEnv(env = process.env) {
  const b64 = env.POLICY_PACK_PUBLIC_KEY;
  if (!b64 || !String(b64).trim()) return null;
  return publicKeyFromRaw(b64);
}

export function loadPrivateKeyFromEnv(env = process.env) {
  const b64 = env.POLICY_PACK_PRIVATE_KEY;
  if (!b64 || !String(b64).trim()) return null;
  return privateKeyFromRaw(b64);
}

export function packDir(env = process.env) {
  return env.POLICY_PACK_DIR || join(process.cwd(), 'data', 'policy-packs');
}

export function packMode(env = process.env) {
  if (env.POLICY_PACK_MODE === 'observe' || env.POLICY_PACK_MODE === 'enforce') {
    return env.POLICY_PACK_MODE;
  }
  return loadPublicKeyFromEnv(env) ? 'enforce' : 'observe';
}

/**
 * Collect sorted YAML files from a policy directory and compute the
 * engine-identical content hash (sha256 over concatenated raw bytes).
 */
export function collectPolicyFiles(policyDir) {
  const st = statSync(policyDir);
  if (!st.isDirectory()) {
    throw new Error(`policy path is not a directory: ${policyDir}`);
  }
  const names = readdirSync(policyDir)
    .filter((f) => /\.ya?ml$/i.test(f))
    .sort();
  if (names.length === 0) throw new Error(`no YAML policy files in ${policyDir}`);

  const hasher = createHash('sha256');
  const files = [];
  for (const name of names) {
    const abs = join(policyDir, name);
    const raw = readFileSync(abs);
    hasher.update(raw);
    files.push({
      name,
      sha256: createHash('sha256').update(raw).digest('hex'),
      size: raw.length,
      contentB64: b64e(raw),
    });
  }
  return { policyHash: hasher.digest('hex'), files };
}

/**
 * Build an unsigned payload from a policy directory (+ optional policyVersion).
 */
export function buildPayloadFromDir(policyDir, { policyVersion = null } = {}) {
  const { policyHash, files } = collectPolicyFiles(policyDir);
  let version = policyVersion;
  if (version == null) {
    try {
      const first = Buffer.from(files[0].contentB64, 'base64').toString('utf8');
      const m = first.match(/^\s*version:\s*(\d+)/m);
      if (m) version = Number(m[1]);
    } catch {
      /* ignore */
    }
  }
  return {
    policyVersion: version ?? 1,
    policyHash,
    files: files.map(({ name, sha256, size, contentB64 }) => ({
      name,
      sha256,
      size,
      contentB64,
    })),
  };
}

/** Recompute policy_hash from pack file contents; returns hex or throws. */
export function recomputePolicyHash(files) {
  if (!Array.isArray(files) || files.length === 0) {
    throw new Error('pack has no files');
  }
  const sorted = [...files].sort((a, b) => String(a.name).localeCompare(String(b.name)));
  const hasher = createHash('sha256');
  for (const f of sorted) {
    if (!f?.contentB64) throw new Error(`file ${f?.name} missing contentB64`);
    const raw = b64d(f.contentB64);
    const expected = createHash('sha256').update(raw).digest('hex');
    if (f.sha256 && f.sha256 !== expected) {
      throw new Error(`file ${f.name} sha256 mismatch`);
    }
    hasher.update(raw);
  }
  return hasher.digest('hex');
}

export function signPayload(payload, privateKey, { keyId, signedAt, packId } = {}) {
  if (!payload || typeof payload !== 'object') throw new Error('payload must be an object');
  if (!keyId) throw new Error('keyId is required to sign a policy pack');
  const key = typeof privateKey === 'string' || Buffer.isBuffer(privateKey)
    ? privateKeyFromRaw(privateKey)
    : privateKey;
  const msg = Buffer.from(canonical(payload), 'utf8');
  const signature = b64e(cryptoSign(null, msg, key));
  const id = packId || `pack-${payload.policyHash.slice(0, 16)}`;
  return {
    schema: PACK_SCHEMA,
    alg: PACK_ALG,
    keyId,
    signedAt: signedAt || new Date().toISOString(),
    packId: id,
    payload,
    signature,
  };
}

/**
 * Verify a pack envelope.
 * @returns {{ ok: boolean, reason: string, checks: Array<{name, ok, detail}>, payload?: object }}
 */
export function verifyPack(envelope, publicKey, { expectedKeyId = null } = {}) {
  const checks = [];
  const check = (name, ok, detail) => {
    checks.push({ name, ok, detail });
    return ok;
  };

  if (!envelope || typeof envelope !== 'object') {
    check('structure', false, 'missing envelope');
    return { ok: false, reason: 'missing_envelope', checks };
  }
  if (!check('schema', envelope.schema === PACK_SCHEMA, envelope.schema ?? 'missing')) {
    return { ok: false, reason: 'unknown_schema', checks };
  }
  if (!check('alg', envelope.alg === PACK_ALG, envelope.alg ?? 'missing')) {
    return { ok: false, reason: 'unsupported_alg', checks };
  }
  const payload = envelope.payload;
  if (!check('payload', !!payload && typeof payload === 'object', 'payload must be object')) {
    return { ok: false, reason: 'missing_payload', checks };
  }
  if (!check('signature present', typeof envelope.signature === 'string' && envelope.signature.length > 0, 'missing')) {
    return { ok: false, reason: 'missing_signature', checks };
  }
  if (expectedKeyId != null) {
    if (!check('keyId', envelope.keyId === expectedKeyId, `expected ${expectedKeyId}, got ${envelope.keyId}`)) {
      return { ok: false, reason: 'key_id_mismatch', checks };
    }
  }

  if (!publicKey) {
    check('public key', false, 'POLICY_PACK_PUBLIC_KEY not configured');
    return { ok: false, reason: 'no_public_key', checks };
  }

  let key;
  try {
    key = typeof publicKey === 'string' || Buffer.isBuffer(publicKey)
      ? publicKeyFromRaw(publicKey)
      : publicKey;
  } catch (err) {
    check('public key', false, err.message);
    return { ok: false, reason: 'bad_public_key', checks };
  }
  check('public key', true, 'ok');

  let sigOk = false;
  try {
    const msg = Buffer.from(canonical(payload), 'utf8');
    sigOk = cryptoVerify(null, msg, key, b64d(envelope.signature));
  } catch (err) {
    check('signature', false, err.message);
    return { ok: false, reason: 'verify_error', checks };
  }
  if (!check('signature', sigOk, sigOk ? 'valid Ed25519' : 'invalid signature')) {
    return { ok: false, reason: 'invalid_signature', checks };
  }

  let recomputed;
  try {
    recomputed = recomputePolicyHash(payload.files);
  } catch (err) {
    check('content hash', false, err.message);
    return { ok: false, reason: 'bad_files', checks };
  }
  if (!check(
    'content hash',
    recomputed === payload.policyHash,
    recomputed === payload.policyHash
      ? 'policy_hash matches file bytes'
      : `recomputed ${recomputed} != declared ${payload.policyHash}`,
  )) {
    return { ok: false, reason: 'hash_mismatch', checks };
  }

  return { ok: true, reason: 'ok', checks, payload };
}

function ensureDir(dir) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

function atomicWriteJson(file, obj) {
  const tmp = `${file}.tmp-${process.pid}`;
  writeFileSync(tmp, `${JSON.stringify(obj, null, 2)}\n`, 'utf8');
  renameSync(tmp, file);
}

export function packPath(dir, packId) {
  const safe = String(packId).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 128);
  return join(dir, `${safe}.json`);
}

/** Persist a signed pack into the registry. Returns absolute path. */
export function storePack(dir, pack) {
  if (!pack?.packId || !pack?.payload?.policyHash) {
    throw new Error('pack must include packId and payload.policyHash');
  }
  ensureDir(dir);
  const path = packPath(dir, pack.packId);
  atomicWriteJson(path, pack);
  return path;
}

export function loadPack(dir, packId) {
  const path = packPath(dir, packId);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function listPacks(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json') && f !== ACTIVE_POINTER)
    .sort()
    .map((f) => {
      try {
        const pack = JSON.parse(readFileSync(join(dir, f), 'utf8'));
        return {
          packId: pack.packId,
          policyHash: pack.payload?.policyHash ?? null,
          policyVersion: pack.payload?.policyVersion ?? null,
          keyId: pack.keyId ?? null,
          signedAt: pack.signedAt ?? null,
          schema: pack.schema ?? null,
          file: f,
        };
      } catch {
        return { packId: f, error: 'unreadable' };
      }
    });
}

export function readActive(dir) {
  const path = join(dir, ACTIVE_POINTER);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Promote a verified pack: write active pointer with provenance.
 * Caller must verify first when mode is enforce.
 */
export function writeActivePointer(dir, {
  pack,
  actor,
  verified,
  mode,
}) {
  ensureDir(dir);
  const pointer = {
    packId: pack.packId,
    policyHash: pack.payload.policyHash,
    policyVersion: pack.payload.policyVersion,
    keyId: pack.keyId,
    signedAt: pack.signedAt,
    signature: pack.signature,
    promotedAt: new Date().toISOString(),
    promotedBy: actor,
    verified: verified === true,
    mode,
  };
  atomicWriteJson(join(dir, ACTIVE_POINTER), pointer);
  storePack(dir, pack);
  return pointer;
}

/**
 * Build + sign a pack from a live policy directory using env keys.
 * Returns the signed envelope (does not store).
 */
export function buildAndSignFromDir(policyDir, env = process.env) {
  const priv = loadPrivateKeyFromEnv(env);
  if (!priv) throw new Error('POLICY_PACK_PRIVATE_KEY is not configured');
  const keyId = env.POLICY_PACK_KEY_ID || 'aim-policy-default';
  const payload = buildPayloadFromDir(policyDir);
  return signPayload(payload, priv, { keyId });
}

/**
 * Redacted public view of a pack (no file contents).
 */
export function publicPackView(pack, verifyResult = null) {
  if (!pack) return null;
  return {
    schema: pack.schema,
    alg: pack.alg,
    packId: pack.packId,
    keyId: pack.keyId,
    signedAt: pack.signedAt,
    policyVersion: pack.payload?.policyVersion ?? null,
    policyHash: pack.payload?.policyHash ?? null,
    files: (pack.payload?.files ?? []).map((f) => ({
      name: f.name,
      sha256: f.sha256,
      size: f.size,
    })),
    hasSignature: typeof pack.signature === 'string' && pack.signature.length > 0,
    verification: verifyResult
      ? { ok: verifyResult.ok, reason: verifyResult.reason, checks: verifyResult.checks }
      : null,
  };
}

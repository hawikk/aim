/**
 * Signed collector build identity verification.
 *
 * Collectors report a `build` block in the batch envelope:
 *   { package, version, tool, git_sha?, built_at?, key_id?, sig? }
 *
 * When INGEST_ATTESTATION_MODE is:
 *   - off     (default): do not verify; metrics still optional
 *   - shadow: verify and count, never reject the batch
 *   - enforce: reject with 403 when signature is missing/invalid
 *
 * Trust chain: docs/security/collector-build-attestation.md
 */

import { createPublicKey, verify, type KeyObject } from "node:crypto";

export type AttestationMode = "off" | "shadow" | "enforce";

export interface BuildIdentity {
  package: string;
  version: string;
  tool: string;
  git_sha?: string;
  built_at?: string;
  key_id?: string;
  sig?: string;
}

export interface AttestationControl {
  mode: AttestationMode;
  /**
   * Map of key_id → raw 32-byte Ed25519 public key.
   * Empty when no keys configured (enforce then rejects all signed claims).
   */
  publicKeys: Map<string, Buffer>;
}

export type AttestationVerdict =
  | { status: "skipped" }
  | { status: "valid"; keyId: string; build: BuildIdentity }
  | { status: "unsigned"; build?: BuildIdentity; reason: string }
  | { status: "invalid"; build?: BuildIdentity; reason: string };

export const ATTEST_MESSAGE_VERSION = "AIM-BUILD-ATTEST-V1";

const MAX_FIELD = 256;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Build the exact bytes the release pipeline signed. */
export function canonicalBuildMessage(build: BuildIdentity): Buffer {
  const lines = [
    ATTEST_MESSAGE_VERSION,
    `package=${build.package || "-"}`,
    `version=${build.version || "-"}`,
    `tool=${build.tool || "-"}`,
    `git_sha=${build.git_sha || "-"}`,
    `built_at=${build.built_at || "-"}`,
  ];
  return Buffer.from(lines.join("\n") + "\n", "utf8");
}

function b64urlDecode(input: string): Buffer | null {
  try {
    const padded = input + "=".repeat((4 - (input.length % 4)) % 4);
    return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  } catch {
    return null;
  }
}

function ed25519PublicKeyFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${raw.length}`);
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

/**
 * Parse INGEST_ATTESTATION_PUBKEYS.
 * Format: `key_id:base64url(raw32)[,key_id2:base64url(...)]`
 */
export function parseAttestationPublicKeys(raw: string | undefined): Map<string, Buffer> {
  const map = new Map<string, Buffer>();
  if (!raw || !raw.trim()) return map;
  for (const entry of raw.split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const colon = trimmed.indexOf(":");
    if (colon <= 0) {
      throw new Error(
        `invalid INGEST_ATTESTATION_PUBKEYS entry ${trimmed!}: expected key_id:base64url`,
      );
    }
    const keyId = trimmed.slice(0, colon).trim();
    const b64 = trimmed.slice(colon + 1).trim();
    const buf = b64urlDecode(b64);
    if (!buf || buf.length !== 32) {
      throw new Error(
        `invalid INGEST_ATTESTATION_PUBKEYS key ${keyId}: expected 32-byte Ed25519 public key`,
      );
    }
    map.set(keyId, buf);
  }
  return map;
}

export function parseAttestationMode(raw: string | undefined): AttestationMode {
  const v = (raw ?? "off").trim().toLowerCase();
  if (v === "off" || v === "shadow" || v === "enforce") return v;
  throw new Error(`invalid INGEST_ATTESTATION_MODE: ${raw} (expected off|shadow|enforce)`);
}

/**
 * Validate optional `build` object from the collector envelope.
 * Returns undefined when absent; error string when present but malformed.
 */
export function parseBuildIdentity(
  value: unknown,
): { build?: BuildIdentity } | { error: string } {
  if (value === undefined || value === null) {
    return {};
  }
  if (typeof value !== "object" || Array.isArray(value)) {
    return { error: "collector.build must be an object" };
  }
  const raw = value as Record<string, unknown>;
  const required = ["package", "version", "tool"] as const;
  const build: BuildIdentity = {
    package: "",
    version: "",
    tool: "",
  };
  for (const key of required) {
    const v = raw[key];
    if (typeof v !== "string" || v.length === 0 || v.length > MAX_FIELD) {
      return { error: `collector.build.${key} must be a string of 1-${MAX_FIELD} chars` };
    }
    build[key] = v;
  }
  for (const key of ["git_sha", "built_at", "key_id", "sig"] as const) {
    const v = raw[key];
    if (v === undefined || v === null) continue;
    if (typeof v !== "string" || v.length === 0 || v.length > 2048) {
      return { error: `collector.build.${key} must be a non-empty string` };
    }
    build[key] = v;
  }
  return { build };
}

/**
 * Verify a build identity against configured public keys.
 * Does not consult mode — callers decide reject vs metric.
 */
export function verifyBuildAttestation(
  build: BuildIdentity | undefined,
  publicKeys: Map<string, Buffer>,
): AttestationVerdict {
  if (!build) {
    return { status: "unsigned", reason: "collector.build missing" };
  }
  if (!build.sig || !build.key_id) {
    return { status: "unsigned", build, reason: "collector.build missing key_id/sig" };
  }
  const rawKey = publicKeys.get(build.key_id);
  if (!rawKey) {
    return {
      status: "invalid",
      build,
      reason: `unknown attestation key_id: ${build.key_id}`,
    };
  }
  const sig = b64urlDecode(build.sig);
  if (!sig || sig.length !== 64) {
    return { status: "invalid", build, reason: "collector.build.sig is not a 64-byte Ed25519 signature" };
  }
  let key: KeyObject;
  try {
    key = ed25519PublicKeyFromRaw(rawKey);
  } catch (err) {
    return {
      status: "invalid",
      build,
      reason: `attestation key material error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  const message = canonicalBuildMessage(build);
  const ok = verify(null, message, key, sig);
  if (!ok) {
    return { status: "invalid", build, reason: "collector.build signature verification failed" };
  }
  return { status: "valid", keyId: build.key_id, build };
}

/**
 * Apply mode: when enforce, map non-valid to a 403 reason string.
 * When off, always skipped. When shadow, verify for metrics only.
 */
export function evaluateAttestation(
  build: BuildIdentity | undefined,
  control: AttestationControl,
): { verdict: AttestationVerdict; rejectReason?: string } {
  if (control.mode === "off") {
    return { verdict: { status: "skipped" } };
  }
  const verdict = verifyBuildAttestation(build, control.publicKeys);
  if (control.mode === "enforce" && verdict.status !== "valid") {
    const reason =
      verdict.status === "unsigned" || verdict.status === "invalid"
        ? verdict.reason
        : "collector build attestation required";
    return { verdict, rejectReason: reason };
  }
  return { verdict };
}

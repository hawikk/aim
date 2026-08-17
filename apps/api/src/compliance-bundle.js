// Signed compliance evidence bundles (AIM-99).
//
// A bundle is the immutable, regulator-ready form of the compliance report:
//   { kind, version, report, chainAnchor, bundleHash, signature, auditRecord }
//
// Evidence chain, both directions:
//   1. bundleHash = sha256(canonicalJSON({kind, version, report, chainAnchor}))
//      — any edit to the report or the chain anchor changes the hash.
//   2. chainAnchor carries the audit chain's head seq+seal at export time —
//      the bundle is pinned to a specific audit-trail state.
//   3. The export itself is appended to the audit chain as a
//      `compliance.export` event carrying bundleHash — the chain seals the
//      bundle, and verifyBundle() requires that sealed record to exist.
//   4. signature = HMAC-SHA256(AUDIT_HMAC_KEY, bundleHash) — the same key
//      that seals the audit trail, so one secret verifies both.
//
// Snapshots reuse the same payload/hash construction (kind
// 'aim-compliance-snapshot') so one verifier covers exports and history.
import { createHash, createHmac } from 'node:crypto';
import { AuditLog } from '../../../packages/audit/src/audit-log.ts';

export const BUNDLE_KIND = 'aim-compliance-evidence-bundle';
export const SNAPSHOT_KIND = 'aim-compliance-snapshot';

// Deterministic JSON — same semantics as packages/audit canonical(): object
// keys sorted recursively, undefined object values omitted. Duplicated here
// (not exported from the audit package) so the evidence layer doesn't depend
// on the audit package's internals beyond the verifier.
export function canonical(value) {
  if (value === undefined) return 'null'; // only reachable inside arrays
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}

export function hashEvidencePayload(payload) {
  return createHash('sha256').update(canonical(payload), 'utf8').digest('hex');
}

export function signBundleHash(key, bundleHash) {
  return createHmac('sha256', key).update(bundleHash, 'utf8').digest('hex');
}

// Assemble the signed bundle around an already-built report.
//   chainAnchor: { enabled, ok, records, headSeq, headSeal } (from auditHead
//   merged with the chain verification result already in the report)
//   appendAudit: (actor, action, resource, detail) => audit record | null
//   signKey: HMAC secret or null (no signature when unset)
export function buildBundle({ report, chainAnchor, actor, appendAudit, signKey }) {
  const payload = { kind: BUNDLE_KIND, version: 1, report, chainAnchor };
  const bundleHash = hashEvidencePayload(payload);
  const record = appendAudit(actor, 'compliance.export', 'compliance/bundle', {
    bundleHash,
    periodFrom: report.period.from,
    periodTo: report.period.to,
    frameworks: report.frameworks.map((f) => f.id),
  });
  return {
    ...payload,
    bundleHash,
    signature: signKey ? signBundleHash(signKey, bundleHash) : null,
    auditRecord: record ? { seq: record.seq, seal: record.seal } : null,
  };
}

// Verify a bundle against the audit hash chain. Returns
// { ok, checks: [{ name, ok, detail }] } — every check is reported, never
// short-circuited silently, so an auditor sees exactly what passed.
export function verifyBundle(bundle, { path, key }) {
  const checks = [];
  const check = (name, ok, detail) => { checks.push({ name, ok, detail }); return ok; };

  const payload = bundle && { kind: bundle.kind, version: bundle.version, report: bundle.report, chainAnchor: bundle.chainAnchor };
  check('structure', !!bundle && bundle.kind === BUNDLE_KIND && !!bundle.report && typeof bundle.bundleHash === 'string',
    bundle?.kind ?? 'missing/invalid bundle');
  if (!checks[0].ok) return { ok: false, checks };

  check('content hash', hashEvidencePayload(payload) === bundle.bundleHash,
    'sha256 over canonical {kind,version,report,chainAnchor} must equal bundleHash');

  if (key && bundle.signature) {
    check('signature', signBundleHash(key, bundle.bundleHash) === bundle.signature,
      'HMAC-SHA256(key, bundleHash) must equal signature');
  } else {
    check('signature', false, bundle.signature ? 'no key provided' : 'bundle is unsigned (audit trail was not configured at export time)');
  }

  if (path && key) {
    const chain = AuditLog.verify({ path, key });
    check('audit chain', chain.ok, chain.ok ? `${chain.count} records verified` : `${chain.reason} at seq ${chain.failedSeq}`);

    const links = AuditLog.query({ path, action: 'compliance.export' })
      .filter((r) => r.detail?.bundleHash === bundle.bundleHash);
    const link = links.find((r) => !bundle.auditRecord || (r.seq === bundle.auditRecord.seq && r.seal === bundle.auditRecord.seal));
    check('export sealed in chain', !!link, link
      ? `compliance.export record at seq ${link.seq} seals this bundleHash`
      : 'no compliance.export record carries this bundleHash (bundle not exported by this platform, or chain truncated)');

    if (link && bundle.chainAnchor?.headSeq) {
      check('chain anchor', bundle.chainAnchor.headSeq <= link.seq,
        `anchor head seq ${bundle.chainAnchor.headSeq} must precede the export record seq ${link.seq}`);
    }
  } else {
    check('audit chain', false, 'AUDIT_LOG_PATH / AUDIT_HMAC_KEY not provided');
    check('export sealed in chain', false, 'cannot check without the audit trail');
  }

  return { ok: checks.every((c) => c.ok), checks };
}

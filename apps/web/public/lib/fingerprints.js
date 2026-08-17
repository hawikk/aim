/* — extract redacted secret fingerprints from finding
 * evidence and optionally annotate them with fixture-registry cluster hints.
 *
 * Findings never carry matched content; secret/pii match_flags entries carry
 * a keyed, truncated HMAC fingerprint instead (schema v1.8). The guardrail
 * evidence shape puts the evaluated event field under evidence.matched[].actual
 * — for detector rules that is the event's match_flags array. This walks that
 * structure and returns the deduped fingerprint list for display: enough for
 * an analyst to prove and dedupe a finding without ever seeing the secret.
 *
 * when a fingerprint is in the company fixture allowlist (offline
 * HMAC of known dead keys with AIM_HASH_SALT), suggest incident cluster A
 * (known synthetic / fixture). The registry stores only
 * detector+fingerprint+label+source — never raw secrets.
 */

export function extractFingerprints(evidence) {
  const out = [];
  const seen = new Set();
  const walk = (node) => {
    if (Array.isArray(node)) return node.forEach(walk);
    if (!node || typeof node !== 'object') return;
    if (typeof node.detector === 'string' && typeof node.fingerprint === 'string') {
      const key = `${node.detector}|${node.fingerprint}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push({
          detector: node.detector,
          fingerprint: node.fingerprint,
          offset: Number.isInteger(node.offset) ? node.offset : null,
          surface: typeof node.surface === 'string' ? node.surface : null,
        });
      }
      return; // a fingerprint entry is a leaf — never descend into it
    }
    Object.values(node).forEach(walk);
  };
  walk(evidence?.matched);
  return out.sort(
    (a, b) => a.detector.localeCompare(b.detector) || a.fingerprint.localeCompare(b.fingerprint)
  );
}

/** Index a fixture-fingerprint-registry.json payload for O(1) lookup. */
export function indexFixtureRegistry(registry) {
  const byDetectorFp = new Map();
  const byFp = new Map();
  const entries = Array.isArray(registry?.entries) ? registry.entries : [];
  for (const e of entries) {
    if (typeof e?.detector !== 'string' || typeof e?.fingerprint !== 'string') continue;
    const hit = {
      detector: e.detector,
      fingerprint: e.fingerprint,
      label: typeof e.label === 'string' ? e.label : e.fingerprint,
      source: typeof e.source === 'string' ? e.source : null,
      cluster: typeof e.cluster_hint === 'string' ? e.cluster_hint : 'A',
    };
    byDetectorFp.set(`${e.detector}|${e.fingerprint}`, hit);
    // First label wins for fingerprint-only collision (rare across detectors).
    if (!byFp.has(e.fingerprint)) byFp.set(e.fingerprint, hit);
  }
  return { byDetectorFp, byFp, saltId: registry?.salt_id ?? null };
}

/** Look up a fixture registry hit for a detector+fingerprint pair. */
export function fixtureClusterHint(detector, fingerprint, index) {
  if (!index) return null;
  return (
    index.byDetectorFp.get(`${detector}|${fingerprint}`) ||
    index.byFp.get(fingerprint) ||
    null
  );
}

/** Annotate extractFingerprints() rows with optional fixtureHint. */
export function annotateWithFixtureHints(fps, index) {
  if (!index || !Array.isArray(fps)) return fps ?? [];
  return fps.map((p) => {
    const hit = fixtureClusterHint(p.detector, p.fingerprint, index);
    if (!hit) return p;
    return {
      ...p,
      fixtureHint: {
        label: hit.label,
        source: hit.source,
        cluster: hit.cluster,
      },
    };
  });
}

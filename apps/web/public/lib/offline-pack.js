/* — Auditor offline evidence pack v2.
 *
 * Pure, DOM-free helpers that assemble a complete compliance evidence pack a
 * non-engineer auditor can take offline:
 *   - human-readable README + SUMMARY
 *   - live report JSON
 *   - regulator CSV
 * - signed evidence bundle
 *   - SHA256SUMS (gnu coreutils `sha256sum -c` compatible)
 *   - MANIFEST.json (machine-readable inventory + pack hash)
 *
 * Packaged as an uncompressed ZIP (store method only — no third-party zip
 * library; supply-chain posture matches the rest of apps/web).
 *
 * Checksums are content hashes any auditor can recompute with stock tools.
 * Full cryptographic chain verification still uses
 * scripts/verify-compliance-bundle.mjs (ops-held AUDIT_HMAC_KEY) — the pack
 * points at that path without requiring it for integrity of the files.
 */

export const PACK_KIND = 'aim-compliance-offline-pack';
export const PACK_VERSION = 2;

const te = new TextEncoder();

/* ---------- hashing ---------- */

/** Encode string or Uint8Array as bytes. */
export function toBytes(data) {
  if (data instanceof Uint8Array) return data;
  if (typeof data === 'string') return te.encode(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  throw new TypeError('toBytes expects string | Uint8Array | ArrayBuffer');
}

/**
 * SHA-256 hex digest. Uses Web Crypto when available (browser + modern Node),
 * falls back to node:crypto so pure unit tests stay environment-agnostic.
 * @param {string|Uint8Array|ArrayBuffer} data
 * @returns {Promise<string>} lowercase hex
 */
export async function sha256Hex(data) {
  const bytes = toBytes(data);
  if (globalThis.crypto?.subtle) {
    // subtle.digest wants a BufferSource; pass a clean ArrayBuffer slice.
    const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    const digest = await globalThis.crypto.subtle.digest('SHA-256', ab);
    return bytesToHex(new Uint8Array(digest));
  }
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(bytes).digest('hex');
}

function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

/* ---------- CRC-32 (ZIP) ---------- */

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c >>> 0;
  }
  return table;
})();

/** IEEE CRC-32 of a byte array (ZIP local-header checksum). */
export function crc32(data) {
  const bytes = toBytes(data);
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

/* ---------- text builders ---------- */

/**
 * GNU `sha256sum` / `sha256sum -c` compatible listing.
 * Two spaces between hash and name (text mode); names are relative, no leading `./`.
 * @param {Array<{ name: string, sha256: string }>} entries
 */
export function buildChecksumsFile(entries) {
  return entries
    .map((e) => `${e.sha256}  ${e.name}`)
    .join('\n') + (entries.length ? '\n' : '');
}

/**
 * Stable pack ZIP filename for a reporting period.
 * @param {{ from?: string, to?: string }} [period]
 * @param {string|Date} [when]
 */
export function packFilename(period = {}, when = new Date()) {
  const d = when instanceof Date ? when : new Date(when);
  const stamp = Number.isFinite(d.getTime())
    ? d.toISOString().slice(0, 10).replace(/-/g, '')
    : 'undated';
  const from = String(period.from ?? '').slice(0, 10).replace(/-/g, '') || 'start';
  const to = String(period.to ?? '').slice(0, 10).replace(/-/g, '') || 'end';
  return `aim-compliance-offline-pack_${from}_${to}_${stamp}.zip`;
}

/**
 * Executive summary a non-engineer auditor can read offline.
 * @param {object} report  GET /api/compliance/report body (or bundle.report)
 * @param {{ exportedAt?: string, bundleHash?: string|null }} [meta]
 */
export function buildSummaryText(report, meta = {}) {
  const r = report && typeof report === 'object' ? report : {};
  const period = r.period ?? {};
  const chain = r.auditChain ?? {};
  const coverage = r.coverage ?? {};
  const totalFindings = Array.isArray(r.rules)
    ? r.rules.reduce((n, rule) => n + (Number(rule?.findings?.total) || 0), 0)
    : 0;
  const openFindings = Array.isArray(r.rules)
    ? r.rules.reduce((n, rule) => n + (Number(rule?.findings?.open) || 0), 0)
    : 0;
  const frameworks = Array.isArray(r.frameworks) ? r.frameworks : [];
  const lines = [
    'AI Monitoring — Compliance evidence pack (SUMMARY)',
    '==================================================',
    '',
    `Exported at:     ${meta.exportedAt ?? r.generatedAt ?? 'unknown'}`,
    `Period:          ${period.from ?? '—'} → ${period.to ?? '—'}`,
    `Policy version:  ${r.policy?.version ?? '—'}  hash ${shortHash(r.policy?.contentHash)}`,
    `Mapping version: ${r.mapping?.version ?? '—'}  hash ${shortHash(r.mapping?.contentHash)}`,
    `Bundle hash:     ${meta.bundleHash ? shortHash(meta.bundleHash) : '(not sealed / unsigned export)'}`,
    '',
    'Audit chain',
    '-----------',
    chain.enabled
      ? (chain.ok
        ? `VERIFIED — ${chain.records ?? '?'} records`
        : `FAILED — ${chain.reason ?? 'unknown reason'}`)
      : 'Not configured on this deployment',
    '',
    'Findings in period',
    '------------------',
    `Total: ${totalFindings}`,
    `Open:  ${openFindings}`,
    '',
    'Rule coverage',
    '-------------',
    coverage.ok
      ? `Complete — ${coverage.rules ?? '?'} rules mapped`
      : `GAPS — ${(coverage.gaps ?? []).length} gap(s)${(coverage.gaps ?? []).length
        // Auditor-facing framework labels: soc2 → SOC2, eu-ai-act → EU-AI-ACT.
        ? ': ' + coverage.gaps.map((g) => {
          const fw = String(g.framework ?? g.frameworkId ?? '').trim();
          const fwLabel = fw ? fw.toUpperCase() : '—';
          return `${g.ruleId}/${fwLabel}`;
        }).join('; ')
        : ''}`,
    '',
    'Frameworks',
    '----------',
  ];
  if (!frameworks.length) {
    lines.push('(none in report)');
  } else {
    for (const fw of frameworks) {
      const controls = Array.isArray(fw.controls) ? fw.controls : [];
      const withFindings = controls.filter((c) => (c.findings?.total ?? 0) > 0).length;
      lines.push(`- ${fw.name ?? fw.id}: ${controls.length} control(s), ${withFindings} with findings`);
    }
  }
  lines.push('', 'Scoping note', '------------', String(r.scopingNote ?? '(none)'), '');
  return lines.join('\n');
}

/**
 * README with offline verification steps that do not require engineering tools.
 * Full chain verification is documented as an optional ops path.
 */
export function buildReadmeText({ period, exportedAt, files, packSha256 } = {}) {
  const fileList = (files ?? []).map((f) => `  - ${f.name}  (${f.sha256?.slice(0, 12) ?? '?'}…)`).join('\n');
  return [
    'AI Monitoring — Offline compliance evidence pack v2',
    '===================================================',
    '',
    'Who this is for',
    '---------------',
    'External or internal auditors who need a complete, self-contained',
    'evidence package without live product access. No engineer required',
    'to open or integrity-check the files.',
    '',
    'What is in this ZIP',
    '-------------------',
    fileList || '  (see MANIFEST.json)',
    '',
    'Period covered',
    '--------------',
    `  From: ${period?.from ?? '—'}`,
    `  To:   ${period?.to ?? '—'}`,
    `  Pack exported at: ${exportedAt ?? '—'}`,
    packSha256 ? `  Pack SHA-256 (this ZIP body before packaging note): see MANIFEST.json` : '',
    '',
    'Step 1 — Integrity check (no special tools)',
    '-------------------------------------------',
    'On macOS / Linux (GNU coreutils or equivalent):',
    '',
    '  sha256sum -c SHA256SUMS',
    '',
    'On Windows (PowerShell 7+):',
    '',
    '  Get-FileHash -Algorithm SHA256 .\\report.json',
    '  # compare each hash to the matching line in SHA256SUMS',
    '',
    'Every file listed in SHA256SUMS must report OK. A single FAIL means the',
    'pack was altered after export — request a fresh pack from the operator.',
    '',
    'Step 2 — Read the evidence',
    '--------------------------',
    '  SUMMARY.txt              — one-page executive summary',
    '  report.json              — full structured compliance report',
    '  report.csv               — same numbers in spreadsheet form',
    ' evidence-bundle.json — signed, audit-chain-anchored bundle',
    '  MANIFEST.json            — machine inventory + pack metadata',
    '',
    'Step 3 — Optional: cryptographic chain verification (ops)',
    '--------------------------------------------------------',
    'The signed evidence bundle can be verified against the live audit hash',
    'chain by an operator who holds AUDIT_HMAC_KEY and AUDIT_LOG_PATH:',
    '',
    '  AUDIT_LOG_PATH=... AUDIT_HMAC_KEY=... \\',
    '    node scripts/verify-compliance-bundle.mjs evidence-bundle.json',
    '',
    'This step is stronger than SHA-256 file integrity: it proves the bundle',
    'was sealed by this platform and still matches the audit trail. It is not',
    'required for an auditor to open and review the pack contents.',
    '',
    'Privacy',
    '-------',
    'This pack contains compliance posture, rule mappings, finding counts and',
    'metadata already exposed by the Compliance report API. It does not add',
    'prompt text, response text, or matched content beyond what the signed',
    'bundle already carries from the platform export path.',
    '',
    'No-content posture (auditor one-pager + offline hooks)',
    '------------------------------------------------------',
    'Product repo (for operators who can access source):',
    '  docs/privacy/auditor-privacy-overview.md',
    '  Continuous no-content gate:',
    '    python3 scripts/no_content_egress.py --check',
    '  Details: docs/security/no-content-egress.md',
    'This ZIP does not embed those scripts; they live in the product repo / CI.',
    '',
    `Pack kind: ${PACK_KIND}  version: ${PACK_VERSION}`,
    '',
  ].filter((line) => line !== null && line !== undefined).join('\n');
}

function shortHash(h) {
  if (h == null || h === '') return '—';
  const s = String(h);
  return s.length > 12 ? `${s.slice(0, 12)}…` : s;
}

/* ---------- pack assembly ---------- */

/**
 * Build the offline pack file set (not yet zipped).
 *
 * @param {{
 *   report: object,
 *   csvText: string,
 *   bundle: object|null,
 *   period?: { from?: string, to?: string },
 *   exportedAt?: string,
 * }} input
 * @returns {Promise<{
 *   files: Array<{ name: string, text: string, sha256: string }>,
 *   checksumsText: string,
 *   manifest: object,
 *   packSha256: string,
 * }>}
 */
export async function buildOfflinePackFiles(input) {
  const report = input.report && typeof input.report === 'object' ? input.report : {};
  const period = input.period ?? report.period ?? {};
  const exportedAt = input.exportedAt ?? report.generatedAt ?? new Date().toISOString();
  const bundle = input.bundle && typeof input.bundle === 'object' ? input.bundle : null;
  const csvText = typeof input.csvText === 'string' ? input.csvText : '';

  const reportJson = `${JSON.stringify(report, null, 2)}\n`;
  const bundleJson = bundle
    ? `${JSON.stringify(bundle, null, 2)}\n`
    : `${JSON.stringify({
      kind: 'aim-compliance-evidence-bundle',
      note: 'Bundle was unavailable at export time. Use report.json + SHA256SUMS for integrity; re-export when the signed bundle endpoint is healthy.',
      report,
    }, null, 2)}\n`;

  const summaryText = buildSummaryText(report, {
    exportedAt,
    bundleHash: bundle?.bundleHash ?? null,
  });

  // Hash content files first (README/MANIFEST/SHA256SUMS depend on them).
  const contentSpecs = [
    { name: 'SUMMARY.txt', text: summaryText },
    { name: 'report.json', text: reportJson },
    { name: 'report.csv', text: csvText.endsWith('\n') ? csvText : `${csvText}\n` },
    { name: 'evidence-bundle.json', text: bundleJson },
  ];
  const hashed = [];
  for (const spec of contentSpecs) {
    hashed.push({ name: spec.name, text: spec.text, sha256: await sha256Hex(spec.text) });
  }

  const checksumsText = buildChecksumsFile(hashed.map((f) => ({ name: f.name, sha256: f.sha256 })));
  const checksumsSha = await sha256Hex(checksumsText);

  const readmeText = buildReadmeText({
    period,
    exportedAt,
    files: hashed,
  });
  const readmeSha = await sha256Hex(readmeText);

  // MANIFEST lists content files + SHA256SUMS + README (not itself — avoids self-hash churn).
  const manifest = {
    kind: PACK_KIND,
    version: PACK_VERSION,
    exportedAt,
    period: { from: period.from ?? null, to: period.to ?? null },
    files: [
      ...hashed.map((f) => ({ name: f.name, sha256: f.sha256, bytes: toBytes(f.text).byteLength })),
      { name: 'SHA256SUMS', sha256: checksumsSha, bytes: toBytes(checksumsText).byteLength },
      { name: 'README.txt', sha256: readmeSha, bytes: toBytes(readmeText).byteLength },
    ],
    evidence: {
      bundleHash: bundle?.bundleHash ?? null,
      bundleSignaturePresent: Boolean(bundle?.signature),
      auditChain: report.auditChain ?? null,
      policyHash: report.policy?.contentHash ?? null,
      mappingHash: report.mapping?.contentHash ?? null,
    },
    verify: {
      integrity: 'sha256sum -c SHA256SUMS',
      chain: 'node scripts/verify-compliance-bundle.mjs evidence-bundle.json (requires AUDIT_HMAC_KEY + AUDIT_LOG_PATH)',
      noContent: 'python3 scripts/no_content_egress.py --check (product repo / CI; see docs/privacy/auditor-privacy-overview.md)',
      privacyOverview: 'docs/privacy/auditor-privacy-overview.md',
    },
  };
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
  const manifestSha = await sha256Hex(manifestText);

  const files = [
    { name: 'README.txt', text: readmeText, sha256: readmeSha },
    { name: 'SUMMARY.txt', text: summaryText, sha256: hashed[0].sha256 },
    { name: 'report.json', text: reportJson, sha256: hashed[1].sha256 },
    { name: 'report.csv', text: contentSpecs[2].text, sha256: hashed[2].sha256 },
    { name: 'evidence-bundle.json', text: bundleJson, sha256: hashed[3].sha256 },
    { name: 'SHA256SUMS', text: checksumsText, sha256: checksumsSha },
    { name: 'MANIFEST.json', text: manifestText, sha256: manifestSha },
  ];

  // Canonical pack hash = SHA-256 of SHA256SUMS (stable inventory of content files).
  return {
    files,
    checksumsText,
    manifest,
    packSha256: checksumsSha,
  };
}

/**
 * High-level: build pack files and zip them.
 * @returns {Promise<{ filename: string, zip: Uint8Array, files: object[], packSha256: string, manifest: object }>}
 */
export async function buildOfflinePack(input) {
  const { files, packSha256, manifest } = await buildOfflinePackFiles(input);
  const zip = buildZipStore(files.map((f) => ({ name: f.name, data: f.text })));
  const period = input.period ?? input.report?.period ?? {};
  return {
    filename: packFilename(period, input.exportedAt ?? new Date()),
    zip,
    files,
    packSha256,
    manifest,
  };
}

/* ---------- ZIP (store method, no compression, no deps) ---------- */

/**
 * Build an uncompressed ZIP archive (method 0 / store).
 * @param {Array<{ name: string, data: string|Uint8Array }>} entries
 * @returns {Uint8Array}
 */
export function buildZipStore(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBytes = te.encode(entry.name);
    if (nameBytes.length > 0xffff) {
      throw new Error(`ZIP entry name too long: ${entry.name}`);
    }
    const data = toBytes(entry.data);
    if (data.byteLength > 0xffffffff) {
      throw new Error(`ZIP entry too large: ${entry.name}`);
    }
    const crc = crc32(data);
    const size = data.byteLength;

    // Local file header (30 bytes + name + data)
    const local = new Uint8Array(30 + nameBytes.length + size);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true); // local file header signature
    lv.setUint16(4, 20, true);         // version needed
    lv.setUint16(6, 0, true);          // flags
    lv.setUint16(8, 0, true);          // method = store
    lv.setUint16(10, 0, true);         // mod time
    lv.setUint16(12, 0, true);         // mod date
    lv.setUint32(14, crc, true);
    lv.setUint32(18, size, true);      // compressed size
    lv.setUint32(22, size, true);      // uncompressed size
    lv.setUint16(26, nameBytes.length, true);
    lv.setUint16(28, 0, true);         // extra length
    local.set(nameBytes, 30);
    local.set(data, 30 + nameBytes.length);

    // Central directory header (46 bytes + name)
    const central = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, 0x02014b50, true); // central file header signature
    cv.setUint16(4, 20, true);         // version made by
    cv.setUint16(6, 20, true);         // version needed
    cv.setUint16(8, 0, true);          // flags
    cv.setUint16(10, 0, true);         // method
    cv.setUint16(12, 0, true);         // mod time
    cv.setUint16(14, 0, true);         // mod date
    cv.setUint32(16, crc, true);
    cv.setUint32(20, size, true);
    cv.setUint32(24, size, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint16(30, 0, true);         // extra
    cv.setUint16(32, 0, true);         // comment
    cv.setUint16(34, 0, true);         // disk start
    cv.setUint16(36, 0, true);         // int attrs
    cv.setUint32(38, 0, true);         // ext attrs
    cv.setUint32(42, offset, true);    // relative offset of local header
    central.set(nameBytes, 46);

    locals.push(local);
    centrals.push(central);
    offset += local.length;
  }

  const centralSize = centrals.reduce((n, c) => n + c.length, 0);
  const centralOffset = offset;

  // End of central directory (22 bytes, no comment)
  const end = new Uint8Array(22);
  const ev = new DataView(end.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(4, 0, true); // disk
  ev.setUint16(6, 0, true); // disk with central dir
  ev.setUint16(8, entries.length, true);
  ev.setUint16(10, entries.length, true);
  ev.setUint32(12, centralSize, true);
  ev.setUint32(16, centralOffset, true);
  ev.setUint16(20, 0, true); // comment length

  const total = offset + centralSize + end.length;
  const out = new Uint8Array(total);
  let pos = 0;
  for (const local of locals) {
    out.set(local, pos);
    pos += local.length;
  }
  for (const central of centrals) {
    out.set(central, pos);
    pos += central.length;
  }
  out.set(end, pos);
  return out;
}

/**
 * Trigger a browser download of a Blob/Uint8Array/string.
 * DOM-dependent — not used in pure unit tests.
 */
export function triggerDownload(filename, body, mime = 'application/octet-stream') {
  const blob = body instanceof Blob
    ? body
    : new Blob([body], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

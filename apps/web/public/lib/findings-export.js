/* — Findings export for SOC handoff (CSV/JSON).
 *
 * Pure, DOM-free helpers so node:test can lock three contracts:
 *   1. Export query mirrors the visible findings filters (status/severity/rule).
 *   2. Payload is metadata-only — no prompt/response/matched content.
 *   3. CSV and JSON export the same column set the API CSV already uses
 *      (apps/api FINDINGS_CSV_COLS), so formats stay interchangeable.
 *
 * The API already enforces the privacy gate and formula-safe CSV. The UI is
 * responsible for pointing both export buttons at the *current* filter set
 * and for stripping JSON to the metadata column set before download (the
 * JSON list endpoint still carries detector evidence for the inbox UI).
 */

/** Same cap the findings console list uses. */
export const EXPORT_LIMIT = 200;

/**
 * Columns for a SOC handoff row — mirrors API FINDINGS_CSV_COLS exactly.
 * Order is stable so CSV/JSON consumers can treat either format the same.
 */
export const EXPORT_COLUMNS = Object.freeze([
  { key: 'findingId', label: 'finding_id' },
  { key: 'detectedAt', label: 'detected_at' },
  { key: 'ruleId', label: 'rule_id' },
  { key: 'severity', label: 'severity' },
  { key: 'title', label: 'title' },
  { key: 'status', label: 'status' },
  { key: 'subject', label: 'subject' },
  { key: 'decision', label: 'decision' },
  { key: 'eventId', label: 'event_id' },
  { key: 'triagedBy', label: 'triaged_by' },
  { key: 'triagedAt', label: 'triaged_at' },
  { key: 'triageNote', label: 'triage_note' },
]);

export const EXPORT_FIELD_KEYS = Object.freeze(EXPORT_COLUMNS.map((c) => c.key));

/**
 * Keys (and key-name fragments) that must never appear on an export row.
 * Matched case-insensitively against every object key in the payload tree.
 * Intentionally broad: SOC handoff is metadata-only by product policy.
 */
export const FORBIDDEN_KEY_PATTERNS = Object.freeze([
  'prompt',
  'prompt_text',
  'prompttext',
  'response',
  'response_text',
  'responsetext',
  'matched_content',
  'matchedcontent',
  'matched_snippet',
  'snippet',
  'file_contents',
  'filecontents',
  'file_content',
  'raw_content',
  'rawcontent',
  'message_content',
  'completion',
  'chat_history',
  'chathistory',
  // Full evidence blobs stay in the inbox detail view, not the handoff file.
  'evidence',
]);

/**
 * Map the UI status picker value to the API `status` query param.
 * - `open` → new,acknowledged
 * - `all`  → omitted (no status filter)
 * - else   → the status string itself
 */
export function statusQueryValue(fstatus) {
  if (fstatus == null || fstatus === '' || fstatus === 'all') return null;
  if (fstatus === 'open') return 'new,acknowledged';
  return String(fstatus);
}

/**
 * Build the query-string (no leading `?`) for GET /api/findings that mirrors
 * the visible console filters. `format` is optional (`csv` | `json` | omit).
 *
 * @param {{ fstatus?: string, fsev?: string, ruleId?: string|null, days?: number }} state
 * @param {{ format?: 'csv'|'json'|null, limit?: number }} [opts]
 */
export function buildFindingsExportQuery(state = {}, opts = {}) {
  const params = new URLSearchParams();
  const limit = Number.isFinite(opts.limit) ? Math.max(1, Math.floor(opts.limit)) : EXPORT_LIMIT;
  params.set('limit', String(limit));

  const status = statusQueryValue(state.fstatus);
  if (status) params.set('status', status);

  if (state.fsev && state.fsev !== 'all') params.set('severity', String(state.fsev));

  if (typeof state.ruleId === 'string' && state.ruleId) {
    params.set('rule_id', state.ruleId);
  }

  if (opts.format === 'csv' || opts.format === 'json') {
    params.set('format', opts.format);
  }

  return params.toString();
}

/**
 * Full path for a findings export download.
 * @param {object} state  findings console filter state
 * @param {'csv'|'json'} [format='csv']
 */
export function buildFindingsExportUrl(state = {}, format = 'csv') {
  const q = buildFindingsExportQuery(state, { format, limit: EXPORT_LIMIT });
  return `/api/findings?${q}`;
}

/** Pick the metadata-only export shape from a full API finding object. */
export function toMetadataExportRow(finding) {
  const f = finding && typeof finding === 'object' ? finding : {};
  const row = {};
  for (const key of EXPORT_FIELD_KEYS) {
    const v = f[key];
    row[key] = v === undefined ? null : v;
  }
  return row;
}

/**
 * Package findings into a SOC handoff JSON document.
 * Includes filter echo + export timestamp so the file is self-describing.
 */
export function buildMetadataExportPayload(findings, meta = {}) {
  const rows = Array.isArray(findings) ? findings.map(toMetadataExportRow) : [];
  return {
    schema: 'aim.findings-export/v1',
    exportedAt: meta.exportedAt ?? new Date().toISOString(),
    filters: {
      status: meta.status ?? null,
      severity: meta.severity ?? null,
      ruleId: meta.ruleId ?? null,
    },
    privacy: 'metadata_only',
    note: 'No prompt text, response text, or matched content. Pseudonyms and detector metadata only.',
    total: rows.length,
    findings: rows,
  };
}

/**
 * Walk a value tree and return paths of any forbidden keys.
 * Empty array = privacy-safe for handoff.
 */
export function privacyViolations(value, path = '$') {
  const hits = [];
  if (value == null) return hits;
  if (Array.isArray(value)) {
    value.forEach((item, i) => hits.push(...privacyViolations(item, `${path}[${i}]`)));
    return hits;
  }
  if (typeof value !== 'object') return hits;
  for (const [k, v] of Object.entries(value)) {
    const keyPath = `${path}.${k}`;
    const norm = String(k).toLowerCase().replace(/[-]/g, '');
    for (const forbidden of FORBIDDEN_KEY_PATTERNS) {
      const fNorm = forbidden.replace(/[-_]/g, '');
      if (norm === fNorm || norm.includes(fNorm)) {
        hits.push(keyPath);
        break;
      }
    }
    hits.push(...privacyViolations(v, keyPath));
  }
  return hits;
}

/**
 * Trigger a browser file download. DOM-dependent — not used in unit tests.
 * @param {string} filename
 * @param {Blob|string} body
 * @param {string} [mime]
 */
export function triggerDownload(filename, body, mime = 'application/octet-stream') {
  const blob = body instanceof Blob ? body : new Blob([body], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke after the click has a chance to start the download.
  setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

/** Stable handoff filenames (filesystem-safe, no filter params). */
export function exportFilename(format) {
  if (format === 'csv') return 'aim-findings.csv';
  if (format === 'json') return 'aim-findings.json';
  return `aim-findings.${format || 'bin'}`;
}

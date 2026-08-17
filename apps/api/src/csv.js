// CSV export helpers. One shared serializer so every endpoint exports
// exactly the rows its JSON response carries — the export can't drift from the
// on-screen numbers.
//
// Two safety rules baked in:
//   * Formula injection: values starting with = + - @ (or tab/CR) are prefixed
//     with a single quote so a hostile team name or tool string can't become a
//     spreadsheet formula when Legal opens the export in Excel.
//   * Dates serialize to ISO 8601; nulls/undefined become empty cells.

// format=csv triggers an export; any other format value is rejected by the
// caller (explicit beats silently ignored).
export function wantsCsv(req) {
  return req.query?.format === 'csv';
}

export function checkFormat(req, reply, extra = []) {
  const f = req.query?.format;
  if (f === undefined || f === 'csv' || f === 'json' || extra.includes(f)) return true;
  reply.code(400).send({ error: 'bad_request', detail: `format must be 'csv'${extra.length ? `, ${extra.map((e) => `'${e}'`).join(', ')}` : ''} (or omitted for JSON)` });
  return false;
}

function cell(v) {
  if (v === null || v === undefined) return '';
  if (v instanceof Date) v = v.toISOString();
  else if (typeof v === 'object') v = JSON.stringify(v);
  else v = String(v);
  // Neutralize spreadsheet formula injection before quoting.
  if (/^[=+\-@\t\r]/.test(v)) v = `'${v}`;
  return /[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

// cols: [{ key, label }]; rows: array of objects keyed by col.key.
export function toCsv(cols, rows) {
  const head = cols.map((c) => cell(c.label)).join(',');
  const body = rows.map((r) => cols.map((c) => cell(r[c.key])).join(','));
  return [head, ...body].join('\r\n') + '\r\n';
}

// Sends a CSV attachment. filename should be stable and filesystem-safe.
export function sendCsv(reply, filename, cols, rows) {
  // Filenames can embed URL params (e.g. tool name) — keep the header safe.
  const safe = String(filename).replace(/[^A-Za-z0-9._-]/g, '_');
  return reply
    .header('content-type', 'text/csv; charset=utf-8')
    .header('content-disposition', `attachment; filename="${safe}"`)
    .send(toCsv(cols, rows));
}

/* Case / investigation workflow model.
 *
 * Pure module — no DOM, no fetch — so unit tests and the API route can share
 * the same status machine and attachment vocabulary. Cases are the unit of
 * investigation beyond a findings list: open a case, attach findings/users/
 * tools (refs only — never prompt content), track status, export a package.
 *
 * Privacy: attachment refs are finding UUIDs, user_ref HMAC pseudonyms, or
 * tool names. Labels are display hints only. The UI and API must never put
 * matched content or cleartext identity into a case record.
 */

export const CASE_STATUSES = Object.freeze(['open', 'investigating', 'contained', 'closed']);
export const CASE_SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low']);
export const ATTACH_KINDS = Object.freeze(['finding', 'user', 'tool']);

/** Allowed status transitions. Closing is always available; reopening is too. */
export const STATUS_TRANSITIONS = Object.freeze({
  open: Object.freeze(['investigating', 'closed']),
  investigating: Object.freeze(['contained', 'closed', 'open']),
  contained: Object.freeze(['closed', 'investigating']),
  closed: Object.freeze(['open', 'investigating']),
});

export const STATUS_LABEL = Object.freeze({
  open: 'Open',
  investigating: 'Investigating',
  contained: 'Contained',
  closed: 'Closed',
});

export const ATTACH_LABEL = Object.freeze({
  finding: 'Finding',
  user: 'User',
  tool: 'Tool',
});

export const SEV_RANK = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3 });

const TITLE_MAX = 200;
const DESC_MAX = 4000;
const NOTE_MAX = 4000;
const LABEL_MAX = 200;
const REF_MAX = 200;

export function statusLabel(status) {
  return STATUS_LABEL[status] ?? String(status ?? '');
}

export function canTransition(from, to) {
  if (!CASE_STATUSES.includes(from) || !CASE_STATUSES.includes(to)) return false;
  if (from === to) return false;
  return (STATUS_TRANSITIONS[from] ?? []).includes(to);
}

export function nextActions(status) {
  return [...(STATUS_TRANSITIONS[status] ?? [])];
}

/** Sort: open work first, then severity (critical first), then newest update. */
export function sortCases(cases) {
  const statusRank = { open: 0, investigating: 1, contained: 2, closed: 3 };
  return [...cases].sort((a, b) => {
    const sa = statusRank[a.status] ?? 9;
    const sb = statusRank[b.status] ?? 9;
    if (sa !== sb) return sa - sb;
    const va = SEV_RANK[a.severity] ?? 9;
    const vb = SEV_RANK[b.severity] ?? 9;
    if (va !== vb) return va - vb;
    const ta = Date.parse(a.updatedAt ?? a.createdAt ?? 0) || 0;
    const tb = Date.parse(b.updatedAt ?? b.createdAt ?? 0) || 0;
    return tb - ta;
  });
}

function trimStr(v, max) {
  if (v === undefined || v === null) return null;
  if (typeof v !== 'string') return false;
  const t = v.trim();
  if (t === '') return null;
  if (t.length > max) return false;
  return t;
}

export function validateCreate(body = {}) {
  const title = trimStr(body.title, TITLE_MAX);
  if (title === null || title === false) {
    return { ok: false, detail: `title must be a non-empty string of 1..${TITLE_MAX} chars` };
  }
  const severity = body.severity;
  if (!CASE_SEVERITIES.includes(severity)) {
    return { ok: false, detail: `severity must be one of ${CASE_SEVERITIES.join(', ')}` };
  }
  let description = null;
  if (body.description !== undefined && body.description !== null) {
    description = trimStr(body.description, DESC_MAX);
    if (description === false) {
      return { ok: false, detail: `description must be a string of at most ${DESC_MAX} chars` };
    }
  }
  const status = body.status ?? 'open';
  if (!CASE_STATUSES.includes(status)) {
    return { ok: false, detail: `status must be one of ${CASE_STATUSES.join(', ')}` };
  }
  const seeds = validateSeedAttachments(body);
  if (!seeds.ok) return seeds;
  return {
    ok: true,
    value: {
      title,
      severity,
      description,
      status,
      findingIds: seeds.findingIds,
      userRefs: seeds.userRefs,
      tools: seeds.tools,
    },
  };
}

function validateSeedAttachments(body) {
  const findingIds = normalizeRefList(body.findingIds ?? body.finding_ids, 'findingIds');
  if (findingIds.detail) return { ok: false, detail: findingIds.detail };
  const userRefs = normalizeRefList(body.userRefs ?? body.user_refs, 'userRefs');
  if (userRefs.detail) return { ok: false, detail: userRefs.detail };
  const tools = normalizeRefList(body.tools, 'tools');
  if (tools.detail) return { ok: false, detail: tools.detail };
  return { ok: true, findingIds: findingIds.list, userRefs: userRefs.list, tools: tools.list };
}

function normalizeRefList(raw, name) {
  if (raw === undefined || raw === null) return { list: [] };
  if (!Array.isArray(raw)) return { detail: `${name} must be an array of strings` };
  if (raw.length > 50) return { detail: `${name} may contain at most 50 entries` };
  const list = [];
  for (const item of raw) {
    if (typeof item !== 'string' || !item.trim() || item.trim().length > REF_MAX) {
      return { detail: `${name} entries must be non-empty strings ≤${REF_MAX} chars` };
    }
    list.push(item.trim());
  }
  return { list };
}

export function validatePatch(body = {}) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, detail: 'body must be an object' };
  }
  const value = {};
  if (body.title !== undefined) {
    const title = trimStr(body.title, TITLE_MAX);
    if (title === null || title === false) {
      return { ok: false, detail: `title must be a non-empty string of 1..${TITLE_MAX} chars` };
    }
    value.title = title;
  }
  if (body.description !== undefined) {
    if (body.description === null || body.description === '') {
      value.description = null;
    } else {
      const description = trimStr(body.description, DESC_MAX);
      if (description === false) {
        return { ok: false, detail: `description must be a string of at most ${DESC_MAX} chars` };
      }
      value.description = description;
    }
  }
  if (body.severity !== undefined) {
    if (!CASE_SEVERITIES.includes(body.severity)) {
      return { ok: false, detail: `severity must be one of ${CASE_SEVERITIES.join(', ')}` };
    }
    value.severity = body.severity;
  }
  if (body.status !== undefined) {
    if (!CASE_STATUSES.includes(body.status)) {
      return { ok: false, detail: `status must be one of ${CASE_STATUSES.join(', ')}` };
    }
    value.status = body.status;
  }
  if (Object.keys(value).length === 0) {
    return { ok: false, detail: 'no updatable fields provided (title, description, severity, status)' };
  }
  return { ok: true, value };
}

export function validateAttachment(body = {}) {
  const kind = body.kind ?? body.type;
  if (!ATTACH_KINDS.includes(kind)) {
    return { ok: false, detail: `kind must be one of ${ATTACH_KINDS.join(', ')}` };
  }
  const ref = trimStr(body.ref, REF_MAX);
  if (ref === null || ref === false) {
    return { ok: false, detail: `ref must be a non-empty string of 1..${REF_MAX} chars` };
  }
  let label = null;
  if (body.label !== undefined && body.label !== null) {
    label = trimStr(body.label, LABEL_MAX);
    if (label === false) {
      return { ok: false, detail: `label must be a string of at most ${LABEL_MAX} chars` };
    }
  }
  return { ok: true, value: { kind, ref, label } };
}

export function validateNote(body = {}) {
  const note = trimStr(body.body ?? body.note, NOTE_MAX);
  if (note === null || note === false) {
    return { ok: false, detail: `body must be a non-empty string of 1..${NOTE_MAX} chars` };
  }
  return { ok: true, value: { body: note } };
}

export function buildCaseExport(detail) {
  const c = detail?.case ?? detail;
  const attachments = detail?.attachments ?? c?.attachments ?? [];
  const events = detail?.events ?? c?.events ?? [];
  return {
    schema: 'aim.case.export/v1',
    case: {
      caseId: c.caseId ?? c.case_id,
      title: c.title,
      description: c.description ?? null,
      severity: c.severity,
      status: c.status,
      createdBy: c.createdBy ?? c.created_by,
      createdAt: c.createdAt ?? c.created_at,
      updatedAt: c.updatedAt ?? c.updated_at,
      closedAt: c.closedAt ?? c.closed_at ?? null,
      closedBy: c.closedBy ?? c.closed_by ?? null,
    },
    attachments: attachments.map((a) => ({
      attachmentId: a.attachmentId ?? a.attachment_id,
      kind: a.kind,
      ref: a.ref,
      label: a.label ?? null,
      attachedBy: a.attachedBy ?? a.attached_by,
      attachedAt: a.attachedAt ?? a.attached_at,
    })),
    events: events.map((e) => ({
      eventId: e.eventId ?? e.event_id,
      kind: e.kind,
      body: e.body ?? null,
      actor: e.actor,
      meta: e.meta ?? null,
      createdAt: e.createdAt ?? e.created_at,
    })),
  };
}

export function caseExportCsvRows(detail) {
  const pkg = buildCaseExport(detail);
  const base = {
    caseId: pkg.case.caseId,
    title: pkg.case.title,
    severity: pkg.case.severity,
    status: pkg.case.status,
    createdBy: pkg.case.createdBy,
    createdAt: pkg.case.createdAt,
    updatedAt: pkg.case.updatedAt,
    closedAt: pkg.case.closedAt,
    closedBy: pkg.case.closedBy,
  };
  if (pkg.attachments.length === 0) {
    return [{ ...base, attachKind: '', attachRef: '', attachLabel: '' }];
  }
  return pkg.attachments.map((a) => ({
    ...base,
    attachKind: a.kind,
    attachRef: a.ref,
    attachLabel: a.label ?? '',
  }));
}

export const CASE_CSV_COLS = Object.freeze([
  { key: 'caseId', label: 'case_id' },
  { key: 'title', label: 'title' },
  { key: 'severity', label: 'severity' },
  { key: 'status', label: 'status' },
  { key: 'createdBy', label: 'created_by' },
  { key: 'createdAt', label: 'created_at' },
  { key: 'updatedAt', label: 'updated_at' },
  { key: 'closedAt', label: 'closed_at' },
  { key: 'closedBy', label: 'closed_by' },
  { key: 'attachKind', label: 'attach_kind' },
  { key: 'attachRef', label: 'attach_ref' },
  { key: 'attachLabel', label: 'attach_label' },
]);

export function openCaseCount(cases) {
  return cases.filter((c) => c.status && c.status !== 'closed').length;
}

export function groupAttachments(attachments = []) {
  const groups = { finding: [], user: [], tool: [] };
  for (const a of attachments) {
    if (groups[a.kind]) groups[a.kind].push(a);
  }
  return groups;
}

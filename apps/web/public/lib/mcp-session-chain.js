/* AIM-800 — MCP session chain timeline helpers.
 *
 * Pure render/logic for GET /api/mcp-sessions/:sessionId (AIM-627 backend).
 * Analyst UI surfaces ordered tool_calls + agent_handoffs with parent/child
 * edges and a chain-completeness badge. Metadata only — never args, results,
 * prompts, command lines, or URLs.
 *
 * Importable under node:test without a DOM (same pattern as lib/triage.js).
 */

import { esc } from './dom.js';

import { fmtTs, shortRef } from './format.js';

/** Keys that must never appear in rendered output (privacy boundary). */
export const FORBIDDEN_KEYS = Object.freeze([
  'arguments',
  'args',
  'result',
  'results',
  'result_body',
  'resultBody',
  'prompt',
  'content',
  'command',
  'url',
  'env',
  'body',
  'raw',
  'payload',
]);

/** Deep-link into the MCP tab with a session selected. */
export function sessionHash(sessionId) {
  if (!sessionId) return '#/mcp';
  return `#/mcp?session=${encodeURIComponent(String(sessionId))}`;
}

/**
 * Read `session` from a location hash (`#/mcp?session=…` or `#/mcp?days=7&session=…`).
 * Returns null when absent/empty/too long.
 */
export function parseSessionFromHash(hash = '') {
  const raw = String(hash || '');
  const qIdx = raw.indexOf('?');
  if (qIdx < 0) return null;
  const q = new URLSearchParams(raw.slice(qIdx + 1));
  const sid = (q.get('session') || '').trim();
  if (!sid || sid.length > 128) return null;
  return sid;
}

/**
 * Pull a session id from finding evidence (engine context) without walking
 * nested content blobs that might hold sensitive material.
 */
export function extractSessionId(evidence) {
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) return null;
  const direct = evidence.session_id ?? evidence.sessionId;
  if (typeof direct === 'string' && direct.trim()) return direct.trim().slice(0, 128);
  const ctx = evidence.context;
  if (ctx && typeof ctx === 'object' && !Array.isArray(ctx)) {
    const nested = ctx.session_id ?? ctx.sessionId;
    if (typeof nested === 'string' && nested.trim()) return nested.trim().slice(0, 128);
  }
  return null;
}

/**
 * Chain completeness from the API summary counters.
 * - full: every tool call has callId + resultStatus
 * - partial: some chain fields present
 * - none: tool calls exist but no chain fields (pre-v1.10 collectors)
 * - empty: no tool calls at all
 */
export function completenessLevel(chainCompleteness, toolCallCount = 0) {
  const n = Number(toolCallCount) || 0;
  if (n <= 0) return 'empty';
  const withCallId = Number(chainCompleteness?.withCallId) || 0;
  const withParent = Number(chainCompleteness?.withParent) || 0;
  const withResult = Number(chainCompleteness?.withResultStatus) || 0;
  if (withCallId === 0 && withParent === 0 && withResult === 0) return 'none';
  if (withCallId >= n && withResult >= n) return 'full';
  return 'partial';
}

export function completenessBadge(chainCompleteness, toolCallCount = 0) {
  const level = completenessLevel(chainCompleteness, toolCallCount);
  const withCallId = Number(chainCompleteness?.withCallId) || 0;
  const withParent = Number(chainCompleteness?.withParent) || 0;
  const withResult = Number(chainCompleteness?.withResultStatus) || 0;
  const n = Number(toolCallCount) || 0;
  const tip = `call_id ${withCallId}/${n} · parent ${withParent}/${n} · result_status ${withResult}/${n}`;
  const labels = {
    full: { cls: 'good', text: 'chain complete' },
    partial: { cls: 'warn', text: 'chain partial' },
    none: { cls: 'muted', text: 'no chain ids' },
    empty: { cls: 'muted', text: 'no tool calls' },
  };
  const { cls, text } = labels[level] ?? labels.none;
  return `<span class="pill ${cls}" title="${esc(tip)}">${esc(text)}</span>`;
}

export function resultStatusPill(status) {
  if (status == null || status === '') return '<span class="faint">—</span>';
  const s = String(status);
  let cls = 'muted';
  if (s === 'ok' || s === 'success' || s === 'allowed') cls = 'good';
  else if (s === 'denied' || s === 'error' || s === 'blocked' || s === 'failed') cls = 'bad';
  else if (s === 'timeout' || s === 'unknown' || s === 'confirmed') cls = 'warn';
  return `<span class="pill ${cls}">${esc(s)}</span>`;
}

export function actionClassPill(actionClass) {
  if (actionClass == null || actionClass === '') return '<span class="faint">—</span>';
  return `<span class="pill muted mcp-action">${esc(String(actionClass))}</span>`;
}

/** Depth map: callId → nesting depth via parentCallId (roots = 0). */
export function callDepths(toolCalls = []) {
  const byId = new Map();
  for (const c of toolCalls) {
    if (c?.callId) byId.set(c.callId, c);
  }
  const depthMemo = new Map();
  function depthOf(id, stack = new Set()) {
    if (!id || !byId.has(id)) return 0;
    if (depthMemo.has(id)) return depthMemo.get(id);
    if (stack.has(id)) return 0; // cycle guard
    stack.add(id);
    const parent = byId.get(id)?.parentCallId;
    const d = parent && byId.has(parent) ? depthOf(parent, stack) + 1 : 0;
    depthMemo.set(id, d);
    return d;
  }
  const out = new Map();
  for (const c of toolCalls) {
    if (c?.callId) out.set(c.callId, depthOf(c.callId));
  }
  return out;
}

/** Parent/child edge label for one tool call. */
export function edgeLabel(call) {
  if (!call) return '';
  const parts = [];
  if (call.callId) parts.push(`id ${shortRef(call.callId, 10) || call.callId}`);
  if (call.parentCallId) {
    parts.push(`← parent ${shortRef(call.parentCallId, 10) || call.parentCallId}`);
  } else if (call.callId) {
    parts.push('root');
  }
  if (call.seq != null) parts.push(`seq ${call.seq}`);
  return parts.join(' · ');
}

/**
 * Strip forbidden keys from a plain object (shallow). Used as a belt-and-
 * suspenders guard before any field is stringified for display.
 */
export function sanitizeMeta(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return obj;
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (FORBIDDEN_KEYS.includes(k)) continue;
    const lower = k.toLowerCase();
    if (lower.includes('argument') || lower.includes('prompt') || lower.endsWith('_body')
      || lower === 'result' || lower === 'results' || lower === 'content') {
      continue;
    }
    out[k] = v;
  }
  return out;
}

/** True when `html` appears free of forbidden content keys as labels/values. */
export function htmlLooksSafe(html) {
  const s = String(html || '');
  if (/\barguments?\b/i.test(s) && /["{[]/.test(s)) return false;
  if (/\bresult_body\b/i.test(s)) return false;
  if (/\b"prompt"\s*:/i.test(s)) return false;
  return true;
}

export function toolCallRowHtml(call, depth = 0) {
  const c = sanitizeMeta(call) || {};
  const pad = Math.min(Number(depth) || 0, 8) * 14;
  const edge = edgeLabel(c);
  const toolName = c.toolName ?? '—';
  const mcpServer = c.mcpServer ?? '—';
  return `<li class="mcp-chain-item mcp-chain-call" style="padding-left:${pad}px" data-call-id="${esc(c.callId || '')}" data-parent-id="${esc(c.parentCallId || '')}">
    <div class="mcp-chain-head">
      <span class="mcp-chain-kind pill muted">tool_call</span>
      <code class="mcp-chain-tool">${esc(toolName)}</code>
      ${actionClassPill(c.actionClass)}
      ${resultStatusPill(c.resultStatus)}
    </div>
    <div class="mcp-chain-meta">
      <span class="mono muted" title="${esc(c.ts || '')}">${esc(fmtTs(c.ts))}</span>
      <span>server <code>${esc(mcpServer)}</code></span>
      ${c.tool ? `<span>AI tool <code>${esc(c.tool)}</code></span>` : ''}
      ${edge ? `<span class="mcp-chain-edge mono muted">${esc(edge)}</span>` : ''}
    </div>
  </li>`;
}

export function handoffRowHtml(handoff) {
  const h = sanitizeMeta(handoff) || {};
  const child = h.childSessionId
    ? `<a class="mono" href="${esc(sessionHash(h.childSessionId))}" title="${esc(h.childSessionId)}">child ${esc(shortRef(h.childSessionId, 12) || h.childSessionId)}</a>`
    : '<span class="faint">no child session</span>';
  return `<li class="mcp-chain-item mcp-chain-handoff">
    <div class="mcp-chain-head">
      <span class="mcp-chain-kind pill warn">handoff</span>
      <code class="mcp-chain-tool">${esc(h.toolName ?? h.handoffKind ?? 'agent')}</code>
      ${h.handoffKind ? `<span class="pill muted">${esc(h.handoffKind)}</span>` : ''}
      ${resultStatusPill(h.status)}
    </div>
    <div class="mcp-chain-meta">
      <span class="mono muted" title="${esc(h.ts || '')}">${esc(fmtTs(h.ts))}</span>
      ${h.tool ? `<span>AI tool <code>${esc(h.tool)}</code></span>` : ''}
      ${h.parentCallId ? `<span class="mono muted">← parent ${esc(shortRef(h.parentCallId, 10) || h.parentCallId)}</span>` : ''}
      <span>${child}</span>
    </div>
  </li>`;
}

/**
 * Ordered timeline: tool_calls (by seq/ts) with depth indent, handoffs
 * interleaved by timestamp when both are present.
 */
export function timelineItemsHtml(data) {
  const calls = Array.isArray(data?.toolCalls) ? data.toolCalls.map(sanitizeMeta) : [];
  const handoffs = Array.isArray(data?.agentHandoffs) ? data.agentHandoffs.map(sanitizeMeta) : [];
  const depths = callDepths(calls);

  const items = [
    ...calls.map((c) => ({ kind: 'call', ts: c.ts, seq: c.seq ?? null, c })),
    ...handoffs.map((h) => ({ kind: 'handoff', ts: h.ts, seq: null, h })),
  ];
  items.sort((a, b) => {
    if (a.seq != null && b.seq != null && a.seq !== b.seq) return a.seq - b.seq;
    return String(a.ts || '').localeCompare(String(b.ts || ''));
  });

  if (!items.length) {
    return '<p class="hint">No tool_calls or agent_handoffs in this session window.</p>';
  }

  const rows = items.map((it) => {
    if (it.kind === 'handoff') return handoffRowHtml(it.h);
    const d = it.c.callId ? (depths.get(it.c.callId) ?? 0) : 0;
    return toolCallRowHtml(it.c, d);
  });
  return `<ol class="mcp-chain-list">${rows.join('')}</ol>`;
}

/** Full panel body for a successful session API response. */
export function sessionPanelHtml(data) {
  const sid = data?.sessionId ?? '—';
  const badge = completenessBadge(data?.chainCompleteness, data?.toolCallCount);
  const summary = [
    `<span>${esc(String(data?.toolCallCount ?? 0))} tool calls</span>`,
    `<span>${esc(String(data?.handoffCount ?? 0))} handoffs</span>`,
    `<span>${esc(String(data?.eventCount ?? 0))} events</span>`,
    `<span>last ${esc(String(data?.rangeDays ?? '—'))}d</span>`,
  ].join(' · ');

  return `
    <div class="mcp-chain-summary">
      <div class="mcp-chain-title-row">
        <span>Session <code class="mono">${esc(sid)}</code></span>
        ${badge}
      </div>
      <p class="hint">${summary}</p>
      <p class="hint muted">Metadata only — args, results, prompts, and command lines are never shown.</p>
    </div>
    ${timelineItemsHtml(data)}
  `;
}

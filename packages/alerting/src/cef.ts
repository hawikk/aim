/**
 * CEF (Common Event Format) formatter for guardrail findings.
 * Format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
 *
 * Metadata-only: pattern ids / pseudonyms / hashes — never prompt content.
 *
 * Custom-string keys (cs1–cs7) always ship with matching *Label fields so
 * Sentinel / ArcSight parsers and SOC KQL can resolve meaning without a
 * side-channel schema. See docs/aim-585-sentinel-cef-field-matrix.md.
 */

const VENDOR = 'AIMonitoring';
const PRODUCT = 'GuardrailEngine';
const VERSION = '1.0';

/** Cap CEF extension values that can grow (event id lists). */
const MAX_EXT_VALUE_LEN = 512;

export interface CefFinding {
  findingId: string;
  findingType: string;
  title?: string;
  timestamp: string;
  userId: string;
  tool: string;
  model?: string;
  repo?: string;
  /** Pattern ids only — never content (metadata-only policy). */
  matchFlags?: string;
  runbookUrl?: string;
  /** Team slug for SOC routing (JSON Team already existed; CEF was missing it). */
  team?: string;
  /** Endpoint host pseudonym (subject.host_ref) — required for device triage. */
  hostRef?: string;
  /** Guardrail policy hash at evaluation time (audit / drift detection). */
  policyHash?: string;
  /**
   * Engine severity band (critical|high|medium|low|informational). Distinct from
   * the CEF/Sentinel taxonomy severity — Sentinel has no Critical; SLA rules
   * key off the engine band.
   */
  engineSeverity?: string;
  /**
   * Platform/endpoint decision: observe | blocked | would_block | confirmed.
   * Maps to CEF `act`. Defaults to alert (observe) when absent.
   */
  decision?: string;
  /** Comma-separated source event ids for correlation back to raw telemetry. */
  eventIds?: string;
}

function escapeHeader(value: unknown): string {
  return String(value).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[\r\n]/g, ' ');
}

function escapeExtension(value: unknown): string {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/=/g, '\\=')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n');
}

function clip(value: string, max = MAX_EXT_VALUE_LEN): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}

/** Map finding.decision onto CEF act. */
export function cefAct(decision?: string): string {
  switch (decision) {
    case 'blocked':
      return 'block';
    case 'would_block':
      return 'would_block';
    case 'confirmed':
      return 'allow'; // break-glass / PII confirm — content proceeded, audited
    case 'observe':
    case 'alert':
    case undefined:
    case '':
      return 'alert';
    default:
      return 'alert';
  }
}

/**
 * Build a CEF string for a finding.
 * @param severity CEF numeric severity 0-10 (from cefSeverity()).
 */
export function toCef(finding: CefFinding, { severity }: { severity: number }): string {
  const name = finding.title ?? finding.findingType;
  const ext = [
    ['rt', finding.timestamp],
    ['suser', finding.userId],
    // Device / host attribution (pseudonym). Standard CEF key — no label needed.
    ['dvchost', finding.hostRef ?? ''],
    // Human-readable name for parsers that ignore the CEF Name header field.
    ['msg', name],
    // Stable category for SIEM filtering / ASIM custom mappings.
    ['cat', 'ai-security'],
    // Custom strings — ALWAYS paired with labels (critical gap).
    ['cs1Label', 'AITool'],
    ['cs1', finding.tool],
    ['cs2Label', 'Model'],
    ['cs2', finding.model ?? ''],
    ['cs3Label', 'Repository'],
    ['cs3', finding.repo ?? ''],
    ['cs4Label', 'MatchFlags'],
    ['cs4', finding.matchFlags ?? ''],
    ['cs5Label', 'Runbook'],
    ['cs5', finding.runbookUrl ?? ''],
    ['cs6Label', 'Team'],
    ['cs6', finding.team ?? ''],
    ['cs7Label', 'EngineSeverity'],
    ['cs7', finding.engineSeverity ?? ''],
    ['flexString1Label', 'PolicyHash'],
    ['flexString1', finding.policyHash ?? ''],
    ['flexString2Label', 'EventIds'],
    ['flexString2', clip(finding.eventIds ?? '')],
    ['externalId', finding.findingId],
    ['act', cefAct(finding.decision)],
  ]
    .map(([k, v]) => `${k}=${escapeExtension(v ?? '')}`)
    .join(' ');

  return [
    'CEF:0',
    escapeHeader(VENDOR),
    escapeHeader(PRODUCT),
    escapeHeader(VERSION),
    escapeHeader(finding.findingType),
    escapeHeader(name),
    String(severity),
    ext,
  ].join('|');
}

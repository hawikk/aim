/**
 * Microsoft Sentinel forwarder via the Log Analytics Data Collector API
 * (HTTP Data Collector, api-version 2016-04-01).
 *
 * Auth: SharedKey — HMAC-SHA256(workspaceId + string-to-sign, base64 sharedKey).
 * String to sign: "POST\n{contentLength}\napplication/json\nx-ms-date:{rfc1123}\n/api/logs"
 *
 * The endpoint is injectable for tests. For production, prefer migrating to
 * the DCR-based Logs Ingestion API (Entra ID auth, no shared keys) — tracked
 * as hardening work; Data Collector API is the pragmatic v1.
 *
 * Metadata-only guarantee: findings contain no prompt content; the CEF and
 * JSON records built here only pass through finding metadata fields.
 */

import { createHmac } from 'node:crypto';
import { toCef } from './cef.ts';
import { classifyFinding, cefSeverity } from './severity.ts';

const API_PATH = '/api/logs';
const API_VERSION = '2016-04-01';
const MAX_RETRIES = 3;

/** Canonical guardrail finding (metadata-only — no prompt/response content). */
export interface Finding {
  findingId: string;
  findingType: string;
  title?: string;
  timestamp: string;
  userId: string;
  team?: string;
  tool: string;
  model?: string;
  repo?: string;
  matchFlags?: string;
  /** Endpoint host pseudonym (subject.host_ref). */
  hostRef?: string;
  /** Guardrail policy hash at evaluation time. */
  policyHash?: string;
  /** Engine severity band (critical|high|medium|low|informational). */
  engineSeverity?: string;
  /** observe | blocked | would_block | confirmed | … */
  decision?: string;
  /** Comma-separated source event ids. */
  eventIds?: string;
}

export interface ForwardAuditEvent {
  action: 'alert.forwarded';
  destination: 'sentinel';
  logType: string;
  findingIds: string[];
  count: number;
}

export interface SentinelForwarderConfig {
  /** Log Analytics workspace ID. */
  workspaceId: string;
  /** Workspace primary/secondary key (base64). */
  sharedKey: string;
  /** Custom log table name (appears in Sentinel as <logType>_CL). */
  logType?: string;
  /** Override full URL (tests / sovereign clouds). */
  endpoint?: string;
  /** e.g. https://wiki.corp/runbooks/ — prefixed onto taxonomy runbook slugs. */
  runbookBaseUrl?: string;
  /** Audit hook, called once per successfully forwarded batch. */
  onForward?: (event: ForwardAuditEvent) => void;
  fetchImpl?: typeof fetch;
}

export class SentinelForwarder {
  private readonly workspaceId: string;
  private readonly sharedKey: string;
  private readonly logType: string;
  private readonly endpoint: string;
  private readonly runbookBaseUrl: string;
  private readonly onForward?: (event: ForwardAuditEvent) => void;
  private readonly fetchImpl: typeof fetch;

  constructor({ workspaceId, sharedKey, logType = 'AIGuardrailFinding', endpoint, runbookBaseUrl = '', onForward, fetchImpl = fetch }: SentinelForwarderConfig) {
    if (!workspaceId || !sharedKey) throw new Error('workspaceId and sharedKey are required');
    this.workspaceId = workspaceId;
    this.sharedKey = sharedKey;
    this.logType = logType;
    this.endpoint = endpoint ?? `https://${workspaceId}.ods.opinsights.azure.com${API_PATH}?api-version=${API_VERSION}`;
    this.runbookBaseUrl = runbookBaseUrl;
    this.onForward = onForward;
    this.fetchImpl = fetchImpl;
  }

  /** Enrich a raw finding with taxonomy classification + runbook pointer. */
  buildRecord(finding: Finding): Record<string, unknown> {
    const cls = classifyFinding(finding.findingType);
    if (!cls.known) {
      // Loud fallback: unknown finding types must be added to the taxonomy.
      console.error(`[alerting] unknown findingType "${finding.findingType}" — using fallback severity`);
    }
    const runbookUrl = this.runbookBaseUrl ? `${this.runbookBaseUrl}${cls.runbook}` : cls.runbook;
    // EnforcementMode remains for legacy KQL; Decision carries the live act
    // so SOC can filter would_block / blocked without losing the old column.
    const decision = finding.decision ?? 'observe';
    const enriched: Record<string, unknown> = {
      FindingId: finding.findingId,
      TimeGenerated: finding.timestamp,
      FindingType: finding.findingType,
      Title: finding.title ?? finding.findingType,
      Severity: cls.severity,
      EngineSeverity: finding.engineSeverity ?? '',
      UserId: finding.userId,
      Team: finding.team ?? '',
      HostRef: finding.hostRef ?? '',
      Tool: finding.tool,
      Model: finding.model ?? '',
      Repo: finding.repo ?? '',
      MatchFlags: finding.matchFlags ?? '',
      PolicyHash: finding.policyHash ?? '',
      EventIds: finding.eventIds ?? '',
      Decision: decision,
      RunbookUrl: runbookUrl,
      EnforcementMode: decision === 'blocked' ? 'enforce' : 'observe-only',
    };
    const cef = toCef({ ...finding, runbookUrl, decision }, { severity: cefSeverity(cls.severity) });
    return { ...enriched, Cef: cef };
  }

  /** SharedKey authorization header value. */
  #sign(dateRfc1123: string, contentLength: number): string {
    const stringToSign = `POST\n${contentLength}\napplication/json\nx-ms-date:${dateRfc1123}\n${API_PATH}`;
    const mac = createHmac('sha256', Buffer.from(this.sharedKey, 'base64'))
      .update(stringToSign, 'utf8')
      .digest('base64');
    return `SharedKey ${this.workspaceId}:${mac}`;
  }

  /**
   * Forward a batch of findings. Throws after retries are exhausted;
   * callers (pipeline) should dead-letter failed batches, not drop them.
   */
  async forward(findings: Finding[]): Promise<{ sent: number; status?: number }> {
    if (!Array.isArray(findings) || findings.length === 0) return { sent: 0 };
    const records = findings.map((f) => this.buildRecord(f));
    const body = Buffer.from(JSON.stringify(records), 'utf8');

    let lastError: unknown;
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      const date = new Date().toUTCString();
      try {
        const res = await this.fetchImpl(this.endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Log-Type': this.logType,
            'x-ms-date': date,
            'time-generated-field': 'TimeGenerated',
            Authorization: this.#sign(date, body.length),
          },
          body,
        });
        if (res.ok) {
          this.onForward?.({
            action: 'alert.forwarded',
            destination: 'sentinel',
            logType: this.logType,
            findingIds: findings.map((f) => f.findingId),
            count: findings.length,
          });
          return { sent: findings.length, status: res.status };
        }
        if (res.status === 429 || res.status >= 500) {
          lastError = new Error(`Sentinel ingestion transient failure: HTTP ${res.status}`);
        } else {
          // 4xx (non-429) won't heal with retries — fail fast.
          throw new Error(`Sentinel ingestion rejected batch: HTTP ${res.status} ${await res.text()}`);
        }
      } catch (err) {
        if (err instanceof Error && err.message.startsWith('Sentinel ingestion rejected')) throw err;
        lastError = err;
      }
      if (attempt < MAX_RETRIES) {
        await new Promise((r) => setTimeout(r, 2 ** attempt * 500));
      }
    }
    throw lastError;
  }
}

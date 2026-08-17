export { SentinelForwarder } from './sentinel.ts';
export type { Finding, ForwardAuditEvent, SentinelForwarderConfig } from './sentinel.ts';
export { toCef, cefAct } from './cef.ts';
export type { CefFinding } from './cef.ts';
export {
  TAXONOMY,
  RULE_ID_ALIASES,
  SENTINEL_SEVERITY,
  CEF_SEVERITY,
  classifyFinding,
  cefSeverity,
} from './severity.ts';
export type { Classification, SentinelSeverity, TaxonomyEntry } from './severity.ts';

"""Alert delivery for guardrail findings.

Wires new findings out of Postgres to external destinations so they reach a
SIEM instead of only sitting in the findings table:

- ``WebhookNotifier`` — generic HTTPS webhook: one POST per batch of new
  findings, JSON body, HMAC-SHA256 signature header (``X-AIM-Signature:
  sha256=<hex>``) over the exact body bytes, minimum-severity filter.
- ``SentinelNotifier`` — faithful Python port of the TypeScript forwarder in
  ``packages/alerting/src/sentinel.ts`` (Log Analytics Data Collector API,
  SharedKey HMAC-SHA256 auth, CEF mapping). Kept deliberately small; the TS
  remains the reference implementation.
- ``GoogleChatNotifier`` — Google Chat incoming-webhook destination
  for the company standard channel. Webhook URL is env-only (never UI), one
  Cards V2 message per batch (severity / rule / tool / pseudonymous subject /
  deep link to the findings triage view), min-severity filter.
- ``EmailNotifier`` — SMTP email destination. Recipients + enable
  + min_severity are policy/UI-managed; SMTP host/from/user/password stay
  env-only (``ALERT_EMAIL_SMTP_*`` / ``ALERT_EMAIL_FROM``). One plain-text
  message per batch, metadata only.
- ``SlackNotifier`` — optional Slack incoming-webhook destination
  behind ``ALERT_SLACK_ENABLED`` (default off — SOC opt-in only). Webhook URL
  is env-only (``ALERT_SLACK_WEBHOOK_URL``; the URL *is* the secret). One
  Block Kit message per batch, same metadata-only posture as Google Chat.
- ``PagerDutyNotifier`` — Events API v2 trigger per finding. Routing
  key is env-only (``ALERT_PAGERDUTY_ROUTING_KEY``). Designed as the late
  stage of multi-stage escalation (Slack → PagerDuty with timers).

All are off by default (no URL / no workspace = disabled) and share the TS
retry policy: 3 retries with exponential backoff (0.5s, 1s, 2s) on HTTP
429/5xx and network errors; other 4xx fails fast.

Metadata-only guarantee: payloads are built from finding metadata fields
(rule id, severity, pseudonymous refs, detector names) — never prompt or
response content. Alert payloads leave the platform, so they carry
pseudonyms and links, not raw evidence (trust boundary).

Config is via env (see ``notifiers_from_env``) or the policy ruleset's
``settings.alerts`` section (see ``notifiers_from_config``, — secrets
stay env-managed either way); transports are injectable so tests need no
network.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import smtplib
import sys
import time
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate
from typing import Any, Callable, NamedTuple

MAX_RETRIES = 3
BACKOFF_BASE_SECONDS = 0.5
DEFAULT_TIMEOUT_SECONDS = 10.0

SENTINEL_API_PATH = "/api/logs"
SENTINEL_API_VERSION = "2016-04-01"
DEFAULT_SENTINEL_LOG_TYPE = "AIGuardrailFinding"

# Google Chat Cards V2 / Slack Block Kit: cap findings per batch so a rule
# storm cannot flood the channel with multi-MB cards. Overflow is summarized
# as "+N more" with one triage deep link (same batch-once posture as
# WebhookNotifier).
GOOGLE_CHAT_MAX_FINDINGS_PER_CARD = 8
# Email: same cap — one message per batch, overflow summarized with a triage link.
EMAIL_MAX_FINDINGS_PER_MESSAGE = 8
# Recipients: keep the To header bounded so a misconfigured policy cannot
# fan-out a finding to hundreds of addresses.
EMAIL_MAX_RECIPIENTS = 20
# Conservative RFC 5322-ish local@domain check (not a full RFC parser).
_EMAIL_ADDR_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SLACK_MAX_FINDINGS_PER_MESSAGE = 8
# Pseudonym display width in chat — full hash stays in Postgres; chat only needs
# enough of the prefix to correlate with the findings table.
_PSEUDONYM_DISPLAY_CHARS = 12
# Slack is SOC opt-in. Default off until ALERT_SLACK_ENABLED is set
# truthy (1/true/yes/on). Without the flag the notifier never registers even
# if a webhook URL is present in the environment.
_TRUTHY_FLAG_VALUES = frozenset({"1", "true", "yes", "on"})

# Engine severity scale (findings table CHECK constraint).
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Transport contract: POST body to url with headers, return the HTTP status
# code. Network failures raise. Injectable for tests.
Transport = Callable[[str, dict[str, str], bytes], int]
# Email transport: send one EmailMessage (raises on SMTP/network errors).
EmailTransport = Callable[[EmailMessage], None]


def default_transport(url: str, headers: dict[str, str], body: bytes) -> int:
    """stdlib urllib transport with a connect/read timeout (no extra deps)."""
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_SECONDS) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        # HTTP status received (4xx/5xx) — a response, not a network error.
        return exc.code


class DeliveryResult(NamedTuple):
    """What a notifier managed to send in one deliver() call."""

    finding_ids: list[str]
    http_status: int | None
    attempts: int


class DeliveryError(Exception):
    """Raised when a batch could not be delivered after the retry policy."""

    def __init__(
        self,
        message: str,
        *,
        finding_ids: list[str],
        http_status: int | None = None,
        attempts: int = 1,
    ):
        super().__init__(message)
        self.finding_ids = finding_ids
        self.http_status = http_status
        self.attempts = attempts


# -- finding -> record mapping ----------------------------------------------

def finding_fields(finding: dict) -> dict:
    """Map an engine finding dict onto the flat notifier record fields.

    rule_id becomes FindingType, subject.user_ref becomes UserId, the
    metadata-only evidence.context carries tool/model/repo_ref, and
    evidence.matched (detector names, never content) becomes MatchFlags as a
    JSON string.

    also surface host_ref, policy_hash, engine severity, decision,
    and source event_ids — SOC triage fields previously dropped between the
    engine finding and the Sentinel/CEF payload.
    """
    evidence = finding.get("evidence") or {}
    context = evidence.get("context") or {}
    subject = finding.get("subject") or {}
    matched = evidence.get("matched")
    # Subject for alert payloads: prefer user_ref; fall back to host_ref so
    # proxy/App-LLM findings (no employee identity) still show a pivot key
    # in webhook/Sentinel/Chat (new-source signal is host-keyed).
    subject_ref = subject.get("user_ref") or subject.get("host_ref") or ""
    event_ids = evidence.get("event_ids") or []
    if isinstance(event_ids, (list, tuple)):
        event_ids_str = ",".join(str(e) for e in event_ids if e)
    else:
        event_ids_str = str(event_ids) if event_ids else ""
    return {
        "finding_id": finding.get("finding_id"),
        "finding_type": finding.get("rule_id"),
        "title": finding.get("title"),
        "timestamp": finding.get("ts"),
        "user_id": subject_ref,
        # team budgets + scoped allowlists carry team on subject/context.
        "team": subject.get("team") or context.get("team") or "",
        "tool": context.get("tool") or context.get("provider") or "",
        "model": context.get("model") or "",
        "repo": context.get("repo_ref") or "",
        "match_flags": json.dumps(matched, sort_keys=True) if matched else "",
        "host_ref": subject.get("host_ref") or context.get("host_ref") or "",
        "policy_hash": finding.get("policy_hash") or "",
        "engine_severity": finding.get("severity") or "",
        "decision": finding.get("decision") or "observe",
        "event_ids": event_ids_str,
    }


# -- severity taxonomy (port of packages/alerting/src/severity.ts, kept small)

# finding_type -> (Sentinel severity, runbook slug).
TAXONOMY: dict[str, tuple[str, str]] = {
    "secret_pattern_detected": ("High", "rb-secret-exposure"),
    "unapproved_tool_detected": ("Medium", "rb-unapproved-tool"),
    "pii_pattern_detected": ("Medium", "rb-pii-exposure"),
    # AI tool used against a restricted repository. Engine severity is
    # critical; Sentinel tops out at High.
    "restricted_repo_access": ("High", "rb-restricted-repo"),
    # Sanctioned tool talking to an unapproved provider/model. Same triage path
    # as an unapproved tool: unsanctioned egress, may be benign.
    "unapproved_provider_or_model": ("Medium", "rb-unapproved-tool"),
    "usage_anomaly": ("Low", "rb-usage-anomaly"),
    "policy_violation": ("High", "rb-policy-violation"),
    # per-tool-call rail. shell in a restricted repo pages like
    # restricted_repo_access (High); network egress there is lower confidence.
    "shell_tool_restricted_repo": ("High", "rb-restricted-repo"),
    "network_tool_restricted_repo": ("Medium", "rb-restricted-repo"),
    # Unapproved MCP server present in tool config (inventory event) —
    # intent-to-use, not observed traffic; same triage path as unapproved tool.
    "unapproved_mcp_server_configured": ("Medium", "rb-unapproved-tool"),
    "telemetry_gap": ("Informational", "rb-telemetry-gap"),
    # team budget thresholds + scoped model/provider allowlist.
    "team_budget_threshold": ("Medium", "rb-usage-anomaly"),
    "model_provider_not_permitted": ("Medium", "rb-unapproved-tool"),
    # expanded detection depth.
    "credential_shaped_tool_call": ("High", "rb-secret-exposure"),
    "high_volume_repo_egress": ("High", "rb-usage-anomaly"),
    "bulk_shell_hourly": ("Medium", "rb-usage-anomaly"),
    "high_volume_repo_tokens": ("Medium", "rb-usage-anomaly"),
    # first-ever proxy provider-API caller (App-LLM phase-1 signal).
    # Medium — SOC reviews host_ref + provider; may be sanctioned app rollout.
    "app_llm_new_source": ("Medium", "rb-app-llm-new-source"),
    # catalogue completeness — uncatalogued provider/model first-seen.
    # Low — ops/catalogue ownership signal, not a user-security incident.
    "app_llm_new_provider": ("Low", "rb-app-llm-catalogue-drift"),
    "app_llm_new_model": ("Low", "rb-app-llm-catalogue-drift"),
}
FALLBACK_TAXONOMY = ("Low", "rb-unknown-finding")

# Engine rule ids (kebab-case) -> taxonomy finding types (snake_case), so the
# v1 ruleset classifies onto the same taxonomy as the TS forwarder.
RULE_ID_ALIASES = {
    "secret-pattern-in-prompt": "secret_pattern_detected",
    "unapproved-tool": "unapproved_tool_detected",
    "unapproved-provider-or-model": "unapproved_provider_or_model",
    "restricted-repo-access": "restricted_repo_access",
    "pii-in-prompt": "pii_pattern_detected",
    # MCP call to an unapproved server. Maps to the generic
    # policy_violation type — a dedicated Sentinel finding type would be a
    # taxonomy change, which is Security's call.
    "unapproved-mcp-server": "policy_violation",
    # prompt-injection detector fired. Generic policy_violation type,
    # same rationale as unapproved-mcp-server (taxonomy change is Security's call).
    "injection-attempt-in-prompt": "policy_violation",
    # per-tool-call rail: dedicated finding types (see TAXONOMY).
    "shell-tool-restricted-repo": "shell_tool_restricted_repo",
    "network-tool-restricted-repo": "network_tool_restricted_repo",
    "unapproved-mcp-server-configured": "unapproved_mcp_server_configured",
    "unapproved-mcp-tool": "policy_violation",
    "anomalous-volume-hourly": "usage_anomaly",
    "off-hours-bulk-usage": "usage_anomaly",
    # model/cost governance.
    "model-provider-not-permitted": "model_provider_not_permitted",
    "team-budget-tokens-warn": "team_budget_threshold",
    "team-budget-tokens-critical": "team_budget_threshold",
    "team-budget-cost-warn": "team_budget_threshold",
    "team-budget-cost-critical": "team_budget_threshold",
    # expanded detection depth.
    "credential-shaped-tool-call": "credential_shaped_tool_call",
    "high-volume-repo-egress": "high_volume_repo_egress",
    "bulk-shell-hourly": "bulk_shell_hourly",
    "high-volume-repo-tokens": "high_volume_repo_tokens",
    # App-LLM new-sources → SOC.
    "app-llm-new-source": "app_llm_new_source",
    # catalogue drift.
    "app-llm-new-provider": "app_llm_new_provider",
    "app-llm-new-model": "app_llm_new_model",
}

# Sentinel severity label -> CEF numeric severity (0-10).
CEF_SEVERITY = {"Informational": 2, "Low": 4, "Medium": 6, "High": 9}


def classify(finding_type: str) -> tuple[str, str, bool]:
    """Resolve a finding type to (Sentinel severity, runbook slug, known)."""
    entry = TAXONOMY.get(RULE_ID_ALIASES.get(finding_type, finding_type))
    if entry:
        return entry[0], entry[1], True
    return FALLBACK_TAXONOMY[0], FALLBACK_TAXONOMY[1], False


# -- CEF (port of packages/alerting/src/cef.ts, field completeness) ---

_CEF_VENDOR = "AIMonitoring"
_CEF_PRODUCT = "GuardrailEngine"
_CEF_VERSION = "1.0"
# Cap extension values that can grow (event id lists) — keep CEF parseable.
_MAX_EXT_VALUE_LEN = 512


def _escape_header(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _escape_extension(value: Any) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def _clip_ext(value: str, max_len: int = _MAX_EXT_VALUE_LEN) -> str:
    if len(value) <= max_len:
        return value
    return value[: max_len - 1] + "…"


def cef_act(decision: str | None) -> str:
    """Map finding.decision onto CEF act (port of packages/alerting cefAct)."""
    if decision == "blocked":
        return "block"
    if decision == "would_block":
        return "would_block"
    if decision == "confirmed":
        return "allow"
    return "alert"


def to_cef(fields: dict, severity: int, runbook_url: str = "") -> str:
    """Build a CEF string for a finding. Metadata-only: pattern ids, never content.

    Custom strings always ship with *Label pairs so Sentinel parsers
    do not need a side-channel schema.
    """
    name = fields.get("title") or fields["finding_type"]
    ext = " ".join(
        f"{k}={_escape_extension(v)}"
        for k, v in [
            ("rt", fields["timestamp"]),
            ("suser", fields["user_id"]),
            ("dvchost", fields.get("host_ref") or ""),
            ("msg", name),
            ("cat", "ai-security"),
            ("cs1Label", "AITool"),
            ("cs1", fields["tool"]),
            ("cs2Label", "Model"),
            ("cs2", fields.get("model") or ""),
            ("cs3Label", "Repository"),
            ("cs3", fields.get("repo") or ""),
            ("cs4Label", "MatchFlags"),
            ("cs4", fields.get("match_flags") or ""),
            ("cs5Label", "Runbook"),
            ("cs5", runbook_url),
            ("cs6Label", "Team"),
            ("cs6", fields.get("team") or ""),
            ("cs7Label", "EngineSeverity"),
            ("cs7", fields.get("engine_severity") or ""),
            ("flexString1Label", "PolicyHash"),
            ("flexString1", fields.get("policy_hash") or ""),
            ("flexString2Label", "EventIds"),
            ("flexString2", _clip_ext(fields.get("event_ids") or "")),
            ("externalId", fields["finding_id"]),
            ("act", cef_act(fields.get("decision"))),
        ]
    )
    return "|".join([
        "CEF:0",
        _escape_header(_CEF_VENDOR),
        _escape_header(_CEF_PRODUCT),
        _escape_header(_CEF_VERSION),
        _escape_header(fields["finding_type"]),
        _escape_header(name),
        str(severity),
        ext,
    ])


# Canonical Sentinel / webhook JSON field set (+ completeness).
SENTINEL_RECORD_FIELDS = (
    "FindingId",
    "TimeGenerated",
    "FindingType",
    "Title",
    "Severity",
    "EngineSeverity",
    "UserId",
    "Team",
    "HostRef",
    "Tool",
    "Model",
    "Repo",
    "MatchFlags",
    "PolicyHash",
    "EventIds",
    "Decision",
    "RunbookUrl",
    "EnforcementMode",
    "Cef",
)


def build_record(finding: dict, runbook_base_url: str = "") -> dict:
    """Enrich an engine finding into the notifier JSON record.

    Same field set as the TS SentinelForwarder.buildRecord — see
    SENTINEL_RECORD_FIELDS and docs/aim-585-sentinel-cef-field-matrix.md.
    """
    fields = finding_fields(finding)
    severity, runbook, known = classify(fields["finding_type"])
    if not known:
        # Loud fallback: unknown finding types must be added to the taxonomy.
        print(
            f'[alerting] unknown findingType "{fields["finding_type"]}" — using fallback severity',
            file=sys.stderr,
        )
    runbook_url = f"{runbook_base_url}{runbook}" if runbook_base_url else runbook
    decision = fields.get("decision") or "observe"
    return {
        "FindingId": fields["finding_id"],
        "TimeGenerated": fields["timestamp"],
        "FindingType": fields["finding_type"],
        "Title": fields["title"] or fields["finding_type"],
        "Severity": severity,
        "EngineSeverity": fields.get("engine_severity") or "",
        "UserId": fields["user_id"],
        "Team": fields.get("team") or "",
        "HostRef": fields.get("host_ref") or "",
        "Tool": fields["tool"],
        "Model": fields["model"],
        "Repo": fields["repo"],
        "MatchFlags": fields["match_flags"],
        "PolicyHash": fields.get("policy_hash") or "",
        "EventIds": fields.get("event_ids") or "",
        "Decision": decision,
        "RunbookUrl": runbook_url,
        "EnforcementMode": "enforce" if decision == "blocked" else "observe-only",
        "Cef": to_cef(fields, CEF_SEVERITY[severity], runbook_url),
    }


# -- shared retry loop ---------------------------------------------------------

def _post_with_retry(
    destination: str,
    finding_ids: list[str],
    build_headers: Callable[[], dict[str, str]],
    url: str,
    body: bytes,
    transport: Transport,
    sleep: Callable[[float], None],
) -> DeliveryResult:
    """POST with the TS retry policy: 3 retries, backoff 0.5*2^attempt, on
    429/5xx and network errors; other 4xx fails fast. ``build_headers`` is
    called per attempt because signed headers (x-ms-date) are time-dependent."""
    last_error: DeliveryError | None = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            status = transport(url, build_headers(), body)
        except Exception as exc:  # network error — transient, retry
            last_error = DeliveryError(
                f"{destination} delivery network error: {exc}",
                finding_ids=finding_ids,
                attempts=attempt + 1,
            )
        else:
            if 200 <= status < 300:
                return DeliveryResult(finding_ids, status, attempt + 1)
            if status == 429 or status >= 500:
                last_error = DeliveryError(
                    f"{destination} delivery transient failure: HTTP {status}",
                    finding_ids=finding_ids,
                    http_status=status,
                    attempts=attempt + 1,
                )
            else:
                # 4xx (non-429) won't heal with retries — fail fast.
                raise DeliveryError(
                    f"{destination} delivery rejected batch: HTTP {status}",
                    finding_ids=finding_ids,
                    http_status=status,
                    attempts=attempt + 1,
                )
        if attempt < MAX_RETRIES:
            sleep(BACKOFF_BASE_SECONDS * 2**attempt)
    raise last_error  # type: ignore[misc]


# -- notifiers -----------------------------------------------------------------


class WebhookNotifier:
    """Generic HMAC-signed HTTPS webhook.

    One POST per batch: JSON array of records, signed with
    ``X-AIM-Signature: sha256=<hex HMAC-SHA256 of body>`` keyed by the
    configured secret. Findings below ``min_severity`` are dropped.
    """

    destination = "webhook"

    def __init__(
        self,
        url: str,
        secret: str,
        min_severity: str = "low",
        runbook_base_url: str = "",
        *,
        transport: Transport = default_transport,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if not url:
            raise ValueError("webhook url is required")
        if not secret:
            raise ValueError("ALERT_WEBHOOK_SECRET is required when ALERT_WEBHOOK_URL is set")
        if min_severity not in SEVERITY_ORDER:
            raise ValueError(
                f"ALERT_WEBHOOK_MIN_SEVERITY must be one of {sorted(SEVERITY_ORDER)}, got {min_severity!r}"
            )
        self.url = url
        self.secret = secret
        self.min_severity = min_severity
        self.runbook_base_url = runbook_base_url
        self.transport = transport
        self.sleep = sleep

    def deliver(self, findings: list[dict]) -> DeliveryResult:
        floor = SEVERITY_ORDER[self.min_severity]
        eligible = [
            f for f in findings
            if SEVERITY_ORDER.get(f.get("severity", "low"), 0) >= floor
        ]
        if not eligible:
            return DeliveryResult([], None, 0)
        body = json.dumps([build_record(f, self.runbook_base_url) for f in eligible]).encode("utf-8")
        signature = hmac.new(self.secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

        def build_headers() -> dict[str, str]:
            return {
                "Content-Type": "application/json",
                "X-AIM-Signature": f"sha256={signature}",
            }

        return _post_with_retry(
            self.destination,
            [f["finding_id"] for f in eligible],
            build_headers,
            self.url,
            body,
            self.transport,
            self.sleep,
        )


class SentinelNotifier:
    """Microsoft Sentinel via the Log Analytics Data Collector API.

    Faithful Python port of packages/alerting/src/sentinel.ts: same
    string-to-sign, ``SharedKey {workspaceId}:{base64-hmac}`` Authorization
    header, same record shape and retry policy.
    """

    destination = "sentinel"

    def __init__(
        self,
        workspace_id: str,
        shared_key: str,
        log_type: str = DEFAULT_SENTINEL_LOG_TYPE,
        endpoint: str | None = None,
        runbook_base_url: str = "",
        *,
        transport: Transport = default_transport,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if not workspace_id or not shared_key:
            raise ValueError("SENTINEL_WORKSPACE_ID and SENTINEL_SHARED_KEY are both required")
        self.workspace_id = workspace_id
        self.shared_key = shared_key
        self.log_type = log_type
        self.endpoint = endpoint or (
            f"https://{workspace_id}.ods.opinsights.azure.com"
            f"{SENTINEL_API_PATH}?api-version={SENTINEL_API_VERSION}"
        )
        self.runbook_base_url = runbook_base_url
        self.transport = transport
        self.sleep = sleep

    def sign(self, date_rfc1123: str, content_length: int) -> str:
        """SharedKey authorization header value (same string-to-sign as the TS)."""
        string_to_sign = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{date_rfc1123}\n{SENTINEL_API_PATH}"
        )
        mac = base64.b64encode(
            hmac.new(
                base64.b64decode(self.shared_key),
                string_to_sign.encode("utf-8"),
                hashlib.sha256,
            ).digest()
        ).decode("ascii")
        return f"SharedKey {self.workspace_id}:{mac}"

    def deliver(self, findings: list[dict]) -> DeliveryResult:
        if not findings:
            return DeliveryResult([], None, 0)
        body = json.dumps([build_record(f, self.runbook_base_url) for f in findings]).encode("utf-8")

        def build_headers() -> dict[str, str]:
            date = formatdate(timeval=None, localtime=False, usegmt=True)
            return {
                "Content-Type": "application/json",
                "Log-Type": self.log_type,
                "x-ms-date": date,
                "time-generated-field": "TimeGenerated",
                "Authorization": self.sign(date, len(body)),
            }

        return _post_with_retry(
            self.destination,
            [f["finding_id"] for f in findings],
            build_headers,
            self.endpoint,
            body,
            self.transport,
            self.sleep,
        )


def _short_ref(value: str, n: int = _PSEUDONYM_DISPLAY_CHARS) -> str:
    """Truncate a pseudonym for chat display. Never invents identity."""
    value = (value or "").strip()
    if not value:
        return "—"
    if len(value) <= n:
        return value
    return f"{value[:n]}…"


def triage_deep_link(base_url: str, finding_id: str | None = None) -> str:
    """HTTPS deep link into the findings triage view.

    ``AIM_BASE_URL`` (dashboard origin) + ``#/findings``. When a single finding
    id is known, append ``?id=`` so a future UI can open that row; today's
    findings view still lands on the triage list if it ignores the param.
    Empty base yields a relative hash-only link (never a secret).
    """
    base = (base_url or "").rstrip("/")
    path = "#/findings"
    if finding_id:
        path = f"{path}?id={finding_id}"
    if not base:
        return path
    return f"{base}/{path}" if not base.endswith("/") else f"{base}{path}"


def build_google_chat_card(
    findings: list[dict],
    *,
    triage_base_url: str = "",
    max_findings: int = GOOGLE_CHAT_MAX_FINDINGS_PER_CARD,
) -> dict:
    """Build a Google Chat Cards V2 payload for one batch of findings.

    Metadata only: severity, rule, tool, truncated pseudonymous subject, deep
    link. Never prompt/response content, never full evidence blobs.
    """
    if not findings:
        raise ValueError("google chat card requires at least one finding")

    shown = findings[:max_findings]
    overflow = len(findings) - len(shown)
    first = shown[0]
    single = len(findings) == 1
    header_title = first.get("title") or first.get("rule_id") or "Guardrail finding"
    if not single:
        header_title = f"{len(findings)} guardrail findings"
    header_subtitle = (
        f"{(first.get('severity') or 'unknown').upper()}"
        if single
        else f"highest shown: {(max(shown, key=lambda f: SEVERITY_ORDER.get(f.get('severity', 'low'), 0)).get('severity') or 'unknown').upper()}"
    )

    sections: list[dict] = []
    for finding in shown:
        fields = finding_fields(finding)
        severity = (finding.get("severity") or "unknown").upper()
        rule = fields["finding_type"] or "—"
        tool = fields["tool"] or "—"
        subject = _short_ref(fields["user_id"])
        link = triage_deep_link(triage_base_url, fields["finding_id"] if single else None)
        widgets: list[dict] = [
            {
                "decoratedText": {
                    "topLabel": "Severity",
                    "text": severity,
                    "wrapText": True,
                }
            },
            {
                "decoratedText": {
                    "topLabel": "Rule",
                    "text": rule,
                    "wrapText": True,
                }
            },
            {
                "decoratedText": {
                    "topLabel": "Tool",
                    "text": tool,
                    "wrapText": True,
                }
            },
            {
                "decoratedText": {
                    "topLabel": "Subject (pseudonym)",
                    "text": subject,
                    "wrapText": True,
                }
            },
            {
                "buttonList": {
                    "buttons": [
                        {
                            "text": "Open triage",
                            "onClick": {"openLink": {"url": link}},
                        }
                    ]
                }
            },
        ]
        section_header = finding.get("title") or rule
        if not single:
            section_header = f"[{severity}] {section_header}"
        sections.append({"header": section_header, "widgets": widgets})

    if overflow > 0:
        link = triage_deep_link(triage_base_url)
        sections.append({
            "widgets": [
                {
                    "decoratedText": {
                        "text": f"+{overflow} more in this batch — open triage for the full list.",
                        "wrapText": True,
                    }
                },
                {
                    "buttonList": {
                        "buttons": [
                            {
                                "text": "Open triage",
                                "onClick": {"openLink": {"url": link}},
                            }
                        ]
                    }
                },
            ]
        })

    card_id = first.get("finding_id") or "guardrail-batch"
    if not single:
        card_id = f"batch-{card_id}"
    return {
        "cardsV2": [
            {
                "cardId": str(card_id)[:64],
                "card": {
                    "header": {
                        "title": str(header_title)[:200],
                        "subtitle": header_subtitle,
                    },
                    "sections": sections,
                },
            }
        ]
    }


class GoogleChatNotifier:
    """Google Chat incoming webhook.

    One Cards V2 POST per batch of eligible findings. The webhook URL is the
    secret (Google Chat space keys live in the URL path/query) and is only
    ever read from ``ALERT_GOOGLE_CHAT_WEBHOOK_URL`` — never from policy or the
    Rules UI. Findings below ``min_severity`` are dropped so a noisy rule
    cannot flood the company space.

    Same retry policy as the other notifiers. Payload is metadata-only.
    """

    destination = "google_chat"

    def __init__(
        self,
        webhook_url: str,
        min_severity: str = "high",
        triage_base_url: str = "",
        *,
        transport: Transport = default_transport,
        sleep: Callable[[float], None] = time.sleep,
        max_findings_per_card: int = GOOGLE_CHAT_MAX_FINDINGS_PER_CARD,
    ):
        if not webhook_url:
            raise ValueError(
                "ALERT_GOOGLE_CHAT_WEBHOOK_URL is required when google_chat is enabled"
            )
        if min_severity not in SEVERITY_ORDER:
            raise ValueError(
                f"ALERT_GOOGLE_CHAT_MIN_SEVERITY must be one of {sorted(SEVERITY_ORDER)}, "
                f"got {min_severity!r}"
            )
        self.webhook_url = webhook_url
        self.min_severity = min_severity
        self.triage_base_url = triage_base_url
        self.transport = transport
        self.sleep = sleep
        self.max_findings_per_card = max_findings_per_card

    def deliver(self, findings: list[dict]) -> DeliveryResult:
        floor = SEVERITY_ORDER[self.min_severity]
        eligible = [
            f for f in findings
            if SEVERITY_ORDER.get(f.get("severity", "low"), 0) >= floor
        ]
        if not eligible:
            return DeliveryResult([], None, 0)
        # Sort highest severity first so the card header / capped list surface
        # the worst findings when a batch is truncated.
        eligible.sort(
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "low"), 0),
            reverse=True,
        )
        payload = build_google_chat_card(
            eligible,
            triage_base_url=self.triage_base_url,
            max_findings=self.max_findings_per_card,
        )
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        def build_headers() -> dict[str, str]:
            return {"Content-Type": "application/json; charset=UTF-8"}

        return _post_with_retry(
            self.destination,
            [f["finding_id"] for f in eligible],
            build_headers,
            self.webhook_url,
            body,
            self.transport,
            self.sleep,
        )



def slack_feature_enabled(env: dict | None = None) -> bool:
    """Slack destination is behind ALERT_SLACK_ENABLED (default off).

    SOC opt-in only — research ranked Slack/email destinations as "only if the
    security team asks." The flag must be truthy *and* a webhook URL must be
    configured before any message leaves the platform.
    """
    env = env if env is not None else os.environ
    raw = (env.get("ALERT_SLACK_ENABLED") or "").strip().lower()
    return raw in _TRUTHY_FLAG_VALUES


def build_slack_message(
    findings: list[dict],
    *,
    triage_base_url: str = "",
    max_findings: int = SLACK_MAX_FINDINGS_PER_MESSAGE,
) -> dict:
    """Build a Slack Incoming Webhook payload (Block Kit) for one batch.

    Metadata only: severity, rule, tool, truncated pseudonymous subject, deep
    link. Never prompt/response content, never full evidence blobs, never the
    webhook URL itself.
    """
    if not findings:
        raise ValueError("slack message requires at least one finding")

    shown = findings[:max_findings]
    overflow = len(findings) - len(shown)
    first = shown[0]
    single = len(findings) == 1
    header = first.get("title") or first.get("rule_id") or "Guardrail finding"
    if not single:
        header = f"{len(findings)} guardrail findings"
    # Slack plain_text headers max out at 150 chars.
    header = str(header)[:150]

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": header, "emoji": False},
        }
    ]

    for finding in shown:
        fields = finding_fields(finding)
        severity = (finding.get("severity") or "unknown").upper()
        rule = fields["finding_type"] or "—"
        tool = fields["tool"] or "—"
        subject = _short_ref(fields["user_id"])
        title = finding.get("title") or rule
        if not single:
            title = f"[{severity}] {title}"
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{str(title)[:200]}*",
            },
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity*\n{severity}"},
                {"type": "mrkdwn", "text": f"*Rule*\n`{rule}`"},
                {"type": "mrkdwn", "text": f"*Tool*\n`{tool}`"},
                {"type": "mrkdwn", "text": f"*Subject*\n`{subject}`"},
            ],
        })
        link = triage_deep_link(
            triage_base_url, fields["finding_id"] if single else None,
        )
        # Slack button URLs must be absolute https; fall back to a plain link
        # line when AIM_BASE_URL is unset (local/dev).
        if link.startswith("http://") or link.startswith("https://"):
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Open triage", "emoji": False},
                        "url": link,
                    }
                ],
            })
        else:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"<{link}|Open triage>"},
            })

    if overflow > 0:
        link = triage_deep_link(triage_base_url)
        if link.startswith("http://") or link.startswith("https://"):
            overflow_text = (
                f"+{overflow} more in this batch — open triage for the full list."
            )
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": overflow_text},
            })
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Open triage", "emoji": False},
                        "url": link,
                    }
                ],
            })
        else:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"+{overflow} more in this batch — "
                        f"<{link}|open triage> for the full list."
                    ),
                },
            })

    # Fallback text for clients that ignore blocks (and for push notification
    # previews). Metadata only.
    if single:
        fields = finding_fields(first)
        fallback = (
            f"[{(first.get('severity') or 'unknown').upper()}] "
            f"{first.get('title') or fields['finding_type'] or 'finding'}"
        )
    else:
        fallback = f"{len(findings)} guardrail findings"

    return {"text": fallback[:500], "blocks": blocks}


class SlackNotifier:
    """Slack incoming webhook — SOC opt-in via ALERT_SLACK_ENABLED.

    One Block Kit POST per batch of eligible findings. The webhook URL is the
    secret (Slack signing tokens live in the path) and is only ever read from
    ``ALERT_SLACK_WEBHOOK_URL`` — never from policy or the Rules UI. The
    feature flag defaults off; without it, ``notifiers_from_*`` never builds
    this notifier even if a URL is present.

    Same retry policy as the other notifiers. Payload is metadata-only.
    """

    destination = "slack"

    def __init__(
        self,
        webhook_url: str,
        min_severity: str = "high",
        triage_base_url: str = "",
        *,
        transport: Transport = default_transport,
        sleep: Callable[[float], None] = time.sleep,
        max_findings_per_message: int = SLACK_MAX_FINDINGS_PER_MESSAGE,
    ):
        if not webhook_url:
            raise ValueError(
                "ALERT_SLACK_WEBHOOK_URL is required when slack is enabled"
            )
        if min_severity not in SEVERITY_ORDER:
            raise ValueError(
                f"ALERT_SLACK_MIN_SEVERITY must be one of {sorted(SEVERITY_ORDER)}, "
                f"got {min_severity!r}"
            )
        self.webhook_url = webhook_url
        self.min_severity = min_severity
        self.triage_base_url = triage_base_url
        self.transport = transport
        self.sleep = sleep
        self.max_findings_per_message = max_findings_per_message

    def deliver(self, findings: list[dict]) -> DeliveryResult:
        floor = SEVERITY_ORDER[self.min_severity]
        eligible = [
            f for f in findings
            if SEVERITY_ORDER.get(f.get("severity", "low"), 0) >= floor
        ]
        if not eligible:
            return DeliveryResult([], None, 0)
        eligible.sort(
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "low"), 0),
            reverse=True,
        )
        payload = build_slack_message(
            eligible,
            triage_base_url=self.triage_base_url,
            max_findings=self.max_findings_per_message,
        )
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        def build_headers() -> dict[str, str]:
            return {"Content-Type": "application/json; charset=UTF-8"}

        return _post_with_retry(
            self.destination,
            [f["finding_id"] for f in eligible],
            build_headers,
            self.webhook_url,
            body,
            self.transport,
            self.sleep,
        )




# PagerDuty Events API v2 — on-call page destination escalation.
PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
# Map engine severity → PD payload severity.
PAGERDUTY_SEVERITY = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
}


def build_pagerduty_event(
    finding: dict,
    *,
    routing_key: str,
    source: str = "ai-monitoring",
    triage_base_url: str = "",
) -> dict:
    """Build one Events API v2 trigger payload (metadata-only).

    ``dedup_key`` is stable on ``finding_id`` so re-drives and multi-stage
    re-fires collapse into one open incident at PagerDuty.
    """
    fields = finding_fields(finding)
    sev = finding.get("severity") or "high"
    summary = (finding.get("title") or fields["finding_type"] or "AI Monitoring finding")[:1024]
    details = {
        "rule_id": fields["finding_type"],
        "engine_severity": sev,
        "user_ref": (fields.get("user_id") or "")[:_PSEUDONYM_DISPLAY_CHARS],
        "host_ref": (fields.get("host_ref") or "")[:_PSEUDONYM_DISPLAY_CHARS],
        "tool": fields.get("tool") or "",
        "policy_hash": (fields.get("policy_hash") or "")[:16],
        "decision": fields.get("decision") or finding.get("decision") or "observe",
    }
    link = triage_deep_link(triage_base_url)
    if link.startswith("http://") or link.startswith("https://"):
        details["triage_url"] = link
    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": f"aim:{finding['finding_id']}",
        "payload": {
            "summary": summary,
            "severity": PAGERDUTY_SEVERITY.get(sev, "error"),
            "source": source,
            "component": "guardrail",
            "group": fields["finding_type"] or "guardrail",
            "class": "ai-security",
            "custom_details": details,
        },
    }


class PagerDutyNotifier:
    """PagerDuty Events API v2 — on-call page destination.

    One trigger event per eligible finding (not batched): PagerDuty dedupes
    on ``dedup_key=aim:<finding_id>``. Routing key is env-only
    (``ALERT_PAGERDUTY_ROUTING_KEY``). Pair with ``escalation_policies`` so
    Slack (or chat) pages first and PagerDuty only after a timer while the
    finding is still open.
    """

    destination = "pagerduty"

    def __init__(
        self,
        routing_key: str,
        min_severity: str = "critical",
        triage_base_url: str = "",
        source: str = "ai-monitoring",
        *,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        events_url: str = PAGERDUTY_EVENTS_URL,
    ):
        if not routing_key:
            raise ValueError(
                "ALERT_PAGERDUTY_ROUTING_KEY is required when pagerduty is enabled"
            )
        if min_severity not in SEVERITY_ORDER:
            raise ValueError(
                f"ALERT_PAGERDUTY_MIN_SEVERITY must be one of {sorted(SEVERITY_ORDER)}, "
                f"got {min_severity!r}"
            )
        self.routing_key = routing_key
        self.min_severity = min_severity
        self.triage_base_url = triage_base_url
        self.source = source
        # Late-bind default so tests can patch notify.default_transport.
        self.transport = transport or default_transport
        self.sleep = sleep
        self.events_url = events_url
    def deliver(self, findings: list[dict]) -> DeliveryResult:
        floor = SEVERITY_ORDER[self.min_severity]
        eligible = [
            f for f in findings
            if SEVERITY_ORDER.get(f.get("severity", "low"), 0) >= floor
        ]
        if not eligible:
            return DeliveryResult([], None, 0)

        delivered_ids: list[str] = []
        last_status: int | None = None
        total_attempts = 0
        for finding in eligible:
            payload = build_pagerduty_event(
                finding,
                routing_key=self.routing_key,
                source=self.source,
                triage_base_url=self.triage_base_url,
            )
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

            def build_headers() -> dict[str, str]:
                return {"Content-Type": "application/json"}

            result = _post_with_retry(
                self.destination,
                [finding["finding_id"]],
                build_headers,
                self.events_url,
                body,
                self.transport,
                self.sleep,
            )
            delivered_ids.append(finding["finding_id"])
            last_status = result.http_status
            total_attempts += result.attempts
        return DeliveryResult(delivered_ids, last_status, total_attempts or 1)

    def deliver_test(self) -> DeliveryResult:
        """Fire a synthetic Events API v2 trigger (delivery proof).

        Always pages once regardless of ``min_severity`` so operators can
        prove the routing key and PD service integration without waiting for
        a real critical finding. Dedup key is stable on the synthetic
        finding_id so repeated test pages collapse into one open incident.
        """
        finding = build_test_pagerduty_finding()
        payload = build_pagerduty_event(
            finding,
            routing_key=self.routing_key,
            source=self.source,
            triage_base_url=self.triage_base_url,
        )
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        def build_headers() -> dict[str, str]:
            return {"Content-Type": "application/json"}

        return _post_with_retry(
            self.destination,
            [finding["finding_id"]],
            build_headers,
            self.events_url,
            body,
            self.transport,
            self.sleep,
        )


def build_test_pagerduty_finding() -> dict:
    """Synthetic critical finding for the PagerDuty notify-test path."""
    return {
        "finding_id": "00000000-0000-4000-8000-00000000pdte",
        "rule_id": "pagerduty-destination-test",
        "severity": "critical",
        "title": "AIM PagerDuty alert destination test page",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "subject": {"user_ref": "c" * 64, "host_ref": "d" * 64},
        "evidence": {
            "event_ids": [],
            "matched": [],
            "context": {"tool": "guardrail-test", "model": "", "repo_ref": ""},
        },
        "policy_hash": "0" * 64,
        "decision": "observe",
    }


def _normalize_email_addrs(raw: Any) -> list[str]:
    """Parse a recipient list from policy (list) or env (comma-separated)."""
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.replace(";", ",").split(",")]
    elif isinstance(raw, (list, tuple)):
        parts = [str(p).strip() for p in raw]
    else:
        raise ValueError("email.to must be a list of addresses or a comma-separated string")
    addrs: list[str] = []
    seen: set[str] = set()
    for part in parts:
        if not part:
            continue
        if not _EMAIL_ADDR_RE.match(part):
            raise ValueError(f"invalid email address: {part!r}")
        key = part.lower()
        if key in seen:
            continue
        seen.add(key)
        addrs.append(part)
    if len(addrs) > EMAIL_MAX_RECIPIENTS:
        raise ValueError(
            f"email.to may list at most {EMAIL_MAX_RECIPIENTS} recipients, got {len(addrs)}"
        )
    return addrs


def build_email_message(
    findings: list[dict],
    *,
    from_addr: str,
    to_addrs: list[str],
    triage_base_url: str = "",
    max_findings: int = EMAIL_MAX_FINDINGS_PER_MESSAGE,
    subject_prefix: str = "[AIM]",
) -> EmailMessage:
    """Build a plain-text email for one batch of findings (metadata only)."""
    if not findings:
        raise ValueError("email message requires at least one finding")
    if not to_addrs:
        raise ValueError("email message requires at least one recipient")

    shown = findings[:max_findings]
    overflow = len(findings) - len(shown)
    first = shown[0]
    single = len(findings) == 1
    top_sev = (
        (first.get("severity") or "unknown")
        if single
        else (
            max(shown, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "low"), 0)).get(
                "severity"
            )
            or "unknown"
        )
    )
    if single:
        title = first.get("title") or first.get("rule_id") or "Guardrail finding"
        subject = f"{subject_prefix} [{str(top_sev).upper()}] {title}"
    else:
        subject = f"{subject_prefix} [{str(top_sev).upper()}] {len(findings)} guardrail findings"
    # Keep subjects mail-client friendly.
    subject = " ".join(str(subject).split())[:200]

    lines = [
        "AI Monitoring guardrail alert",
        "=============================",
        "",
        "Metadata only — no prompt/response content is included.",
        "",
    ]
    for finding in shown:
        fields = finding_fields(finding)
        severity = (finding.get("severity") or "unknown").upper()
        rule = fields["finding_type"] or "—"
        tool = fields["tool"] or "—"
        subject_ref = _short_ref(fields["user_id"])
        link = triage_deep_link(triage_base_url, fields["finding_id"] if single else None)
        title = finding.get("title") or rule
        lines.extend([
            f"--- {title}",
            f"Severity:  {severity}",
            f"Rule:      {rule}",
            f"Tool:      {tool}",
            f"Subject:   {subject_ref} (pseudonym)",
            f"Finding:   {fields['finding_id'] or '—'}",
            f"Triage:    {link}",
            "",
        ])
    if overflow > 0:
        lines.extend([
            f"+{overflow} more in this batch — open triage for the full list:",
            triage_deep_link(triage_base_url),
            "",
        ])
    lines.append("— AI Monitoring guardrail engine")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg["Date"] = formatdate(timeval=None, localtime=False, usegmt=True)
    msg.set_content("\n".join(lines))
    return msg


def build_test_email_finding() -> dict:
    """Synthetic finding used by the notify-test path (delivery proof)."""
    return {
        "finding_id": "00000000-0000-4000-8000-00000000test",
        "rule_id": "email-destination-test",
        "severity": "high",
        "title": "AIM email alert destination test message",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "subject": {"user_ref": "c" * 64, "host_ref": "d" * 64},
        "evidence": {
            "event_ids": [],
            "matched": [],
            "context": {"tool": "guardrail-test", "model": "", "repo_ref": ""},
        },
        "policy_hash": "0" * 64,
        "decision": "observe",
    }


def default_email_transport(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    use_tls: bool,
    use_ssl: bool,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> EmailTransport:
    """Build an SMTP sender bound to the configured host (stdlib smtplib only)."""

    def send(message: EmailMessage) -> None:
        if use_ssl:
            client: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=timeout)
        else:
            client = smtplib.SMTP(host, port, timeout=timeout)
        try:
            client.ehlo()
            if use_tls and not use_ssl:
                client.starttls()
                client.ehlo()
            if user:
                client.login(user, password)
            client.send_message(message)
        finally:
            try:
                client.quit()
            except Exception:
                client.close()

    return send


class EmailNotifier:
    """SMTP email destination.

    One plain-text message per batch of eligible findings. SMTP credentials and
    From address are env-managed (``ALERT_EMAIL_SMTP_*`` / ``ALERT_EMAIL_FROM``);
    recipients and min-severity are non-secret policy/UI fields. Findings below
    ``min_severity`` are dropped.

    Retry policy matches the HTTP notifiers (3 retries, exponential backoff) on
    SMTP/network errors. Payload is metadata-only.
    """

    destination = "email"

    def __init__(
        self,
        *,
        smtp_host: str,
        from_addr: str,
        to_addrs: list[str],
        smtp_port: int = 587,
        smtp_user: str = "",
        smtp_password: str = "",
        min_severity: str = "high",
        triage_base_url: str = "",
        use_tls: bool = True,
        use_ssl: bool = False,
        transport: EmailTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_findings_per_message: int = EMAIL_MAX_FINDINGS_PER_MESSAGE,
    ):
        if not smtp_host:
            raise ValueError(
                "ALERT_EMAIL_SMTP_HOST is required when email alerts are enabled"
            )
        if not from_addr or not _EMAIL_ADDR_RE.match(from_addr):
            raise ValueError(
                "ALERT_EMAIL_FROM must be a valid address when email alerts are enabled"
            )
        to_addrs = _normalize_email_addrs(to_addrs)
        if not to_addrs:
            raise ValueError(
                "email.to must list at least one recipient when email alerts are enabled"
            )
        if min_severity not in SEVERITY_ORDER:
            raise ValueError(
                f"ALERT_EMAIL_MIN_SEVERITY must be one of {sorted(SEVERITY_ORDER)}, "
                f"got {min_severity!r}"
            )
        if smtp_user and not smtp_password:
            raise ValueError(
                "ALERT_EMAIL_SMTP_PASSWORD is required when ALERT_EMAIL_SMTP_USER is set"
            )
        try:
            smtp_port = int(smtp_port)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"ALERT_EMAIL_SMTP_PORT must be an integer, got {smtp_port!r}"
            ) from exc
        if not (1 <= smtp_port <= 65535):
            raise ValueError(f"ALERT_EMAIL_SMTP_PORT out of range: {smtp_port}")

        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user or ""
        self.smtp_password = smtp_password or ""
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.min_severity = min_severity
        self.triage_base_url = triage_base_url
        self.use_tls = use_tls
        self.use_ssl = use_ssl
        self.sleep = sleep
        self.max_findings_per_message = max_findings_per_message
        self.transport = transport or default_email_transport(
            host=smtp_host,
            port=smtp_port,
            user=self.smtp_user,
            password=self.smtp_password,
            use_tls=use_tls,
            use_ssl=use_ssl,
        )

    def _send_with_retry(self, message: EmailMessage, finding_ids: list[str]) -> DeliveryResult:
        last_error: DeliveryError | None = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                self.transport(message)
            except Exception as exc:
                last_error = DeliveryError(
                    f"{self.destination} delivery SMTP error: {exc}",
                    finding_ids=finding_ids,
                    attempts=attempt + 1,
                )
                if attempt < MAX_RETRIES:
                    self.sleep(BACKOFF_BASE_SECONDS * 2**attempt)
                continue
            # 250 = SMTP "requested mail action okay, completed"
            return DeliveryResult(finding_ids, 250, attempt + 1)
        raise last_error  # type: ignore[misc]

    def deliver(self, findings: list[dict]) -> DeliveryResult:
        floor = SEVERITY_ORDER[self.min_severity]
        eligible = [
            f for f in findings
            if SEVERITY_ORDER.get(f.get("severity", "low"), 0) >= floor
        ]
        if not eligible:
            return DeliveryResult([], None, 0)

        eligible.sort(
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "low"), 0),
            reverse=True,
        )
        message = build_email_message(
            eligible,
            from_addr=self.from_addr,
            to_addrs=self.to_addrs,
            triage_base_url=self.triage_base_url,
            max_findings=self.max_findings_per_message,
        )
        return self._send_with_retry(message, [f["finding_id"] for f in eligible])

    def deliver_test(self) -> DeliveryResult:
        """Send a synthetic test message (delivery proof)."""
        finding = build_test_email_finding()
        message = build_email_message(
            [finding],
            from_addr=self.from_addr,
            to_addrs=self.to_addrs,
            triage_base_url=self.triage_base_url,
            max_findings=self.max_findings_per_message,
            subject_prefix="[AIM TEST]",
        )
        return self._send_with_retry(message, [finding["finding_id"]])


def _email_smtp_from_env(env: dict) -> dict[str, Any]:
    """Pull SMTP connection settings from env (never from policy)."""
    use_ssl_raw = (env.get("ALERT_EMAIL_SMTP_SSL") or "").strip().lower()
    use_tls_raw = (env.get("ALERT_EMAIL_SMTP_TLS") or "1").strip().lower()
    use_ssl = use_ssl_raw in ("1", "true", "yes", "on")
    use_tls = use_tls_raw in ("1", "true", "yes", "on")
    port_raw = env.get("ALERT_EMAIL_SMTP_PORT")
    if port_raw is None or port_raw == "":
        port: int | str = 465 if use_ssl else 587
    else:
        port = port_raw
    return {
        "smtp_host": env.get("ALERT_EMAIL_SMTP_HOST") or "",
        "smtp_port": port,
        "smtp_user": env.get("ALERT_EMAIL_SMTP_USER") or "",
        "smtp_password": env.get("ALERT_EMAIL_SMTP_PASSWORD") or "",
        "from_addr": env.get("ALERT_EMAIL_FROM") or "",
        "use_tls": use_tls and not use_ssl,
        "use_ssl": use_ssl,
        "triage_base_url": env.get("AIM_BASE_URL") or "",
    }


def notifiers_from_env(env: dict | None = None) -> list:
    """Build the configured notifiers from env. Off by default: no URL /
    no workspace id means that destination is disabled."""
    env = env if env is not None else os.environ
    notifiers: list = []

    webhook_url = env.get("ALERT_WEBHOOK_URL")
    if webhook_url:
        notifiers.append(WebhookNotifier(
            webhook_url,
            env.get("ALERT_WEBHOOK_SECRET") or "",
            min_severity=env.get("ALERT_WEBHOOK_MIN_SEVERITY") or "low",
            runbook_base_url=env.get("RUNBOOK_BASE_URL") or "",
        ))

    workspace_id = env.get("SENTINEL_WORKSPACE_ID")
    shared_key = env.get("SENTINEL_SHARED_KEY")
    if workspace_id or shared_key:
        notifiers.append(SentinelNotifier(
            workspace_id or "",
            shared_key or "",
            log_type=env.get("SENTINEL_LOG_TYPE") or DEFAULT_SENTINEL_LOG_TYPE,
            endpoint=env.get("SENTINEL_ENDPOINT") or None,
            runbook_base_url=env.get("RUNBOOK_BASE_URL") or "",
        ))

    # Google Chat company channel. Webhook URL is the secret.
    google_chat_url = env.get("ALERT_GOOGLE_CHAT_WEBHOOK_URL")
    if google_chat_url:
        notifiers.append(GoogleChatNotifier(
            google_chat_url,
            min_severity=env.get("ALERT_GOOGLE_CHAT_MIN_SEVERITY") or "high",
            triage_base_url=env.get("AIM_BASE_URL") or "",
        ))

    # Slack — feature-flagged off by default (SOC opt-in).
    if slack_feature_enabled(env):
        slack_url = env.get("ALERT_SLACK_WEBHOOK_URL")
        if slack_url:
            notifiers.append(SlackNotifier(
                slack_url,
                min_severity=env.get("ALERT_SLACK_MIN_SEVERITY") or "high",
                triage_base_url=env.get("AIM_BASE_URL") or "",
            ))

    # PagerDuty Events API v2 — on-call page / escalation stage.
    pd_key = env.get("ALERT_PAGERDUTY_ROUTING_KEY")
    if pd_key:
        notifiers.append(PagerDutyNotifier(
            pd_key,
            min_severity=env.get("ALERT_PAGERDUTY_MIN_SEVERITY") or "critical",
            triage_base_url=env.get("AIM_BASE_URL") or "",
            source=env.get("ALERT_PAGERDUTY_SOURCE") or "ai-monitoring",
        ))

    if env.get("ALERT_BUS_URL"):
        notifiers.append(bus_notifier(env))

    # SIEM exporters (Splunk HEC / syslog-CEF). Off by default.
    # Env-configured SIEM destinations export pseudonyms only — the
    # identity_map knob exists solely in the policy path (siem.py).
    from .siem import siem_notifiers_from_env

    notifiers.extend(siem_notifiers_from_env(env))


    # email via SMTP. Host + From gate the destination; recipients
    # come from ALERT_EMAIL_TO (comma-separated) when policy is not used.
    if env.get("ALERT_EMAIL_SMTP_HOST") and env.get("ALERT_EMAIL_FROM"):
        to_addrs = _normalize_email_addrs(env.get("ALERT_EMAIL_TO") or "")
        if to_addrs:
            smtp = _email_smtp_from_env(env)
            notifiers.append(EmailNotifier(
                to_addrs=to_addrs,
                min_severity=env.get("ALERT_EMAIL_MIN_SEVERITY") or "high",
                **smtp,
            ))

    return notifiers


def bus_notifier(env: dict):
    """Build the unified-alert-bus publisher.

    Imported lazily to keep the bus adapter off the import path of every
    guardrail entrypoint — `notify` is imported by the streaming CLI, which
    has no reason to load a Redis client.

    `producer.version` is required by the contract precisely so a noisy build
    can be identified and rolled back (D3.1 §3.1), and the container has no
    git context at runtime, so it is baked in as a build arg.
    """
    from .bus import BusNotifier

    return BusNotifier(
        producer_version=env.get("GUARDRAIL_VERSION") or "unknown",
        stream_key=env.get("ALERT_BUS_STREAM") or "secstack:alerts:v1",
    )


def notifiers_from_config(alerts: dict, env: dict | None = None) -> list:
    """Build notifiers from the policy's ``settings.alerts`` section.

    Non-secret config (enabled, url, min_severity, workspace_id, log_type)
    comes from policy-as-code; secrets stay env-managed
    (ALERT_WEBHOOK_SECRET / SENTINEL_SHARED_KEY / ALERT_GOOGLE_CHAT_WEBHOOK_URL
    / ALERT_EMAIL_SMTP_* / ALERT_SLACK_WEBHOOK_URL). Disabled or missing sections produce no
    notifier; unknown keys are ignored so newer policy revisions stay loadable
    by older engines. Slack additionally requires ``ALERT_SLACK_ENABLED``
    (default off).
    """
    env = env if env is not None else os.environ
    alerts = alerts or {}
    notifiers: list = []

    webhook = alerts.get("webhook") or {}
    if webhook.get("enabled") and webhook.get("url"):
        notifiers.append(WebhookNotifier(
            webhook["url"],
            env.get("ALERT_WEBHOOK_SECRET") or "",
            min_severity=webhook.get("min_severity") or "high",
            runbook_base_url=env.get("RUNBOOK_BASE_URL") or "",
        ))

    sentinel = alerts.get("sentinel") or {}
    if sentinel.get("enabled") and sentinel.get("workspace_id"):
        notifiers.append(SentinelNotifier(
            sentinel["workspace_id"],
            env.get("SENTINEL_SHARED_KEY") or "",
            log_type=sentinel.get("log_type") or DEFAULT_SENTINEL_LOG_TYPE,
            endpoint=env.get("SENTINEL_ENDPOINT") or None,
            runbook_base_url=env.get("RUNBOOK_BASE_URL") or "",
        ))

    # Google Chat. Policy owns enable + min_severity only; the
    # incoming-webhook URL is env-only (same posture as webhook secret).
    google_chat = alerts.get("google_chat") or {}
    if google_chat.get("enabled"):
        notifiers.append(GoogleChatNotifier(
            env.get("ALERT_GOOGLE_CHAT_WEBHOOK_URL") or "",
            min_severity=google_chat.get("min_severity") or "high",
            triage_base_url=env.get("AIM_BASE_URL") or "",
        ))

    # Slack. Feature flag first (default off); policy owns enable +
    # min_severity; webhook URL is env-only.
    slack = alerts.get("slack") or {}
    if slack.get("enabled") and slack_feature_enabled(env):
        notifiers.append(SlackNotifier(
            env.get("ALERT_SLACK_WEBHOOK_URL") or "",
            min_severity=slack.get("min_severity") or "high",
            triage_base_url=env.get("AIM_BASE_URL") or "",
        ))

    # PagerDuty. Policy owns enable + min_severity; routing key is
    # env-only (ALERT_PAGERDUTY_ROUTING_KEY). Typically listed in a later
    # escalation stage rather than fired on every finding.
    pagerduty = alerts.get("pagerduty") or {}
    if pagerduty.get("enabled"):
        notifiers.append(PagerDutyNotifier(
            env.get("ALERT_PAGERDUTY_ROUTING_KEY") or "",
            min_severity=pagerduty.get("min_severity") or "critical",
            triage_base_url=env.get("AIM_BASE_URL") or "",
            source=env.get("ALERT_PAGERDUTY_SOURCE") or "ai-monitoring",
        ))

    # The bus connection string is infrastructure, not policy: it is generated
    # by the stack launcher and carries a password, so it stays env-managed
    # like the other secrets. Policy decides only whether to publish.
    bus = alerts.get("bus") or {}
    if bus.get("enabled") and env.get("ALERT_BUS_URL"):
        notifiers.append(bus_notifier(env))

    # SIEM exporters. identity_map (the admin's explicit
    # pseudonym -> identity mapping) is honored only here, in policy-as-code.
    from .siem import siem_notifiers_from_config

    notifiers.extend(siem_notifiers_from_config(alerts, env))


    # email. Policy owns enable + min_severity + recipients; SMTP
    # host/from/credentials stay env-managed.
    email = alerts.get("email") or {}
    if email.get("enabled"):
        to_addrs = email.get("to")
        if not to_addrs:
            to_addrs = env.get("ALERT_EMAIL_TO") or ""
        smtp = _email_smtp_from_env(env)
        notifiers.append(EmailNotifier(
            to_addrs=to_addrs,
            min_severity=email.get("min_severity") or "high",
            **smtp,
        ))

    return notifiers

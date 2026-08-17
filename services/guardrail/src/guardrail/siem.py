"""First-class SIEM export for guardrail findings.

Two destinations, both metadata-only and both reusing the finding_deliveries
accounting contract (one row per finding per destination):

- ``SplunkHecNotifier`` — Splunk HTTP Event Collector. Payload is an
  **OCSF Detection Finding** (class 2004): our finding contract is already an
  OCSF subset (metadata-only, pseudonymous subject, detector names), so the
  native mapping is lossless. This is the reference integration.
  projects the SOC triage fields (host, team, policy hash,
  event ids, dynamic decision) that the early mapper dropped.
- ``SyslogCefNotifier`` — RFC 5424 syslog (UDP, TCP, or TCP+TLS) carrying the
  CEF record from ``notify.to_cef``. The fallback for SIEMs without an HTTP /
  OCSF intake.

Delivery semantics: both destinations opt into the run-start
sweeper (``sweeps_undelivered``) so a SIEM outage lasting one guardrail cycle
no longer truncates the export — findings that committed but never reached
the receiver are re-driven on the next run (at-least-once; receivers dedupe
on the stable finding id, which is the OCSF ``finding_info.uid`` / CEF
``externalId``). Re-drive is bounded by ``sweep_attempt_cap``: when the
accumulated attempts reach the cap, the sweeper dead-letters the row
(``status='dead'``) instead of retrying forever. Lag is visible via the
``guardrail.alert.lag`` run log line and the poller's ``/lagz`` endpoint
(see ``dbrunner.delivery_lag``).

Data minimization (acceptance criterion): the exported identity is
the pseudonymous ``user_ref`` — never a raw identity — unless the admin
explicitly maps it. The mapping is policy-as-code
(``settings.alerts.<dest>.identity_map``, pseudonym -> identity) and exists
**only** in the policy path; env-configured destinations cannot map
identities at all. ``actor.user.uid`` always stays the pseudonym so
pseudonymous correlation keeps working when a mapping is active.

Secrets stay env-managed (``SPLUNK_HEC_TOKEN``), same posture as the
webhook/Sentinel notifiers. Transports are injectable so tests need no
network, and the HEC contract is additionally proven over a real loopback
socket by ``tests/splunk_hec_contract_double.py`` (mirroring).
"""

from __future__ import annotations

import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable

from . import notify

# -- sweep policy -------------------------------------------------------------

# A SIEM outage is re-driven once per guardrail run; 8 attempts at the
# default 15s poll interval dead-letters a finding after roughly 2 minutes of
# continuous receiver failure — fast enough to surface in the same shift,
# slow enough to ride out a receiver restart. Redrive cadence is the run
# interval (no per-row backoff column in v1 — see migration 019).
SIEM_SWEEP_ATTEMPT_CAP = 8

# -- OCSF Detection Finding (class 2004, category 2 "Findings") --------------

OCSF_VERSION = "1.3.0"
OCSF_CLASS_UID = 2004
OCSF_CATEGORY_UID = 2
OCSF_ACTIVITY_CREATE = 1

# Engine severity (findings table CHECK) -> OCSF severity_id.
OCSF_SEVERITY_ID = {"low": 2, "medium": 3, "high": 4, "critical": 5}
OCSF_SEVERITY_NAME = {2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

# Engine severity -> syslog severity (RFC 5424): critical=2, high=3,
# medium=4, low=6 (same gradient the taxonomy's CEF numeric uses).
SYSLOG_SEVERITY = {"critical": 2, "high": 3, "medium": 4, "low": 6}
SYSLOG_FACILITY_LOCAL0 = 16

DEFAULT_HEC_SOURCETYPE = "aim:guardrail:ocsf:detection_finding"
DEFAULT_HEC_SOURCE = "aim-guardrail"
SYSLOG_APP_NAME = "aim-guardrail"
SYSLOG_MSGID = "AIM324"

# HEC transport: like notify.Transport but also returns the response body —
# HEC can answer HTTP 200 with a non-zero JSON "code", which is a failure the
# status code alone cannot see.
HecTransport = Callable[[str, dict[str, str], bytes], "tuple[int, str]"]

# Syslog sender: ship one framed message; raise on failure. Injectable.
SyslogSender = Callable[[bytes], None]


def default_hec_transport(url: str, headers: dict[str, str], body: bytes) -> "tuple[int, str]":
    """stdlib urllib transport returning (status, decoded response body)."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=notify.DEFAULT_TIMEOUT_SECONDS) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _epoch_ms(ts: Any) -> int:
    """finding ts (ISO string or psycopg aware datetime) -> epoch milliseconds."""
    if isinstance(ts, datetime):
        dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    return int(datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp() * 1000)


def _rfc5424_ts(ts: Any) -> str:
    """finding ts -> RFC 5424 TIMESTAMP (millisecond precision, UTC)."""
    if isinstance(ts, datetime):
        dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    else:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def apply_identity_map(pseudonym: str, identity_map: dict | None) -> str:
    """Resolve the exported identity: the admin's explicit mapping, else the
    pseudonym itself. The ONLY path by which a raw identity may leave the
    product in a SIEM payload (data-minimization criterion)."""
    if identity_map and pseudonym in identity_map:
        return identity_map[pseudonym]
    return pseudonym


def _enforcement_mode(decision: str | None) -> str:
    """Map finding.decision onto the legacy EnforcementMode string.

    Parity with notify.build_record / CEF: only a real ``blocked``
    decision is enforce; would_block / observe / confirmed stay observe-only.
    """
    return "enforce" if decision == "blocked" else "observe-only"


def to_ocsf_detection_finding(
    finding: dict,
    *,
    runbook_base_url: str = "",
    identity_map: dict | None = None,
) -> dict:
    """Map an engine finding onto an OCSF Detection Finding (2004) dict.

    Metadata-only: built from the same fields as notify.build_record — rule
    id, severity, pseudonymous subject, detector names — never prompt or
    response content. ``finding_info.uid`` is the stable finding id
    so the receiver can dedupe the sweeper's at-least-once re-drives.

    project the SOC triage fields that were present on the
    engine finding / CEF path but previously dropped from OCSF — host
    (``device.uid``), team (``actor.user.groups``), policy hash
    (``finding_info.analytic``), event ids + match flags (``evidences``),
    and dynamic decision / enforcement mode (``unmapped``).
    """
    fields = notify.finding_fields(finding)
    severity, runbook, known = classify(finding)
    if not known:
        print(
            f'[alerting] unknown findingType "{fields["finding_type"]}" — using fallback severity',
            file=sys.stderr,
        )
    engine_severity = fields.get("engine_severity") or finding.get("severity") or "low"
    severity_id = OCSF_SEVERITY_ID.get(engine_severity, 1)
    time_ms = _epoch_ms(fields["timestamp"])
    runbook_url = f"{runbook_base_url}{runbook}" if runbook_base_url else runbook
    # Prefer real user_ref for actor; finding_fields falls back to host_ref
    # for subject-less proxy findings — that case is represented via device.
    subject = finding.get("subject") or {}
    user_ref = subject.get("user_ref") or ""
    actor_uid = user_ref or fields["user_id"]
    finding_id = str(fields["finding_id"])
    decision = fields.get("decision") or "observe"
    host_ref = fields.get("host_ref") or ""
    team = fields.get("team") or ""
    policy_hash = fields.get("policy_hash") or ""
    event_ids = fields.get("event_ids") or ""
    match_flags = fields.get("match_flags") or ""

    actor_user: dict[str, Any] = {
        # Pseudonym unless the admin explicitly mapped it (policy-only
        # knobs, see module docstring). uid is ALWAYS the pseudonym.
        "name": apply_identity_map(actor_uid, identity_map) if actor_uid else "",
        "uid": actor_uid,
    }
    if team:
        # OCSF-native home for team routing; mirrors CEF cs6 / JSON Team.
        actor_user["groups"] = [{"name": team}]

    finding_info: dict[str, Any] = {
        "uid": finding_id,
        "title": fields["title"] or fields["finding_type"],
        "types": [fields["finding_type"]],
        "created_time": time_ms,
    }
    if policy_hash:
        # Analytic uid = policy_hash so SOC can correlate drift without a
        # private side-channel (parity with CEF flexString1 / PolicyHash).
        finding_info["analytic"] = {
            "uid": policy_hash,
            "name": fields["finding_type"] or "aim-guardrail",
            "type": "Rule",
            "type_id": 1,
        }

    event: dict[str, Any] = {
        "class_uid": OCSF_CLASS_UID,
        "class_name": "Detection Finding",
        "category_uid": OCSF_CATEGORY_UID,
        "category_name": "Findings",
        "activity_id": OCSF_ACTIVITY_CREATE,
        "activity_name": "Create",
        "type_uid": OCSF_CLASS_UID * 100 + OCSF_ACTIVITY_CREATE,
        "severity_id": severity_id,
        "severity": OCSF_SEVERITY_NAME.get(severity_id, "Unknown"),
        "status_id": 1,
        "status": "New",
        "time": time_ms,
        "metadata": {
            "version": OCSF_VERSION,
            "uid": finding_id,
            "product": {
                "name": "AI Monitoring Guardrail Engine",
                "vendor_name": "AIMonitoring",
                "version": "1.0",
            },
        },
        "finding_info": finding_info,
        "actor": {"user": actor_user},
        "remediation": {"desc": runbook_url},
        # AI-tool context has no OCSF-native home in 2004; unmapped is the
        # schema-sanctioned place for it. Detector names only, never content.
        # Decision / enforcement_mode / policy_hash / event_ids also land
        # here so CEF/Sentinel parity consumers can read one bag.
        "unmapped": {
            "tool": fields["tool"],
            "model": fields["model"],
            "repo": fields["repo"],
            "match_flags": match_flags,
            "team": team,
            "host_ref": host_ref,
            "policy_hash": policy_hash,
            "event_ids": event_ids,
            "decision": decision,
            "taxonomy_severity": severity,
            "engine_severity": engine_severity,
            "enforcement_mode": _enforcement_mode(decision),
        },
    }

    if host_ref:
        # Pseudonym only — never a raw hostname (posture).
        event["device"] = {
            "uid": host_ref,
            "type": "Unknown",
            "type_id": 0,
        }

    evidences: list[dict[str, Any]] = []
    if event_ids:
        evidences.append({"name": "event_ids", "data": event_ids})
    if match_flags:
        # Detector *names* only (JSON string from finding_fields) — never
        # matched secret values or prompt/response content.
        evidences.append({"name": "match_flags", "data": match_flags})
    if evidences:
        event["evidences"] = evidences

    if fields.get("repo"):
        event["resources"] = [
            {
                "uid": fields["repo"],
                "name": fields["repo"],
                "type": "repository",
            }
        ]

    return event

def classify(finding: dict) -> "tuple[str, str, bool]":
    """Taxonomy classification of a finding (delegates to notify)."""
    return notify.classify(notify.finding_fields(finding)["finding_type"])


def build_cef_message(
    finding: dict,
    *,
    runbook_base_url: str = "",
    identity_map: dict | None = None,
) -> str:
    """RFC 5424 syslog message carrying the finding's CEF record as MSG.

    Format: ``<PRI>1 TIMESTAMP HOST APP PROCID MSGID - <CEF>``. PRI is
    local0 + a syslog severity mapped from the engine severity; TIMESTAMP is
    the finding's own time (event time, not send time) so the SIEM's timeline
    survives sweeper re-drives.
    """
    fields = dict(notify.finding_fields(finding))
    fields["user_id"] = apply_identity_map(fields["user_id"], identity_map)
    severity, runbook, _known = classify(finding)
    runbook_url = f"{runbook_base_url}{runbook}" if runbook_base_url else runbook
    cef = notify.to_cef(fields, notify.CEF_SEVERITY[severity], runbook_url)
    engine_severity = finding.get("severity") or "low"
    pri = SYSLOG_FACILITY_LOCAL0 * 8 + SYSLOG_SEVERITY.get(engine_severity, 6)
    return (
        f"<{pri}>1 {_rfc5424_ts(fields['timestamp'])} {SYSLOG_APP_NAME} "
        f"{SYSLOG_APP_NAME} - {SYSLOG_MSGID} - {cef}"
    )


# -- Splunk HEC ----------------------------------------------------------------


class SplunkHecNotifier:
    """Splunk HTTP Event Collector, OCSF Detection Finding payload.

    One POST per batch to ``<url>/services/collector/event`` — HEC accepts a
    batch as concatenated JSON event envelopes. Auth is the HEC token
    (``Authorization: Splunk <token>``), env-managed. Success is HTTP 2xx AND
    a response body of ``{"code": 0}``; HEC can answer 200 with a non-zero
    code, which is a rejection the status line alone cannot see.

    Retry policy matches the other notifiers: 3 retries, backoff
    0.5*2^attempt, on HTTP 429/5xx and network errors; other 4xx and
    non-zero-code 2xx fail fast.
    """

    destination = "splunk_hec"
    # At-least-once: opted into the run-start sweeper, bounded by the cap —
    # after SIEM_SWEEP_ATTEMPT_CAP accumulated attempts the row is
    # dead-lettered ('dead') instead of retried forever.
    sweeps_undelivered = True
    sweep_attempt_cap = SIEM_SWEEP_ATTEMPT_CAP

    def __init__(
        self,
        url: str,
        token: str,
        sourcetype: str = DEFAULT_HEC_SOURCETYPE,
        index: str | None = None,
        host: str = DEFAULT_HEC_SOURCE,
        runbook_base_url: str = "",
        identity_map: dict | None = None,
        *,
        transport: HecTransport = default_hec_transport,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if not url:
            raise ValueError("SPLUNK_HEC_URL is required")
        if not token:
            raise ValueError("SPLUNK_HEC_TOKEN is required when SPLUNK_HEC_URL is set")
        self.endpoint = url.rstrip("/") + "/services/collector/event"
        self.token = token
        self.sourcetype = sourcetype
        self.index = index
        self.host = host
        self.runbook_base_url = runbook_base_url
        self.identity_map = identity_map
        self.transport = transport
        self.sleep = sleep

    def build_envelope(self, finding: dict) -> dict:
        """One HEC event envelope: metadata fields + the OCSF event."""
        ocsf = to_ocsf_detection_finding(
            finding,
            runbook_base_url=self.runbook_base_url,
            identity_map=self.identity_map,
        )
        envelope: dict[str, Any] = {
            "time": ocsf["time"] / 1000,
            "host": self.host,
            "source": DEFAULT_HEC_SOURCE,
            "sourcetype": self.sourcetype,
            "event": ocsf,
        }
        if self.index:
            envelope["index"] = self.index
        return envelope

    def deliver(self, findings: list[dict]) -> notify.DeliveryResult:
        import json

        if not findings:
            return notify.DeliveryResult([], None, 0)
        finding_ids = [f["finding_id"] for f in findings]
        # HEC batches events as concatenated JSON objects (no delimiter).
        body = "".join(json.dumps(self.build_envelope(f)) for f in findings).encode("utf-8")

        def build_headers() -> dict[str, str]:
            return {
                "Content-Type": "application/json",
                "Authorization": f"Splunk {self.token}",
            }

        last_error: notify.DeliveryError | None = None
        for attempt in range(notify.MAX_RETRIES + 1):
            try:
                status, response_text = self.transport(self.endpoint, build_headers(), body)
            except Exception as exc:  # network error — transient, retry
                last_error = notify.DeliveryError(
                    f"{self.destination} delivery network error: {exc}",
                    finding_ids=finding_ids,
                    attempts=attempt + 1,
                )
            else:
                if 200 <= status < 300:
                    # A 2xx is only a delivery when HEC's ack code is 0
                    # ("Success"); e.g. code 8 ("invalid token") can ride a
                    # 200 on some tiers and will not heal with retries.
                    code = _hec_ack_code(response_text)
                    if code == 0:
                        return notify.DeliveryResult(finding_ids, status, attempt + 1)
                    raise notify.DeliveryError(
                        f"{self.destination} delivery rejected batch: HTTP {status} ack code {code}",
                        finding_ids=finding_ids,
                        http_status=status,
                        attempts=attempt + 1,
                    )
                if status == 429 or status >= 500:
                    last_error = notify.DeliveryError(
                        f"{self.destination} delivery transient failure: HTTP {status}",
                        finding_ids=finding_ids,
                        http_status=status,
                        attempts=attempt + 1,
                    )
                else:
                    raise notify.DeliveryError(
                        f"{self.destination} delivery rejected batch: HTTP {status}",
                        finding_ids=finding_ids,
                        http_status=status,
                        attempts=attempt + 1,
                    )
            if attempt < notify.MAX_RETRIES:
                self.sleep(notify.BACKOFF_BASE_SECONDS * 2**attempt)
        raise last_error  # type: ignore[misc]


def _hec_ack_code(response_text: str) -> int | None:
    """Parse HEC's JSON ack ({"text": ..., "code": N}); None when unparseable."""
    import json

    try:
        code = json.loads(response_text).get("code")
    except (ValueError, AttributeError):
        return None
    return code if isinstance(code, int) else None


# -- syslog / CEF --------------------------------------------------------------


def _make_syslog_sender(host: str, port: int, protocol: str, use_tls: bool) -> SyslogSender:
    """Build the production sender. One connection per batch tick for TCP
    (connect-per-deliver is deliberate: the poller ticks every few seconds and
    a long-lived socket to a restarting SIEM is a failure mode, not an
    optimization); UDP is connectionless by construction."""
    if protocol == "udp":

        def send_udp(message: bytes) -> None:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(notify.DEFAULT_TIMEOUT_SECONDS)
                sock.sendto(message, (host, port))

        return send_udp

    def send_tcp(message: bytes) -> None:
        sock = socket.create_connection((host, port), timeout=notify.DEFAULT_TIMEOUT_SECONDS)
        try:
            if use_tls:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    # Octet-counting framing (RFC 6587) so the receiver can
                    # split messages that share a segment.
                    tls_sock.sendall(str(len(message)).encode("ascii") + b" " + message)
            else:
                with sock:
                    sock.sendall(str(len(message)).encode("ascii") + b" " + message)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    return send_tcp


class SyslogCefNotifier:
    """RFC 5424 syslog carrying the CEF record (syslog/CEF fallback).

    One message per finding; a send failure raises with the whole batch's
    finding ids — at-least-once tolerates the duplicates (the receiver
    dedupes on CEF ``externalId``, the stable finding id) and silently
    dropping the unsent tail would not.
    """

    destination = "syslog_cef"
    sweeps_undelivered = True
    sweep_attempt_cap = SIEM_SWEEP_ATTEMPT_CAP

    def __init__(
        self,
        host: str,
        port: int = 514,
        protocol: str = "udp",
        use_tls: bool = False,
        runbook_base_url: str = "",
        identity_map: dict | None = None,
        *,
        sender: SyslogSender | None = None,
    ):
        if not host:
            raise ValueError("SYSLOG_CEF_HOST is required")
        if protocol not in ("udp", "tcp"):
            raise ValueError(f"SYSLOG_CEF_PROTOCOL must be 'udp' or 'tcp', got {protocol!r}")
        if use_tls and protocol != "tcp":
            raise ValueError("SYSLOG_CEF_TLS requires SYSLOG_CEF_PROTOCOL=tcp")
        if not 0 < port < 65536:
            raise ValueError(f"SYSLOG_CEF_PORT must be 1-65535, got {port}")
        self.host = host
        self.port = port
        self.protocol = protocol
        self.use_tls = use_tls
        self.runbook_base_url = runbook_base_url
        self.identity_map = identity_map
        self.sender = sender or _make_syslog_sender(host, port, protocol, use_tls)

    def deliver(self, findings: list[dict]) -> notify.DeliveryResult:
        if not findings:
            return notify.DeliveryResult([], None, 0)
        finding_ids = [f["finding_id"] for f in findings]
        attempts = 0
        for finding in findings:
            message = build_cef_message(
                finding,
                runbook_base_url=self.runbook_base_url,
                identity_map=self.identity_map,
            ).encode("utf-8")
            attempts += 1
            try:
                self.sender(message)
            except Exception as exc:
                raise notify.DeliveryError(
                    f"{self.destination} delivery send error: {exc}",
                    finding_ids=finding_ids,
                    attempts=attempts,
                ) from exc
        return notify.DeliveryResult(finding_ids, None, attempts)


# -- wiring --------------------------------------------------------------------


def siem_notifiers_from_env(env: dict) -> list:
    """Build the SIEM notifiers from env. Off by default. Identity mapping is
    deliberately NOT available here: exporting raw identities requires the
    admin's explicit policy-as-code mapping (settings.alerts.<dest>.identity_map)."""
    notifiers: list = []

    hec_url = env.get("SPLUNK_HEC_URL")
    if hec_url:
        notifiers.append(SplunkHecNotifier(
            hec_url,
            env.get("SPLUNK_HEC_TOKEN") or "",
            sourcetype=env.get("SPLUNK_HEC_SOURCETYPE") or DEFAULT_HEC_SOURCETYPE,
            index=env.get("SPLUNK_HEC_INDEX") or None,
            runbook_base_url=env.get("RUNBOOK_BASE_URL") or "",
        ))

    syslog_host = env.get("SYSLOG_CEF_HOST")
    if syslog_host:
        notifiers.append(SyslogCefNotifier(
            syslog_host,
            port=int(env.get("SYSLOG_CEF_PORT") or "514"),
            protocol=env.get("SYSLOG_CEF_PROTOCOL") or "udp",
            use_tls=(env.get("SYSLOG_CEF_TLS") or "").lower() in ("1", "true", "yes"),
            runbook_base_url=env.get("RUNBOOK_BASE_URL") or "",
        ))

    return notifiers


def siem_notifiers_from_config(alerts: dict, env: dict) -> list:
    """Build the SIEM notifiers from the policy's ``settings.alerts`` section.

    Non-secret config (enabled, url, host/port/protocol, index, sourcetype,
    identity_map) is policy-as-code; secrets stay env-managed
    (SPLUNK_HEC_TOKEN). ``identity_map`` is the admin's explicit
    pseudonym -> identity mapping; absent, only pseudonyms are exported.
    """
    notifiers: list = []

    splunk = alerts.get("splunk") or {}
    if splunk.get("enabled") and splunk.get("url"):
        notifiers.append(SplunkHecNotifier(
            splunk["url"],
            env.get("SPLUNK_HEC_TOKEN") or "",
            sourcetype=splunk.get("sourcetype") or DEFAULT_HEC_SOURCETYPE,
            index=splunk.get("index") or None,
            runbook_base_url=env.get("RUNBOOK_BASE_URL") or "",
            identity_map=splunk.get("identity_map") or None,
        ))

    syslog = alerts.get("syslog") or {}
    if syslog.get("enabled") and syslog.get("host"):
        notifiers.append(SyslogCefNotifier(
            syslog["host"],
            port=int(syslog.get("port") or 514),
            protocol=syslog.get("protocol") or "udp",
            use_tls=bool(syslog.get("tls")),
            runbook_base_url=env.get("RUNBOOK_BASE_URL") or "",
            identity_map=syslog.get("identity_map") or None,
        ))

    return notifiers

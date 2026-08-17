"""AIM's publisher adapter for the cross-pillar alert bus.

Maps ``guardrail.finding/v1`` rows onto ``security.alert/v1.1`` and writes
them to the Redis stream ``secstack:alerts:v1``, per decision record D3.1
. The contract is in ``packages/schema/schema/v1/security-alert.schema.json``;
this module is the AIM half of "an alert is a pointer, not a copy".

Design points that are normative rather than incidental:

* **Nothing content-bearing crosses the boundary.** The alert carries rule
  ids, pseudonyms, counts and a link. The finding stays in AIM's Postgres.
  ``additionalProperties: false`` in the schema means a future field cannot
  be stapled on without a contract change.
* **Publishers validate strictly and fail loudly** (§6.1, §12 item 21). The
  check runs at the construction site — ``build()``, not the XADD — and a
  failure raises ``AlertRejected`` naming the offending field. An invalid
  alert is never XADDed and the failure is never swallowed: it leaves this
  module as an exception, the finding is left unpublished for the §4.5
  sweeper, and only ``dbrunner.deliver_batch`` decides that a publisher bug
  must not take the guardrail run down. The split in §6.1 buys nothing if the
  strict half is quiet.
* **`resource` follows the §3.3 two-branch rule**: ``repo_ref`` when the
  finding has one, otherwise the host pseudonym, which the ingest contract
  guarantees. Without the fallback the flagship ``unapproved-tool`` rule is
  unpublishable.
* **`observed_count` is omitted, not set to 1** (§3.1.1(e)). AIM findings are
  per-event, so a literal 1 would read as "seen once" when the truth is "this
  publisher cannot count the group".
* **`status` is always `new`** (§3.1.1(d)). Guardrail is observe-only and has
  no finding lifecycle; consumers must not wait for retractions AIM will
  never send.

Delivery accounting reuses ``finding_deliveries`` with ``destination='bus'``,
which is what makes the run-start sweeper in dbrunner able to tell "published"
from "committed but never published" after a bus outage (§4.5).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Callable

from .notify import DeliveryError, DeliveryResult

SCHEMA_VERSION = "1.1"
PILLAR = "ai_usage"
PRODUCER_NAME = "aim-guardrail"
STREAM_KEY = "secstack:alerts:v1"

# §4.3 — first-line bound on stream growth. The daily XTRIM MINID in
# trim_retention() enforces the actual 30-day retention rule; MAXLEN is the
# belt-and-braces cap that keeps a runaway publisher inside `maxmemory`.
STREAM_MAXLEN = 50_000
# Wire field name, owned by packages/schema/conformance/security-alert-wire.json
# and pinned by tests/test_wire_contract.py. publishing under any
# other name is a silent 100% drop — the consumer counts it malformed and every
# health check stays green.
WIRE_FIELD = "alert"

# §3.2 — one severity scale, normalized at the publisher. AIM's engine scale is
# already a subset (a CHECK constraint on the findings table), so the table is
# here for robustness and to keep both pillars degrading identically.
SEVERITY_NORMAL = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low",
    "INFORMATIONAL": "informational", "INFO": "informational",
}
SEVERITY_ID = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}

MAX_TITLE = 200
MAX_SUMMARY = 240
MAX_LABEL_VALUE = 128

_SEVERITY_RAW_SAFE = re.compile(r"[^A-Za-z0-9_.:-]")


def normalize_severity(raw: str | None) -> tuple[str, int, dict[str, str]]:
    """§3.2 publisher-side normalization -> (severity, severity_id, extra labels).

    An unrecognized label degrades to medium and preserves the original in
    ``labels['severity_raw']`` (sanitized — it is untrusted text per §7.9).
    Never drops the alert, never raises: a new upstream severity label must
    surface as a metric and a preserved string, not as a silent severity shift.
    """
    key = (raw or "").strip().upper()
    if key in SEVERITY_NORMAL:
        severity = SEVERITY_NORMAL[key]
        return severity, SEVERITY_ID[severity], {}
    safe = _SEVERITY_RAW_SAFE.sub("_", (raw or "")[:MAX_LABEL_VALUE])
    return "medium", 3, {"severity_raw": safe}


def _resolve_resource(finding: dict) -> dict:
    """§3.3 — repo when the finding carries one, host otherwise.

    ``host_ref`` is required by the ingest contract, so branch 2 always
    terminates. Both branches are pseudonyms; this does not widen identity
    exposure, and §7.7 still forbids resolving them.
    """
    context = (finding.get("evidence") or {}).get("context") or {}
    repo_ref = context.get("repo_ref")
    if repo_ref:
        resource = {"kind": "repo", "ref": repo_ref, "display": f"repo:{repo_ref[:8]}"}
    else:
        host_ref = (finding.get("subject") or {}).get("host_ref") or ""
        resource = {"kind": "host", "ref": host_ref, "display": f"host:{host_ref[:8]}"}
    # §3.1.1(f) — legitimately null for the whole AI-usage pillar.
    resource.update({"provider": None, "account_ref": None, "region": None})
    return resource


def dedupe_key(finding_type: str, resource_ref: str) -> str:
    """§3.1.1(a) — inputs are (pillar, finding_type, resource.ref) and never prose.

    Deriving this from a title would rotate every key the first time someone
    copy-edits a rule description, duplicating the whole inbox at once.
    """
    return hashlib.sha256(f"{PILLAR}|{finding_type}|{resource_ref}".encode()).hexdigest()


def _source_uri(finding_id: str, rule_id: str, resource_ref: str, detail_count: int) -> str:
    """§3.4 — the query form is REQUIRED when detail_count > 1.

    A deduped alert stands for a set; linking to one arbitrary member tells the
    analyst something narrower than the alert claims.
    """
    if detail_count > 1:
        return (f"aim:/findings?rule_id={rule_id.replace('-', '_')}"
                f"&resource_ref={resource_ref[:16]}")
    return f"aim:/findings/{finding_id}"


_PSEUDONYM = re.compile(r"^[0-9a-f]{64}$")


def _subject_ref(subject: dict) -> dict | None:
    """§3.1 subject_ref, or None when we do not have a full pseudonym pair.

    The contract types subject_ref as ``["object", "null"]`` and requires both
    members when it is an object. The AI-usage event contract, meanwhile, makes
    ``user_ref`` explicitly nullable — proxy-sourced events carry no identity
    until identity mapping lands. Filling the gap with ``""`` produced an alert
    that failed the pseudonym pattern, so every finding from a proxy-sourced
    event was rejected by our own validator and silently never published: the
    alert disappeared and only a log line remained.

    null is the contract's own way to say "this alert is not attributed", and
    an unattributed alert is still a security finding worth showing. Anything
    that is not a well-formed pseudonym is treated the same way, so a malformed
    ref degrades to unattributed rather than taking the alert down with it.
    """
    user_ref = subject.get("user_ref") or ""
    host_ref = subject.get("host_ref") or ""
    if _PSEUDONYM.match(user_ref) and _PSEUDONYM.match(host_ref):
        return {"user_ref": user_ref, "host_ref": host_ref}
    return None


def to_utc_second(ts: Any) -> Any:
    """Normalize an event timestamp to the contract's ``utcSecond`` form.

    The event contract admits a numeric UTC offset (``2026-07-25T12:00:00+02:00``);
    the alert contract's ``utcSecond`` requires a literal ``Z``. Copying the
    event value verbatim therefore made every alert from a non-UTC collector
    fail validation and vanish. Converting is correct rather than merely
    permissive: the two forms denote the same instant.

    Anything unparseable is returned unchanged so it fails validation loudly
    instead of being silently rewritten into a plausible-but-wrong time.
    """
    if isinstance(ts, datetime):
        return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not isinstance(ts, str) or ts.endswith("Z"):
        return ts
    try:
        return datetime.fromisoformat(ts).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return ts


def to_security_alert(finding: dict, *, producer_version: str) -> dict:
    """Map one guardrail.finding/v1 row onto a security.alert/v1.1 alert."""
    evidence = finding.get("evidence") or {}
    context = evidence.get("context") or {}
    subject = finding.get("subject") or {}
    rule_id = finding.get("rule_id") or ""
    finding_type = f"{PILLAR}.{rule_id.replace('-', '_')}"
    resource = _resolve_resource(finding)
    severity, severity_id, severity_labels = normalize_severity(finding.get("severity"))

    detail_count = max(len(evidence.get("event_ids") or []), 1)
    tool = context.get("tool_raw") or context.get("tool") or "an AI tool"
    ts = to_utc_second(finding.get("ts"))

    # Labels are built only from columns the findings table actually persists.
    # `ruleset_version` is on the in-memory engine finding but is NOT a column,
    # so labelling with it would make a swept alert (rebuilt from the row)
    # differ from the live one for the same finding_id — consumers merge on
    # alert_id (§7.2) and would see the label flap on redelivery. `policy_hash`
    # is persisted and identifies the ruleset more precisely anyway, which is
    # what "which build started emitting this noise" (§3.1) actually needs.
    labels = {"rule_id": rule_id, "decision": finding.get("decision") or "observe"}
    policy_hash = finding.get("policy_hash")
    if policy_hash:
        labels["policy_hash"] = str(policy_hash)[:16]
    # tool on the wire so sentinel child links can attribute which AI
    # coding tool produced the finding, and so operators can optionally narrow
    # correlate_on with labels.tool. Metadata only — tool id/raw, never content.
    tool_label = context.get("tool") or context.get("tool_raw")
    if tool_label:
        labels["tool"] = str(tool_label)[:MAX_LABEL_VALUE]
    labels.update(severity_labels)

    alert = {
        "schema_version": SCHEMA_VERSION,
        "alert_id": finding.get("finding_id"),
        "dedupe_key": dedupe_key(finding_type, resource["ref"]),
        "pillar": PILLAR,
        "producer": {"name": PRODUCER_NAME, "version": producer_version},
        "finding_type": finding_type,
        "title": (finding.get("title") or rule_id)[:MAX_TITLE],
        "severity": severity,
        "severity_id": severity_id,
        # §3.1.1(d) — guardrail is observe-only; there is no lifecycle to report.
        "status": "new",
        "observed_at": ts,
        "first_seen_at": ts,
        "last_seen_at": ts,
        "resource": resource,
        "subject_ref": _subject_ref(subject),
        "evidence": {
            "source_uri": _source_uri(
                finding.get("finding_id") or "", rule_id, resource["ref"], detail_count),
            "detail_count": detail_count,
            # Metadata only: which tool, which rule. Never prompt or response text.
            "summary": f"{tool} flagged by rule {rule_id}."[:MAX_SUMMARY],
        },
        # §3.1.1(e) — observed_count is absent by construction, not set to 1:
        # AIM findings are per-event, so this publisher cannot count the group.
        "labels": {k: str(v)[:MAX_LABEL_VALUE] for k, v in labels.items() if v is not None},
    }
    return alert


def _log_json(payload: dict) -> None:
    print(json.dumps(payload), file=sys.stderr, flush=True)


class AlertRejected(DeliveryError):
    """An alert failed publisher-side validation and must not be published.

    D3.1 §12 item 21: this is a *publisher bug*, not a delivery failure, and
    the split in §6.1 only pays off if the strict side is loud. So it is
    raised at the construction site, it names the offending field, and it is
    never swallowed — the finding stays undelivered and the §4.5 sweeper
    re-drives it on the next run, which keeps the bug visible until it is
    fixed instead of losing the finding to a log line nobody reads.

    Subclasses DeliveryError so `dbrunner.deliver_batch` records it against
    exactly the findings it names (status='failed'), the same way a bus
    outage is recorded. `delivered` carries the ids that *did* reach the
    stream in the same batch, so one bad finding does not make the sweeper
    re-drive its healthy neighbours forever.
    """

    # Read by dbrunner: a rejection is not retryable the way a bus outage is,
    # so it is recorded terminally instead of being left for the next sweep to
    # re-map and re-reject forever.
    terminal = True

    def __init__(self, message: str, *, finding_ids: list[str], delivered: list[str] | None = None):
        super().__init__(message, finding_ids=finding_ids, attempts=1)
        self.delivered = delivered or []


def load_validator() -> Callable[[dict], list[str]] | None:
    """Return a validate(alert) -> [error strings] callable, or None.

    None means "this process cannot validate", which `BusNotifier.validate`
    treats as a rejection rather than as a pass (§12 item 21). Both inputs
    are guaranteed in the shipped image — `jsonschema` is a runtime
    dependency in pyproject.toml and the schema is COPYed in with
    SECURITY_ALERT_SCHEMA_PATH pointing at it — so None is a deployment bug,
    not a supported mode. It stays a *return* rather than a raise so that a
    misconfigured bus disables publishing loudly instead of taking the whole
    guardrail run down with it: detection is the primary job, the bus is a
    destination.
    """
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        return None
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.environ.get("SECURITY_ALERT_SCHEMA_PATH"),
        os.path.join(here, "schema", "security-alert.schema.json"),
        os.path.abspath(os.path.join(
            here, "..", "..", "..", "..", "packages", "schema", "schema", "v1",
            "security-alert.schema.json")),
    ]
    for path in candidates:
        if path and os.path.exists(path):
            with open(path) as fh:
                validator = Draft202012Validator(json.load(fh))
            # "evidence.source_uri: ..." rather than "['evidence', 'source_uri']".
            # §12 item 21 requires the failure to name the field, and the
            # person reading it is looking for a key in this module's mapping.
            return lambda alert: [
                f"{'.'.join(str(p) for p in e.path) or '(root)'}: {e.message}"
                for e in sorted(validator.iter_errors(alert), key=lambda e: list(e.path))
            ]
    return None


class BusNotifier:
    """Publishes guardrail findings to the unified alert bus (§4.5, §12 item 5).

    Registered like any other destination, so `finding_deliveries` accounting,
    the "delivery never fails the run" rule and the run-start sweeper all apply
    unchanged. ``publish`` is injectable so the mapping and the validation
    gate are testable without a Redis server.
    """

    destination = "bus"

    # Opts this destination into the run-start sweeper. Safe here and only
    # here: the bus is a replayable log whose consumers must be idempotent on
    # alert_id (§7.2), so a redelivery is normal operation. Re-driving the
    # webhook or Sentinel forwarders would instead re-page a SOC.
    sweeps_undelivered = True

    def __init__(
        self,
        *,
        producer_version: str = "unknown",
        publish: Callable[[str, dict], str] | None = None,
        validator: Callable[[dict], list[str]] | None = None,
        stream_key: str = STREAM_KEY,
    ):
        self.producer_version = producer_version
        self.stream_key = stream_key
        self._publish = publish if publish is not None else _redis_publish
        self.validator = validator if validator is not None else load_validator()

    def build(self, finding: dict) -> dict:
        """Map and validate one finding. The construction site (§12 item 21).

        Validation lives here, not at the XADD, because that is where the bug
        is: a mapping this module got wrong is a *publisher* defect, and the
        stack trace should point at the code that built the bad field rather
        than at a transport call several frames away. `deliver` and every test
        that builds an alert therefore get the check for free — there is no
        way to construct an alert that skips it.
        """
        alert = to_security_alert(finding, producer_version=self.producer_version)
        self.validate(alert, finding_id=finding.get("finding_id"))
        return alert

    def validate(self, alert: dict, *, finding_id: str | None = None) -> None:
        """Raise AlertRejected naming the offending field(s). Never returns false.

        `self.validator is None` means this process could not load jsonschema
        or the schema file, and it is treated as a rejection: unvalidated and
        invalid are the same thing at the boundary. Passing an alert we could
        not check would put the one guarantee consumers are given — that the
        strict side is strict — behind a dependency nobody would notice was
        missing, which is the whole failure class D3.1 revision 6 exists to
        close.
        """
        if self.validator is None:
            raise AlertRejected(
                "cannot validate: jsonschema or the security.alert schema is unavailable"
                " (set SECURITY_ALERT_SCHEMA_PATH); refusing to publish unvalidated",
                finding_ids=[finding_id] if finding_id else [],
            )
        errors = self.validator(alert)
        if errors:
            raise AlertRejected(
                "alert failed security.alert/v1.1 validation: " + "; ".join(errors[:3]),
                finding_ids=[finding_id] if finding_id else [],
            )

    def deliver(self, findings: list[dict]) -> DeliveryResult:
        """Publish a batch. Raises rather than swallowing a rejection (§12 item 21).

        A rejected finding does not stall its healthy neighbours — they are
        published first — but the batch still ends in an exception, because
        "never swallow the failure" means the publisher bug has to leave the
        publisher as an error and not as a log line. `dbrunner.deliver_batch`
        catches it, records the rejected ids terminally and the published ids
        as delivered, and the run continues.
        """
        published: list[str] = []
        rejected: list[str] = []
        reasons: list[str] = []
        for index, finding in enumerate(findings):
            finding_id = finding.get("finding_id")
            try:
                alert = self.build(finding)
            except AlertRejected as exc:
                rejected.append(finding_id)
                reasons.append(f"{finding_id}: {exc}")
                _log_json({
                    "event": "guardrail.bus.rejected",
                    "finding_id": finding_id,
                    "reason": str(exc),
                })
                continue
            try:
                self._publish(self.stream_key, alert)
            except Exception as exc:  # noqa: BLE001 — surfaced as a DeliveryError below
                # Only the findings that did NOT reach the stream. Reporting
                # the whole batch would record already-published alerts as
                # failed and republish them on the next sweep — a security
                # tool claiming it failed to deliver an alert it delivered.
                undelivered = [
                    f.get("finding_id") for f in findings[index:]
                    if f.get("finding_id") not in rejected
                ]
                raise DeliveryError(
                    f"bus publish failed: {exc}",
                    finding_ids=undelivered,
                    attempts=1,
                ) from exc
            published.append(finding_id)
        if rejected:
            raise AlertRejected(
                f"{len(rejected)} of {len(findings)} alert(s) rejected by the publisher's own"
                f" contract check, {len(published)} published — " + "; ".join(reasons[:3]),
                finding_ids=rejected,
                delivered=published,
            )
        return DeliveryResult(published, None, 1)


# §5 — 30 days on-bus, then only in the source pillar. Long enough for a
# consumer to be down over a holiday and still replay; short enough that the
# bus never becomes an accidental long-term record of who-used-what-AI-tool,
# which is the over-collection this company exists to prevent.
RETENTION_DAYS = 30

# §4.3 — if the MAXLEN cap ever evicts an entry younger than this, the pillars
# are far noisier than the design point. That is a tuning problem to fix, and
# it must never be a silent drop.
PRESSURE_FLOOR_DAYS = 7


def trim_retention(
    client: Any,
    *,
    stream_key: str = STREAM_KEY,
    now_ms: int | None = None,
    retention_days: int = RETENTION_DAYS,
) -> dict:
    """Enforce the retention limit, and report pressure loudly (§4.3, §5).

    Returns a summary dict. Trimming is not data loss: the source pillar keeps
    the finding, and consumers persist what they need (§5) — the bus is a
    transport with a replay window, not a system of record.

    The pressure check reads the oldest surviving entry *after* the trim. If
    the stream still starts inside the pressure floor, MAXLEN — not age — is
    what bounded it, so entries are ageing out early and the volume needs
    tuning.
    """
    import time as _time

    now_ms = now_ms if now_ms is not None else int(_time.time() * 1000)
    minid = now_ms - retention_days * 86_400_000
    # approximate=False is load-bearing, not a tuning knob. redis-py defaults
    # to approximate=True, which sends `XTRIM ... MINID ~ <id>`; Redis then
    # only drops whole macro-nodes and will happily keep entries older than
    # the window — on a low-volume stream it removes nothing at all. A
    # retention limit is a privacy commitment (§5), and "approximately 30
    # days" does not honour it. Exact trimming costs a bounded scan of the
    # entries that were leaving anyway.
    removed = client.xtrim(stream_key, minid=minid, approximate=False)

    oldest_ms = None
    entries = client.xrange(stream_key, count=1)
    if entries:
        # Stream ids are "<ms>-<seq>"; the ms half is the publish time.
        oldest_ms = int(str(entries[0][0]).split("-")[0])

    pressure = (
        oldest_ms is not None
        and oldest_ms > now_ms - PRESSURE_FLOOR_DAYS * 86_400_000
        and client.xlen(stream_key) >= STREAM_MAXLEN * 0.9
    )
    summary = {
        "event": "bus.retention.trim",
        "stream": stream_key,
        "removed": removed,
        "retention_days": retention_days,
        "oldest_age_days": None if oldest_ms is None else round((now_ms - oldest_ms) / 86_400_000, 2),
        "pressure": bool(pressure),
    }
    _log_json(summary)
    if pressure:
        _log_json({
            "event": "bus.pressure",
            "stream": stream_key,
            "detail": (
                f"stream is at the {STREAM_MAXLEN} MAXLEN cap with nothing older than "
                f"{PRESSURE_FLOOR_DAYS}d — publishers are noisier than the design point"
            ),
        })
    return summary


_CLIENTS: dict[str, Any] = {}


def _redis_client():
    """Connect with the publisher ACL user. No new credential surface: the
    URL and password come from the launcher-generated stack secrets, and
    `secbus_pub` is +xadd/+xtrim on this stream only (§5).

    Cached per URL. redis-py's client owns a connection pool that already
    handles reconnection, so building a new one per call meant a fresh TCP
    connect and AUTH for every single alert — a 5000-finding sweep opened 5000
    connections to publish 5000 entries, and could exhaust the bus's
    `maxclients` while doing it.
    """
    import redis  # imported lazily so the mapping is importable without the dep

    url = os.environ.get("ALERT_BUS_URL")
    if not url:
        raise RuntimeError("ALERT_BUS_URL is not set")
    client = _CLIENTS.get(url)
    if client is None:
        client = _CLIENTS[url] = redis.Redis.from_url(url, decode_responses=True)
    return client


def _redis_publish(stream_key: str, alert: dict) -> str:
    """XADD one alert, capped at MAXLEN (§4.3).

    MAXLEN is approximate here, unlike the exact MINID in trim_retention: this
    one is a memory guard where trimming a few entries late is harmless, while
    retention is a privacy commitment that has to be exact.

    `noeviction` on the bus means a full stream returns an error here rather
    than silently evicting consumer-group state — the failure propagates to
    finding_deliveries and the sweeper retries it.
    """
    client = _redis_client()
    return client.xadd(
        stream_key,
        {WIRE_FIELD: json.dumps(alert, separators=(",", ":"))},
        maxlen=STREAM_MAXLEN,
        approximate=True,
    )

"""Pillar 4's publisher onto the cross-pillar alert bus (D3.1 / AIM-158).

Deliberately the same shape as `gatehouse/bus.py` and `guardrail/bus.py`: map at
the construction site, validate strictly before the XADD, and raise rather than
swallow when the mapping is wrong. Four pillars publishing four slightly
different interpretations of one contract is how an inbox stops being trusted.

What is specific to this pillar:

* **Liveness drives severity, and it is the only thing that reaches `critical`.**
  A secret in history is `high`: real, needs rotating, not a 3am page. A secret
  that answered an identity call in the last few seconds is `critical`, because
  the window between "we know" and "someone else uses it" is open right now.
  Sentinel pages on `critical` (AIM-165), so this mapping is the load-bearing
  half of the acceptance criterion — it is asserted directly in the tests.

* **`alert_id` is derived, not random.** This scan runs nightly over the same
  repos and republishes the same findings. A fresh uuid4 per run would put 30
  copies of one leak in the inbox in a month.

* **Nothing content-bearing crosses, and there is nothing that could.** The
  alert is built from a `Finding`, and `Finding` has no field a raw secret fits
  in (see models.py). The masked stub and the keyed fingerprint are the most
  specific things on the wire, by construction rather than by review.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from typing import Any, Callable

from .models import SEVERITY_ID, Finding, dedupe_key

SCHEMA_VERSION = "1.1"
PILLAR = "secrets_hygiene"
PRODUCER_NAME = "hygiene"
STREAM_KEY = os.environ.get("HYGIENE_ALERT_STREAM", "secstack:alerts:v1")
STREAM_MAXLEN = 50_000
# Wire field name, owned by packages/schema/conformance/security-alert-wire.json
# and pinned by tests/test_wire_contract.py. AIM-392: publishing under any
# other name is a silent 100% drop — the consumer counts it malformed and every
# health check stays green.
WIRE_FIELD = "alert"

MAX_TITLE = 200
MAX_SUMMARY = 240
MAX_LABEL_VALUE = 128
MAX_LABELS = 10

# The "this scan could not see" alert. See degraded_alert for why it is `high`
# and not `critical`.
DEGRADED_FINDING_TYPE = "hygiene.scan_degraded"
DEGRADED_SEVERITY = "high"

_PATH_SAFE = re.compile(r"[^A-Za-z0-9._~-]")

UNSET: object = object()


class AlertRejected(RuntimeError):
    """An alert failed our own contract check. Never published, never silent."""


def _log(payload: dict) -> None:
    print(json.dumps(payload), file=sys.stderr, flush=True)


def alert_id_for(dedupe: str) -> str:
    """A stable, uuid4-*shaped* id derived from the dedupe key.

    Same technique and same caveat as gatehouse: the contract's pattern wants
    the version and variant nibbles of a v4 UUID, but not that the bits came
    from a random source — and a random source is exactly what would break
    idempotent redelivery for a scan that repeats nightly.
    """
    hexed = dedupe[:32].ljust(32, "0")
    return (f"{hexed[0:8]}-{hexed[8:12]}-4{hexed[13:16]}-"
            f"{'89ab'[int(hexed[16], 16) % 4]}{hexed[17:20]}-{hexed[20:32]}")


def severity_for(finding: Finding) -> str:
    """The escalation rule, in one place so the report and the bus cannot
    disagree about it.

    Only a *verified live* credential becomes `critical`. `unknown` never
    escalates — an unreachable issuer must not manufacture a page — and it
    never de-escalates either, because "we could not check" is not evidence of
    safety. A credential the issuer positively rejected drops to `medium`: the
    history purge is still owed, but nobody needs to be woken up for it.
    """
    if finding.liveness == "live":
        return "critical"
    if finding.liveness == "dead":
        return "medium" if finding.severity in ("critical", "high") else finding.severity
    return finding.severity


def _uri_repo(repo: str) -> str:
    """Scrub a repo label for use as a `source_uri` path segment. The contract
    rejects traversal segments and `%`, so this is the only way a repo name
    reaches a URI."""
    scrubbed = "/".join(_PATH_SAFE.sub("_", part) for part in (repo or "unknown").split("/")
                        if part and part.strip(".") )
    return scrubbed or "unknown"


def source_uri(finding: Finding, dedupe: str) -> str:
    """`hygiene:/…` — a pointer resolved by the gateway, never an absolute URL,
    and never one that embeds the secret or its location in a query string."""
    return f"hygiene:/repos/{_uri_repo(finding.repo)}/findings/{dedupe[:16]}"


def to_alert(finding: Finding, *, now: str, status: str = "new",
             history: dict | None = None, producer_version: str = "0.1.0") -> dict:
    """Map one hygiene finding onto a security.alert/v1.1 alert."""
    dedupe = dedupe_key(finding)
    history = history or {}
    severity = severity_for(finding)

    labels = dict(finding.labels)
    labels["check"] = finding.check
    labels["liveness"] = finding.liveness
    if finding.fingerprint:
        # The keyed fingerprint is how a consumer correlates the same credential
        # across repos. Truncated further here: 16 hex is ample to join on, and
        # the shortest useful form is the right one to broadcast.
        labels["cred_fp"] = finding.fingerprint[:16]

    alert = {
        "schema_version": SCHEMA_VERSION,
        "alert_id": alert_id_for(dedupe),
        "dedupe_key": dedupe,
        "pillar": PILLAR,
        "producer": {"name": PRODUCER_NAME, "version": producer_version},
        "finding_type": finding.finding_type,
        "title": finding.title[:MAX_TITLE] or finding.rule_id[:MAX_TITLE],
        "severity": severity,
        "severity_id": SEVERITY_ID[severity],
        "status": status,
        "observed_at": now,
        "first_seen_at": history.get("first_seen_at") or now,
        "last_seen_at": now,
        **({"observed_count": history["observed_count"]} if history.get("observed_count") else {}),
        "resource": {
            "kind": "repo",
            "ref": f"github:{finding.repo}" if "/" in finding.repo else f"repo:{finding.repo}",
            "display": (finding.repo or "unknown")[:120],
            "provider": "github" if "/" in finding.repo else None,
            "account_ref": (finding.repo.split("/", 1)[0] if "/" in finding.repo else None),
            "region": None,
        },
        # A repo-hygiene finding is about a repository and a credential, not
        # about a monitored person. The commit author is already visible in git
        # to anyone entitled to see it; copying them onto the alert bus would
        # widen exposure and turn a hygiene report into an attribution list.
        "subject_ref": None,
        "evidence": {
            "source_uri": source_uri(finding, dedupe),
            "detail_count": 1,
            "summary": _summary(finding),
        },
        "labels": _cap_labels(labels),
    }
    if finding.remediation:
        alert["remediation_hint"] = finding.remediation[:500]
        if len(finding.remediation) > 500:
            # The full step list lives behind source_uri; say so rather than
            # letting a truncated command line look like the whole fix.
            alert["truncated"] = True
    return alert


def _fair_detail(failed: list[str], errors: dict[str, str], budget: int) -> str:
    """`check: why` for every failed check, within `budget` characters.

    Naive truncation of the joined string is a silent drop of its own: one long
    message — a tmpdir path in a mount error is enough — pushes every later
    check past the cap, and the operator reads "2 checks failed" above a line
    that only explains one, with nothing marking the loss. So each check gets an
    equal share of the budget and clipped shares end in `…`, which makes the
    truncation visible and keeps the `source_uri` the place to get the full text.
    """
    if not failed:
        return ""
    share = max(24, budget // len(failed))
    parts = []
    for name in failed:
        text = " ".join(str(errors[name]).split())
        room = share - len(name) - 2
        if room < len(text):
            # Clip the middle, not the tail. These messages are mostly
            # `<long path> is not a git repository` — the reason is at the end,
            # and head-clipping would keep the part the operator can guess and
            # drop the part they cannot.
            keep = max(1, room - 1)
            tail = keep * 2 // 3
            text = text[:keep - tail] + "…" + (text[-tail:] if tail else "")
        parts.append(f"{name}: {text}")
    return ", ".join(parts)[:budget]


def degraded_alert(repo: str, errors: dict[str, str], ran: list[str], *,
                   now: str, producer_version: str = "0.1.0") -> dict:
    """The alert that says *this scan could not see*, for a check that failed.

    Without this, a broken scanner is indistinguishable from a clean repo on the
    bus: both publish zero findings. The report and the CLI exit code already
    tell the truth (see orchestrator's docstring), but nobody reads a nightly
    container's stdout — the cron deliberately swallows the exit code so one
    broken check cannot stop the scheduler, which means the bus is the only
    place this can surface. A scanner that has been blind for three weeks while
    the inbox stayed quiet is the failure mode this pillar exists to prevent.

    `high`, never `critical`. Critical is reserved for a credential verified
    live in the last few seconds, and that meaning is worth protecting — a
    blind spot is urgent but it is not a known-open door. Escalating here would
    teach the on-call that critical sometimes means "a path was misconfigured".

    Deduped on the *set of failed checks*, not on the error text, so a nightly
    failure is one standing alert rather than thirty; but a second check going
    down changes the identity and re-opens it.
    """
    failed = sorted(errors)
    dedupe = hashlib.sha256(
        f"degraded|{repo}|{','.join(failed)}".encode("utf-8", "replace")).hexdigest()[:32]
    head = f"{len(failed)} of 3 checks did not run; {len(ran)} did. "
    detail = _fair_detail(failed, errors, MAX_SUMMARY - len(head))
    return {
        "schema_version": SCHEMA_VERSION,
        "alert_id": alert_id_for(dedupe),
        "dedupe_key": dedupe,
        "pillar": PILLAR,
        "producer": {"name": PRODUCER_NAME, "version": producer_version},
        "finding_type": DEGRADED_FINDING_TYPE,
        "title": (f"Secrets scan incomplete on {repo}: "
                  f"{len(failed)} of 3 checks failed")[:MAX_TITLE],
        "severity": DEGRADED_SEVERITY,
        "severity_id": SEVERITY_ID[DEGRADED_SEVERITY],
        "status": "new",
        "observed_at": now,
        "first_seen_at": now,
        "last_seen_at": now,
        "resource": {
            "kind": "repo",
            "ref": f"github:{repo}" if "/" in repo else f"repo:{repo}",
            "display": (repo or "unknown")[:120],
            "provider": "github" if "/" in repo else None,
            "account_ref": (repo.split("/", 1)[0] if "/" in repo else None),
            "region": None,
        },
        "subject_ref": None,
        "evidence": {
            # Query form: this alert stands for the set of checks that failed,
            # which is what `detail_count` counts.
            "source_uri": f"hygiene:/repos/{_uri_repo(repo)}/health?run={dedupe[:16]}",
            "detail_count": len(failed),
            "summary": (head + detail)[:MAX_SUMMARY],
        },
        "labels": _cap_labels({
            "check": ",".join(failed),
            "ran": ",".join(sorted(ran)) or "none",
            "degraded": "true",
        }),
        "remediation_hint": (
            "This is a scanner fault, not a repository finding. Check that the "
            "checkout exists and is a git repo, that gitleaks is present in the "
            "image, and re-run `hygiene scan` for this repo. Treat the repo as "
            "unscanned until this clears — 0 findings here means 'did not look'."
        )[:500],
    }


def _summary(finding: Finding) -> str:
    """One line, with the masked stub — never the value, never the source line."""
    where = finding.location or finding.repo
    live = ""
    if finding.liveness == "live":
        live = f" VERIFIED LIVE as {finding.liveness_detail or 'a valid identity'}."
    elif finding.liveness == "dead":
        live = " Issuer reports the credential is no longer valid."
    stub = f" [{finding.masked}]" if finding.masked else ""
    return f"{finding.rule_id} at {where}{stub}.{live}"[:MAX_SUMMARY]


def _cap_labels(labels: dict) -> dict:
    """The contract caps labels at 10 keys of 128 chars. Truncate values and
    keep the most useful keys rather than losing the whole alert over a label."""
    priority = ["check", "liveness", "rule", "issuer", "cred_fp", "path", "commit",
                "principal", "token_kind", "extra", "granted", "missing", "entropy"]
    ordered = sorted(labels.items(),
                     key=lambda kv: (priority.index(kv[0]) if kv[0] in priority else 99, kv[0]))
    return {k: str(v)[:MAX_LABEL_VALUE] for k, v in ordered[:MAX_LABELS] if v is not None}


def load_validator() -> Callable[[dict], list[str]] | None:
    """validate(alert) -> [errors], or None when this process cannot validate.

    None is treated as a rejection by `Publisher.validate` — unvalidated and
    invalid are the same thing at a trust boundary.
    """
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        return None
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (
        os.environ.get("SECURITY_ALERT_SCHEMA_PATH"),
        os.path.join(here, "schema", "security-alert.schema.json"),
        os.path.abspath(os.path.join(here, "..", "..", "..", "..", "packages", "schema",
                                     "schema", "v1", "security-alert.schema.json")),
    ):
        if path and os.path.exists(path):
            with open(path) as fh:
                validator = Draft202012Validator(json.load(fh))
            return lambda alert: [
                f"{'.'.join(str(p) for p in e.path) or '(root)'}: {e.message}"
                for e in sorted(validator.iter_errors(alert), key=lambda e: list(e.path))
            ]
    return None


class Publisher:
    """Validates, then XADDs. `publish` is injectable so the mapping is testable
    without Redis — and `tests/test_bus_integration.py` runs it against a real
    server, because a fake cannot tell you what the server decided."""

    def __init__(self, *, publish: Callable[[str, dict], str] | None = None,
                 validator: Callable[[dict], list[str]] | None = UNSET,
                 stream_key: str = STREAM_KEY):
        self.stream_key = stream_key
        self._publish = publish if publish is not None else _redis_publish
        # `validator=None` ("this process cannot validate") and no argument
        # ("load the default") must not collapse: defaulting None to the loader
        # makes the fail-closed branch unreachable, and therefore untestable.
        self.validator = load_validator() if validator is UNSET else validator
        self.published = 0
        self.rejected = 0

    def validate(self, alert: dict) -> None:
        if self.validator is None:
            raise AlertRejected(
                "cannot validate: jsonschema or the security.alert schema is unavailable "
                "(set SECURITY_ALERT_SCHEMA_PATH); refusing to publish unvalidated")
        errors = self.validator(alert)
        if errors:
            raise AlertRejected("security.alert/v1.1 validation failed: " + "; ".join(errors[:3]))

    def emit(self, alerts: list[dict]) -> list[str]:
        """Publish a batch, returning the ids that reached the stream.

        A rejected alert does not stop its neighbours, but it is counted and
        logged with the offending field, and `rejected > 0` is what makes the
        CLI exit non-zero instead of reporting a clean run.
        """
        delivered: list[str] = []
        for alert in alerts:
            try:
                self.validate(alert)
            except AlertRejected as exc:
                self.rejected += 1
                _log({"event": "hygiene.bus.rejected",
                      "alert_id": alert.get("alert_id"), "reason": str(exc)})
                continue
            try:
                self._publish(self.stream_key, alert)
            except Exception as exc:  # noqa: BLE001 — reported, never swallowed
                self.rejected += 1
                _log({"event": "hygiene.bus.publish_failed",
                      "alert_id": alert.get("alert_id"), "reason": str(exc)[:200]})
                continue
            self.published += 1
            delivered.append(alert["alert_id"])
        return delivered


def _redis_publish(stream_key: str, alert: dict) -> str:
    """XADD one alert. Wire field is ``alert`` (security.alert/v1.1 JSON),
    matching guardrail + cnapp + sentinel. MAXLEN-capped on write (§4.3).

    Historical note (AIM-392): this used to XADD field ``payload``. Sentinel
    only reads ``alert``, so hygiene pages never landed. Do not reintroduce
    ``payload``.
    """
    import redis  # imported lazily so the CLI works without the dependency

    client = redis.Redis.from_url(
        os.environ.get("ALERT_BUS_URL", "redis://redis-bus:6379/0"),
        socket_timeout=5, socket_connect_timeout=5)
    return client.xadd(
        stream_key, {WIRE_FIELD: json.dumps(alert, separators=(",", ":"))},
        maxlen=STREAM_MAXLEN, approximate=True)


def utc_second(when: Any = None) -> str:
    """The contract's `utcSecond` form. Subsecond precision is rejected by the
    schema, so this is the only place a timestamp is formatted."""
    import datetime

    if isinstance(when, str):
        return when
    when = when or datetime.datetime.now(datetime.timezone.utc)
    return when.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

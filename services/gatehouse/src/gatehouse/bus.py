"""gatehouse's publisher adapter for the cross-pillar alert bus (D3.1 / AIM-158).

The pillar-3 counterpart of `guardrail/bus.py`, and deliberately the same shape:
map at the construction site, **validate strictly before the XADD**, and raise
rather than swallow when the mapping is wrong. A publisher bug that logs and
continues is a finding that vanished, which is the failure this whole product
exists to make impossible.

Three decisions specific to this pillar:

* **`alert_id` is derived, not random.** A PR is rescanned on every push, so the
  same finding is republished many times. A fresh uuid4 each time would put N
  copies of one problem in the inbox; consumers dedupe on `alert_id` (§7.2), so
  deriving it from the `dedupe_key` makes redelivery idempotent by construction.
* **The lifecycle is real.** `new` on first sight, `updated` on a rescan,
  `suppressed` when `.gatehouse.yml` muted it, `resolved` when a push fixed it.
  Pillar 3 is the one pillar that *can* tell you a finding went away, and an
  inbox that never closes anything is an inbox people stop opening.
* **Nothing content-bearing crosses.** Rule ids, paths, line numbers, a masked
  hint and a link. Never the matched secret, never the source line. The
  workspace holding the code is gone before the alert is read.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Callable

from .dedupe import dedupe_key
from .models import SEVERITY_ID, Finding, ScanTarget

SCHEMA_VERSION = "1.1"
PILLAR = "pr_security"
PRODUCER_NAME = "gatehouse"
STREAM_KEY = os.environ.get("GATEHOUSE_ALERT_STREAM", "secstack:alerts:v1")
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

_PATH_SAFE = re.compile(r"[^A-Za-z0-9._~-]")

# Sentinel for "argument not supplied", so `validator=None` can keep its own
# meaning. See Publisher.__init__.
UNSET: object = object()


class AlertRejected(RuntimeError):
    """An alert failed our own contract check. Never published, never silent."""


def _log(payload: dict) -> None:
    print(json.dumps(payload), file=sys.stderr, flush=True)


def alert_id_for(dedupe: str) -> str:
    """A stable, uuid4-*shaped* id derived from the dedupe key.

    The contract's pattern requires the version and variant nibbles of a v4
    UUID; it does not require the bits to have come from a random source, and
    a random source is precisely what would break idempotent redelivery here.
    This is a UUIDv8-style derived identifier wearing the v4 costume the
    contract's regex insists on — noted plainly rather than left for someone to
    discover while debugging why two "random" ids keep matching.
    """
    hexed = dedupe[:32].ljust(32, "0")
    return (f"{hexed[0:8]}-{hexed[8:12]}-4{hexed[13:16]}-"
            f"{'89ab'[int(hexed[16], 16) % 4]}{hexed[17:20]}-{hexed[20:32]}")


def source_uri(target: ScanTarget, dedupe: str, check_run_id: int | str = 0) -> str:
    """`gatehouse:/…` — a pointer resolved by the gateway, never an absolute URL.

    Points at the check run when we have one (that is where the annotation with
    the line and the masked evidence lives) and at the PR-scoped finding
    otherwise, so the link never 404s just because the check API call failed.
    """
    if check_run_id:
        return f"gatehouse:/checks/{_PATH_SAFE.sub('_', str(check_run_id))}/findings/{dedupe[:16]}"
    return (f"gatehouse:/repos/{_PATH_SAFE.sub('_', target.repo_full_name)}"
            f"/pulls/{target.pr_number}/findings/{dedupe[:16]}")


def to_alert(finding: Finding, target: ScanTarget, *, now: str, status: str = "new",
             history: dict | None = None, producer_version: str = "0.1.0",
             check_run_id: int | str = 0, suppression_reason: str = "") -> dict:
    """Map one normalized finding onto a security.alert/v1.1 alert."""
    # Repo-scoped identity (AIM-299 AC#3). The PR lives on resource.ref + labels.
    dedupe = dedupe_key(finding, target.identity_ref)
    history = history or {}
    labels = dict(finding.labels)
    labels["scanner"] = finding.scanner
    if finding.rule_id and "rule" not in labels:
        labels["rule"] = finding.rule_id
    labels["head_sha"] = (target.head_sha or "")[:12]
    # Action context (AIM-299 AC#4): repo is resource.account_ref + resource.ref,
    # PR/file/line/commit/author/rule/severity are labels + top-level fields.
    # Author is the public GitHub *login*, never an email and never subject_ref
    # (subject_ref is the monitored-person pseudonym channel; a PR author is not).
    if target.pr_number:
        labels["pr"] = str(target.pr_number)
    if target.head_ref:
        labels["branch"] = target.head_ref[:MAX_LABEL_VALUE]
    if target.author_login:
        labels["author"] = target.author_login[:MAX_LABEL_VALUE]
    if suppression_reason:
        # Why a finding is muted belongs on the bus, not only in a YAML file in
        # a repo the security team may not read.
        labels["suppressed_reason"] = suppression_reason[:MAX_LABEL_VALUE]

    # The file location, machine-readable. `evidence.summary` has carried it as
    # prose since v1, but prose is not a coordinate: sentinel's draft-PR
    # remediation (AIM-185) needs the path and line as fields it can act on, and
    # parsing them back out of a human sentence is the kind of coupling that
    # breaks the moment someone improves the wording. Emitted only when they
    # survive intact — a path longer than the contract's 128-char label limit is
    # omitted rather than truncated, because a truncated path is a *plausible*
    # path, and a consumer that patched it would be editing the wrong file.
    if finding.path and len(finding.path) <= MAX_LABEL_VALUE:
        labels["path"] = finding.path
        if finding.line:
            labels["line"] = str(finding.line)

    location = f"{finding.path}:{finding.line}" if finding.line else finding.path
    # AIM-327: SCA reachability + dependency path belong in evidence.summary so
    # they survive the 10-label cap. Labels still carry the short verdict for
    # machine filters (reachable / unreachable / unknown).
    evidence_summary = f"{finding.scanner}/{finding.rule_id} at {location}."
    if finding.finding_type == "pr_security.vulnerable_dependency":
        fl = finding.labels or {}
        bits = [evidence_summary.rstrip(".")]
        if fl.get("reachability"):
            bits.append(f"reachability={fl['reachability']}")
        if fl.get("reach_evidence"):
            bits.append(fl["reach_evidence"])
        if fl.get("dep_path"):
            bits.append(f"dep_path={fl['dep_path']}")
        if fl.get("fixed_version") and fl.get("fixed_version") != "none":
            bits.append(f"fixed={fl['fixed_version']}")
        evidence_summary = "; ".join(bits) + "."
    alert = {
        "schema_version": SCHEMA_VERSION,
        "alert_id": alert_id_for(dedupe),
        "dedupe_key": dedupe,
        "pillar": PILLAR,
        "producer": {"name": PRODUCER_NAME, "version": producer_version},
        "finding_type": finding.finding_type,
        "title": finding.title[:MAX_TITLE] or finding.rule_id[:MAX_TITLE],
        "severity": finding.severity,
        "severity_id": SEVERITY_ID[finding.severity],
        "status": status,
        "observed_at": now,
        "first_seen_at": history.get("first_seen_at") or now,
        "last_seen_at": now,
        # Honest because the store counts open PR *occurrences* of this key
        # (§3.1.1(e) / AIM-299 AC#3); omitted rather than faked to 1 when there
        # is no history row to read it from.
        **({"observed_count": history["observed_count"]} if history.get("observed_count") else {}),
        "resource": {
            "kind": "pull_request",
            "ref": target.resource_ref,
            "display": f"{target.repo_full_name}#{target.pr_number}"[:120],
            "provider": "github",
            "account_ref": target.owner[:128],
            "region": None,
        },
        # subject_ref stays null: this is not a monitored-person finding. The
        # PR author (when known) is a public GitHub login in labels.author.
        "subject_ref": None,
        "evidence": {
            "source_uri": source_uri(target, dedupe, check_run_id),
            "detail_count": 1,
            "summary": evidence_summary[:MAX_SUMMARY],
        },
        "labels": _cap_labels(labels),
    }
    if finding.remediation:
        alert["remediation_hint"] = finding.remediation[:500]
    return alert


def _cap_labels(labels: dict) -> dict:
    """The contract caps labels at 10 keys of 128 chars (§3.1). Truncate the
    values and keep the most useful keys rather than letting the whole alert be
    rejected over a label."""
    # Action coordinates (path/line/pr/rule/commit/author) outrank context that
    # a human only reads. Losing path/line degrades remediation to "no file".
    # suppressed_reason ranks with the coordinates: why a finding is muted is
    # governance data, not context — an alert that says "suppressed" but cannot
    # say why is exactly what a reviewer must never see.
    # cnapp_rule / would_be_cloud: AIM-329 code-to-cloud parity labels — keep
    # them over cosmetic keys so the bus still names the would-be cloud finding.
    # AIM-327: reachability + dep_path outrank cosmetic context so SCA alerts
    # stay filterable after the 10-label contract cap.
    priority = ["scanner", "rule", "suppressed_reason", "check", "path", "line",
                "pr", "branch", "author", "head_sha", "cnapp_rule", "cnapp_sev",
                "would_be_cloud", "cve", "cwe", "reachability", "dep_path",
                "pkg", "fixed_version", "also_found_by",
                "reach_evidence", "installed_version"]
    ordered = sorted(labels.items(),
                     key=lambda kv: (priority.index(kv[0]) if kv[0] in priority else 99, kv[0]))
    return {k: str(v)[:MAX_LABEL_VALUE] for k, v in ordered[:MAX_LABELS] if v is not None}


def load_validator() -> Callable[[dict], list[str]] | None:
    """validate(alert) -> [errors], or None when this process cannot validate.

    None is treated as a rejection by `publish` — unvalidated and invalid are
    the same thing at a trust boundary. Both inputs ship in the image, so None
    is a deployment bug rather than a supported mode.
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
    without Redis — but `tests/test_bus_integration.py` runs it against a real
    server, because a fake cannot tell you what the server decided."""

    def __init__(self, *, publish: Callable[[str, dict], str] | None = None,
                 validator: Callable[[dict], list[str]] | None = UNSET,
                 stream_key: str = STREAM_KEY):
        self.stream_key = stream_key
        self._publish = publish if publish is not None else _redis_publish
        # `validator=None` and "no validator argument" mean different things and
        # must not collapse: the first is "this process cannot validate", which
        # `validate()` treats as a rejection, and the second is "load the
        # default". Defaulting None to the loader would make the fail-closed
        # branch unreachable — and untestable, which is how it would stay broken.
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
        orchestrator degrade the check run instead of reporting a clean
        publish. Silence is never an option here.
        """
        delivered: list[str] = []
        for alert in alerts:
            try:
                self.validate(alert)
            except AlertRejected as exc:
                self.rejected += 1
                _log({"event": "gatehouse.bus.rejected",
                      "alert_id": alert.get("alert_id"), "reason": str(exc)})
                continue
            try:
                self._publish(self.stream_key, alert)
            except Exception as exc:  # noqa: BLE001 — reported, never swallowed
                self.rejected += 1
                _log({"event": "gatehouse.bus.publish_failed",
                      "alert_id": alert.get("alert_id"), "reason": str(exc)[:200]})
                continue
            self.published += 1
            delivered.append(alert["alert_id"])
        return delivered


def _redis_publish(stream_key: str, alert: dict) -> str:
    """XADD one alert. Wire field is ``alert`` (security.alert/v1.1 JSON),
    matching guardrail + cnapp + sentinel. MAXLEN-capped on write (§4.3).

    Historical note (AIM-392): this used to XADD field ``payload``. Sentinel
    only reads ``alert``, so 100% of pr_security pages were dropped as
    malformed while health stayed green. Do not reintroduce ``payload``.
    """
    import redis  # imported lazily so the CLI works without the dependency

    client = redis.Redis.from_url(
        os.environ.get("ALERT_BUS_URL", "redis://redis-bus:6379/0"),
        socket_timeout=5, socket_connect_timeout=5)
    return client.xadd(
        stream_key, {WIRE_FIELD: json.dumps(alert, separators=(",", ":"))},
        maxlen=STREAM_MAXLEN, approximate=True)


def utc_second(when: Any) -> str:
    """The contract's `utcSecond` form. Subsecond precision is rejected by the
    schema, so this is the only place a timestamp is formatted."""
    import datetime

    if isinstance(when, str):
        return when
    when = when or datetime.datetime.now(datetime.timezone.utc)
    return when.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

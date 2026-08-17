"""Read half of the unified alert bus, as a consumer (D3.1 §7).

Port of the consumer rules already implemented for the API in
``apps/api/src/alertbus.js``; the two are held together by
``tests/test_consumer_parity.py`` and by the shared contract files. The rules
that matter, restated because they are the ones easy to get wrong:

* **Validate against the CONSUMER PROFILE, not the strict publisher schema**
  (§6.1). The profile tolerates unknown fields and unknown open-vocabulary enum
  members, and still enforces every security constraint. Validating against the
  strict schema here would make the first additive minor bump — one new
  optional field — vanish from triage as "invalid": the defect.
* **Project onto known fields before anything is stored or rendered** (§2).
  Tolerating an unknown field must mean dropping it, not carrying it: nothing
  constrains its contents, so a buggy or compromised publisher could park a
  secret value or a plaintext identity there and the sentinel would put it in a
  Slack message and an LLM prompt.
* **Rank on ``severity_id``, not the label** (§7.4). A minor bump may add a
  label this build has never heard of; the id is still 1..5 and still means
  what it means. Ranking an unknown label as medium is how a critical public
  bucket gets read as routine.
* **A malformed entry is counted and skipped, never fatal** (§7.10). One bad
  publish must not stall triage for every other pillar — but it is a decision
  in the log, not a silent discard.
* **No XACK, no XDEL, no consumer group.** Reads are pure XRANGE; the cursor is
  ours (``store.Store``). A reader here can never change what another reader
  sees, and an alert read but not yet triaged is re-read after a crash rather
  than lost.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
DEFAULT_STREAM = "secstack:alerts:v1"
# Wire field name, owned by packages/schema/conformance/security-alert-wire.json
# and pinned by tests/test_wire_contract.py. gatehouse and hygiene
# published under `payload` while this reader looked for `alert` — every
# pr_security alert was counted malformed and skipped with all health green.
WIRE_FIELD = "alert"
# One-release shim for earlier publishers still writing `payload`.
LEGACY_WIRE_FIELDS = ("payload",)


class ContractUnavailable(Exception):
    """The schema files are not readable — every alert would fail validation.

    Raised at construction, not at first entry: without this, a packaging
    mistake reads exactly like a quiet bus, which is the failure mode this
    stack exists to eliminate.
    """


def _schema_paths() -> tuple[str, str]:
    here = os.path.dirname(os.path.abspath(__file__))
    override = os.environ.get("SECURITY_ALERT_SCHEMA_DIR")
    candidates = [
        override,
        os.path.join(here, "schema"),
        os.path.abspath(os.path.join(here, "..", "..", "..", "..",
                                     "packages", "schema", "schema", "v1")),
    ]
    for base in candidates:
        if not base:
            continue
        profile = os.path.join(base, "security-alert.consumer.schema.json")
        strict = os.path.join(base, "security-alert.schema.json")
        if os.path.exists(profile) and os.path.exists(strict):
            return profile, strict
    raise ContractUnavailable(
        "security.alert contract files not found (looked in: "
        + ", ".join(c for c in candidates if c) + "); set SECURITY_ALERT_SCHEMA_DIR")


@dataclass
class ReadStats:
    entries: int = 0
    accepted: int = 0
    malformed: int = 0
    invalid: int = 0
    unsupported_version: int = 0
    invalid_samples: list[str] = field(default_factory=list)
    # Field names seen on entries that carried no canonical wire field.
    # tell: publisher/consumer disagreement shows up here as
    # "malformed=N, samples=['payload']" instead of only in a database.
    malformed_samples: list[str] = field(default_factory=list)


class Contract:
    """Compiled consumer profile plus the strict schema used as a field map."""

    def __init__(self) -> None:
        from jsonschema import Draft202012Validator

        profile_path, strict_path = _schema_paths()
        try:
            with open(profile_path) as fh:
                profile = json.load(fh)
            with open(strict_path) as fh:
                self.strict = json.load(fh)
        except (OSError, ValueError) as err:
            raise ContractUnavailable(f"alert contract unreadable: {err}") from err
        self._validator = Draft202012Validator(profile)

    def validate(self, alert: Any) -> list[str]:
        if not isinstance(alert, dict):
            return ["alert is not an object"]
        return [f"{'.'.join(str(p) for p in e.path) or '(root)'}: {e.message}"
                for e in sorted(self._validator.iter_errors(alert), key=lambda e: list(e.path))]

    def project(self, alert: dict) -> dict:
        return _project(alert, self.strict)


def _project(value: Any, spec: dict | None) -> Any:
    if not spec or not isinstance(value, (dict, list)):
        return value
    if isinstance(value, list):
        items = spec.get("items")
        if not isinstance(items, dict):
            return value
        return [_project(v, items) for v in value]
    # Only closed objects are projected. `additionalProperties` as a schema
    # (labels) means the extra keys are known by shape and were validated.
    if spec.get("additionalProperties") is not False or "properties" not in spec:
        return value
    out = {}
    for key, child in spec["properties"].items():
        # Present-and-null is kept, not dropped: `subject_ref: null` is the
        # contract's way of saying "this pillar deliberately collected no
        # identity", which is different from "this build did not look".
        if key in value:
            out[key] = _project(value[key], child if isinstance(child, dict) else None)
    return out


def severity_rank(alert: dict) -> int:
    sid = alert.get("severity_id")
    if isinstance(sid, int) and not isinstance(sid, bool) and 1 <= sid <= 5:
        return sid
    return SEVERITY_RANK.get(alert.get("severity"), SEVERITY_RANK["medium"])


def is_supported_version(alert: dict) -> bool:
    """§7.4 — reject only an unknown MAJOR version; a minor bump is additive."""
    version = alert.get("schema_version")
    return isinstance(version, str) and version.split(".")[0] == "1"


def decode_entry(fields: dict, stats: ReadStats) -> dict | None:
    """One stream entry -> a validated, projected alert, or None if unusable.

    Wire field is ``WIRE_FIELD`` (packages/schema/conformance/security-alert-wire.json).
    Accept legacy ``LEGACY_WIRE_FIELDS`` as a one-release compatibility shim so
    dogfood streams and any un-upgraded publisher still page instead of being
    counted malformed while health stays green (class of silent failure).
    """
    if not isinstance(fields, dict):
        stats.malformed += 1
        return None
    raw = fields.get(WIRE_FIELD)
    if raw is None:
        for legacy in LEGACY_WIRE_FIELDS:
            raw = fields.get(legacy)
            if raw is not None:
                break
    if raw is None:
        stats.malformed += 1
        if len(stats.malformed_samples) < 5:
            seen = sorted(fields.keys())
            sample = ",".join(str(k) for k in seen) or "(no fields)"
            if sample not in stats.malformed_samples:
                stats.malformed_samples.append(sample)
        return None
    try:
        alert = json.loads(raw)
    except (TypeError, ValueError):
        stats.malformed += 1
        return None
    if not isinstance(alert, dict):
        # json.loads succeeds for "null", "5" and '"x"'. Reading a field off
        # those is a TypeError that would escape the loop and stall triage.
        stats.malformed += 1
        return None
    if not is_supported_version(alert):
        stats.unsupported_version += 1
        return None
    return alert


class BusReader:
    """Cursor-based reader. `xrange` is injectable so triage is testable
    without a Redis — but ``tests/test_bus_integration.py`` runs the real
    thing, because a fake cannot tell you what the *server* decided."""

    def __init__(self, *, url: str = "", stream_key: str = DEFAULT_STREAM,
                 xrange: Callable[[str, str, int], list] | None = None,
                 contract: Contract | None = None):
        self.stream_key = stream_key
        self.url = url
        self.contract = contract or Contract()
        self._xrange = xrange or self._redis_xrange
        self._client = None

    # A read-only client. Nothing in this service calls XADD, XDEL, XTRIM or
    # XGROUP; retention on the bus is the publisher's job (§4.3) and staying
    # read-only is what makes it safe to run more than one consumer.
    def _redis_client(self):
        if self._client is None:
            import redis
            self._client = redis.Redis.from_url(self.url, decode_responses=True,
                                                socket_timeout=5, socket_connect_timeout=5)
        return self._client

    def _redis_xrange(self, stream: str, start: str, count: int) -> list:
        return self._redis_client().xrange(stream, min=start, max="+", count=count)

    @staticmethod
    def exclusive(entry_id: str) -> str:
        """Redis XRANGE is inclusive on both ends; '(id' is the exclusive form.

        Kept explicit because the alternative — incrementing the sequence by
        hand — silently re-delivers or skips at a millisecond boundary, and the
        skip direction loses an alert.
        """
        return entry_id if entry_id == "0-0" else f"({entry_id}"

    def read(self, cursor: str, limit: int = 200) -> tuple[list[tuple[str, dict]], ReadStats]:
        """Return [(entry_id, alert)] after `cursor`, plus counters.

        Unusable entries advance the cursor. Retrying a malformed publish
        forever would stall every well-formed alert behind it — the counters
        and the decision log are what keep that from being silent.
        """
        stats = ReadStats()
        out: list[tuple[str, dict]] = []
        for entry_id, fields in self._xrange(self.stream_key, self.exclusive(cursor), limit):
            stats.entries += 1
            alert = decode_entry(fields, stats)
            if alert is None:
                out.append((entry_id, {}))
                continue
            errors = self.contract.validate(alert)
            if errors:
                stats.invalid += 1
                if len(stats.invalid_samples) < 5:
                    stats.invalid_samples.append(
                        f"{alert.get('alert_id', '?')}: {'; '.join(errors[:2])}")
                out.append((entry_id, {}))
                continue
            stats.accepted += 1
            out.append((entry_id, self.contract.project(alert)))
        return out, stats

    def ping(self) -> None:
        """Raises if the bus is unreachable. Used by health and the stall check."""
        self._redis_client().ping()


def iter_alerts(reader: BusReader, cursor: str, limit: int = 200
                ) -> Iterator[tuple[str, dict, ReadStats]]:
    entries, stats = reader.read(cursor, limit)
    for entry_id, alert in entries:
        yield entry_id, alert, stats

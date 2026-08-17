"""Streaming policy evaluator.

Consumes canonical usage events (schema v1), evaluates every rule, and emits:
  - findings: structured violation events (decision is ALWAYS "observe" in v1)
  - audit records: one per (event, rule) evaluation — every policy decision is logged

Threshold rules keep per-group sliding windows in memory. For the pilot this
runs as a single consumer post-ingest; the state interface is intentionally
tiny so it can move to Redis/Postgres when volume requires it.
"""

from __future__ import annotations

import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from .conditions import eval_tree
from .rules import Ruleset

FINDING_SCHEMA = "guardrail.finding/v1"
AUDIT_SCHEMA = "guardrail.audit/v1"
DECISION = "observe"  # v1 posture: detect-and-alert only, never block.


def _parse_ts(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _metric_value(metric: str, event: dict) -> float:
    if metric == "count":
        return 1.0
    if metric == "sum_tokens":
        return float(event.get("tokens_in") or 0) + float(event.get("tokens_out") or 0)
    if metric == "sum_cost_usd":
        # cost_estimate_usd is an estimate (list prices / collector tables).
        return float(event.get("cost_estimate_usd") or 0)
    if metric.startswith("sum:"):
        return float(event.get(metric[4:]) or 0)
    raise ValueError(f"unknown metric {metric!r}")


class _Window:
    """Sliding window of (epoch_seconds, value, event_id) for one group key."""

    __slots__ = ("entries", "total", "triggered")

    def __init__(self) -> None:
        self.entries: deque[tuple[float, float, str]] = deque()
        self.total = 0.0
        self.triggered = False  # edge-trigger: refire only after dropping below threshold

    def add(self, now: float, span: float, value: float, event_id: str) -> float:
        self.entries.append((now, value, event_id))
        self.total += value
        cutoff = now - span
        while self.entries and self.entries[0][0] < cutoff:
            _, v, _ = self.entries.popleft()
            self.total -= v
        return self.total


class Engine:
    def __init__(self, ruleset: Ruleset):
        self.ruleset = ruleset
        # rule_id -> group_key -> _Window
        self._windows: dict[str, dict[tuple, _Window]] = defaultdict(lambda: defaultdict(_Window))

    # -- public API ---------------------------------------------------------

    def evaluate(self, event: dict) -> tuple[list[dict], list[dict]]:
        """Evaluate one event against all rules. Returns (findings, audit_records)."""
        findings: list[dict] = []
        audit: list[dict] = []
        for rule in self.ruleset.rules:
            try:
                finding, detail = self._eval_rule(rule, event)
            except Exception as exc:  # rule errors must not kill the stream
                audit.append(self._audit(rule, event, "error", {"error": str(exc)}))
                continue
            if finding is not None:
                findings.append(finding)
                audit.append(self._audit(rule, event, "fired", detail))
            else:
                audit.append(self._audit(rule, event, "clear", detail))
        return findings, audit

    def evaluate_stream(self, events: Iterable[dict]) -> Iterator[tuple[dict, list[dict], list[dict]]]:
        """Yields (event, findings, audit_records) per input event."""
        for event in events:
            findings, audit = self.evaluate(event)
            yield event, findings, audit

    # -- internals ----------------------------------------------------------

    def _eval_rule(self, rule: dict, event: dict) -> tuple[dict | None, dict]:
        if rule["type"] == "match":
            return self._eval_match(rule, event)
        return self._eval_threshold(rule, event)

    def _eval_match(self, rule: dict, event: dict) -> tuple[dict | None, dict]:
        matched, details = eval_tree(rule["when"], event, self.ruleset.settings)
        if not matched:
            return None, {}
        evidence = {
            "event_ids": [event.get("event_id")],
            "matched": details,
            "context": self._context(event),
        }
        return self._finding(rule, event, evidence), {"matched": details}

    def _eval_threshold(self, rule: dict, event: dict) -> tuple[dict | None, dict]:
        if "filter" in rule:
            passes, _ = eval_tree(rule["filter"], event, self.ruleset.settings)
            if not passes:
                return None, {}
        key = tuple(event.get(f) for f in rule["group_by"])
        now = _parse_ts(event["ts"]).timestamp()
        window = self._windows[rule["id"]][key]
        total = window.add(now, rule["window_seconds"], _metric_value(rule["metric"], event), event.get("event_id", ""))

        threshold = rule.get("gt", rule.get("gte"))
        op = "gt" if "gt" in rule else "gte"
        over = total > threshold if op == "gt" else total >= threshold
        detail = {"metric": rule["metric"], "window_value": total, "threshold": f"{op} {threshold}"}
        if over and not window.triggered:
            window.triggered = True
            evidence = {
                "event_ids": [eid for _, _, eid in window.entries],
                "detail": detail,
                "group_by": dict(zip(rule["group_by"], key)),
                "context": self._context(event),
            }
            return self._finding(rule, event, evidence), detail
        if not over:
            window.triggered = False
        return None, detail

    def _finding(self, rule: dict, event: dict, evidence: dict) -> dict:
        subject = {
            "user_ref": event.get("user_ref"),
            "host_ref": event.get("host_ref"),
        }
        if event.get("team") is not None:
            subject["team"] = event.get("team")
        return {
            "schema": FINDING_SCHEMA,
            "finding_id": str(uuid.uuid4()),
            "rule_id": rule["id"],
            "ruleset_version": self.ruleset.version,
            "policy_hash": self.ruleset.content_hash,
            "severity": rule.get("severity", "medium"),
            "title": rule.get("title", rule["id"]),
            "decision": DECISION,
            "ts": event.get("ts"),
            "subject": subject,
            "evidence": evidence,
        }

    def _audit(self, rule: dict, event: dict, result: str, detail: dict) -> dict:
        return {
            "schema": AUDIT_SCHEMA,
            "ts": datetime.now(timezone.utc).isoformat(),
            "event_id": event.get("event_id"),
            "rule_id": rule["id"],
            "ruleset_version": self.ruleset.version,
            "policy_hash": self.ruleset.content_hash,
            "result": result,  # fired | clear | error
            "decision": DECISION,
            "detail": detail or None,
        }

    @staticmethod
    def _context(event: dict) -> dict:
        """Metadata-only context copied onto findings. Never includes content."""
        return {
            k: event.get(k)
            for k in (
                "tool", "tool_raw", "tool_version", "provider", "model",
                "repo_ref", "session_id", "source", "team",
            )
            if event.get(k) is not None
        }

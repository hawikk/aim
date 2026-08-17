"""Alerts in, incidents out — the layer that decides what counts as "again".

Three levels of sameness, and conflating any two of them produces a bad
product:

1. **Identical finding restated.** Same ``dedupe_key``. A publisher re-emits
   because the finding is still true, not because anything new happened.
   Never a new incident, never a second ping.

2. **Same root cause, different resource / tool / user.** One ``terraform
   apply`` turns forty buckets public — or one secret pattern fires in Claude
   Code for Alice and Cursor for Bob in the same window. Forty (or two) alerts,
   many dedupe keys, one root cause. These collapse onto a *correlation key*
   — by default (pillar, finding_type, account) — inside a burst window, and
   the parent incident keeps **child links** for every attached finding so the
   SOC can still open each tool/user/resource. The default key does
   **not** include tool or user: correlating across tools and users is the
   product requirement; operators who want per-tool or per-user paging add
   ``labels.tool`` or ``subject_ref.user_ref`` to ``correlate_on``.

3. **The same problem, tomorrow.** Outside the burst window the incident is
   closed by age and a recurrence opens a new one. A finding that comes back a
   week later is news. The window is configurable (``burst_window_seconds``).

The correlation key is configurable (``correlate_on``) because the right
grouping is a policy call, not an engineering one: a team that runs one AWS
account per service wants the account in the key; a team with one shared
account may want the region or a label instead. The default is the conservative
choice — grouping too little produces noise, grouping too much hides a second
real problem behind the first, and noise is the recoverable error.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .bus import severity_rank


def field_value(alert: dict, path: str) -> str:
    """Dotted lookup over the projected alert; missing reads as empty."""
    node: object = alert
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return ""
        node = node[part]
    return "" if node is None else str(node)


def correlation_key(alert: dict, fields: tuple[str, ...]) -> str:
    """Stable hash of the configured grouping fields.

    Hashed rather than concatenated so the key is fixed-width in the database
    and cannot smuggle a resource ref (which can contain anything) into an
    index, a log line or a Slack message through the incident id.
    """
    parts = [f"{f}={field_value(alert, f)}" for f in sorted(fields)]
    digest = hashlib.sha256("\x1f".join(parts).encode()).hexdigest()
    return digest[:32]


def incident_id(correlation: str, opened_at: float) -> str:
    """`inc-<key12>-<opened>` — readable in a Slack thread and in a log grep."""
    return f"inc-{correlation[:12]}-{int(opened_at)}"


@dataclass(frozen=True)
class Routing:
    """What the agent decided to do with one alert, and why."""

    action: str            # page | suppress_cooldown | digest | duplicate
    incident_id: str
    reason: str
    correlation_key: str = ""
    is_new_incident: bool = False
    escalated: bool = False


def route(alert: dict, store, cfg, now: float) -> Routing:
    """Decide the fate of one accepted alert. Pure of I/O beyond the store.

    The severity test uses the *rank*, not the label (§7.4): an alert carrying
    a severity label this build has never seen still has a severity_id, and a
    critical finding must not be routed to a digest because a newer publisher
    renamed the band.
    """
    key = correlation_key(alert, cfg.correlate_on)
    rank = severity_rank(alert)
    page_rank = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}[cfg.page_from]

    if rank < page_rank:
        # Below the paging bar. It is still recorded — the digest is the
        # difference between "we didn't tell you" and "we didn't wake you".
        return Routing(action="digest", incident_id="", correlation_key=key,
                       reason=f"severity_id {rank} below page threshold "
                              f"({cfg.page_from}={page_rank}); queued for daily digest")

    window_start = now - cfg.burst_window_seconds
    existing = store.find_open_incident(key, window_start=window_start)
    if existing is None:
        return Routing(action="page", incident_id=incident_id(key, now), correlation_key=key,
                       reason="first alert of a new correlation group at or above the page "
                              "threshold", is_new_incident=True)

    iid = existing["incident_id"]

    # Checked BEFORE the duplicate test, and the order is load-bearing. An
    # incident whose page never went out (the process died mid-notify, or every
    # channel failed) has its alert already attached — so a retry of that very
    # alert would match its own dedupe_key and be classified as a restatement
    # of a finding nobody has ever been told about. Silence, with a tidy audit
    # trail saying "duplicate". An unnotified incident always pages.
    last = existing["last_notified_at"]
    if last is None:
        return Routing(action="page", incident_id=iid, correlation_key=key,
                       reason="open incident has never been notified successfully; paging "
                              "rather than attaching to a thread nobody has seen")

    known = {r for r in _dedupe_keys(store, iid)}
    if alert["dedupe_key"] in known:
        return Routing(action="duplicate", incident_id=iid, correlation_key=key,
                       reason=f"dedupe_key already present in {iid}; restatement of a known "
                              f"finding, no new information")

    prev_rank = {"informational": 1, "low": 2, "medium": 3, "high": 4,
                 "critical": 5}.get(existing["notified_severity"] or existing["severity"], 0)
    if rank > prev_rank:
        # Escalation always speaks, cooldown or not. The cooldown exists to
        # stop repetition, not to stop news — a medium incident that turns
        # critical is the single case where a second page is the whole point.
        return Routing(action="page", incident_id=iid, escalated=True, correlation_key=key,
                       reason=f"severity escalated from {existing['notified_severity'] or existing['severity']} "
                              f"to {alert['severity']} within the open incident")

    if now - last < cfg.renotify_cooldown_seconds:
        return Routing(action="suppress_cooldown", incident_id=iid, correlation_key=key,
                       reason=f"new resource in open incident {iid}, but it paged "
                              f"{int(now - last)}s ago (cooldown "
                              f"{cfg.renotify_cooldown_seconds}s); attached to the thread instead")
    return Routing(action="page", incident_id=iid, correlation_key=key,
                   reason=f"open incident {iid} is past its renotify cooldown and has new "
                          f"affected resources")


def _dedupe_keys(store, incident_id: str) -> list[str]:
    rows = store.db.execute(
        "SELECT DISTINCT dedupe_key FROM incident_alerts WHERE incident_id=?",
        (incident_id,)).fetchall()
    return [r["dedupe_key"] for r in rows]

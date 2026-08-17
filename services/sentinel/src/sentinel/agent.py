"""The loop: read the bus, decide, triage, notify, record. One alert at a time.

Ordering inside ``_page`` is the part worth reading carefully, because it is
what makes the agent safe to restart at any instant:

    claim → open/join incident → attach alert → triage → render → send
          → record delivery → mark_notified → log decision → mark_decided
          → advance cursor

The cursor advances *last*, and ``mark_decided`` is second-to-last. A crash
anywhere before those two re-reads the entry and finds it claimed but not
decided, which is a re-claim rather than a skip — so the failure mode of a
restart is "one alert re-examined, possibly one duplicate ping", never "one
alert skipped". The reverse order (cursor first, or a one-state seen table)
trades a duplicate ping for a lost critical finding, and this stack has a
standing answer about which of those is worse.

The other invariant: **every path through ``_handle`` writes exactly one
decision row.** That is what makes "why did it page / not page at 04:12"
answerable, including for the alerts that were deliberately quiet.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Callable

from . import draftpr, render, telemetry
from .bus import BusReader, ReadStats
from .correlate import route
from .draftpr import DraftPROpener
from .notify import Notifier
from .remediate import Catalogue, propose
from .store import Store
from .triage import Triager


class Agent:
    def __init__(self, *, cfg, store: Store, reader: BusReader, triager: Triager,
                 notifier: Notifier, catalogue: Catalogue,
                 clock: Callable[[], float] = time.time, opener=None):
        self.cfg = cfg
        self.store = store
        self.reader = reader
        self.triager = triager
        self.notifier = notifier
        self.catalogue = catalogue
        self.clock = clock
        # Constructed only when the feature is on, so a deployment that leaves
        # draft PRs off never builds a GitHub client and never reads a key.
        # Store is threaded through so opened PRs feed the AIM-330 acceptance
        # rate metric (merged / terminal).
        self.opener = opener if opener is not None else (
            DraftPROpener(cfg, store=store)
            if getattr(cfg, "draft_pr", None) and cfg.draft_pr.enabled
            else None)
        self.last_bus_ok = clock()
        self.last_stats = ReadStats()

    # ---- one pass ---------------------------------------------------------

    def poll_once(self) -> dict:
        """Read and process one batch. Returns a small summary for logs/tests.

        A bus read failure is caught here rather than at the top of the daemon:
        the loop must keep running (so a transient Redis restart self-heals),
        and the stall check below is what turns a *persistent* failure into a
        notification instead of into quiet.
        """
        now = self.clock()
        cursor = self.store.cursor()
        try:
            entries, stats = self.reader.read(cursor, self.cfg.batch_size)
        except Exception as err:  # noqa: BLE001 — any client error is a bus outage to us
            self._on_bus_error(err, now)
            return {"read_error": f"{type(err).__name__}: {err}", "processed": 0}

        self.last_bus_ok = now
        self.last_stats = stats
        self.store.meta_set("bus_last_ok", str(now))
        if self.store.meta_get("bus_stalled") == "1":
            self._clear_stall(now)

        actions: dict[str, int] = {}
        for entry_id, alert in entries:
            if alert:
                action = self._handle(alert, entry_id, now=self.clock())
            else:
                # Malformed or unsupported: counted by the reader, but a counter
                # nobody reads is a silent drop with extra steps. It gets a
                # decision row like everything else.
                self.store.log_decision(action="drop_invalid", alert_ids=[],
                                        reason=f"stream entry {entry_id} failed the consumer "
                                               f"profile or carried an unsupported major version",
                                        now=self.clock())
                action = "drop_invalid"
            actions[action] = actions.get(action, 0) + 1
            self.store.set_cursor(entry_id)

        # AIM-736: export any GenAI spans produced by triage this batch.
        try:
            telemetry.flush()
        except Exception:  # noqa: BLE001 — telemetry loss must never stall the agent
            pass

        return {"processed": len(entries), "actions": actions,
                "accepted": stats.accepted, "malformed": stats.malformed,
                "malformed_samples": stats.malformed_samples,
                "invalid": stats.invalid, "invalid_samples": stats.invalid_samples}

    def _handle(self, alert: dict, entry_id: str, now: float) -> str:
        if not self.store.claim(alert["alert_id"], entry_id, now):
            # Already decided: a re-read after a restart, or a publisher that
            # XADDed the same alert twice. Not logged as a decision — the
            # original row is the record, and a second one would make the audit
            # trail lie about how many times the agent decided anything.
            return "already_decided"

        routing = route(alert, self.store, self.cfg, now)
        if routing.action == "digest":
            self.store.queue_digest(alert, now)
            self.store.log_decision(action="digest", reason=routing.reason,
                                    alert_ids=[alert["alert_id"]], severity=alert["severity"],
                                    now=now)
            self.store.mark_decided(alert["alert_id"], now)
            return "digest"

        incident = self._ensure_incident(alert, routing, now)
        self.store.attach_alert(routing.incident_id, alert, now)

        if routing.action in ("duplicate", "suppress_cooldown"):
            self.store.log_decision(action=routing.action, reason=routing.reason,
                                    alert_ids=[alert["alert_id"]],
                                    incident_id=routing.incident_id,
                                    severity=alert["severity"], now=now)
            self.store.mark_decided(alert["alert_id"], now)
            return routing.action

        if routing.escalated:
            self.store.escalate(routing.incident_id, alert["severity"])
        action = self._page(alert, routing, incident, now)
        self.store.mark_decided(alert["alert_id"], now)
        return action

    def _ensure_incident(self, alert: dict, routing, now: float) -> dict:
        existing = self.store.get_incident(routing.incident_id)
        if existing is None:
            resource = alert.get("resource") or {}
            self.store.open_incident(
                incident_id=routing.incident_id,
                correlation_key=routing.correlation_key,
                severity=alert["severity"], title=alert["title"], pillar=alert["pillar"],
                finding_type=alert["finding_type"],
                resource_display=resource.get("display") or resource.get("ref") or "",
                first_alert_id=alert["alert_id"], now=now)
            existing = self.store.get_incident(routing.incident_id)
        return dict(existing)

    def _page(self, alert: dict, routing, incident: dict, now: float) -> str:
        resources = self.store.incident_resources(routing.incident_id)
        # AIM-700: every attached finding is a child link under the parent
        # incident (tool / user / host / evidence), including the paged one.
        children = self.store.incident_children(routing.incident_id)
        # The alert being paged is already attached, so it has to be excluded
        # here or the incident reads as one resource larger than it is — and
        # "and 1 more affected resource(s)" on a single-resource finding is the
        # kind of small lie that costs a channel its credibility.
        siblings = [{"alert_id": m["alert_id"], "severity": m["severity"],
                     "resource": {"display": m["resource_ref"]}}
                    for m in self.store.incident_members(routing.incident_id)
                    if m["alert_id"] != alert["alert_id"]]
        triage = self.triager.triage(alert, siblings)
        proposal = propose(alert, self.catalogue)
        pr = self._maybe_draft_pr(alert, proposal, incident)

        slack_payload = render.incident_slack(alert=alert, triage=triage, proposal=proposal,
                                              incident=incident, cfg=self.cfg,
                                              resources=resources, children=children, pr=pr)
        text = render.incident_text(alert=alert, triage=triage, proposal=proposal,
                                    incident=incident, cfg=self.cfg, resources=resources,
                                    children=children, pr=pr)
        subject = f"[{alert['severity'].upper()}] {alert['title']}"[:180]
        results = self.notifier.send(slack_payload=slack_payload, text=text, subject=subject)

        delivered_any = False
        for result in results:
            outbox_id = self.store.record_delivery(
                channel=result.channel, kind="incident", body=text,
                incident_id=routing.incident_id, delivered=result.delivered,
                error=result.error, attempts=result.attempts, now=now)
            delivered_any = delivered_any or result.delivered
            if not result.delivered:
                # Left in the outbox on purpose: retried by retry_outbox() and
                # counted by /healthz. An undeliverable critical page must be
                # visible as a number somewhere.
                self.store.bump_attempt(outbox_id, result.error)

        if delivered_any:
            # Only a delivery that actually happened starts the renotify
            # cooldown. Stamping it on a failed send would silence the *next*
            # alerts in this group on behalf of a message no human received.
            self.store.mark_notified(routing.incident_id, alert["severity"], now)
        self.store.log_decision(
            action="page",
            reason=(routing.reason
                    + ("" if delivered_any else " — DELIVERY FAILED on every channel; "
                                                "notification is queued in the outbox")),
            alert_ids=self.store.incident_alert_ids(routing.incident_id),
            incident_id=routing.incident_id, severity=alert["severity"],
            triage=triage.as_dict(), llm_used=not triage.degraded,
            # Both degradations are recorded, not just the first one found. A
            # page that was both un-triaged AND undelivered is a worse state
            # than either alone, and a field that can only hold one of them
            # hides exactly that case from whoever reads the log afterwards.
            degraded=", ".join(filter(None, [
                triage.degraded, None if delivered_any else "delivery_failed"])) or None,
            now=now)
        return "page"

    def _maybe_draft_pr(self, alert: dict, proposal, incident: dict):
        """The draft-PR attempt, or None when the feature is off (AIM-185).

        `None` means "print nothing about pull requests"; every other outcome
        renders a sentence. The distinction matters: with the feature disabled
        the channel should look exactly like v1, whereas with it enabled the
        operator must never be left guessing whether a PR was opened.

        The broad catch is deliberate and is the second one on this path —
        `maybe_open` already converts its own failures into a reportable
        outcome, so reaching this handler means a bug in the remediation code
        itself. Even then the page goes out: a lost PR is a degraded feature,
        a lost critical page is the failure this service exists to prevent.
        """
        if self.opener is None:
            return None
        try:
            return self.opener.maybe_open(
                alert=alert, proposal=proposal, incident=incident,
                evidence_url=render.resolve_evidence(
                    (alert.get("evidence") or {}).get("source_uri", ""),
                    self.cfg.gateway_base_url))
        except Exception as err:  # noqa: BLE001 — never let remediation lose the page
            return draftpr.PROutcome(
                state="failed",
                note=(f"draft PR could NOT be opened ({type(err).__name__}: {err}) — this is a "
                      f"bug in sentinel's remediation path, not in your repo. The copy-paste "
                      f"fix above is unaffected."))

    # ---- the agent watching itself ---------------------------------------

    def _on_bus_error(self, err: Exception, now: float) -> None:
        """A bus we cannot read is an incident about the stack, not a log line.

        Without this the product's worst failure is also its quietest one: the
        bus dies, no alerts arrive, no pings are sent, and every dashboard says
        "all clear". The stall notification is rate-limited to once per
        renotify cooldown so a long outage does not become its own storm.
        """
        stalled_for = now - self.last_bus_ok
        if stalled_for < self.cfg.bus_stall_alert_seconds:
            return
        last_sent = float(self.store.meta_get("bus_stall_notified_at", "0") or 0)
        if last_sent and now - last_sent < self.cfg.renotify_cooldown_seconds:
            return
        text = render.self_alert_text(
            kind="Alert bus unreachable",
            detail=f"No successful read for {int(stalled_for)}s "
                   f"({type(err).__name__}: {err}). Stream {self.cfg.stream_key} at "
                   f"{self.cfg.bus_url.split('@')[-1]}.")
        results = self.notifier.send(slack_payload={"text": text}, text=text,
                                     subject="[SENTINEL] alert bus unreachable")
        for result in results:
            self.store.record_delivery(channel=result.channel, kind="self", body=text,
                                       incident_id=None, delivered=result.delivered,
                                       error=result.error, attempts=result.attempts, now=now)
        self.store.meta_set("bus_stall_notified_at", str(now))
        self.store.meta_set("bus_stalled", "1")
        self.store.log_decision(action="page", reason="alert bus unreachable past the stall "
                                                      "threshold; notified operators",
                                alert_ids=[], degraded="bus_unreachable", now=now)

    def _clear_stall(self, now: float) -> None:
        text = ("✅ Sentinel recovered — the alert bus is readable again. Alerts published "
                "during the outage stayed on the bus and are being processed now.")
        results = self.notifier.send(slack_payload={"text": text}, text=text,
                                     subject="[SENTINEL] alert bus recovered")
        for result in results:
            self.store.record_delivery(channel=result.channel, kind="self", body=text,
                                       incident_id=None, delivered=result.delivered,
                                       error=result.error, attempts=result.attempts, now=now)
        self.store.meta_set("bus_stalled", "0")
        self.store.meta_set("bus_stall_notified_at", "0")

    def retry_outbox(self, limit: int = 20) -> int:
        """Re-attempt undelivered notifications. Returns how many cleared."""
        cleared = 0
        for row in self.store.undelivered(limit):
            if row["channel"] == "(none)":
                continue  # nothing to retry against; it is a config problem
            results = self.notifier.send(slack_payload={"text": row["body"]}, text=row["body"],
                                         subject="[SENTINEL] retry")
            if any(r.delivered for r in results):
                self.store.mark_delivered(row["id"], self.clock())
                cleared += 1
            else:
                self.store.bump_attempt(row["id"], results[0].error if results else "unknown")
        return cleared

    # ---- digest -----------------------------------------------------------

    def maybe_digest(self, now: float | None = None) -> bool:
        now = now or self.clock()
        stamp = datetime.fromtimestamp(now, tz=timezone.utc)
        today = stamp.strftime("%Y-%m-%d")
        if stamp.hour < self.cfg.digest_hour_utc:
            return False
        if self.store.meta_get("last_digest_date") == today:
            return False
        # A failed digest backs off instead of retrying on every poll pass
        # (AIM-250): with no channel configured, an unthrottled retry is a
        # ~12k-rows/day `delivery_failed` storm in the decision log.
        retry_not_before = float(self.store.meta_get("digest_retry_not_before", "0") or 0)
        if now < retry_not_before:
            return False
        self.send_digest(now, day=today)
        return True

    def send_digest(self, now: float | None = None, day: str | None = None) -> dict:
        now = now or self.clock()
        day = day or datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d")
        items = self.store.pending_digest()
        text = render.digest_text(items, day=day)
        results = self.notifier.send(slack_payload={"text": text}, text=text,
                                     subject=f"[SENTINEL] daily digest {day}")
        delivered_any = any(r.delivered for r in results)
        for result in results:
            outbox_id = self.store.record_delivery(
                channel=result.channel, kind="digest", body=text, incident_id=None,
                delivered=result.delivered, error=result.error, attempts=result.attempts, now=now)
            if not result.delivered:
                self.store.bump_attempt(outbox_id, result.error)
        if delivered_any:
            # Only clear the queue on a delivery that happened. Marking them
            # digested regardless would drop a day of medium findings on the
            # floor the one time Slack was down.
            self.store.mark_digested([i["alert_id"] for i in items], now)
            self.store.meta_set("last_digest_date", day)
            self.store.meta_set("digest_retry_fails", "0")
            self.store.meta_set("digest_retry_not_before", "0")
            note = ""
        else:
            note = self._digest_failed(now, day)
        self.store.log_decision(
            action="digest",
            reason=f"daily digest for {day}: {len(items)} finding(s) below the paging bar"
                   + note,
            alert_ids=[i["alert_id"] for i in items], now=now,
            degraded=None if delivered_any else "delivery_failed")
        return {"items": len(items), "delivered": delivered_any}

    def _digest_failed(self, now: float, day: str) -> str:
        """Bookkeeping for a failed digest: exponential backoff, daily cap.

        Returns the reason suffix for the decision row. The queue is retained
        either way — the cap only stops the *retry noise* until tomorrow, it
        never drops findings.
        """
        # The failure counter resets at the day boundary, so a channel that
        # broke yesterday does not eat today's attempts.
        fails = (1 if self.store.meta_get("digest_retry_date") != day
                 else int(self.store.meta_get("digest_retry_fails", "0") or 0) + 1)
        self.store.meta_set("digest_retry_date", day)
        self.store.meta_set("digest_retry_fails", str(fails))
        if fails >= self.cfg.digest_retry_daily_cap:
            # Stamp the date so maybe_digest stops until tomorrow. The queue
            # stays pending; tomorrow's digest carries these findings.
            self.store.meta_set("last_digest_date", day)
            return (f" — DELIVERY FAILED {fails} time(s) today (daily cap); "
                    f"retrying tomorrow, queue retained")
        delay = min(self.cfg.digest_retry_base_seconds * (2 ** (fails - 1)),
                    self.cfg.digest_retry_max_seconds)
        self.store.meta_set("digest_retry_not_before", str(now + delay))
        return f" — DELIVERY FAILED, queue retained; retry {fails} in {int(delay)}s"

    # ---- daemon -----------------------------------------------------------

    def health(self) -> dict:
        stats = self.store.stats()
        now = self.clock()
        bus_age = now - self.last_bus_ok
        channels = [c.name for c in self.notifier.enabled_channels]
        # `detail` is the human sentence the stack health strip surfaces
        # (AIM-250). "No channel configured" is a first-class degraded state:
        # before any notification is attempted the outbox is still empty, so
        # `undelivered` alone would report this deployment as healthy while
        # every page goes nowhere.
        problems = []
        if not channels:
            problems.append("no notification channel configured")
        if bus_age > self.cfg.bus_stall_alert_seconds:
            problems.append(f"alert bus unreadable for {int(bus_age)}s")
        if stats["undelivered"]:
            problems.append(f"{stats['undelivered']} undelivered notification(s) in outbox")
        return {
            "status": "degraded" if problems else "ok",
            "detail": "; ".join(problems) or None,
            "bus_last_ok_seconds_ago": int(bus_age),
            "channels": channels,
            "llm": {"enabled": self.cfg.llm.enabled, "configured": bool(self.cfg.llm.endpoint)},
            **stats,
        }

    def run_forever(self, *, iterations: int | None = None,
                    log: Callable[[str], None] = print) -> None:
        i = 0
        last_prune = 0.0
        while iterations is None or i < iterations:
            i += 1
            summary = self.poll_once()
            if summary.get("processed") or summary.get("read_error"):
                log(f"sentinel poll: {summary}")
            # AIM-392: a wire-field mismatch is only visible as malformed=N unless
            # we name the fields we saw. Surface them once per poll so the next
            # contract break is one log line, not a database excavation.
            samples = summary.get("malformed_samples") or []
            if summary.get("malformed") and samples:
                log(
                    "WARNING: sentinel saw stream entries without the canonical "
                    f"wire field (samples={samples}); publishers must XADD "
                    "packages/schema/conformance/security-alert-wire.json field "
                    "(AIM-392)."
                )
            if self.store.stats()["undelivered"]:
                self.retry_outbox()
            self.maybe_digest()
            now = self.clock()
            if now - last_prune > 86400:
                self.store.prune(now)
                last_prune = now
            if iterations is None or i < iterations:
                time.sleep(self.cfg.poll_interval_seconds)

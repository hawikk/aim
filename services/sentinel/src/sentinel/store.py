"""Durable state: bus cursor, incidents, the decision log, digest queue, outbox.

SQLite, one file, WAL. The whole point of this store is that three questions
survive a restart:

1. *Where did I get to on the bus?* The cursor lives here and nowhere else.
   The bus deliberately has no consumer groups (see ``apps/api/src/alertbus.js``):
   acking at read time would drop an alert that was read but never triaged.
   Re-reading is the safe direction, and idempotency is this module's job —
   ``mark_seen`` is the gate every alert passes exactly once.

2. *Why did it page, or not page?* Every decision the agent makes is written to
   ``decisions`` with the alert ids that produced it and the reasoning summary,
   including the decisions to stay quiet. "It never told me" and "it decided
   not to tell you, at 04:12, because ..." are very different conversations.

3. *What did we fail to deliver?* A notification that could not be sent is not
   forgotten; it sits in ``outbox`` with its error and is visible in health.

Retention (D5: every stored field needs a justification and a limit) is
enforced by ``prune``: incidents and decisions are kept 90 days because that is
the audit window for "why did we page"; digest items are dropped once digested;
outbox rows are kept 30 days. No alert *content* beyond the bus contract's own
metadata is stored — the alert is already a pointer, not a copy.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Idempotency gate, in two states, and the second one is the whole point.
--
-- A row appears when an alert is claimed, and `decided_at` is filled only once
-- a terminal decision has been written for it. A claimed-but-undecided row is
-- an alert this process was holding when it died: on restart it is CLAIMED
-- AGAIN, not skipped. Marking "seen" once and refusing to look again would
-- turn any crash between the claim and the page into exactly the failure this
-- stack exists to prevent — a finding that disappears with no error anywhere.
-- The cost of the other direction is at worst one duplicate ping.
CREATE TABLE IF NOT EXISTS seen (
  alert_id    TEXT PRIMARY KEY,
  received_at REAL NOT NULL,
  entry_id    TEXT NOT NULL,
  decided_at  REAL
);

CREATE TABLE IF NOT EXISTS incidents (
  incident_id      TEXT PRIMARY KEY,
  correlation_key  TEXT NOT NULL,
  opened_at        REAL NOT NULL,
  last_seen_at     REAL NOT NULL,
  severity         TEXT NOT NULL,
  title            TEXT NOT NULL,
  pillar           TEXT NOT NULL,
  finding_type     TEXT NOT NULL,
  resource_display TEXT NOT NULL,
  alert_count      INTEGER NOT NULL DEFAULT 0,
  first_alert_id   TEXT NOT NULL,
  last_notified_at REAL,
  notified_severity TEXT,
  notify_count     INTEGER NOT NULL DEFAULT 0,
  thread_ref       TEXT
);
CREATE INDEX IF NOT EXISTS incidents_by_key ON incidents(correlation_key, last_seen_at);

CREATE TABLE IF NOT EXISTS incident_alerts (
  incident_id  TEXT NOT NULL,
  alert_id     TEXT NOT NULL,
  dedupe_key   TEXT NOT NULL,
  resource_ref TEXT NOT NULL,
  severity     TEXT NOT NULL,
  received_at  REAL NOT NULL,
  -- AIM-700 child-link metadata: which tool/user produced this child finding.
  -- Empty strings mean "unknown / not on the wire", never invented.
  tool         TEXT NOT NULL DEFAULT '',
  user_ref     TEXT NOT NULL DEFAULT '',
  host_ref     TEXT NOT NULL DEFAULT '',
  source_uri   TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE IF NOT EXISTS decisions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  at           REAL NOT NULL,
  incident_id  TEXT,
  alert_ids    TEXT NOT NULL,   -- json array: the inputs this decision was made from
  action       TEXT NOT NULL,   -- page | join | suppress_cooldown | digest | duplicate | drop_invalid
  reason       TEXT NOT NULL,   -- why, in one line, answerable to a human
  severity     TEXT,
  triage       TEXT,            -- json: llm summary, blast radius, is_real, confidence
  llm_used     INTEGER NOT NULL DEFAULT 0,
  degraded     TEXT             -- null when nothing degraded, else the reason
);
CREATE INDEX IF NOT EXISTS decisions_by_incident ON decisions(incident_id, at);

CREATE TABLE IF NOT EXISTS digest_items (
  alert_id     TEXT PRIMARY KEY,
  at           REAL NOT NULL,
  severity     TEXT NOT NULL,
  pillar       TEXT NOT NULL,
  finding_type TEXT NOT NULL,
  title        TEXT NOT NULL,
  resource     TEXT NOT NULL,
  digested_at  REAL
);

CREATE TABLE IF NOT EXISTS outbox (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  at           REAL NOT NULL,
  incident_id  TEXT,
  channel      TEXT NOT NULL,
  kind         TEXT NOT NULL,   -- incident | digest | self
  body         TEXT NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  last_error   TEXT,
  delivered_at REAL
);
CREATE INDEX IF NOT EXISTS outbox_pending ON outbox(delivered_at, at);

-- AIM-330: autofix PR outcomes. Acceptance rate = merged / terminal.
-- state: opened | merged | closed | superseded
CREATE TABLE IF NOT EXISTS autofix_prs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  opened_at     REAL NOT NULL,
  repo          TEXT NOT NULL,
  pr_number     INTEGER NOT NULL DEFAULT 0,
  pr_url        TEXT NOT NULL,
  branch        TEXT NOT NULL DEFAULT '',
  alert_id      TEXT NOT NULL DEFAULT '',
  finding_type  TEXT NOT NULL DEFAULT '',
  entry_id      TEXT NOT NULL DEFAULT '',
  incident_id   TEXT NOT NULL DEFAULT '',
  finding_link  TEXT NOT NULL DEFAULT '',
  state         TEXT NOT NULL DEFAULT 'opened',
  closed_at     REAL,
  UNIQUE(repo, pr_number)
);
CREATE INDEX IF NOT EXISTS autofix_prs_by_state ON autofix_prs(state, opened_at);
"""

RETAIN_INCIDENT_SECONDS = 90 * 86400
RETAIN_OUTBOX_SECONDS = 30 * 86400


def child_link_fields(alert: dict) -> dict[str, str]:
    """Extract AIM-700 child-link fields from a security.alert/v1 payload.

    Tool comes from ``labels.tool`` (publishers that care about attribution put
    it there). User/host come from ``subject_ref`` when the alert is attributed;
    empty when it is not. Never invents values.
    """
    labels = alert.get("labels") or {}
    subject = alert.get("subject_ref") or {}
    evidence = alert.get("evidence") or {}
    if not isinstance(labels, dict):
        labels = {}
    if not isinstance(subject, dict):
        subject = {}
    if not isinstance(evidence, dict):
        evidence = {}
    return {
        "tool": str(labels.get("tool") or ""),
        "user_ref": str(subject.get("user_ref") or ""),
        "host_ref": str(subject.get("host_ref") or ""),
        "source_uri": str(evidence.get("source_uri") or ""),
    }


# AIM-700 columns added after the original schema. CREATE TABLE IF NOT EXISTS
# will not widen an existing table, so open() applies these idempotently.
_INCIDENT_ALERT_COLUMNS = (
    ("tool", "TEXT NOT NULL DEFAULT ''"),
    ("user_ref", "TEXT NOT NULL DEFAULT ''"),
    ("host_ref", "TEXT NOT NULL DEFAULT ''"),
    ("source_uri", "TEXT NOT NULL DEFAULT ''"),
)


class Store:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, timeout=10, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)
        self._migrate()
        self.db.commit()

    def _migrate(self) -> None:
        """Widen incident_alerts for AIM-700 child links on existing state DBs."""
        existing = {
            row["name"]
            for row in self.db.execute("PRAGMA table_info(incident_alerts)").fetchall()
        }
        for name, decl in _INCIDENT_ALERT_COLUMNS:
            if name not in existing:
                self.db.execute(f"ALTER TABLE incident_alerts ADD COLUMN {name} {decl}")

    def close(self) -> None:
        self.db.close()

    # ---- cursor -----------------------------------------------------------

    def cursor(self) -> str:
        row = self.db.execute("SELECT value FROM meta WHERE key='cursor'").fetchone()
        # "0-0" means "from the beginning of the stream". A fresh sentinel
        # replays what is still on the bus rather than starting blind at the
        # tail: alerts published while it was being deployed are exactly the
        # ones nobody has looked at.
        return row["value"] if row else "0-0"

    def set_cursor(self, entry_id: str) -> None:
        self._meta_set("cursor", entry_id)

    def _meta_set(self, key: str, value: str) -> None:
        self.db.execute("INSERT INTO meta(key,value) VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        self.db.commit()

    def meta_get(self, key: str, default: str = "") -> str:
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def meta_set(self, key: str, value: str) -> None:
        self._meta_set(key, value)

    # ---- idempotency ------------------------------------------------------

    def claim(self, alert_id: str, entry_id: str, now: float | None = None) -> bool:
        """True if this alert still needs a decision, False if it already has one.

        An alert claimed by a process that died before deciding is claimable
        again — see the `seen` table comment. The re-claim is what makes a
        crash cost a duplicate ping instead of a lost critical finding.
        """
        now = now or time.time()
        try:
            self.db.execute("INSERT INTO seen(alert_id, received_at, entry_id) VALUES(?,?,?)",
                            (alert_id, now, entry_id))
            self.db.commit()
            return True
        except sqlite3.IntegrityError:
            row = self.db.execute("SELECT decided_at FROM seen WHERE alert_id=?",
                                  (alert_id,)).fetchone()
            return row is not None and row["decided_at"] is None

    def mark_decided(self, alert_id: str, now: float | None = None) -> None:
        self.db.execute("UPDATE seen SET decided_at=? WHERE alert_id=?",
                        (now or time.time(), alert_id))
        self.db.commit()

    # ---- incidents --------------------------------------------------------

    def open_incident(self, *, incident_id: str, correlation_key: str, severity: str,
                      title: str, pillar: str, finding_type: str, resource_display: str,
                      first_alert_id: str, now: float) -> None:
        self.db.execute(
            "INSERT INTO incidents(incident_id, correlation_key, opened_at, last_seen_at, "
            "severity, title, pillar, finding_type, resource_display, alert_count, first_alert_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,0,?)",
            (incident_id, correlation_key, now, now, severity, title, pillar, finding_type,
             resource_display, first_alert_id))
        self.db.commit()

    def find_open_incident(self, correlation_key: str, *, window_start: float) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM incidents WHERE correlation_key=? AND last_seen_at>=? "
            "ORDER BY last_seen_at DESC LIMIT 1", (correlation_key, window_start)).fetchone()

    def get_incident(self, incident_id: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM incidents WHERE incident_id=?",
                               (incident_id,)).fetchone()

    def attach_alert(self, incident_id: str, alert: dict, now: float) -> None:
        child = child_link_fields(alert)
        self.db.execute(
            "INSERT OR IGNORE INTO incident_alerts(incident_id, alert_id, dedupe_key, "
            "resource_ref, severity, received_at, tool, user_ref, host_ref, source_uri) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (incident_id, alert["alert_id"], alert["dedupe_key"],
             alert["resource"]["ref"], alert["severity"], now,
             child["tool"], child["user_ref"], child["host_ref"], child["source_uri"]))
        self.db.execute(
            "UPDATE incidents SET alert_count=(SELECT COUNT(*) FROM incident_alerts "
            "WHERE incident_id=?), last_seen_at=? WHERE incident_id=?",
            (incident_id, now, incident_id))
        self.db.commit()

    def escalate(self, incident_id: str, severity: str) -> None:
        self.db.execute("UPDATE incidents SET severity=? WHERE incident_id=?",
                        (severity, incident_id))
        self.db.commit()

    def mark_notified(self, incident_id: str, severity: str, now: float,
                      thread_ref: str | None = None) -> None:
        self.db.execute(
            "UPDATE incidents SET last_notified_at=?, notified_severity=?, "
            "notify_count=notify_count+1, thread_ref=COALESCE(?, thread_ref) "
            "WHERE incident_id=?", (now, severity, thread_ref, incident_id))
        self.db.commit()

    def incident_resources(self, incident_id: str) -> list[str]:
        rows = self.db.execute(
            "SELECT DISTINCT resource_ref FROM incident_alerts WHERE incident_id=? "
            "ORDER BY received_at", (incident_id,)).fetchall()
        return [r["resource_ref"] for r in rows]

    def incident_members(self, incident_id: str) -> list[dict]:
        """(alert_id, resource_ref, severity) per attached alert, oldest first.

        Distinct from ``incident_resources``: two alerts can name one resource,
        so zipping the two lists would pair an alert with someone else's
        resource. Callers that need both want this.
        """
        rows = self.db.execute(
            "SELECT alert_id, resource_ref, severity FROM incident_alerts "
            "WHERE incident_id=? ORDER BY received_at", (incident_id,)).fetchall()
        return [dict(r) for r in rows]

    def incident_children(self, incident_id: str) -> list[dict]:
        """AIM-700: child findings under a parent incident, oldest first.

        Each row is one alert that collapsed into the parent — tool, user, host,
        resource, and the pillar evidence ref so an analyst can open every child
        without re-deriving the grouping.
        """
        rows = self.db.execute(
            "SELECT alert_id, dedupe_key, resource_ref, severity, received_at, "
            "tool, user_ref, host_ref, source_uri "
            "FROM incident_alerts WHERE incident_id=? ORDER BY received_at",
            (incident_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_parent_incident(self, incident_id: str) -> dict | None:
        """Parent incident plus child links (AIM-700 acceptance shape)."""
        row = self.get_incident(incident_id)
        if row is None:
            return None
        parent = dict(row)
        parent["children"] = self.incident_children(incident_id)
        return parent

    def incident_alert_ids(self, incident_id: str) -> list[str]:
        rows = self.db.execute(
            "SELECT alert_id FROM incident_alerts WHERE incident_id=? ORDER BY received_at",
            (incident_id,)).fetchall()
        return [r["alert_id"] for r in rows]

    # ---- decision log -----------------------------------------------------

    def log_decision(self, *, action: str, reason: str, alert_ids: Iterable[str],
                     incident_id: str | None = None, severity: str | None = None,
                     triage: dict | None = None, llm_used: bool = False,
                     degraded: str | None = None, now: float | None = None) -> int:
        cur = self.db.execute(
            "INSERT INTO decisions(at, incident_id, alert_ids, action, reason, severity, "
            "triage, llm_used, degraded) VALUES(?,?,?,?,?,?,?,?,?)",
            (now or time.time(), incident_id, json.dumps(list(alert_ids)), action, reason,
             severity, json.dumps(triage) if triage else None, int(llm_used), degraded))
        self.db.commit()
        return int(cur.lastrowid)

    def decisions(self, *, incident_id: str | None = None, alert_id: str | None = None,
                  limit: int = 50) -> list[dict]:
        sql = "SELECT * FROM decisions"
        args: list[Any] = []
        where = []
        if incident_id:
            where.append("incident_id=?")
            args.append(incident_id)
        if alert_id:
            where.append("alert_ids LIKE ?")
            args.append(f'%"{alert_id}"%')
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY at DESC LIMIT ?"
        args.append(limit)
        out = []
        for row in self.db.execute(sql, args).fetchall():
            item = dict(row)
            item["alert_ids"] = json.loads(item["alert_ids"])
            item["triage"] = json.loads(item["triage"]) if item["triage"] else None
            item["llm_used"] = bool(item["llm_used"])
            out.append(item)
        return out

    # ---- digest -----------------------------------------------------------

    def queue_digest(self, alert: dict, now: float) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO digest_items(alert_id, at, severity, pillar, finding_type, "
            "title, resource) VALUES(?,?,?,?,?,?,?)",
            (alert["alert_id"], now, alert["severity"], alert["pillar"], alert["finding_type"],
             alert["title"], alert["resource"]["display"]))
        self.db.commit()

    def pending_digest(self) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM digest_items WHERE digested_at IS NULL ORDER BY severity, at").fetchall()]

    def mark_digested(self, alert_ids: Iterable[str], now: float) -> None:
        self.db.executemany("UPDATE digest_items SET digested_at=? WHERE alert_id=?",
                            [(now, a) for a in alert_ids])
        self.db.commit()

    # ---- outbox -----------------------------------------------------------

    def record_delivery(self, *, channel: str, kind: str, body: str, incident_id: str | None,
                        delivered: bool, error: str = "", attempts: int = 1,
                        now: float | None = None) -> int:
        now = now or time.time()
        cur = self.db.execute(
            "INSERT INTO outbox(at, incident_id, channel, kind, body, attempts, last_error, "
            "delivered_at) VALUES(?,?,?,?,?,?,?,?)",
            (now, incident_id, channel, kind, body, attempts, error or None,
             now if delivered else None))
        self.db.commit()
        return int(cur.lastrowid)

    def undelivered(self, limit: int = 100) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM outbox WHERE delivered_at IS NULL ORDER BY at LIMIT ?",
            (limit,)).fetchall()]

    def mark_delivered(self, outbox_id: int, now: float | None = None) -> None:
        self.db.execute("UPDATE outbox SET delivered_at=?, last_error=NULL WHERE id=?",
                        (now or time.time(), outbox_id))
        self.db.commit()

    def bump_attempt(self, outbox_id: int, error: str) -> None:
        self.db.execute("UPDATE outbox SET attempts=attempts+1, last_error=? WHERE id=?",
                        (error[:500], outbox_id))
        self.db.commit()

    # ---- autofix acceptance (AIM-330) ------------------------------------

    def record_autofix_pr(self, *, repo: str, pr_number: int, pr_url: str,
                          branch: str = "", alert_id: str = "", finding_type: str = "",
                          entry_id: str = "", incident_id: str = "",
                          finding_link: str = "", now: float | None = None) -> None:
        """Record an opened agent-generated fix PR. Idempotent on (repo, pr_number)."""
        now = now or time.time()
        self.db.execute(
            "INSERT INTO autofix_prs(opened_at, repo, pr_number, pr_url, branch, alert_id, "
            "finding_type, entry_id, incident_id, finding_link, state) "
            "VALUES(?,?,?,?,?,?,?,?,?,?, 'opened') "
            "ON CONFLICT(repo, pr_number) DO UPDATE SET "
            "pr_url=excluded.pr_url, branch=excluded.branch, "
            "alert_id=excluded.alert_id, finding_type=excluded.finding_type, "
            "entry_id=excluded.entry_id, finding_link=excluded.finding_link",
            (now, repo, int(pr_number or 0), pr_url, branch, alert_id, finding_type,
             entry_id, incident_id, finding_link))
        self.db.commit()

    def resolve_autofix_pr(self, *, repo: str, pr_number: int, state: str,
                           now: float | None = None) -> None:
        """Mark a previously opened autofix PR as merged / closed / superseded."""
        if state not in ("merged", "closed", "superseded", "opened"):
            raise ValueError(f"unknown autofix state: {state}")
        now = now or time.time()
        closed_at = None if state == "opened" else now
        self.db.execute(
            "UPDATE autofix_prs SET state=?, closed_at=? WHERE repo=? AND pr_number=?",
            (state, closed_at, repo, int(pr_number)))
        self.db.commit()

    def autofix_acceptance(self) -> dict:
        """Fix acceptance rate — the metric that proves precision, not volume.

        acceptance_rate = merged / (merged + closed + superseded)
        Open (still draft) PRs are excluded from the denominator so a backlog
        of unreviewed drafts does not look like high precision.
        """
        one = lambda sql, *a: int(self.db.execute(sql, a).fetchone()[0])  # noqa: E731
        opened = one("SELECT COUNT(*) FROM autofix_prs WHERE state='opened'")
        merged = one("SELECT COUNT(*) FROM autofix_prs WHERE state='merged'")
        closed = one("SELECT COUNT(*) FROM autofix_prs WHERE state='closed'")
        superseded = one("SELECT COUNT(*) FROM autofix_prs WHERE state='superseded'")
        terminal = merged + closed + superseded
        rate = (merged / terminal) if terminal else None
        by_entry: dict[str, dict] = {}
        for row in self.db.execute(
                "SELECT entry_id, state, COUNT(*) AS n FROM autofix_prs "
                "GROUP BY entry_id, state").fetchall():
            entry = row["entry_id"] or "(none)"
            bucket = by_entry.setdefault(entry, {"opened": 0, "merged": 0,
                                                 "closed": 0, "superseded": 0})
            bucket[row["state"]] = int(row["n"])
        return {
            "opened": opened,
            "merged": merged,
            "closed": closed,
            "superseded": superseded,
            "terminal": terminal,
            "acceptance_rate": rate,
            "by_entry": by_entry,
        }

    # ---- housekeeping -----------------------------------------------------

    def stats(self) -> dict:
        one = lambda sql, *a: self.db.execute(sql, a).fetchone()[0]  # noqa: E731
        acceptance = self.autofix_acceptance()
        return {
            "cursor": self.cursor(),
            "alerts_seen": one("SELECT COUNT(*) FROM seen"),
            "incidents": one("SELECT COUNT(*) FROM incidents"),
            "decisions": one("SELECT COUNT(*) FROM decisions"),
            "digest_pending": one("SELECT COUNT(*) FROM digest_items WHERE digested_at IS NULL"),
            "undelivered": one("SELECT COUNT(*) FROM outbox WHERE delivered_at IS NULL"),
            "autofix_opened": acceptance["opened"],
            "autofix_merged": acceptance["merged"],
            "autofix_closed": acceptance["closed"],
            "autofix_acceptance_rate": acceptance["acceptance_rate"],
        }

    def prune(self, now: float | None = None) -> dict[str, int]:
        now = now or time.time()
        inc_cut = now - RETAIN_INCIDENT_SECONDS
        out_cut = now - RETAIN_OUTBOX_SECONDS
        removed = {}
        cur = self.db.execute(
            "DELETE FROM incident_alerts WHERE incident_id IN "
            "(SELECT incident_id FROM incidents WHERE last_seen_at<?)", (inc_cut,))
        removed["incident_alerts"] = cur.rowcount
        removed["incidents"] = self.db.execute(
            "DELETE FROM incidents WHERE last_seen_at<?", (inc_cut,)).rowcount
        removed["decisions"] = self.db.execute(
            "DELETE FROM decisions WHERE at<?", (inc_cut,)).rowcount
        removed["seen"] = self.db.execute(
            "DELETE FROM seen WHERE received_at<?", (inc_cut,)).rowcount
        removed["digest_items"] = self.db.execute(
            "DELETE FROM digest_items WHERE digested_at IS NOT NULL AND digested_at<?",
            (now - 7 * 86400,)).rowcount
        removed["outbox"] = self.db.execute(
            "DELETE FROM outbox WHERE delivered_at IS NOT NULL AND delivered_at<?",
            (out_cut,)).rowcount
        # Keep autofix acceptance history for the same audit window as decisions.
        removed["autofix_prs"] = self.db.execute(
            "DELETE FROM autofix_prs WHERE opened_at<? AND state!='opened'",
            (inc_cut,)).rowcount
        self.db.commit()
        return removed

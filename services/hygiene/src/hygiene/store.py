"""Findings state — first-seen tracking, and the retention limit (D6 / §5).

Two jobs, and the second is a commitment rather than a feature:

1. **Continuity.** A nightly scan re-derives the same findings every night. The
   store is what lets the report say "leaked 264 days ago, first reported by us
   on 3 March" instead of presenting an eight-month-old leak as breaking news,
   and it is what makes `observed_count` on the bus honest rather than always 1.

2. **Retention.** Every row carries a justification and an expiry. `purge()`
   deletes anything past the window on every single run, before the scan, so
   the limit holds even if the service is only ever run by hand. A retention
   policy enforced by a cron job that someone disabled is not a retention
   policy.

**What is stored, and why each field is allowed to exist.** The table below is
the argument, not a comment on it — if a field cannot be justified in one line,
it does not get a column.

    dedupe_key      identity across runs; a hash of non-secret components
    repo/path/line  where to go fix it; already visible to anyone with the repo
    fingerprint     keyed HMAC — correlates one credential across repos without
                    being reversible off this box (see models.fingerprint)
    masked          issuer prefix + last 4; identifies which key, cannot auth
    severity/status queue ordering and lifecycle
    first/last_seen age of exposure, and the retention clock itself

There is deliberately no column for the secret, the matched line, the commit
message, or the commit author. The first two are credential material. The last
two are attribution, and this pillar reports on repositories, not on people —
git already records who wrote a line, for anyone entitled to look.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass

from .models import Finding, dedupe_key

# The standard window used across the stack (guardrail/bus.py RETENTION_DAYS).
RETENTION_DAYS = 30

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    dedupe_key    TEXT PRIMARY KEY,
    repo          TEXT NOT NULL,
    check_name    TEXT NOT NULL,
    rule_id       TEXT NOT NULL,
    finding_type  TEXT NOT NULL,
    severity      TEXT NOT NULL,
    path          TEXT NOT NULL DEFAULT '',
    line          INTEGER NOT NULL DEFAULT 0,
    fingerprint   TEXT NOT NULL DEFAULT '',
    masked        TEXT NOT NULL DEFAULT '',
    liveness      TEXT NOT NULL DEFAULT 'unknown',
    status        TEXT NOT NULL DEFAULT 'new',
    first_seen_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    observed_count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS findings_last_seen ON findings(last_seen_at);
CREATE INDEX IF NOT EXISTS findings_repo ON findings(repo);
"""


@dataclass(frozen=True)
class Seen:
    """What the store knew about a finding before this run."""

    first_seen_at: int
    observed_count: int
    is_new: bool


class Store:
    def __init__(self, path: str, *, retention_days: int = RETENTION_DAYS):
        self.path = path
        self.retention_days = retention_days
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        # The DB sits next to the HMAC key and holds masked credential stubs;
        # it has no business being group- or world-readable.
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def close(self) -> None:
        self.conn.close()

    def purge(self, *, now: int | None = None) -> int:
        """Delete everything past the retention window. Returns rows removed.

        Called at the start of every run, not on a timer. Retention that only
        happens when a separate scheduler fires is retention that silently
        stops the first time that scheduler breaks.
        """
        now = int(time.time()) if now is None else now
        cutoff = now - self.retention_days * 86_400
        cursor = self.conn.execute("DELETE FROM findings WHERE last_seen_at < ?", (cutoff,))
        self.conn.commit()
        return cursor.rowcount

    def record(self, finding: Finding, *, now: int | None = None) -> Seen:
        """Upsert one finding, returning what we knew about it beforehand."""
        now = int(time.time()) if now is None else now
        key = dedupe_key(finding)
        row = self.conn.execute(
            "SELECT first_seen_at, observed_count FROM findings WHERE dedupe_key = ?",
            (key,)).fetchone()
        if row is None:
            self.conn.execute(
                "INSERT INTO findings (dedupe_key, repo, check_name, rule_id, finding_type,"
                " severity, path, line, fingerprint, masked, liveness, status,"
                " first_seen_at, last_seen_at, observed_count)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
                (key, finding.repo, finding.check, finding.rule_id, finding.finding_type,
                 finding.severity, finding.path, finding.line, finding.fingerprint,
                 finding.masked, finding.liveness, "new", now, now))
            self.conn.commit()
            return Seen(first_seen_at=now, observed_count=1, is_new=True)
        self.conn.execute(
            "UPDATE findings SET last_seen_at = ?, observed_count = observed_count + 1,"
            " severity = ?, liveness = ?, status = 'updated' WHERE dedupe_key = ?",
            (now, finding.severity, finding.liveness, key))
        self.conn.commit()
        return Seen(first_seen_at=int(row["first_seen_at"]),
                    observed_count=int(row["observed_count"]) + 1, is_new=False)

    def resolve_missing(self, repo: str, present: set[str], *, now: int | None = None) -> int:
        """Mark findings we used to see in `repo` but no longer do.

        Only meaningful for the worktree and token checks. A *history* finding
        never legitimately disappears — history is append-only — so a history
        finding that stops appearing means the scan changed, not that the leak
        was fixed, and calling that `resolved` would be a lie the inbox acts on.
        """
        now = int(time.time()) if now is None else now
        cursor = self.conn.execute(
            "UPDATE findings SET status = 'resolved', last_seen_at = ?"
            " WHERE repo = ? AND check_name != 'history' AND status != 'resolved'"
            f" AND dedupe_key NOT IN ({','.join('?' * len(present)) or "''"})",
            (now, repo, *present))
        self.conn.commit()
        return cursor.rowcount

    def counts(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity").fetchall()
        return {r["severity"]: r["n"] for r in rows}

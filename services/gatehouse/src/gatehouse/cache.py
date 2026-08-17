"""Per-PR scan state: what makes a re-push rescan only the delta.

Keyed by **git blob SHA**, not by path. A file whose content is unchanged has
the same blob SHA no matter how the PR was rebased, squashed or force-pushed,
so the cache survives exactly the operations that invalidate a path-and-mtime
cache. It also means two branches that touch the same file content share the
result for free.

What is stored, and why it is allowed to be stored (D4 retention rule — findings
yes, code no):

| Column | Why | Retention |
|---|---|---|
| `blob_sha` | Cache key. A hash of content, not content. | 30 days |
| finding rows | The finding *is* the record this product produces. | 30 days |
| `first_seen_at` | Stable first sighting across every PR that has carried this finding. | 30 days |
| per-(repo, pr, key) rows | One *occurrence* of a finding on one open PR. `observed_count` on the bus is the COUNT of these rows for a key (AIM-299 AC#3: five PRs → one issue, five occurrences). | 30 days |

No source text, no diffs, no secrets — `snippet_digest` is one-way. `prune()`
enforces the 30 days on the same clock as the bus's retention (D3.1 §5), so a
closed PR's findings do not accumulate for the life of the VM.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import asdict

from .models import Finding

RETENTION_DAYS = int(os.environ.get("GATEHOUSE_RETENTION_DAYS", "30"))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_cache (
  repo       TEXT NOT NULL,
  scanner    TEXT NOT NULL,
  blob_sha   TEXT NOT NULL,
  findings   TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (repo, scanner, blob_sha)
);
CREATE TABLE IF NOT EXISTS pr_findings (
  repo          TEXT NOT NULL,
  pr            INTEGER NOT NULL,
  dedupe_key    TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL,
  observed_count INTEGER NOT NULL DEFAULT 1,
  alert_id      TEXT NOT NULL DEFAULT '',
  updated_at    INTEGER NOT NULL,
  PRIMARY KEY (repo, pr, dedupe_key)
);
-- AIM-297: durable webhook delivery ids so a runner restart cannot re-scan
-- a delivery that already completed. In-memory alone is not crash-safe.
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  delivery_id TEXT PRIMARY KEY,
  seen_at     INTEGER NOT NULL
);
-- AIM-332: per-repo gate ledger. One row per completed (or failed-to-complete)
-- gate run so coverage can answer "when did this repo last run, at what mode,
-- with what result?" without inventing green from silence.
CREATE TABLE IF NOT EXISTS gate_runs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  repo          TEXT NOT NULL,
  pr            INTEGER NOT NULL DEFAULT 0,
  head_sha      TEXT NOT NULL DEFAULT '',
  conclusion    TEXT NOT NULL,
  mode          TEXT NOT NULL DEFAULT 'enforce',
  fail_on       TEXT NOT NULL DEFAULT '',
  duration_ms   INTEGER NOT NULL DEFAULT 0,
  error         TEXT NOT NULL DEFAULT '',
  completed_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS gate_runs_repo_completed
  ON gate_runs (repo, completed_at DESC);
"""


class Store:
    """SQLite-backed. One file, no server — the stack has a 16 GB budget (D6)."""

    def __init__(self, path: str | None = None):
        self.path = path or os.environ.get(
            "GATEHOUSE_STATE_DB", "/var/lib/gatehouse/state.db")
        if self.path != ":memory:":
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # ---- delta cache -----------------------------------------------------

    def cached_findings(self, repo: str, scanner: str, blob_sha: str) -> list[Finding] | None:
        """Findings for this exact file content, or None if never scanned.

        None and `[]` are different answers and the caller must not conflate
        them: `[]` means "scanned, clean" and is the whole point of the cache.
        """
        row = self.conn.execute(
            "SELECT findings FROM scan_cache WHERE repo=? AND scanner=? AND blob_sha=?",
            (repo, scanner, blob_sha)).fetchone()
        if row is None:
            return None
        return [Finding(**item) for item in json.loads(row[0])]

    def put_findings(self, repo: str, scanner: str, blob_sha: str,
                     findings: list[Finding]) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO scan_cache VALUES (?,?,?,?,?)",
            (repo, scanner, blob_sha, json.dumps([asdict(f) for f in findings]),
             int(time.time())))
        self.conn.commit()

    # ---- finding lifecycle (multi-PR occurrences, AIM-299) --------------

    def seen(self, repo: str, pr: int) -> dict[str, dict]:
        """Every dedupe_key previously reported on this PR, with its history.

        `observed_count` is the number of open PRs currently carrying this
        key in the whole repo — not the number of pushes on this PR alone.
        """
        rows = self.conn.execute(
            "SELECT dedupe_key, first_seen_at, last_seen_at, alert_id"
            " FROM pr_findings WHERE repo=? AND pr=?", (repo, pr)).fetchall()
        out: dict[str, dict] = {}
        for row in rows:
            key = row[0]
            out[key] = {
                "first_seen_at": self._first_seen(repo, key) or row[1],
                "last_seen_at": row[2],
                "observed_count": self._occurrence_count(repo, key),
                "alert_id": row[3],
            }
        return out

    def _occurrence_count(self, repo: str, dedupe_key: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM pr_findings WHERE repo=? AND dedupe_key=?",
            (repo, dedupe_key)).fetchone()
        return int(row[0]) if row else 0

    def _first_seen(self, repo: str, dedupe_key: str) -> str | None:
        row = self.conn.execute(
            "SELECT MIN(first_seen_at) FROM pr_findings"
            " WHERE repo=? AND dedupe_key=?",
            (repo, dedupe_key)).fetchone()
        return row[0] if row and row[0] else None

    def record(self, repo: str, pr: int, dedupe_key: str, *, now: str,
               alert_id: str) -> dict:
        """Upsert one PR occurrence of a finding and return group history.

        - `is_new` is True only the first time this key is seen on *any* PR
          in the repo (so five PRs sharing a secret produce one `new` and
          four `updated` emissions with rising `observed_count`).
        - `observed_count` is the COUNT of open PR occurrences for the key,
          not a per-PR push counter — re-pushing the same PR does not invent
          a sixth occurrence of a five-PR finding.
        """
        prior_any = self._occurrence_count(repo, dedupe_key) > 0
        prior_row = self.conn.execute(
            "SELECT first_seen_at FROM pr_findings"
            " WHERE repo=? AND pr=? AND dedupe_key=?",
            (repo, pr, dedupe_key)).fetchone()
        first_on_this_pr = prior_row[0] if prior_row else now
        # Group first_seen is the earliest of every occurrence; for a brand-new
        # key that is `now`, for a key already open on other PRs it is theirs.
        group_first = self._first_seen(repo, dedupe_key) or first_on_this_pr
        self.conn.execute(
            "INSERT OR REPLACE INTO pr_findings VALUES (?,?,?,?,?,?,?,?)",
            (repo, pr, dedupe_key, first_on_this_pr, now, 1, alert_id,
             int(time.time())))
        self.conn.commit()
        count = self._occurrence_count(repo, dedupe_key)
        return {
            "first_seen_at": group_first,
            "last_seen_at": now,
            "observed_count": count,
            "alert_id": alert_id,
            "is_new": not prior_any,
            "is_new_on_pr": prior_row is None,
        }

    def forget(self, repo: str, pr: int, dedupe_keys: list[str]) -> list[str]:
        """Drop this PR's occurrences of the given keys.

        Returns the subset that now have **zero** remaining PR occurrences —
        those are the ones the bus should emit as `resolved`. Keys that still
        live on another open PR stay open (updated on the next scan of that
        PR); that is the no-zombie / no-silent-reopen rule for multi-PR
        findings (AIM-299 AC#5).
        """
        if not dedupe_keys:
            return []
        marks = ",".join("?" * len(dedupe_keys))
        self.conn.execute(
            f"DELETE FROM pr_findings WHERE repo=? AND pr=? AND dedupe_key IN ({marks})",
            (repo, pr, *dedupe_keys))
        self.conn.commit()
        fully_gone: list[str] = []
        for key in dedupe_keys:
            if self._occurrence_count(repo, key) == 0:
                fully_gone.append(key)
        return fully_gone

    # ---- gate-run ledger (AIM-332) ---------------------------------------

    def record_gate_run(
        self,
        repo: str,
        *,
        pr: int = 0,
        head_sha: str = "",
        conclusion: str,
        mode: str = "enforce",
        fail_on: str = "",
        duration_ms: int = 0,
        error: str = "",
        completed_at: int | None = None,
    ) -> None:
        """Append one gate run. Coverage reads the latest per repo."""
        if not repo:
            return
        self.conn.execute(
            "INSERT INTO gate_runs "
            "(repo, pr, head_sha, conclusion, mode, fail_on, duration_ms, error, completed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                repo,
                int(pr or 0),
                (head_sha or "")[:64],
                conclusion or "neutral",
                mode or "enforce",
                fail_on or "",
                int(duration_ms or 0),
                (error or "")[:500],
                completed_at if completed_at is not None else int(time.time()),
            ),
        )
        self.conn.commit()

    def latest_gate_runs(self) -> dict[str, dict]:
        """repo → most recent gate run row (metadata only)."""
        rows = self.conn.execute(
            "SELECT repo, pr, head_sha, conclusion, mode, fail_on, duration_ms, "
            "error, completed_at FROM gate_runs "
            "WHERE id IN (SELECT MAX(id) FROM gate_runs GROUP BY repo)"
        ).fetchall()
        out: dict[str, dict] = {}
        for row in rows:
            out[row[0]] = {
                "repo": row[0],
                "pr": int(row[1] or 0),
                "head_sha": row[2] or "",
                "conclusion": row[3] or "neutral",
                "mode": row[4] or "enforce",
                "fail_on": row[5] or "",
                "duration_ms": int(row[6] or 0),
                "error": row[7] or "",
                "completed_at": int(row[8] or 0),
            }
        return out

    # ---- webhook delivery idempotency (AIM-297) --------------------------

    def claim_delivery(self, delivery_id: str, *, now: int | None = None) -> bool:
        """Atomically claim a GitHub delivery id.

        Returns True if this process should handle it, False if a prior claim
        (including one that survived a process restart) already owns it.
        Empty ids are never claimed — the caller must not treat them as
        duplicates (that would drop legitimate unsigned-id traffic).
        """
        if not delivery_id:
            return True
        ts = now if now is not None else int(time.time())
        try:
            self.conn.execute(
                "INSERT INTO webhook_deliveries (delivery_id, seen_at) VALUES (?, ?)",
                (delivery_id, ts))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def has_delivery(self, delivery_id: str) -> bool:
        if not delivery_id:
            return False
        row = self.conn.execute(
            "SELECT 1 FROM webhook_deliveries WHERE delivery_id=?",
            (delivery_id,)).fetchone()
        return row is not None

    # ---- retention -------------------------------------------------------

    def prune(self, *, days: int = RETENTION_DAYS, now: int | None = None) -> int:
        cutoff = (now or int(time.time())) - days * 86400
        cursor = self.conn.execute("DELETE FROM scan_cache WHERE updated_at < ?", (cutoff,))
        removed = cursor.rowcount or 0
        cursor = self.conn.execute("DELETE FROM pr_findings WHERE updated_at < ?", (cutoff,))
        removed += cursor.rowcount or 0
        # Gate runs: keep longer than delivery ids so coverage staleness can
        # still name "last ran 20 days ago" rather than "never". Same 30d
        # ceiling as findings; the latest row per repo is enough in practice.
        cursor = self.conn.execute(
            "DELETE FROM gate_runs WHERE completed_at < ?", (cutoff,))
        removed += cursor.rowcount or 0
        # Deliveries are short-lived: keep 7 days so restarts within the
        # redelivery window stay idempotent without unbounded growth.
        delivery_cutoff = (now or int(time.time())) - min(days, 7) * 86400
        cursor = self.conn.execute(
            "DELETE FROM webhook_deliveries WHERE seen_at < ?", (delivery_cutoff,))
        removed += cursor.rowcount or 0
        self.conn.commit()
        return removed

    def close(self) -> None:
        self.conn.close()

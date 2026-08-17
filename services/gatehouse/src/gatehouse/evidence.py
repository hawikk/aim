"""Durable gate verdict evidence.

An enforcement claim we cannot demonstrate months later is not an enforcement
claim. This store keeps, per merged commit / PR head SHA:

* required-check verdicts (name → conclusion/status + check_run id/url)
* overall classification (clean / unauthorized_bypass / deliberate_bypass / unverified)
* actor, policy hash, notes

Retention default is **90 days** (independent of the 30-day finding cache).
No source text, no diffs, no secret values — only check metadata and SHAs.

Storage is SQLite (same reliability profile as the finding cache). The path is
``GATEHOUSE_EVIDENCE_DB`` or, by default, sibling of ``GATEHOUSE_STATE_DB``:
``/var/lib/gatehouse/gate-evidence.db``.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

DEFAULT_RETENTION_DAYS = 90


def default_db_path() -> str:
    explicit = os.environ.get("GATEHOUSE_EVIDENCE_DB", "").strip()
    if explicit:
        return explicit
    state = os.environ.get("GATEHOUSE_STATE_DB", "/var/lib/gatehouse/state.db")
    candidate = Path(state).with_name("gate-evidence.db")
    # Prefer the production path when it is writable (compose / systemd).
    # Fall back to a per-user cache so CLI/scripts work without root.
    try:
        candidate.parent.mkdir(parents=True, exist_ok=True)
        probe = candidate.parent / ".aim-evidence-write-probe"
        probe.write_text("ok")
        probe.unlink(missing_ok=True)
        return str(candidate)
    except OSError:
        fallback = Path.home() / ".cache" / "gatehouse" / "gate-evidence.db"
        fallback.parent.mkdir(parents=True, exist_ok=True)
        return str(fallback)


def retention_days() -> int:
    raw = os.environ.get("GATEHOUSE_EVIDENCE_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS))
    try:
        return max(1, int(raw))
    except ValueError:
        return DEFAULT_RETENTION_DAYS


@dataclass
class GateVerdict:
    """One required-check outcome at a specific head SHA."""

    name: str
    required: bool = True
    status: str | None = None       # completed / queued / in_progress / None
    conclusion: str | None = None   # success / failure / cancelled / … / None
    check_run_id: int | None = None
    html_url: str | None = None
    details_url: str | None = None
    completed_at: str | None = None

    @property
    def state(self) -> str:
        if self.conclusion:
            return self.conclusion
        if self.status:
            return self.status
        return "ABSENT"

    def is_green(self) -> bool:
        return self.status == "completed" and self.conclusion == "success"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GateEvidence:
    """Retrievable record answering 'why was this allowed / blocked?'."""

    repo: str
    head_sha: str
    pr_number: int | None = None
    merge_sha: str | None = None
    actor: str | None = None
    merged_at: str | None = None
    classification: str = "unknown"  # clean|unauthorized_bypass|deliberate_bypass|unverified|canary_blocked|canary_mergeable
    policy_hash: str | None = None
    notes: list[str] = field(default_factory=list)
    verdicts: list[GateVerdict] = field(default_factory=list)
    # Free-form extras (scanner summary pointers, canary markers, …).
    scanner_output: dict[str, Any] = field(default_factory=dict)
    recorded_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "head_sha": self.head_sha,
            "pr_number": self.pr_number,
            "merge_sha": self.merge_sha,
            "actor": self.actor,
            "merged_at": self.merged_at,
            "classification": self.classification,
            "policy_hash": self.policy_hash,
            "notes": list(self.notes),
            "verdicts": [v.to_dict() for v in self.verdicts],
            "scanner_output": dict(self.scanner_output),
            "recorded_at": self.recorded_at,
        }


class EvidenceStore:
    """SQLite-backed gate evidence with explicit retention prune."""

    def __init__(self, path: str | None = None):
        self.path = path or default_db_path()
        parent = Path(self.path).parent
        parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS gate_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo TEXT NOT NULL,
                head_sha TEXT NOT NULL,
                pr_number INTEGER,
                pr_key INTEGER NOT NULL,
                merge_sha TEXT,
                actor TEXT,
                merged_at TEXT,
                classification TEXT NOT NULL,
                policy_hash TEXT,
                notes_json TEXT NOT NULL DEFAULT '[]',
                verdicts_json TEXT NOT NULL DEFAULT '[]',
                scanner_output_json TEXT NOT NULL DEFAULT '{}',
                recorded_at REAL NOT NULL,
                UNIQUE(repo, head_sha, pr_key)
            );
            CREATE INDEX IF NOT EXISTS idx_gate_evidence_recorded
                ON gate_evidence(recorded_at);
            CREATE INDEX IF NOT EXISTS idx_gate_evidence_merge
                ON gate_evidence(merge_sha);
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def put(self, record: GateEvidence, *, now: float | None = None) -> None:
        """Upsert one evidence row keyed by (repo, head_sha, pr_number)."""
        ts = now if now is not None else time.time()
        record.recorded_at = ts
        pr_key = int(record.pr_number) if record.pr_number is not None else -1
        self._conn.execute(
            """
            INSERT INTO gate_evidence (
                repo, head_sha, pr_number, pr_key, merge_sha, actor, merged_at,
                classification, policy_hash, notes_json, verdicts_json,
                scanner_output_json, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(repo, head_sha, pr_key) DO UPDATE SET
                pr_number=excluded.pr_number,
                merge_sha=excluded.merge_sha,
                actor=excluded.actor,
                merged_at=excluded.merged_at,
                classification=excluded.classification,
                policy_hash=excluded.policy_hash,
                notes_json=excluded.notes_json,
                verdicts_json=excluded.verdicts_json,
                scanner_output_json=excluded.scanner_output_json,
                recorded_at=excluded.recorded_at
            """,
            (
                record.repo,
                record.head_sha,
                record.pr_number,
                pr_key,
                record.merge_sha,
                record.actor,
                record.merged_at,
                record.classification,
                record.policy_hash,
                json.dumps(list(record.notes)),
                json.dumps([v.to_dict() for v in record.verdicts]),
                json.dumps(dict(record.scanner_output)),
                ts,
            ),
        )
        self._conn.commit()

    def get(
        self,
        *,
        repo: str | None = None,
        head_sha: str | None = None,
        merge_sha: str | None = None,
        pr_number: int | None = None,
    ) -> list[GateEvidence]:
        clauses: list[str] = []
        args: list[Any] = []
        if repo:
            clauses.append("repo = ?")
            args.append(repo)
        if head_sha:
            clauses.append("head_sha = ?")
            args.append(head_sha)
        if merge_sha:
            clauses.append("merge_sha = ?")
            args.append(merge_sha)
        if pr_number is not None:
            clauses.append("pr_number = ?")
            args.append(pr_number)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM gate_evidence{where} ORDER BY recorded_at DESC",
            args,
        ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def list_recent(self, *, limit: int = 50, repo: str | None = None) -> list[GateEvidence]:
        if repo:
            rows = self._conn.execute(
                "SELECT * FROM gate_evidence WHERE repo = ? ORDER BY recorded_at DESC LIMIT ?",
                (repo, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM gate_evidence ORDER BY recorded_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def prune(self, *, days: int | None = None, now: float | None = None) -> int:
        days = retention_days() if days is None else max(1, days)
        cutoff = (now if now is not None else time.time()) - days * 86400
        cur = self._conn.execute(
            "DELETE FROM gate_evidence WHERE recorded_at < ?",
            (cutoff,),
        )
        self._conn.commit()
        return int(cur.rowcount or 0)

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> GateEvidence:
        verdicts_raw = json.loads(row["verdicts_json"] or "[]")
        verdicts = [GateVerdict(**v) for v in verdicts_raw]
        return GateEvidence(
            repo=row["repo"],
            head_sha=row["head_sha"],
            pr_number=row["pr_number"],
            merge_sha=row["merge_sha"],
            actor=row["actor"],
            merged_at=row["merged_at"],
            classification=row["classification"],
            policy_hash=row["policy_hash"],
            notes=list(json.loads(row["notes_json"] or "[]")),
            verdicts=verdicts,
            scanner_output=dict(json.loads(row["scanner_output_json"] or "{}")),
            recorded_at=float(row["recorded_at"] or 0),
        )


def verdicts_from_check_runs(
    required: Iterable[str],
    check_runs: list[dict],
) -> list[GateVerdict]:
    """Map required check names onto the latest run per name (same as merge-audit)."""
    by_name: dict[str, dict] = {}
    for run in check_runs:
        name = run.get("name") or ""
        if not name:
            continue
        prev = by_name.get(name)
        if prev is None or (run.get("id") or 0) > (prev.get("id") or 0):
            by_name[name] = run
    out: list[GateVerdict] = []
    for name in required:
        run = by_name.get(name)
        if not run:
            out.append(GateVerdict(name=name, required=True))
            continue
        out.append(GateVerdict(
            name=name,
            required=True,
            status=run.get("status"),
            conclusion=run.get("conclusion"),
            check_run_id=run.get("id"),
            html_url=run.get("html_url"),
            details_url=run.get("details_url"),
            completed_at=run.get("completed_at"),
        ))
    return out


def classification_from_audit(
    *,
    clean: bool,
    unverified: bool,
    deliberate: bool,
    has_bypass: bool,
) -> str:
    if unverified:
        return "unverified"
    if clean and not has_bypass:
        return "clean"
    if deliberate:
        return "deliberate_bypass"
    return "unauthorized_bypass"

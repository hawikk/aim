#!/usr/bin/env python3
"""AIM-647 offline dual-surface proof.

Builds fixture IDE + CLI Kilo surfaces, runs scan_once, and asserts both
produce validated `tool=kilo_code` events. CLI events must carry
`tool_version` prefix `cli/`. No network / ingest required.

Exit 0 on pass, 1 on fail. Prints a small JSON summary to stdout.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

# Resolve collectors/kilo-code onto sys.path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "collectors" / "kilo-code"))

os.environ.setdefault("AIM_HASH_SALT", "aim-647-proof-salt")


def _ide_fixture(root: Path) -> Path:
    storage = root / "ide" / "globalStorage" / "kilocode.kilo-code"
    task = storage / "tasks" / "task-ide-001"
    task.mkdir(parents=True)
    (task / "ui_messages.json").write_text(json.dumps([
        {
            "type": "say",
            "say": "api_req_started",
            "ts": 1752066000000,
            "text": json.dumps({
                "request": "refactor module",
                "tokensIn": 120,
                "tokensOut": 40,
                "cacheReads": 10,
                "cost": 0.002,
                "modelId": "gpt-4.1",
            }),
        }
    ]))
    (task / "api_conversation_history.json").write_text(json.dumps([
        {
            "role": "user",
            "content": (
                "<environment_details>\n"
                "# Current Workspace Directory (/home/u/ide-proj) Files\n"
                "</environment_details>"
            ),
        }
    ]))
    return storage


def _cli_fixture(root: Path) -> Path:
    db = root / "cli" / "kilo.db"
    db.parent.mkdir(parents=True)
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE session (
            id TEXT PRIMARY KEY,
            project_id TEXT,
            directory TEXT,
            version TEXT,
            model TEXT,
            cost REAL,
            tokens_input INTEGER,
            tokens_output INTEGER,
            tokens_reasoning INTEGER,
            tokens_cache_read INTEGER,
            tokens_cache_write INTEGER,
            time_created INTEGER,
            time_updated INTEGER
        );
        CREATE TABLE message (
            id TEXT PRIMARY KEY,
            session_id TEXT,
            time_created INTEGER,
            time_updated INTEGER,
            data TEXT
        );
        CREATE TABLE part (
            id TEXT PRIMARY KEY,
            message_id TEXT,
            session_id TEXT,
            time_created INTEGER,
            time_updated INTEGER,
            data TEXT
        );
        """
    )
    ts = 1752067000000
    conn.execute(
        """INSERT INTO session
           (id, project_id, directory, version, model, cost,
            tokens_input, tokens_output, tokens_reasoning,
            tokens_cache_read, tokens_cache_write, time_created, time_updated)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "ses_cli_001",
            "global",
            "/home/u/cli-proj",
            "7.4.11",
            json.dumps({"id": "claude-sonnet-4-5", "providerID": "kilo"}),
            0.015,
            500,
            80,
            0,
            25,
            0,
            ts,
            ts + 5000,
        ),
    )
    conn.execute(
        "INSERT INTO message VALUES (?,?,?,?,?)",
        ("msg1", "ses_cli_001", ts, ts, json.dumps({"role": "user"})),
    )
    conn.execute(
        "INSERT INTO part VALUES (?,?,?,?,?,?)",
        ("prt1", "msg1", "ses_cli_001", ts, ts,
         json.dumps({"type": "text", "text": "run tests"})),
    )
    conn.commit()
    conn.close()
    return db


def main() -> int:
    from kilo_collector import events, paths, state, watch

    with tempfile.TemporaryDirectory(prefix="aim-647-proof-") as tmp:
        root = Path(tmp)
        ide_storage = _ide_fixture(root)
        cli_db = _cli_fixture(root)
        state_dir = root / "state"
        env = {
            "AIM_STATE_DIR": str(state_dir),
            paths.ENV_STORAGE_DIR: str(ide_storage),
            paths.ENV_CLI_DB: str(cli_db),
            paths.ENV_EXTENSION_DIR: str(root / "no-ext"),
            "AIM_INGEST_URL": "",
            "AIM_COLLECTOR_TOKEN": "",
            "AIM_HASH_SALT": "aim-647-proof-salt",
        }
        old = {k: os.environ.get(k) for k in env}
        try:
            os.environ.update(env)
            n = watch.scan_once()
            spool = state.spool_path()
            rows = [
                json.loads(line)
                for line in spool.read_text().splitlines()
                if line.strip()
            ]
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    for ev in rows:
        events.validate(ev)

    usage = [e for e in rows if e.get("event_type") not in ("inventory", "tool_use")]
    ide = [e for e in usage if not str(e.get("tool_version") or "").startswith("cli/")]
    cli = [e for e in usage if str(e.get("tool_version") or "").startswith("cli/")]

    ok = (
        n >= 2
        and len(ide) >= 1
        and len(cli) >= 1
        and all(e.get("tool") == "kilo_code" for e in usage)
        and all(e.get("source") == "endpoint" for e in usage)
        and "ghp_" not in json.dumps(rows)
        and "/home/u/" not in json.dumps(rows)
    )

    summary = {
        "ok": ok,
        "emitted": n,
        "usage_events": len(usage),
        "ide_usage": len(ide),
        "cli_usage": len(cli),
        "ide_sample": {
            "tool": ide[0]["tool"],
            "model": ide[0].get("model"),
            "tokens_in": ide[0].get("tokens_in"),
            "tool_version": ide[0].get("tool_version"),
        } if ide else None,
        "cli_sample": {
            "tool": cli[0]["tool"],
            "model": cli[0].get("model"),
            "tokens_in": cli[0].get("tokens_in"),
            "tool_version": cli[0].get("tool_version"),
        } if cli else None,
        "claude_cursor_note": (
            "Claude Code IDE+CLI share ~/.claude hooks/transcripts; "
            "Cursor AI surface is IDE-only (no agent CLI on fleet). "
            "See docs/aim-647-dual-surface-completeness.md"
        ),
    }
    print(json.dumps(summary, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

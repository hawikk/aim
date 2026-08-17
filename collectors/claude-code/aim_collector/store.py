"""Embedded SQLite store for personal mode.

Zero-infra alternative to the Postgres event store: the collector writes
metadata-only usage events straight to a local SQLite file (stdlib `sqlite3`,
no server, no network), and the personal dashboard reads aggregates back out
of it. The query functions here return the exact JSON shapes the existing web
app (`apps/web/public/app.js`) already consumes, so the same dashboard renders
against SQLite unchanged.

Content policy is unchanged from the enterprise path: only the
canonical metadata-only event fields are persisted — no prompt text, tool
input/output, file contents, or code. A single implicit local user; events
with a null `user_ref` are attributed to this machine's `host_ref` so the
single-user dashboard reads naturally.
"""

import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from . import state

DEFAULT_DB = "personal.db"
SANCTIONED_TOOLS = {"claude_code", "cursor", "kilo_code", "kimi_code"}


def _sanctioned_sql() -> str:
    """SQL IN-list literal for SANCTIONED_TOOLS (single source of truth)."""
    return "(" + ",".join(f"'{t}'" for t in sorted(SANCTIONED_TOOLS)) + ")"

# List prices, USD per 1M tokens [input, output]. Kept in sync with the
# platform price table (apps/api/src/pricing.js) — apps/api/test/pricing.test.js
# fails CI when the two drift apart. Cost is an estimate only.
# Keep in lockstep with apps/api/src/pricing.js — pricing.test.js enforces parity.
# Anthropic rates: docs.anthropic.com (2026-08). Kimi: Moonshot/OpenRouter list.
# Gemini: ai.google.dev pricing. Grok: docs.x.ai. Cache billed only when a
# collector sets cost_estimate_usd (platform folds cache into tokens_in).
PRICE_PER_MTOK = {
    "claude-fable-5": (10, 50),
    "claude-mythos-5": (10, 50),
    "claude-opus-5": (5, 25),
    "claude-opus-4-8": (5, 25),
    "claude-opus-4-7": (5, 25),
    "claude-opus-4-6": (5, 25),
    "claude-opus-4-5": (5, 25),
    "claude-opus-4-1": (15, 75),
    "claude-opus-4": (15, 75),
    "claude-sonnet-5": (2, 10),
    "claude-sonnet-4-6": (3, 15),
    "claude-sonnet-4-5": (3, 15),
    "claude-sonnet-4": (3, 15),
    "claude-haiku-4-5": (1, 5),
    "claude-haiku-3-5": (0.8, 4),
    "claude-3-7-sonnet": (3, 15),
    "claude-3-5-sonnet": (3, 15),
    "claude-3-5-haiku": (0.8, 4),
    "claude-3-opus": (15, 75),
    "claude-3-haiku": (0.25, 1.25),
    "gpt-4o-mini": (0.15, 0.6),
    "gpt-4o": (2.5, 10),
    "gpt-4.1-mini": (0.4, 1.6),
    "gpt-4.1": (2, 8),
    "gpt-4-turbo": (10, 30),
    "o4-mini": (1.1, 4.4),
    "o3": (2, 8),
    "o1": (15, 60),
    "cursor-auto": (3, 15),
    "swe-1": (3, 15),
    "codeium-chat": (1, 3),
    "grok-4.5": (2, 6),
    "grok-4.3": (1.25, 2.5),
    "grok-4.20": (1.25, 2.5),
    "grok-build-0.1": (1, 2),
    "grok-3": (3, 15),
    "grok-code-fast-1": (0.2, 1.5),
    "kimi-code/k3": (3, 15),
    "kimi-k3": (3, 15),
    "kimi-code/kimi-for-coding": (0.73, 3.5),
    "kimi-for-coding": (0.73, 3.5),
    "kimi-k2.7-code": (0.73, 3.5),
    "kimi-k2.6": (0.59, 2.48),
    "kimi-k2.5": (0.57, 2.85),
    "kimi-k2-thinking": (0.6, 2.5),
    "kimi-k2": (0.57, 2.3),
    "kimi-k2-0905": (0.6, 2.5),
    "moonshot-v1": (1, 3),
    "gemini-3.1-pro": (2, 12),
    "gemini-3-pro": (2, 12),
    "gemini-3.6-flash": (1.5, 7.5),
    "gemini-3.5-flash-lite": (0.3, 2.5),
    "gemini-3.5-flash": (1.5, 9),
    "gemini-3.1-flash-lite": (0.25, 1.5),
    "gemini-3-flash": (0.5, 3),
    "gemini-2.5-pro": (1.25, 10),
    "gemini-2.5-flash-lite": (0.1, 0.4),
    "gemini-2.5-flash": (0.3, 2.5),
    "gemini-1.5-pro": (1.25, 5),
    "gemini-1.5-flash": (0.075, 0.3),
}
DEFAULT_PRICE = (5, 20)

# The only fields we persist. Any event key outside this set is dropped on the
# way in — a defensive backstop on the metadata-only contract, so even a future
# collector bug can't leak content fields into the personal DB.
_COLUMNS = (
    "event_id", "ts", "ts_epoch", "day", "host_ref", "user_ref", "session_id",
    "tool", "tool_raw", "model", "provider", "tokens_in", "tokens_out",
    "source", "match_flags",
)


def db_path() -> Path:
    override = os.environ.get("AIM_PERSONAL_DB")
    if override:
        return Path(override).expanduser()
    return state.state_dir() / DEFAULT_DB


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path or db_path()))
    conn.row_factory = sqlite3.Row
    _init(conn)
    return conn


def _init(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS events (
             event_id   TEXT PRIMARY KEY,
             ts         TEXT NOT NULL,
             ts_epoch   INTEGER NOT NULL,
             day        TEXT NOT NULL,
             host_ref   TEXT,
             user_ref   TEXT,
             session_id TEXT,
             tool       TEXT,
             tool_raw   TEXT,
             model      TEXT,
             provider   TEXT,
             tokens_in  INTEGER,
             tokens_out INTEGER,
             source     TEXT,
             match_flags TEXT
           )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_epoch ON events(ts_epoch)")
    # Retention bookkeeping: last-prune marker so the prune runs at
    # most daily even across many collector restarts. Key/value, one row.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS retention_meta (key TEXT PRIMARY KEY, value TEXT)"
    )
    conn.commit()


def _epoch(ts: str) -> int:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            return int(datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            continue
    return int(time.time())


def insert_events(events: list[dict], conn: sqlite3.Connection | None = None) -> int:
    """Persist canonical events. Idempotent (INSERT OR IGNORE on event_id).

    Serves as the transcript scanner's `sink` in personal mode.
    """
    if not events:
        return 0
    own = conn is None
    conn = conn or connect()
    try:
        n = 0
        for ev in events:
            ts = ev.get("ts") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            host_ref = ev.get("host_ref")
            row = {
                "event_id": ev.get("event_id"),
                "ts": ts,
                "ts_epoch": _epoch(ts),
                "day": ts[:10],
                "host_ref": host_ref,
                # single implicit local user: attribute unidentified events to
                # the host so the single-user dashboard shows 1 active user.
                "user_ref": ev.get("user_ref") or host_ref,
                "session_id": ev.get("session_id"),
                "tool": ev.get("tool"),
                "tool_raw": ev.get("tool_raw"),
                "model": ev.get("model"),
                "provider": ev.get("provider"),
                "tokens_in": ev.get("tokens_in"),
                "tokens_out": ev.get("tokens_out"),
                "source": ev.get("source"),
                "match_flags": json.dumps(ev.get("match_flags") or []),
            }
            cur = conn.execute(
                f"INSERT OR IGNORE INTO events ({','.join(_COLUMNS)}) "
                f"VALUES ({','.join(':' + c for c in _COLUMNS)})",
                row,
            )
            n += cur.rowcount
        conn.commit()
        return n
    finally:
        if own:
            conn.close()


# ---- retention prune ----

PRUNE_MIN_INTERVAL_S = 86400  # at most once per day


def prune(events_days: int, conn: sqlite3.Connection, now: int | None = None,
          dry_run: bool = False) -> dict:
    """Delete events older than the retention window from the personal store.

    Boundary rule (matches the server-mode purger): a row is removed iff it is
    STRICTLY older than the cutoff; an event exactly at the window edge (age ==
    window) is kept. Idempotent — a re-run right after deletes nothing. In
    dry_run, counts what would go and deletes nothing. Returns a metadata-only
    summary (no event content).
    """
    now = int(now if now is not None else time.time())
    cutoff = now - events_days * 86400
    if dry_run:
        n = conn.execute("SELECT COUNT(*) FROM events WHERE ts_epoch < ?", (cutoff,)).fetchone()[0]
        return {"data_class": "events", "window_days": events_days,
                "cutoff_epoch": cutoff, "rows_deleted": 0, "would_delete": n, "dry_run": True}
    cur = conn.execute("DELETE FROM events WHERE ts_epoch < ?", (cutoff,))
    conn.commit()
    return {"data_class": "events", "window_days": events_days, "cutoff_epoch": cutoff,
            "rows_deleted": cur.rowcount, "would_delete": cur.rowcount, "dry_run": False}


def _last_prune_epoch(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT value FROM retention_meta WHERE key='last_prune_epoch'").fetchone()
    try:
        return int(row[0]) if row else 0
    except (TypeError, ValueError):
        return 0


def _set_last_prune_epoch(conn: sqlite3.Connection, epoch: int) -> None:
    conn.execute(
        "INSERT INTO retention_meta(key, value) VALUES('last_prune_epoch', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(epoch),),
    )
    conn.commit()


def maybe_prune(events_days: int, conn: sqlite3.Connection, now: int | None = None,
                dry_run: bool = False, min_interval_s: int = PRUNE_MIN_INTERVAL_S) -> dict | None:
    """Prune, but at most once per `min_interval_s` (default daily). Returns the
    prune summary when it ran, or None when skipped because it ran recently."""
    now = int(now if now is not None else time.time())
    last = _last_prune_epoch(conn)
    if last and now - last < min_interval_s:
        return None
    result = prune(events_days, conn, now=now, dry_run=dry_run)
    _set_last_prune_epoch(conn, now)
    return result


# ---- cost expression, mirroring apps/api/src/pricing.js COST_SQL ----
def _cost_sql(prefix: str = "") -> str:
    pin = " ".join(f"WHEN '{m}' THEN {p[0]}" for m, p in PRICE_PER_MTOK.items())
    pout = " ".join(f"WHEN '{m}' THEN {p[1]}" for m, p in PRICE_PER_MTOK.items())
    ti, to, mdl = f"{prefix}tokens_in", f"{prefix}tokens_out", f"{prefix}model"
    return (
        f"(COALESCE({ti},0) * (CASE {mdl} {pin} ELSE {DEFAULT_PRICE[0]} END) + "
        f"COALESCE({to},0) * (CASE {mdl} {pout} ELSE {DEFAULT_PRICE[1]} END)) / 1000000.0"
    )


def _cutoff(days: int) -> int:
    return int(time.time()) - days * 86400


def _range(days: int, source: str | None):
    clause = "ts_epoch >= ?"
    params: list = [_cutoff(days)]
    if source in ("proxy", "endpoint"):
        clause += " AND source = ?"
        params.append(source)
    return clause, params


def _is_sanctioned(tool: str | None) -> bool:
    return tool in SANCTIONED_TOOLS


def _n(v) -> float:
    return v if isinstance(v, (int, float)) else 0


# ---- read queries: same JSON shapes as apps/api/src/routes/dashboard.js ----

def overview(conn: sqlite3.Connection, days: int = 30, source: str | None = None) -> dict:
    where, params = _range(days, source)
    cost = _cost_sql()
    totals = conn.execute(
        f"""SELECT COUNT(DISTINCT user_ref) AS active_users,
                   COUNT(DISTINCT host_ref) AS active_hosts,
                   COUNT(DISTINCT session_id) AS sessions,
                   COUNT(*) AS events,
                   COALESCE(SUM(tokens_in),0) AS tokens_input,
                   COALESCE(SUM(tokens_out),0) AS tokens_output,
                   COALESCE(SUM({cost}),0) AS cost
              FROM events WHERE {where}""",
        params,
    ).fetchone()
    tools = conn.execute(
        f"""SELECT tool,
                   COUNT(DISTINCT user_ref) AS users,
                   COUNT(DISTINCT host_ref) AS hosts,
                   COUNT(DISTINCT session_id) AS sessions,
                   SUM(CASE WHEN source='proxy' THEN 1 ELSE 0 END) AS proxy_events,
                   SUM(CASE WHEN source='endpoint' THEN 1 ELSE 0 END) AS endpoint_events,
                   COALESCE(SUM(tokens_in + tokens_out),0) AS tokens,
                   COALESCE(SUM({cost}),0) AS cost,
                   MIN(ts) AS first_seen
              FROM events WHERE {where}
              GROUP BY tool ORDER BY tokens DESC""",
        params,
    ).fetchall()
    trend = conn.execute(
        f"""SELECT day,
                   COUNT(DISTINCT user_ref) AS active_users,
                   COUNT(DISTINCT host_ref) AS active_hosts,
                   COUNT(DISTINCT session_id) AS sessions,
                   COALESCE(SUM(tokens_in + tokens_out),0) AS tokens,
                   COALESCE(SUM({cost}),0) AS cost
              FROM events WHERE {where}
              GROUP BY day ORDER BY day""",
        params,
    ).fetchall()
    return {
        "rangeDays": days,
        "source": source or "all",
        "totals": {
            "activeUsers": _n(totals["active_users"]),
            "activeHosts": _n(totals["active_hosts"]),
            "sessions": _n(totals["sessions"]),
            "events": _n(totals["events"]),
            "tokensInput": _n(totals["tokens_input"]),
            "tokensOutput": _n(totals["tokens_output"]),
            "costUsd": _n(totals["cost"]),
        },
        "tools": [{
            "tool": r["tool"],
            "sanctioned": _is_sanctioned(r["tool"]),
            "users": _n(r["users"]),
            "hosts": _n(r["hosts"]),
            "sessions": _n(r["sessions"]),
            "proxyEvents": _n(r["proxy_events"]),
            "endpointEvents": _n(r["endpoint_events"]),
            "tokens": _n(r["tokens"]),
            "costUsd": _n(r["cost"]),
            "firstSeen": r["first_seen"],
        } for r in tools],
        "trend": [{
            "day": r["day"],
            "activeUsers": _n(r["active_users"]),
            "activeHosts": _n(r["active_hosts"]),
            "sessions": _n(r["sessions"]),
            "tokens": _n(r["tokens"]),
            "costUsd": _n(r["cost"]),
        } for r in trend],
        "sanctionedTools": sorted(SANCTIONED_TOOLS),
    }


def providers(conn: sqlite3.Connection, days: int = 30, source: str | None = None) -> dict:
    where, params = _range(days, source)
    cost = _cost_sql()
    by_provider = conn.execute(
        f"""SELECT COALESCE(provider,'unknown') AS provider,
                   COUNT(*) AS events,
                   COUNT(DISTINCT tool) AS tools,
                   COUNT(DISTINCT session_id) AS sessions,
                   COUNT(DISTINCT host_ref) AS hosts,
                   COUNT(DISTINCT user_ref) AS users,
                   COALESCE(SUM(tokens_in + tokens_out),0) AS tokens,
                   COALESCE(SUM({cost}),0) AS cost,
                   MIN(ts) AS first_seen, MAX(ts) AS last_seen
              FROM events WHERE {where}
              GROUP BY 1 ORDER BY events DESC""",
        params,
    ).fetchall()
    # Per-path split is never source-filtered — the point of the view.
    src_where, src_params = _range(days, None)
    by_source = conn.execute(
        f"""SELECT source,
                   COUNT(*) AS events,
                   COUNT(DISTINCT provider) AS providers,
                   COUNT(DISTINCT session_id) AS sessions,
                   COUNT(DISTINCT host_ref) AS hosts,
                   COALESCE(SUM(tokens_in + tokens_out),0) AS tokens,
                   COALESCE(SUM({cost}),0) AS cost
              FROM events WHERE {src_where}
              GROUP BY source ORDER BY source""",
        src_params,
    ).fetchall()
    trend = conn.execute(
        f"""SELECT day, COALESCE(provider,'unknown') AS provider,
                   COUNT(*) AS events,
                   COALESCE(SUM(tokens_in + tokens_out),0) AS tokens
              FROM events WHERE {where}
              GROUP BY 1,2 ORDER BY 1""",
        params,
    ).fetchall()
    return {
        "rangeDays": days,
        "source": source or "all",
        "providers": [{
            "provider": r["provider"], "events": _n(r["events"]), "tools": _n(r["tools"]),
            "sessions": _n(r["sessions"]), "hosts": _n(r["hosts"]), "users": _n(r["users"]),
            "tokens": _n(r["tokens"]), "costUsd": _n(r["cost"]),
            "firstSeen": r["first_seen"], "lastSeen": r["last_seen"],
        } for r in by_provider],
        "bySource": [{
            "source": r["source"], "events": _n(r["events"]), "providers": _n(r["providers"]),
            "sessions": _n(r["sessions"]), "hosts": _n(r["hosts"]),
            "tokens": _n(r["tokens"]), "costUsd": _n(r["cost"]),
        } for r in by_source],
        "trend": [{"day": r["day"], "provider": r["provider"], "events": _n(r["events"]), "tokens": _n(r["tokens"])} for r in trend],
    }


def teams(conn: sqlite3.Connection, days: int = 30) -> dict:
    # Personal mode has no directory/team enrichment; everything is one user.
    where, params = _range(days, None)
    cost = _cost_sql()
    r = conn.execute(
        f"""SELECT COUNT(DISTINCT user_ref) AS active_users,
                   COUNT(DISTINCT host_ref) AS active_hosts,
                   COUNT(DISTINCT session_id) AS sessions,
                   COALESCE(SUM(tokens_in + tokens_out),0) AS tokens,
                   COALESCE(SUM({cost}),0) AS cost,
                   COUNT(DISTINCT CASE WHEN tool IN {_sanctioned_sql()} THEN tool END) AS sanctioned_tools,
                   COUNT(DISTINCT CASE WHEN tool NOT IN {_sanctioned_sql()} THEN tool END) AS unsanctioned_tools,
                   SUM(CASE WHEN tool NOT IN {_sanctioned_sql()} THEN 1 ELSE 0 END) AS unsanctioned_events
              FROM events WHERE {where}""",
        params,
    ).fetchone()
    teams_rows = []
    if _n(r["active_hosts"]):
        teams_rows.append({
            "team": "you",
            "activeUsers": _n(r["active_users"]),
            "activeHosts": _n(r["active_hosts"]),
            "sessions": _n(r["sessions"]),
            "tokens": _n(r["tokens"]),
            "costUsd": _n(r["cost"]),
            "sanctionedToolCount": _n(r["sanctioned_tools"]),
            "unsanctionedToolCount": _n(r["unsanctioned_tools"]),
            "unsanctionedEvents": _n(r["unsanctioned_events"]),
        })
    return {
        "rangeDays": days,
        "note": "Personal mode: single local user, no team directory.",
        "teams": teams_rows,
    }


def tool_detail(conn: sqlite3.Connection, tool: str, days: int = 30) -> dict:
    cost = _cost_sql()
    cutoff = _cutoff(days)
    s = conn.execute(
        f"""SELECT COUNT(DISTINCT user_ref) AS users,
                   COUNT(DISTINCT host_ref) AS hosts,
                   COUNT(DISTINCT session_id) AS sessions,
                   COUNT(*) AS events,
                   COALESCE(SUM(tokens_in),0) AS tokens_input,
                   COALESCE(SUM(tokens_out),0) AS tokens_output,
                   COALESCE(SUM({cost}),0) AS cost,
                   MIN(ts) AS first_seen, MAX(ts) AS last_seen
              FROM events WHERE tool = ? AND ts_epoch >= ?""",
        [tool, cutoff],
    ).fetchone()
    models = conn.execute(
        f"""SELECT model, COUNT(*) AS events,
                   COALESCE(SUM(tokens_in),0) AS tokens_input,
                   COALESCE(SUM(tokens_out),0) AS tokens_output,
                   COALESCE(SUM({cost}),0) AS cost
              FROM events WHERE tool = ? AND model IS NOT NULL AND ts_epoch >= ?
              GROUP BY model ORDER BY tokens_output DESC""",
        [tool, cutoff],
    ).fetchall()
    trend = conn.execute(
        """SELECT day, COUNT(DISTINCT user_ref) AS active_users,
                  COUNT(DISTINCT session_id) AS sessions,
                  COALESCE(SUM(tokens_in + tokens_out),0) AS tokens
             FROM events WHERE tool = ? AND ts_epoch >= ?
             GROUP BY day ORDER BY day""",
        [tool, cutoff],
    ).fetchall()
    return {
        "tool": tool,
        "sanctioned": _is_sanctioned(tool),
        "rangeDays": days,
        "users": _n(s["users"]), "hosts": _n(s["hosts"]), "sessions": _n(s["sessions"]),
        "events": _n(s["events"]),
        "tokensInput": _n(s["tokens_input"]), "tokensOutput": _n(s["tokens_output"]),
        "costUsd": _n(s["cost"]), "firstSeen": s["first_seen"], "lastSeen": s["last_seen"],
        "models": [{
            "model": m["model"], "events": _n(m["events"]),
            "tokensInput": _n(m["tokens_input"]), "tokensOutput": _n(m["tokens_output"]),
            "costUsd": _n(m["cost"]),
        } for m in models],
        "trend": [{"day": r["day"], "activeUsers": _n(r["active_users"]), "sessions": _n(r["sessions"]), "tokens": _n(r["tokens"])} for r in trend],
    }


def flags(conn: sqlite3.Connection, days: int = 30) -> dict:
    # match_flags is a JSON array per row; expand in Python (small dataset).
    where, params = _range(days, None)
    rows = conn.execute(
        f"SELECT day, tool, user_ref, ts, match_flags FROM events WHERE {where}",
        params,
    ).fetchall()
    by_detector: dict = {}
    trend: dict = {}
    by_tool: dict = {}
    for r in rows:
        try:
            entries = json.loads(r["match_flags"] or "[]")
        except (TypeError, json.JSONDecodeError):
            entries = []
        for f in entries:
            det = f.get("detector") if isinstance(f, dict) else None
            if not det:
                continue
            d = by_detector.setdefault(det, {"hits": 0, "users": set(), "tools": set(), "first": r["ts"], "last": r["ts"]})
            d["hits"] += 1
            if r["user_ref"]:
                d["users"].add(r["user_ref"])
            if r["tool"]:
                d["tools"].add(r["tool"])
            d["first"] = min(d["first"], r["ts"])
            d["last"] = max(d["last"], r["ts"])
            trend[(r["day"], det)] = trend.get((r["day"], det), 0) + 1
            by_tool[(r["tool"], det)] = by_tool.get((r["tool"], det), 0) + 1
    detectors = [{
        "detector": det,
        "category": det.split(":")[0],
        "hits": v["hits"], "users": len(v["users"]), "tools": len(v["tools"]),
        "firstSeen": v["first"], "lastSeen": v["last"],
    } for det, v in sorted(by_detector.items(), key=lambda kv: -kv[1]["hits"])]
    return {
        "rangeDays": days,
        "totalHits": sum(d["hits"] for d in detectors),
        "detectors": detectors,
        "trend": [{"day": k[0], "detector": k[1], "hits": v} for k, v in sorted(trend.items())],
        "byTool": [{"tool": k[0], "detector": k[1], "hits": v} for k, v in sorted(by_tool.items())],
    }


def unapproved(conn: sqlite3.Connection, days: int = 90) -> dict:
    where, params = _range(days, None)
    cost = _cost_sql()
    rows = conn.execute(
        f"""SELECT COALESCE(tool_raw, tool) AS tool,
                   MIN(provider) AS provider,
                   MIN(ts) AS first_seen, MAX(ts) AS last_seen,
                   COUNT(*) AS events,
                   COUNT(DISTINCT user_ref) AS users,
                   COUNT(DISTINCT host_ref) AS hosts,
                   COUNT(DISTINCT session_id) AS sessions,
                   COALESCE(SUM(tokens_in + tokens_out),0) AS tokens,
                   COALESCE(SUM({cost}),0) AS cost
              FROM events
              WHERE {where} AND tool NOT IN {_sanctioned_sql()}
              GROUP BY 1 ORDER BY first_seen DESC""",
        params,
    ).fetchall()
    return {
        "rangeDays": days,
        "note": "Personal mode: your own machine only.",
        "unapproved": [{
            "tool": r["tool"], "provider": r["provider"],
            "firstSeen": r["first_seen"], "lastSeen": r["last_seen"],
            "events": _n(r["events"]), "users": _n(r["users"]), "hosts": _n(r["hosts"]),
            "teams": 1, "sessions": _n(r["sessions"]),
            "tokens": _n(r["tokens"]), "costUsd": _n(r["cost"]),
        } for r in rows],
    }

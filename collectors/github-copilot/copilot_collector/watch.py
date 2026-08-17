"""Scan loop: walk local Copilot surfaces, emit metadata-only events."""

from __future__ import annotations

import time

from . import enroll, extract, events, spool, state


def scan_once(*, dry_run: bool = False) -> int:
    """One pass. Returns the number of events produced this scan."""
    cp = state.load_checkpoint()
    seen = cp.setdefault("sources", {})
    if not isinstance(seen, dict):
        seen = {}
        cp["sources"] = seen
    inv_days = set(cp.get("inventory_days") or [])
    today = events.format_ts(None)[:10]

    emitted: list[dict] = []
    try:
        records = extract.collect_records()
    except Exception:
        records = []

    for rec in records:
        key = rec.source_key
        prev = seen.get(key) if isinstance(seen.get(key), dict) else {}
        if rec.kind == "inventory":
            day_key = f"{today}|{key}"
            if day_key in inv_days:
                continue
        elif (
            prev.get("mtime") == rec.mtime
            and prev.get("size") == rec.size
        ):
            continue
        try:
            new_events = events.events_from_record(rec)
        except Exception:
            continue
        emitted.extend(new_events)
        seen[key] = {"mtime": rec.mtime, "size": rec.size}
        if rec.kind == "inventory":
            inv_days.add(f"{today}|{key}")

    if len(seen) > 8000:
        # drop oldest half by insertion order (Py3.7+ dicts)
        keys = list(seen.keys())
        for k in keys[: len(keys) // 2]:
            seen.pop(k, None)
    if len(inv_days) > 400:
        inv_days = set(sorted(inv_days)[-200:])
    cp["sources"] = seen
    cp["inventory_days"] = sorted(inv_days)

    if dry_run:
        return len(emitted)

    spool.append(emitted)
    state.save_checkpoint(cp)
    if emitted:
        spool.flush()
    return len(emitted)


def watch(interval: float = 60.0) -> None:
    last_hb = 0.0
    while True:
        scan_once()
        last_hb = enroll.maybe_heartbeat(last_hb)
        time.sleep(interval)

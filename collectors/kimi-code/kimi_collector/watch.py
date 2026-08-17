"""Scan loop: walk Kimi Code session wire logs, emit delta events, spool + flush."""

from __future__ import annotations

import time

from . import enroll, mcp_inventory, paths, spool, state, wire


def scan_once(dry_run: bool = False) -> list[dict]:
    """One pass over all discovered wire.jsonl files. Returns events emitted.

    Also takes the MCP server config inventory (AIM-97): one
    ``event_type="inventory"`` event when the configured server set changed.

    With ``dry_run=True`` nothing is persisted: the checkpoint and spool are
    left untouched and no flush is attempted (events are scanned from the
    start of each file so the caller sees everything).
    """
    cp = {} if dry_run else state.load_checkpoint()
    file_states = cp.setdefault("files", {})
    tool_version = paths.tool_version()
    emitted: list[dict] = []
    for sess in paths.sessions():
        for wire_path in paths.wire_files(sess["session_dir"]):
            key = str(wire_path)
            try:
                new_events, new_state = wire.collect_wire(
                    wire_path,
                    {} if dry_run else (file_states.get(key) or {}),
                    sess["session_id"],
                    sess["work_dir"],
                    tool_version,
                )
            except Exception:
                continue  # a malformed wire file must not stall the scan
            file_states[key] = new_state
            emitted.extend(new_events)
    try:
        inv = mcp_inventory.scan(cp, tool_version)
    except Exception:
        inv = None  # an inventory failure must not stall the scan
    if inv is not None:
        emitted.append(inv)
    if dry_run:
        return emitted
    spool.append(emitted)
    state.save_checkpoint(cp)
    if emitted:
        spool.flush()
    return emitted


def watch(interval: float = 60.0) -> None:
    """Daemon: scan forever. Kimi Code has no hook API, so polling the wire
    logs is the collection mechanism (Intune: scheduled task; Linux: cron or
    systemd user timer running scan-once)."""
    last_hb = 0.0  # first iteration heartbeats immediately (liveness on start)
    while True:
        scan_once()
        last_hb = enroll.maybe_heartbeat(last_hb)
        time.sleep(interval)

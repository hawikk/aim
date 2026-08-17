"""Scan loop: walk Kilo Code IDE task dirs + CLI SQLite, emit, spool + flush."""

from __future__ import annotations

import time

from . import cli_sessions, enroll, mcp_inventory, paths, spool, state, tasks


def scan_once() -> int:
    """One pass over IDE task dirs and CLI sessions. Returns events emitted."""
    cp = state.load_checkpoint()
    task_states = cp.setdefault("tasks", {})
    tool_version = paths.extension_version()
    emitted: list[dict] = []
    storages = paths.storage_dirs()
    for storage in storages:
        for task_dir in paths.task_dirs(storage):
            key = f"{storage}::{task_dir.name}"
            try:
                new_events, new_state = tasks.collect_task(
                    task_dir, task_states.get(key) or {}, tool_version
                )
            except Exception:
                continue  # a malformed task dir must not stall the scan
            task_states[key] = new_state
            emitted.extend(new_events)
    # CLI surface (AIM-647): standalone kilo binary sessions in kilo.db
    try:
        emitted.extend(cli_sessions.collect(cp))
    except Exception:
        pass  # CLI path must not stall IDE collection
    # MCP server config inventory (AIM-97): one event, only when the
    # configured (name, scope) set changed. Workspace paths come from the
    # per-task checkpoint fragments (never emitted themselves).
    workspaces = [st["workspace"] for st in task_states.values()
                  if isinstance(st, dict) and isinstance(st.get("workspace"), str)]
    inv_ev = mcp_inventory.scan(cp, storages, workspaces, tool_version)
    if inv_ev:
        emitted.append(inv_ev)
    spool.append(emitted)
    state.save_checkpoint(cp)
    if emitted:
        spool.flush()
    return len(emitted)


def watch(interval: float = 60.0) -> None:
    """Daemon: scan forever. Kilo Code has no hook API, so polling IDE task
    logs + CLI SQLite is the collection mechanism (Intune: scheduled task;
    Linux: cron or systemd user timer running scan-once)."""
    last_hb = 0.0  # first iteration heartbeats immediately (liveness on start)
    while True:
        scan_once()
        last_hb = enroll.maybe_heartbeat(last_hb)
        time.sleep(interval)

"""`aim watch` — the one background loop the auto-start service runs.

Before AIM-139 the watcher was a per-collector foreground daemon
(`python -m aim_collector watch`), so it covered only Claude Code and died
with the terminal. This is the unified loop: one process that, every
`interval` seconds, scans + drains the spool for *every* installed tool and
sends a single fleet heartbeat. The auto-start service (see `aim.service`)
runs exactly `<interpreter> -m aim watch`, so telemetry survives reboots
without a terminal open.

Design notes:

  * One pass = for each installed tool, call its collector's `scan_once()`
    (which appends to and drains that tool's own spool) then an explicit
    `spool.flush()` to sweep anything a hook spooled while no watcher ran
    (e.g. between a reboot and the service starting). Idempotent and cheap
    when there's nothing to send.
  * Heartbeat once per pass via the canonical (Claude Code) enroll module.
    Every tool shares one device identity (`join` bridges it), so one
    heartbeat represents the whole machine — no per-tool duplicate liveness.
  * A failure in any single tool is swallowed and recorded in the summary;
    the loop must never crash, or a reboot-surviving service would silently
    stop collecting — the exact failure mode this issue exists to kill.
  * Honours ingest backpressure (AIM-127): if a flush returns a
    `retry_after`, the next sleep is at least that long.
"""

import sys
import time

from . import _bootstrap, tools

DEFAULT_INTERVAL = 30.0

WATCH_USAGE = """usage: aim watch [--interval SECONDS] [--once]

Run the unified scan + spool-flush + heartbeat loop for every installed AI
tool. This is what the auto-start service runs; you rarely invoke it by hand.

  --interval SECONDS   seconds between passes (default 30)
  --once               run a single pass and exit (used by `aim doctor`)
"""


def _as_count(n):
    """scan_once() returns an int (Claude/Cursor/Kilo) or a list (Kimi)."""
    if isinstance(n, list):
        return len(n)
    if isinstance(n, int):
        return n
    return 0


def watch_once() -> dict:
    """One scan+flush pass across every installed tool, plus one heartbeat.

    Returns ``{tool_key: {"scanned": int|None, "flushed": dict|None,
    "error": str|None}, ..., "_retry_after": float|None}``. Never raises."""
    _bootstrap.ensure_on_path()
    summary = {}
    retry_after = None
    for tool in tools.TOOLS:
        if not tool.installed():
            continue
        rec = {"scanned": None, "flushed": None, "error": None}
        try:
            rec["scanned"] = _as_count(tool.module(tool.scan_mod).scan_once())
        except Exception as e:  # noqa: BLE001 — one tool must not stall the rest
            rec["error"] = f"scan: {e}"
        try:
            res = tool.module("spool").flush()
            rec["flushed"] = res
            ra = res.get("retry_after") if isinstance(res, dict) else None
            if isinstance(ra, (int, float)) and ra > 0:
                retry_after = max(retry_after or 0.0, float(ra))
        except Exception as e:  # noqa: BLE001
            rec["error"] = (f"{rec['error']}; " if rec["error"] else "") + f"flush: {e}"
        summary[tool.key] = rec

    # One heartbeat for the whole machine (shared device identity).
    try:
        from aim_collector import enroll as cc_enroll
        if cc_enroll.device_token():
            cc_enroll.heartbeat()
    except Exception:  # noqa: BLE001
        pass
    summary["_retry_after"] = retry_after
    return summary


def watch_loop(interval: float = DEFAULT_INTERVAL) -> None:
    """Run `watch_once` forever. Runs until the service manager kills it."""
    while True:
        sleep_for = interval
        try:
            res = watch_once()
            ra = res.get("_retry_after")
            if isinstance(ra, (int, float)) and ra > 0:
                sleep_for = max(interval, float(ra))
        except Exception:  # noqa: BLE001 — belt-and-suspenders; stay alive
            pass
        time.sleep(sleep_for)


def cmd_watch(args) -> int:
    interval = DEFAULT_INTERVAL
    once = False
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-h", "--help"):
            sys.stdout.write(WATCH_USAGE)
            return 0
        if a == "--once":
            once = True
            i += 1
        elif a == "--interval":
            if i + 1 >= len(args):
                sys.stderr.write(WATCH_USAGE)
                return 2
            interval = float(args[i + 1])
            i += 2
        elif a.startswith("--interval="):
            interval = float(a.split("=", 1)[1])
            i += 1
        else:
            sys.stderr.write(f"aim watch: unknown option {a!r}\n\n{WATCH_USAGE}")
            return 2

    if once:
        summary = watch_once()
        for key, rec in summary.items():
            if key.startswith("_"):
                continue
            print(f"  {key:<12} scanned={rec['scanned']} error={rec['error']}")
        return 0
    watch_loop(interval)
    return 0

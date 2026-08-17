"""CLI entrypoint: python -m copilot_collector <command>"""

import sys

USAGE = """usage: python -m copilot_collector <command>

commands:
  install     write config, enroll the device, verify connectivity:
              install [--ingest-url URL] [--enroll-token TOKEN]
                      [--token EVENTS_TOKEN] [--ring RING]
  uninstall   remove the local device token (stops heartbeats)
  heartbeat   send one fleet heartbeat (no-op when not enrolled)
  scan-once   one pass over local Copilot surfaces; emit metadata-only events
  watch       daemon: poll every N seconds (default 60), heartbeat when enrolled
  flush       drain local spool to ingestion API
"""


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        sys.stderr.write(USAGE)
        return 2 if not argv else 0

    cmd, args = argv[0], argv[1:]

    if cmd == "install":
        from . import install as inst
        return inst.main(args)
    if cmd == "uninstall":
        from . import install as inst
        inst.uninstall()
        print("device token removed; heartbeats stopped "
              "(server-side revocation remains an admin action)")
        return 0
    if cmd == "heartbeat":
        from . import enroll
        res = enroll.heartbeat()
        if res.get("ok"):
            print("heartbeat ok")
            return 0
        if res.get("error") == "not enrolled":
            print("not enrolled; skipping heartbeat")
            return 0
        print(f"heartbeat failed: {res.get('error')}")
        return 1
    if cmd in ("scan-once", "scan"):
        from . import watch
        dry_run = "--dry-run" in args or "--stdout" in args
        n = watch.scan_once(dry_run=dry_run)
        if dry_run:
            sys.stderr.write(f"emitted {n} usage events (dry-run)\n")
        else:
            print(f"emitted {n} usage events")
        return 0
    if cmd == "watch":
        from . import watch
        interval = 60.0
        for a in args:
            if a not in ("--dry-run", "--stdout"):
                interval = float(a)
                break
        watch.watch(interval)
        return 0
    if cmd == "flush":
        from . import spool
        print(spool.flush())
        return 0

    sys.stderr.write(f"unknown command {cmd!r}\n{USAGE}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

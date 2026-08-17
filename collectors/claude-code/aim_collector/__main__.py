"""CLI entrypoint: python -m aim_collector <command>"""

import sys

USAGE = """usage: python -m aim_collector <command>

commands:
  install     register Claude Code hooks (idempotent); with flags also
              writes config, enrolls the device, and verifies connectivity:
              install [--ingest-url URL] [--enroll-token TOKEN]
                      [--token EVENTS_TOKEN] [--ring RING]
  uninstall   remove our hook registrations and the local device token
  heartbeat   send one fleet heartbeat (no-op when not enrolled)
  hook        invoked by Claude Code; reads event JSON from stdin
  watch       daemon: tail transcripts, emit usage events, flush spool,
              heartbeat when enrolled
  scan-once   one transcript pass (for scheduled-task deployments)
  flush       drain local spool to ingestion API
  personal    monitor YOUR OWN usage: scan into local SQLite + serve the
              dashboard on 127.0.0.1 (zero infra, zero network egress)
              options: [--watch] [--port N] [--scan-only]
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
        from . import enroll, install as inst
        print(f"hooks removed from {inst.uninstall()}")
        enroll.clear_device_token()
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
    if cmd == "hook":
        from . import hook
        return hook.main()
    if cmd == "watch":
        from . import transcript
        interval = float(args[0]) if args else 30.0
        transcript.watch(interval)
        return 0
    if cmd == "scan-once":
        from . import transcript
        n = transcript.scan_once()
        print(f"emitted {n} usage events")
        return 0
    if cmd == "flush":
        from . import spool
        print(spool.flush())
        return 0
    if cmd == "personal":
        from . import personal
        return personal.main(args)

    sys.stderr.write(f"unknown command {cmd!r}\n{USAGE}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

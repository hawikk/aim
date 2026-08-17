"""CLI entrypoint: python -m grok_collector <command>"""

import json
import sys

USAGE = """usage: python -m grok_collector <command>

commands:
  install                 write config, enroll the device, verify connectivity:
                          install [--ingest-url URL] [--enroll-token TOKEN]
                                  [--token EVENTS_TOKEN] [--ring RING]
  uninstall               remove the local device token (stops heartbeats)
  heartbeat               send one fleet heartbeat (no-op when not enrolled)
  emit-run [--dry-run]    emit one metadata-only usage event for the current
                          Paperclip/Grok Build run (PAPERCLIP_RUN_ID / --run-id)
                          options: --run-id ID --model MODEL --workspace PATH
                                   --tokens-in N --tokens-out N --force
  scan-once [--dry-run]   emit Paperclip run presence + tail Grok usage log
                          for per-session token deltas (AIM-470); then flush
  scan                    alias for scan-once
  flush                   drain local spool to ingestion API
"""


def _parse_emit_args(args: list[str]) -> dict:
    out: dict = {
        "dry_run": False,
        "force": False,
        "run_id": None,
        "model": None,
        "workspace_path": None,
        "tokens_in": None,
        "tokens_out": None,
    }
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--dry-run", "--stdout"):
            out["dry_run"] = True
        elif a == "--force":
            out["force"] = True
        elif a == "--run-id" and i + 1 < len(args):
            i += 1
            out["run_id"] = args[i]
        elif a == "--model" and i + 1 < len(args):
            i += 1
            out["model"] = args[i]
        elif a == "--workspace" and i + 1 < len(args):
            i += 1
            out["workspace_path"] = args[i]
        elif a == "--tokens-in" and i + 1 < len(args):
            i += 1
            out["tokens_in"] = int(args[i])
        elif a == "--tokens-out" and i + 1 < len(args):
            i += 1
            out["tokens_out"] = int(args[i])
        else:
            sys.stderr.write(f"unknown emit-run option: {a}\n")
            return None  # type: ignore[return-value]
        i += 1
    return out


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
    if cmd == "emit-run":
        from . import emit as emit_mod
        opts = _parse_emit_args(args)
        if opts is None:
            return 2
        try:
            evs = emit_mod.emit_run(**opts)
        except ValueError as e:
            sys.stderr.write(f"emit-run failed: {e}\n")
            return 1
        if opts["dry_run"]:
            for ev in evs:
                print(json.dumps(ev, separators=(",", ":")))
            sys.stderr.write(f"emitted {len(evs)} usage events (dry-run)\n")
        else:
            print(f"emitted {len(evs)} usage events")
        return 0
    if cmd in ("scan-once", "scan"):
        from . import emit as emit_mod
        dry_run = "--dry-run" in args or "--stdout" in args
        evs = emit_mod.scan_once(dry_run=dry_run)
        if dry_run:
            for ev in evs:
                print(json.dumps(ev, separators=(",", ":")))
            sys.stderr.write(f"emitted {len(evs)} usage events (dry-run)\n")
        else:
            if not dry_run and evs:
                from . import spool
                # scan_once already flushes via emit_run; ensure empty path is quiet
                _ = spool
            print(f"emitted {len(evs)} usage events")
        return 0
    if cmd == "flush":
        from . import spool
        print(spool.flush())
        return 0

    sys.stderr.write(f"unknown command {cmd!r}\n{USAGE}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

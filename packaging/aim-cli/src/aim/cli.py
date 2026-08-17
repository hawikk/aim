"""`aim` command-line entry point.

This is the single, versioned surface for the AI Monitoring collectors. It
dispatches to the vendored per-tool collectors without the user ever needing
to know they exist as separate packages.

Commands:

  personal    monitor YOUR OWN AI usage: scan local tool data into SQLite and
              serve the dashboard on 127.0.0.1 — zero infra, zero network
              egress. (= `python3 -m aim_collector personal`)
  version     report the CLI + bundled collector versions
  join        detect, hook, enroll, and verify every installed AI tool with a
              fleet ingestion endpoint (one line for the whole machine)
  status      read-only per-tool hook / enrollment / heartbeat / spool report
  doctor      verify install health; `--fix` re-adds clobbered hooks, restarts
              the auto-start service, and drains the spool
  watch       unified scan + flush + heartbeat loop for every tool (this is
              what the per-user auto-start service runs)
  uninstall   remove everything `aim` wrote outside the package (state dirs,
              all tool hook registrations, device token, auto-start service)
  policy control-plane policy ops: simulate candidate policy
              against historical findings (Δ blocks/alerts, dry-run)

`join`/`status` land the unified-install behavior; `doctor`/`watch`
and per-user auto-start (systemd/launchd/Scheduled Task) land on top
of the packaged CLI. `policy simulate` is an operator surface that
calls the control-plane API (not local collector state).
"""

import sys

from . import __version__, _bootstrap, ensure_supported_python

USAGE = """usage: aim <command> [options]

commands:
  personal     monitor your own AI usage locally (dashboard on 127.0.0.1,
               SQLite, zero outbound calls)
               options: [--watch] [--port N] [--scan-only]
  version      show CLI and bundled collector versions
  join         hook + enroll + verify every installed AI tool in one line
               usage: aim join <ingest-url> --token <enroll-token> [--ring R]
  status       read-only per-tool hook / enrollment / heartbeat / spool report
  doctor       verify + repair install health  (usage: aim doctor [--fix])
  watch        unified scan/flush/heartbeat loop (run by the auto-start service)
  hook [tool]  service one hook event from stdin (registered in a tool's
               settings file by join/doctor; not typically run by hand)
  uninstall    remove all state aim wrote, unhook every tool, drop the
               auto-start service (idempotent)
  policy       control-plane policy ops (simulate candidate vs last N days)
               usage: aim policy simulate [--days N] [--pack-id ID] [--json]

run `aim <command> --help` where supported for command options.
"""

# All CLI surfaces now ship real behavior; nothing is stubbed. (Kept as an
# empty map so `main` keeps its single dispatch shape if a future surface is
# staged again.)
_COMING_SOON = {}


def _require_vendored() -> None:
    """Fail loudly if the collector tree wasn't vendored into the artifact."""
    if not _bootstrap.vendored():
        sys.stderr.write(
            "aim: bundled collectors are missing from this install.\n"
            "This usually means the package was imported from source without "
            "being built.\nBuild the artifact with "
            "`python3 scripts/build_aim_cli.py` and install the wheel.\n")
        raise SystemExit(3)


def _cmd_personal(args) -> int:
    _require_vendored()
    _bootstrap.ensure_on_path()
    from aim_collector import personal
    return personal.main(args)


def _cmd_version(args) -> int:
    """Report the CLI version plus each bundled collector's version."""
    lines = [f"aim {__version__}"]
    if _bootstrap.vendored():
        _bootstrap.ensure_on_path()
        for label, spec in (
            ("claude-code", ("aim_collector", "aim_collector")),
            ("cursor", ("cursor", "cursor_collector")),
            ("kilo-code", ("kilo-code", "kilo_collector")),
            ("kimi-code", ("kimi-code", "kimi_collector")),
            ("github-copilot", ("github-copilot", "copilot_collector")),
        ):
            lines.append(f"  {label:<12} {_collector_version(*spec)}")
    else:
        lines.append("  (bundled collectors not present in this install)")
    print("\n".join(lines))
    return 0


def _collector_version(pkg_dir: str, module: str) -> str:
    """Best-effort __version__ for a vendored collector module."""
    import importlib
    if pkg_dir != "aim_collector":
        d = str(_bootstrap.VENDOR / "collectors" / pkg_dir)
        if d not in sys.path:
            sys.path.insert(0, d)
    try:
        mod = importlib.import_module(module)
        return getattr(mod, "__version__", "unknown")
    except Exception:
        return "unavailable"


def _cmd_join(args) -> int:
    _require_vendored()
    from . import join
    return join.cmd_join(args)


def _cmd_status(args) -> int:
    _require_vendored()
    from . import join
    return join.cmd_status(args)


def _cmd_doctor(args) -> int:
    _require_vendored()
    from . import doctor
    return doctor.cmd_doctor(args)


def _cmd_watch(args) -> int:
    _require_vendored()
    from . import watch
    return watch.cmd_watch(args)


def _cmd_hook(args) -> int:
    """Service one hook event from stdin. Machine-invoked, not typed by hand:
    this is the command `aim join` / `aim doctor` register in a tool's settings
    file (see aim.tools.hook_command). It reads the tool's hook payload on
    stdin, hands it to the selected collector's hook handler, and passes that
    handler's exit code + stdout straight through (so enforcement decisions
    still reach the tool). The tool key selects the collector; it defaults to
    claude-code so a bare `aim hook` stays useful."""
    _require_vendored()
    from . import tools
    has_key = bool(args) and not args[0].startswith("-")
    key = args[0] if has_key else "claude-code"
    tool = tools.by_key(key)
    if tool is None:
        sys.stderr.write(f"aim hook: unknown tool {key!r}\n")
        return 2
    # Trailing args after the tool key are the collector's own hook args (e.g.
    # Cursor passes the event name); Claude's hook takes none and reads stdin.
    extra = list(args[1:]) if has_key else list(args)
    hook = tool.module("hook")
    return hook.main(extra) if extra else hook.main()


def _cmd_uninstall(args) -> int:
    """Remove everything aim wrote outside the package itself. Idempotent.

    Three kinds of thing aim can leave on a machine:
      1. per-user state dirs (~/.aim-collector, ~/.aim-collector-cursor):
         personal SQLite DB, checkpoints, host id, salt, spool, dev config
      2. hook registrations across every hook-capable tool (Claude Code,
         Cursor) in each tool's own settings file
      3. the enrolled device token / id / heartbeat marker
      4. the per-user auto-start service (systemd user unit / launchd agent /
         Scheduled Task) that runs the background watcher
    Each removal is a no-op when its target is already absent, so running
    uninstall twice — or on a machine that only ever ran `aim personal` — is
    safe and reports plainly what (if anything) it cleaned. The per-tool
    sweep lives in `aim.join.uninstall_all`.
    """
    _require_vendored()
    from . import join
    removed = join.uninstall_all()
    if removed:
        for r in removed:
            print(f"removed: {r}")
    else:
        print("nothing to remove — aim left no state on this machine")
    print("uninstall complete (idempotent; safe to re-run)")
    return 0


def _cmd_coming_soon(cmd: str, args) -> int:
    print(f"aim {cmd}: coming soon — {_COMING_SOON[cmd]}.")
    print("This subcommand's surface ships now; its behavior lands in a "
          "follow-on of the magic-install epic.")
    return 0


def main(argv=None) -> int:
    # Defense in depth: import-time check in ``aim/__init__.py`` already runs
    # first; re-check at the CLI surface so a force-installed old wheel still
    # fails with a human message instead of a mid-join TypeError.
    ensure_supported_python()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(USAGE)
        return 0 if argv else 2

    cmd, args = argv[0], argv[1:]

    if cmd == "personal":
        return _cmd_personal(args)
    if cmd in ("version", "--version", "-V"):
        return _cmd_version(args)
    if cmd == "join":
        return _cmd_join(args)
    if cmd == "status":
        return _cmd_status(args)
    if cmd == "doctor":
        return _cmd_doctor(args)
    if cmd == "watch":
        return _cmd_watch(args)
    if cmd == "hook":
        return _cmd_hook(args)
    if cmd == "uninstall":
        return _cmd_uninstall(args)
    if cmd == "policy":
        from . import policy as policy_cmd
        return policy_cmd.cmd_policy(args)
    if cmd in _COMING_SOON:
        return _cmd_coming_soon(cmd, args)

    sys.stderr.write(f"aim: unknown command {cmd!r}\n\n{USAGE}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

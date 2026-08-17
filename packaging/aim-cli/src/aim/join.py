"""`aim join` / `aim status` / shared `uninstall` — the unified fleet install.

`aim join <ingest-url> --token <enroll-token>` is the enterprise-engineer
magic moment: one line detects every supported AI tool on the machine, hooks
the hook-capable ones, enrolls the device ONCE, verifies connectivity, and
prints a per-tool summary. It replaces four separate per-collector installs.

Ordering is a security property, not a convenience: enrollment (which
validates the token against the ingest endpoint) happens BEFORE any hook is
written. A wrong or revoked token fails fast and leaves nothing behind — no
partial hooks to clean up. Only once the token + endpoint are proven do we
touch each tool's settings file.

Everything is user-scoped: hooks live in the tool's own per-user settings
file, config + device identity in `~/.aim-collector*`. Nothing here writes a
system/root path (`/etc/...`, `%ProgramData%`); those are the managed-fleet
deployment surface, out of scope for a single engineer's `join`.
"""

import json
import os
import sys
import time

from . import _bootstrap, service, tools

JOIN_USAGE = """usage: aim join <ingest-url> --token <enroll-token> [options]

Detect, hook, enroll, and verify every AI tool installed on this machine.

  <ingest-url>          fleet ingestion endpoint (or --ingest-url URL)
  --token TOKEN         scoped enroll token (alias: --enroll-token)
  --ring RING           optional rollout ring label
  --ca-bundle PATH      PEM trust bundle for a private ingest CA
                        (alias: --ca-cert). Also honours SSL_CERT_FILE /
                        AIM_CA_BUNDLE. Persisted into config.json so the
                        watch daemon reuses it without ambient env.
  --resolve HOST:PORT:IP
                        dial IP for HOST:PORT while keeping SNI/Host as
                        HOST (curl-compatible; repeatable). Use when the
                        ingest name does not resolve on this host
                        (e.g. ingest.localhost on a stock resolver).
                        Also honours AIM_RESOLVE=host:port:ip[,...].

Idempotent: re-running repairs/refreshes rather than duplicating hooks.
"""

STATUS_USAGE = ("usage: aim status\n\nRead-only per-tool hook / enrollment / heartbeat / "
                "spool / rejected-event report.\n")


# --- argument parsing -------------------------------------------------------

def _set_join_flag(opts, key, val) -> bool:
    if key == "--ingest-url":
        opts["ingest_url"] = val
    elif key in ("--token", "--enroll-token"):
        opts["enroll_token"] = val
    elif key == "--ring":
        opts["ring"] = val
    elif key in ("--ca-bundle", "--ca-cert"):
        opts["ca_bundle"] = val
    elif key == "--resolve":
        opts.setdefault("resolve", []).append(val)
    else:
        return False
    return True


def _parse_join_args(args):
    """Returns opts dict, or 'help', or None on malformed input."""
    opts = {
        "ingest_url": None,
        "enroll_token": None,
        "ring": None,
        "ca_bundle": None,
        "resolve": [],
    }
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-h", "--help"):
            return "help"
        if a.startswith("--") and "=" in a:
            key, _, val = a.partition("=")
            if not _set_join_flag(opts, key, val):
                return None
            i += 1
        elif a.startswith("--"):
            if i + 1 >= len(args) or not _set_join_flag(opts, a, args[i + 1]):
                return None
            i += 2
        elif opts["ingest_url"] is None:
            opts["ingest_url"] = a
            i += 1
        else:
            return None  # a second positional is a mistake
    return opts


# --- user-scoped config + device-identity bridging --------------------------

def _write_user_config(state_dir, url, *, ca_bundle=None, resolve=None):
    """Merge connection settings into ``<state_dir>/config.json`` (user-scoped).

    We write the per-user config explicitly rather than via the collector's
    managed-path search order so `join` can never target a root path.

    ``ca_bundle`` / ``resolve`` are persisted so post-join
    heartbeats and spool flushes keep working without ambient env vars.
    """
    path = state_dir / "config.json"
    cfg = {}
    if path.exists():
        try:
            parsed = json.loads(path.read_text())
            if isinstance(parsed, dict):
                cfg = parsed
        except (OSError, json.JSONDecodeError):
            cfg = {}
    cfg["ingest_url"] = url
    # Point the spool client at the per-device bearer that enrollment writes
    # to ``<state_dir>/device_token``. The vendored collector resolves its
    # token as ``AIM_COLLECTOR_TOKEN`` env > ``token_file`` contents > ``token``
    # field. ``join`` writes the bearer to ``device_token`` but never named it
    # here, so ``token()`` returned None, ``flush()`` no-opped with "ingest not
    # configured", and the spool grew unbounded while heartbeats still
    # succeeded — a collector that looked healthy but shipped zero events. The
    # path is written declaratively: the token file is created by the enroll
    # step just after this first call, and the spool client reads it lazily.
    cfg["token_file"] = str((state_dir / "device_token").expanduser())
    if ca_bundle:
        from pathlib import Path
        cfg["ca_bundle"] = str(Path(ca_bundle).expanduser().resolve())
    if resolve:
        cleaned = [str(e).strip() for e in resolve if str(e).strip()]
        if cleaned:
            cfg["resolve"] = cleaned
    state_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cfg, indent=2) + "\n")
    return path


def _bridge_identity(tool, canonical_dir) -> bool:
    """Give a tool whose state dir differs from canonical the SAME device
    identity, so one physical machine stays one device record. No-op (returns
    False) for tools that already share the canonical dir (Claude/Kilo/Kimi)."""
    dst_dir = tool.state_dir()
    if dst_dir == canonical_dir:
        return False
    dst_dir.mkdir(parents=True, exist_ok=True)
    for name in ("host_id", "device_token", "device_id", "last_heartbeat"):
        src = canonical_dir / name
        if src.exists():
            dst = dst_dir / name
            dst.write_bytes(src.read_bytes())
            if name == "device_token":
                os.chmod(dst, 0o600)  # keep the 0600 the token file requires
    return True


# --- aim join ---------------------------------------------------------------

def cmd_join(args) -> int:
    _bootstrap.ensure_on_path()
    opts = _parse_join_args(args)
    if opts == "help":
        sys.stdout.write(JOIN_USAGE)
        return 0
    if opts is None or not opts["ingest_url"]:
        sys.stderr.write(JOIN_USAGE)
        return 2
    if not opts["enroll_token"]:
        sys.stderr.write("aim join: --token <enroll-token> is required\n\n" + JOIN_USAGE)
        return 2

    url = opts["ingest_url"]
    ca_bundle = opts.get("ca_bundle")
    resolve = opts.get("resolve") or []
    if ca_bundle:
        from pathlib import Path
        ca_path = Path(ca_bundle).expanduser()
        if not ca_path.is_file():
            sys.stderr.write(
                f"aim join: --ca-bundle path does not exist: {ca_bundle}\n")
            return 2
    for entry in resolve:
        # Cheap shape check — host:port:ip has at least two colons.
        if entry.count(":") < 2:
            sys.stderr.write(
                f"aim join: --resolve expects host:port:ip, got {entry!r}\n")
            return 2

    detected = [(t, t.installed()) for t in tools.TOOLS]
    installed = [t for t, ok in detected if ok]

    print(f"aim join → {url}")
    print("detected AI tools: " + (", ".join(t.label for t in installed) or "none"))
    print()

    from aim_collector import enroll as cc_enroll
    canonical = tools.canonical_state_dir()

    # Enroll BEFORE any hook is written. Write the canonical config first so
    # the verification heartbeat can resolve the ingest URL (and so
    # ca_bundle/resolve are already in place for the enroll + heartbeat POSTs).
    # A bad/revoked token or unreachable endpoint aborts here with nothing hooked.
    _write_user_config(canonical, url, ca_bundle=ca_bundle, resolve=resolve)

    # seed the endpoint enforcement bundle so policy mode:enforce is
    # real on this host. Without a delivered bundle the collector fail-opens
    # to observe and every finding stays decision=observe forever.
    try:
        from aim_collector import enforce as cc_enforce
        seed = cc_enforce.seed_default_policy(dest=canonical / "enforcement.json")
        if seed.get("ok"):
            print(
                f"enforcement: {seed.get('action')} "
                f"mode={seed.get('mode')} hash={seed.get('policy_hash')} "
                f"→ {seed.get('path')}"
            )
        else:
            print(f"enforcement: seed skipped — {seed.get('error', 'unknown')}")
    except Exception as e:  # noqa: BLE001 — never block enroll on policy seed
        print(f"enforcement: seed skipped — {e}")

    res = cc_enroll.enroll(url, opts["enroll_token"], ring=opts.get("ring"))
    if not res.get("ok"):
        sys.stdout.flush()
        sys.stderr.write(f"aim join: enrollment failed — {res.get('error')}\n")
        sys.stderr.write("no tools were hooked and no device was enrolled; "
                         "nothing to clean up.\n")
        return 1
    verb = "already enrolled" if res.get("already_enrolled") else "enrolled"
    dev = res.get("device_id") or cc_enroll.device_id() or "id unknown"
    print(f"device {verb}: {dev}")

    hb = cc_enroll.heartbeat()
    if not hb.get("ok"):
        sys.stdout.flush()
        sys.stderr.write("aim join: enrolled but connectivity check failed — "
                         f"{hb.get('error')}\n")
        sys.stderr.write("no tools were hooked. Re-run `aim join` once the "
                         "ingest endpoint is reachable.\n")
        return 1
    print("connectivity verified: heartbeat accepted\n")

    # Token + endpoint proven. Now hook/configure each installed tool. A
    # per-tool failure here is local (permissions, malformed settings file)
    # and is reported without aborting the others.
    rows, failures, changed = [], 0, not res.get("already_enrolled")
    for tool, ok in detected:
        if not ok:
            rows.append((tool.label, "skipped", "not installed"))
            continue
        try:
            if tool.hooks:
                pre = tool.hooks_registered()
                with tools.hook_command_env(tool):
                    path = tool.module("install").install()
                status = "already-hooked" if pre else "hooked"
                note = str(path)
                changed = changed or not pre
                # Breadcrumb so `aim doctor` can later tell a tool-update
                # clobber ('hooked here once, now gone') apart from a box we
                # never joined. See aim.doctor.record_hooked.
                from . import doctor
                doctor.record_hooked(tool)
            else:
                status = "configured"
                note = "scan-based (no hook API)"
            _write_user_config(
                tool.state_dir(), url, ca_bundle=ca_bundle, resolve=resolve)
            _bridge_identity(tool, canonical)
            rows.append((tool.label, status, note))
        except Exception as e:  # noqa: BLE001 — surface, never crash the join
            failures += 1
            rows.append((tool.label, "FAILED", str(e)))

    _register_autostart()
    _print_summary(rows)
    if failures:
        print(f"\n{failures} tool(s) failed — see FAILED rows above.")
        return 1
    if not changed:
        print("\nalready configured — no changes. `aim status` shows live state.")
    else:
        print("\naim join complete. `aim status` shows live state.")
    return 0


def _register_autostart():
    """Register the per-user auto-start service so the watcher survives a
    reboot. Best-effort and non-fatal: a machine without a usable
    per-user service manager still has working hooks + spool, so a failure
    here degrades to 'collection works while logged in' rather than aborting
    the join. Prints a one-line result."""
    try:
        res = service.install()
    except Exception as e:  # noqa: BLE001
        print(f"auto-start: could not register ({e}); collection still works "
              "while `aim watch` runs. Re-run `aim doctor --fix` to retry.")
        return
    if res.get("ok"):
        print(f"auto-start: {res.get('mechanism')} — {res.get('detail')}")
    else:
        print(f"auto-start: not registered — {res.get('detail')}. "
              "Hooks + spool still work; `aim doctor --fix` can retry.")


def _print_summary(rows):
    print("summary:")
    w = max((len(r[0]) for r in rows), default=0)
    for label, status, note in rows:
        print(f"  {label:<{w}}  {status:<14} {note}")


# --- aim status -------------------------------------------------------------

def cmd_status(args) -> int:
    if args and args[0] in ("-h", "--help"):
        sys.stdout.write(STATUS_USAGE)
        return 0
    _bootstrap.ensure_on_path()
    from aim_collector import enroll as cc_enroll

    print("aim status\n")
    enrolled_device = bool(cc_enroll.device_token())
    if enrolled_device:
        dev = cc_enroll.device_id() or "id unknown"
        print(f"device: enrolled ({dev})")
        print(f"last heartbeat: {_ago(cc_enroll.last_heartbeat_at())}")
    else:
        print("device: NOT enrolled  (run `aim join <url> --token …`)")
    print()

    rows, broken = [], False
    any_installed = False
    ledgers, unreadable = {}, []
    for tool in tools.TOOLS:
        if not tool.installed():
            rows.append((tool.label, "not installed", "-", "-", "-"))
            continue
        any_installed = True
        if tool.hooks:
            if tool.hooks_registered():
                hook = "hooked"
            else:
                hook = "NOT hooked (broken)"
                broken = True
        else:
            hook = "scan-based"
        st_enrolled = (tool.state_dir() / "device_token").exists()
        led = _rejections(tool)
        n_rejected = int(led.get("events") or 0)
        if led.get("_error"):
            rejected_cell = "unknown"
            unreadable.append((tool.label, led["_error"]))
        elif n_rejected:
            rejected_cell = f"{n_rejected} REJECTED"
            # Tools can share a state dir (Kilo/Kimi use the Claude Code
            # collector's), so key by ledger path to report each one once.
            ledgers[led["_path"]] = led
        else:
            rejected_cell = "0 rejected"
        rows.append((tool.label, hook,
                     "enrolled" if st_enrolled else "no token",
                     f"{_spool_depth(tool)} spooled",
                     rejected_cell))
    _print_status_table(rows)

    for label, err in unreadable:
        print(f"\nwarning: cannot read {label}'s rejected-event ledger ({err}) — "
              "event loss would be invisible for this tool. Re-run `aim join` to "
              "refresh the collector.")

    # A rejection is telemetry that left the spool and was never stored — the
    # endpoint is the only place that knows. Never print it as a
    # clean send.
    lost = _print_rejections(ledgers)

    if broken:
        print("\nwarning: a hook is missing where the tool is installed — "
              "re-run `aim join` to repair.")
        return 1
    if any_installed and not enrolled_device:
        print("\nwarning: tools are installed but this device is not enrolled — "
              "run `aim join`.")
        return 1
    return 1 if lost else 0


def _rejections(tool) -> dict:
    """The tool's local rejection ledger, tagged with its path for dedupe.

    A ledger we cannot read is reported as unknown, never as zero. A collector
    predating has no `rejections()` at all, and answering "0 rejected"
    for it would recreate the very bug this ledger exists to expose.
    """
    try:
        spool = tool.module("spool")
        led = dict(spool.rejections())
        led["_path"] = str(spool.rejections_path())
        return led
    except Exception as e:  # noqa: BLE001
        return {"_path": None, "_error": str(e) or e.__class__.__name__}


def _print_rejections(ledgers) -> bool:
    """Print the rejection ledgers. Returns True if any events were lost."""
    if not ledgers:
        return False
    for led in ledgers.values():
        full = int(led.get("batches_fully_rejected") or 0)
        print(f"\nEVENTS LOST: ingest rejected {led['events']} event(s) as invalid "
              f"(last {_ago(led.get('last_at'))}).")
        if full:
            print(f"  {full} batch(es) rejected in FULL — this is a schema contract "
                  "mismatch (a producer newer than its ingest), not bad data.")
        for reason in (led.get("reasons") or [])[:3]:
            print(f"  reason: {reason}")
        print("  These events left the spool and were never stored. "
              "Run `aim doctor` for the remedy.")
    return True


def _print_status_table(rows):
    headers = ("tool", "hook", "enrollment", "spool", "rejected")
    cols = list(zip(headers, *rows)) if rows else [(h,) for h in headers]
    widths = [max(len(str(c)) for c in col) for col in cols]
    def line(vals):
        return "  ".join(f"{str(v):<{w}}" for v, w in zip(vals, widths))
    print(line(headers))
    print(line(["-" * w for w in widths]))
    for r in rows:
        print(line(r))


def _spool_depth(tool) -> int:
    try:
        p = tool.module("state").spool_path()
        if p.exists():
            return sum(1 for ln in p.read_text().splitlines() if ln.strip())
    except Exception:
        pass
    return 0


def _ago(epoch):
    if not epoch:
        return "never"
    d = max(0, int(time.time() - epoch))
    if d < 60:
        return f"{d}s ago"
    if d < 3600:
        return f"{d // 60}m ago"
    if d < 86400:
        return f"{d // 3600}h ago"
    return f"{d // 86400}d ago"


# --- shared uninstall (called by aim.cli) -----------------------------------

def uninstall_all():
    """Unhook every tool, clear the device identity, remove aim state dirs.

    Idempotent: each step is a no-op when its target is already absent, so a
    second run — or a run on a machine that only ever did `aim personal` —
    cleans nothing and reports so. Returns a list of human-readable removals."""
    _bootstrap.ensure_on_path()
    import shutil

    removed, state_dirs = [], set()

    # 0. per-user auto-start service (systemd/launchd/Scheduled Task). Removed
    #    first so the watcher stops before we clear the state it reads.
    for r in service.uninstall():
        removed.append(r)

    for tool in tools.TOOLS:
        # 1. hook registrations — only rewrite a settings file that carries our
        #    marker; never normalize a file we didn't contribute to.
        if tool.hooks and tool.hooks_registered():
            path = tool.module("install").uninstall()
            removed.append(f"{tool.label} hook registrations in {path}")
        # 2. device token / id / last-heartbeat for this tool's state dir.
        try:
            tool.module("enroll").clear_device_token()
        except Exception:
            pass
        try:
            state_dirs.add(tool.state_dir())
        except Exception:
            pass

    # 3. state dirs are entirely aim-owned; removed LAST because the calls
    #    above may recreate them. Nothing recreates them after this point.
    for sdir in state_dirs:
        try:
            had = any(sdir.iterdir())
        except OSError:
            had = False
        shutil.rmtree(sdir, ignore_errors=True)
        if had:
            removed.append(f"state dir {sdir}")
    return removed

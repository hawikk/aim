"""`aim doctor` — verify install health, and (`--fix`) repair what it can.

`aim status` is the read-only glance; `doctor` is the diagnosis + treatment.
It answers five questions and, with `--fix`, acts on the ones it can:

  1. Enrollment + reachability — is a device token present and does the ingest
     endpoint answer a heartbeat?
  2. Hooks — for each hook-capable tool that's installed, is our hook still in
     the settings file? This is where the headline failure mode lives: a tool
     update rewrites its own settings.json and silently drops our hook.
     `doctor` names that case specifically (we left a breadcrumb at hook time,
     so a missing hook + surviving settings file = a clobber, not a fresh box)
     and `--fix` re-installs the hook **without touching the spool**, so no
     events queued before the clobber are lost.
  3. Spool — is anything queued locally, and can it drain? `--fix` flushes.
  4. Rejections — did ingest refuse events inside an HTTP 200 (AIM-200)? Those
     already left the spool, so there is nothing to repair; the check exists so
     the loss is *stated* at the endpoint instead of reading as a clean send.
     `--ack-rejections` (never `--fix`) clears the ledger.
  5. Auto-start service — is the per-user watcher registered and running, so
     collection survives a reboot? `--fix` (re-)registers and starts it.
  6. Enforcement bundle (AIM-440) — is the declared secret-pattern enforce
     policy actually loaded on this endpoint? A missing or stale shadow bake
     is the compliance gap where policy claims ``mode: enforce`` but every
     finding stays ``decision: observe``. `--fix` seeds/upgrades the
     packaged enforce bundle into the user state dir.

`doctor` never enrolls (that needs a scoped token via `aim join`) and never
touches a root scope. It exits 0 when everything it checked is healthy, 1 when
an unhealthy item remains (after repair, if `--fix` was given)."""

import json
import sys
import time

from . import _bootstrap, service, tools, watch

HOOKED_BREADCRUMB = "hooked_tools.json"

# finding levels, worst first for exit-code + display purposes
_OK, _INFO, _WARN, _FAIL = "ok", "info", "warn", "fail"
_GLYPH = {_OK: "ok  ", _INFO: "--  ", _WARN: "WARN", _FAIL: "FAIL"}


# --- hook breadcrumb: 'we installed a hook here once' -----------------------

def _breadcrumb_path():
    return tools.canonical_state_dir() / HOOKED_BREADCRUMB


def _read_breadcrumb() -> dict:
    try:
        data = json.loads(_breadcrumb_path().read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def record_hooked(tool) -> None:
    """Remember we installed a hook for `tool`. Lets doctor later distinguish
    'a tool update clobbered our hook' from 'this tool was never joined'.
    Called by `aim join` after a successful hook and by `doctor --fix`."""
    try:
        data = _read_breadcrumb()
        try:
            settings = str(tool.module("install").settings_path())
        except Exception:  # noqa: BLE001
            settings = None
        data[tool.key] = {"settings": settings, "at": int(time.time())}
        p = _breadcrumb_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2) + "\n")
    except Exception:  # noqa: BLE001 — a breadcrumb failure must not fail join
        pass


def forget_hooked(tool_key: str) -> None:
    data = _read_breadcrumb()
    if tool_key in data:
        del data[tool_key]
        try:
            _breadcrumb_path().write_text(json.dumps(data, indent=2) + "\n")
        except OSError:
            pass


# --- findings ---------------------------------------------------------------

class Finding:
    __slots__ = ("scope", "level", "message", "remedy", "tool", "fixed", "fix_note")

    def __init__(self, scope, level, message, remedy=None, tool=None):
        self.scope = scope          # short label, e.g. "device" or a tool label
        self.level = level          # _OK / _INFO / _WARN / _FAIL
        self.message = message
        self.remedy = remedy        # None | "hook" | "service" | "flush"
        self.tool = tool            # Tool object for hook/flush remedies
        self.fixed = False
        self.fix_note = None


def _spool_depth(tool) -> int:
    try:
        p = tool.module("state").spool_path()
        if p.exists():
            return sum(1 for ln in p.read_text().splitlines() if ln.strip())
    except Exception:  # noqa: BLE001
        return 0
    return 0


def _check_enrollment():
    """Returns (findings, reachable: bool)."""
    from aim_collector import enroll as cc_enroll
    if not cc_enroll.device_token():
        return ([Finding("device", _WARN,
                         "not enrolled — run `aim join <url> --token …` "
                         "(doctor can't enroll; that needs a scoped token)")],
                False)
    dev = cc_enroll.device_id() or "id unknown"
    hb = cc_enroll.heartbeat()
    if hb.get("ok"):
        return ([Finding("device", _OK, f"enrolled ({dev}); ingest reachable")], True)
    return ([Finding("device", _WARN,
                     f"enrolled ({dev}) but ingest unreachable — {hb.get('error')} "
                     "(events stay spooled locally until it recovers)")], False)


def _check_tools(breadcrumb, reachable):
    findings = []
    for tool in tools.TOOLS:
        installed = tool.installed()
        joined = tool.key in breadcrumb
        if not installed:
            if joined:
                findings.append(Finding(
                    tool.label, _INFO,
                    "no longer installed — hook breadcrumb is stale "
                    "(harmless; `aim uninstall` clears it)"))
            continue

        if tool.hooks:
            if tool.hooks_registered():
                findings.append(Finding(tool.label, _OK, "hooked"))
            else:
                settings_exists = _settings_exists(tool)
                if joined and settings_exists:
                    findings.append(Finding(
                        tool.label, _FAIL,
                        "hook MISSING but settings file is present — a tool "
                        "update rewrote settings and clobbered our hook; "
                        "spooled events are intact and re-hooking is loss-free",
                        remedy="hook", tool=tool))
                elif joined:
                    findings.append(Finding(
                        tool.label, _FAIL,
                        "hook missing and settings file is gone — re-hooking "
                        "restores collection",
                        remedy="hook", tool=tool))
                else:
                    findings.append(Finding(
                        tool.label, _WARN,
                        "installed but never hooked — run `aim join` to hook it",
                        remedy="hook", tool=tool))
        else:
            findings.append(Finding(tool.label, _OK, "scan-based (no hook API)"))

        depth = _spool_depth(tool)
        if depth > 0:
            if reachable:
                findings.append(Finding(
                    tool.label, _WARN, f"{depth} event(s) spooled — will drain",
                    remedy="flush", tool=tool))
            else:
                findings.append(Finding(
                    tool.label, _WARN,
                    f"{depth} event(s) spooled; waiting for ingest to recover"))
    return findings


def _settings_exists(tool) -> bool:
    try:
        return tool.module("install").settings_path().exists()
    except Exception:  # noqa: BLE001
        return False


def _check_service(enrolled):
    st = service.status()
    if not st.get("supported"):
        return [Finding("auto-start", _INFO, st.get("detail", "unsupported platform"))]
    mech = st.get("mechanism")
    if not st.get("installed"):
        if enrolled:
            return [Finding("auto-start", _FAIL,
                            f"no {mech} registered — telemetry will NOT survive a "
                            "reboot", remedy="service")]
        return [Finding("auto-start", _INFO,
                        f"not registered (no {mech}); registered by `aim join`")]
    if not st.get("running"):
        return [Finding("auto-start", _WARN,
                        f"{mech} registered but not running", remedy="service")]
    return [Finding("auto-start", _OK, f"{mech} registered and running")]


def _check_enforcement():
    """AIM-440: declared enforce posture must match the loaded endpoint bundle.

    Platform findings always carry ``decision: observe`` (engine is detect-and-
    alert only). Real blocks live on usage events as ``enforcement.action``.
    If no bundle is loaded, the endpoint cannot block and auditors will see
    100% observe findings even when ``core.yaml`` claims ``mode: enforce``.
    """
    try:
        from aim_collector import enforce as cc_enforce
    except Exception as e:  # noqa: BLE001
        return [Finding("enforcement", _WARN,
                        f"collector enforce module unavailable — {e}")]

    desired_path = cc_enforce.default_bundle_path()
    desired_hash = None
    desired_mode = None
    try:
        if desired_path.is_file():
            desired = json.loads(desired_path.read_text())
            if isinstance(desired, dict):
                desired_hash = desired.get("policy_hash")
                desired_mode = desired.get("mode")
    except (OSError, json.JSONDecodeError):
        pass

    path = cc_enforce.policy_path()
    if path is None:
        return [Finding(
            "enforcement", _FAIL,
            "no enforcement.json loaded — endpoint fail-opens to observe "
            f"(declared mode={desired_mode or 'enforce'}); "
            "policy and reality disagree",
            remedy="enforcement")]

    pol = cc_enforce.load_policy()
    mode = pol.get("mode") if isinstance(pol, dict) else None
    phash = pol.get("policy_hash") if isinstance(pol, dict) else None
    secret = (
        isinstance(pol, dict)
        and isinstance(pol.get("rules"), dict)
        and isinstance(pol["rules"].get("secret-pattern-in-prompt"), dict)
        and pol["rules"]["secret-pattern-in-prompt"].get("enforce") is True
    )

    if mode == "enforce" and secret:
        if desired_hash and phash and phash != desired_hash:
            return [Finding(
                "enforcement", _WARN,
                f"loaded enforce bundle at {path} (hash={phash}) differs from "
                f"packaged default (hash={desired_hash}) — review before "
                "fleet-wide push",
                remedy="enforcement")]
        return [Finding(
            "enforcement", _OK,
            f"loaded mode=enforce secret-pattern=on hash={phash} path={path}")]

    return [Finding(
        "enforcement", _FAIL,
        f"loaded mode={mode} secret-pattern.enforce={secret} hash={phash} "
        f"at {path}; declared posture is mode=enforce + "
        "secret-pattern-in-prompt (AIM-296). Findings will stay "
        "decision=observe until the enforce bundle is delivered.",
        remedy="enforcement")]


def _check_rejections():
    """Events ingest refused inside a 2xx (AIM-200).

    These already left the spool — nothing local can replay them, so there is
    no remedy flag. The value of the check is that the loss is *stated*: a
    fully-rejected batch means this collector is newer than the ingest it
    talks to, which is an operator action (roll ingest forward), and it would
    otherwise look like a clean send at the endpoint.
    """
    findings, seen = [], set()
    for tool in tools.TOOLS:
        if not tool.installed():
            continue
        try:
            spool = tool.module("spool")
            led = spool.rejections()
            path = str(spool.rejections_path())
        except Exception as e:  # noqa: BLE001
            # An unreadable ledger is not "no rejections". A collector older
            # than AIM-200 has no rejections() at all, and staying silent here
            # would rebuild the silent drop one layer up.
            findings.append(Finding(
                tool.label, _WARN,
                "cannot read the rejected-event ledger "
                f"({e or e.__class__.__name__}) — event loss would be invisible "
                "for this tool; re-run `aim join` to refresh the collector",
                remedy=None, tool=tool))
            continue
        n = int(led.get("events") or 0)
        if not n or path in seen:   # tools can share a state dir
            continue
        seen.add(path)
        full = int(led.get("batches_fully_rejected") or 0)
        reason = led.get("last_error") or "unspecified"
        if full:
            findings.append(Finding(
                tool.label, _FAIL,
                f"{n} event(s) LOST — ingest rejected {full} batch(es) in full "
                f"({reason})",
                remedy=None, tool=tool))
        else:
            findings.append(Finding(
                tool.label, _WARN,
                f"{n} event(s) rejected as invalid and dropped ({reason})",
                remedy=None, tool=tool))
    return findings


def _check_token_file_config(enrolled: bool):
    """Enrolled devices can still fail to ship events if config.json omits
    token_file (older aim join). The spool client then silently no-ops."""
    if not enrolled:
        return []
    try:
        from pathlib import Path
        import json
        from aim_collector import state as cc_state
        state_dir = cc_state.state_dir()
        cfg_path = state_dir / "config.json"
        token_path = state_dir / "device_token"
        if not token_path.exists():
            return []
        cfg = {}
        if cfg_path.exists():
            try:
                parsed = json.loads(cfg_path.read_text())
                if isinstance(parsed, dict):
                    cfg = parsed
            except (OSError, json.JSONDecodeError):
                cfg = {}
        tf = str(cfg.get("token_file") or "").strip()
        expected = str(token_path.expanduser())
        if tf and Path(tf).expanduser() == Path(expected):
            return [Finding("config", _OK, "token_file points at device_token")]
        return [Finding(
            "config", _FAIL,
            "device_token present but config.json token_file missing/wrong — "
            "events may spool forever while heartbeats succeed",
            remedy="token_file")]
    except Exception as e:  # noqa: BLE001
        return [Finding("config", _WARN, f"could not verify token_file: {e}")]


def run_checks():
    """Collect all findings. Returns (findings, enrolled, reachable)."""
    _bootstrap.ensure_on_path()
    from aim_collector import enroll as cc_enroll
    enrolled = bool(cc_enroll.device_token())
    breadcrumb = _read_breadcrumb()

    enroll_findings, reachable = _check_enrollment()
    findings = list(enroll_findings)
    findings += _check_tools(breadcrumb, reachable)
    findings += _check_rejections()
    findings += _check_service(enrolled)
    findings += _check_enforcement()
    findings += _check_token_file_config(enrolled)
    return findings, enrolled, reachable


# --- repair -----------------------------------------------------------------

def apply_fixes(findings, reachable):
    """Attempt the remedy on every fixable finding, in a safe order: re-hook
    first (so newly-covered tools start spooling), then (re)start the service,
    then flush once so recovered/queued events actually leave the box."""
    for f in findings:
        if f.remedy != "token_file":
            continue
        try:
            from aim_collector import state as cc_state
            import json
            state_dir = cc_state.state_dir()
            cfg_path = state_dir / "config.json"
            token_path = state_dir / "device_token"
            cfg = {}
            if cfg_path.exists():
                try:
                    parsed = json.loads(cfg_path.read_text())
                    if isinstance(parsed, dict):
                        cfg = parsed
                except (OSError, json.JSONDecodeError):
                    cfg = {}
            cfg["token_file"] = str(token_path.expanduser())
            state_dir.mkdir(parents=True, exist_ok=True)
            cfg_path.write_text(json.dumps(cfg, indent=2) + "\n")
            f.fixed, f.fix_note = True, f"wrote token_file → {token_path}"
        except Exception as e:  # noqa: BLE001
            f.fix_note = f"token_file repair failed: {e}"
    hooked_any = False
    for f in findings:
        if f.remedy != "hook":
            continue
        try:
            with tools.hook_command_env(f.tool):
                path = f.tool.module("install").install()
            record_hooked(f.tool)
            f.fixed, f.fix_note = True, f"re-hooked in {path}"
            hooked_any = True
        except Exception as e:  # noqa: BLE001
            f.fix_note = f"re-hook failed: {e}"

    for f in findings:
        if f.remedy != "service":
            continue
        res = service.install()
        f.fixed = bool(res.get("ok"))
        f.fix_note = ("service " + ("started" if res.get("activated")
                                    else "registered") + f" — {res.get('detail')}"
                      if res.get("ok") else f"service repair failed: {res.get('detail')}")

    for f in findings:
        if f.remedy != "enforcement":
            continue
        try:
            from aim_collector import enforce as cc_enforce
            seed = cc_enforce.seed_default_policy(force=True)
            f.fixed = bool(seed.get("ok"))
            if f.fixed:
                f.fix_note = (
                    f"{seed.get('action')} mode={seed.get('mode')} "
                    f"hash={seed.get('policy_hash')} → {seed.get('path')}"
                )
            else:
                f.fix_note = f"enforcement seed failed: {seed.get('error')}"
        except Exception as e:  # noqa: BLE001
            f.fix_note = f"enforcement seed failed: {e}"

    # Flush: drain queued events (and anything the just-restored hooks spool).
    # Only meaningful when ingest is reachable; otherwise leave it spooled.
    flush_findings = [f for f in findings if f.remedy == "flush"]
    if (flush_findings or hooked_any) and reachable:
        try:
            watch.watch_once()
        except Exception:  # noqa: BLE001
            pass
        for f in flush_findings:
            depth = _spool_depth(f.tool)
            f.fixed = depth == 0
            f.fix_note = "spool drained" if depth == 0 else f"{depth} still spooled"
    elif flush_findings:
        for f in flush_findings:
            f.fix_note = "ingest unreachable — left spooled"


# --- CLI --------------------------------------------------------------------

DOCTOR_USAGE = """usage: aim doctor [--fix] [--json] [--ack-rejections]

Verify install health across every AI tool: hooks present, spool draining,
ingest reachable, no events rejected, and the per-user auto-start service
running.

  --fix              repair what it can — re-add clobbered hooks (loss-free),
                     wire token_file when device_token exists,
                     register and start the auto-start service, flush the spool
  --json             machine-readable findings
  --ack-rejections   clear the local rejected-event ledger. Rejected events are
                     already gone; --fix deliberately will NOT clear this, so
                     the loss stays visible until a human acknowledges it.

Exit status is 0 when healthy, 1 when an unhealthy item remains.
"""


def ack_rejections():
    """Clear every tool's rejection ledger. Returns the paths cleared.

    Deliberately NOT part of --fix: `--fix` means "repair the install", and
    clearing a record of lost telemetry is not a repair. Requiring a separate
    explicit flag is what keeps the loss from being cleaned up by reflex.
    """
    _bootstrap.ensure_on_path()
    cleared = []
    for tool in tools.TOOLS:
        if not tool.installed():
            continue
        try:
            spool = tool.module("spool")
            path = str(spool.rejections_path())
            if path in cleared:
                continue
            if int(spool.rejections().get("events") or 0):
                spool.clear_rejections()
                cleared.append(path)
        except Exception:  # noqa: BLE001
            continue
    return cleared


def _worst(findings) -> str:
    order = [_OK, _INFO, _WARN, _FAIL]
    return max((f.level for f in findings), key=order.index, default=_OK)


def cmd_doctor(args) -> int:
    fix = False
    as_json = False
    ack = False
    for a in args:
        if a in ("-h", "--help"):
            sys.stdout.write(DOCTOR_USAGE)
            return 0
        if a == "--fix":
            fix = True
        elif a == "--json":
            as_json = True
        elif a == "--ack-rejections":
            ack = True
        else:
            sys.stderr.write(f"aim doctor: unknown option {a!r}\n\n{DOCTOR_USAGE}")
            return 2

    if ack:
        for path in ack_rejections():
            print(f"cleared rejection ledger: {path}")

    findings, enrolled, reachable = run_checks()
    if fix:
        apply_fixes(findings, reachable)
        # Re-check after repair so the final report and exit code reflect the
        # repaired state, not the pre-fix one.
        findings, enrolled, reachable = run_checks()

    if as_json:
        print(json.dumps([{
            "scope": f.scope, "level": f.level, "message": f.message,
            "remedy": f.remedy,
        } for f in findings], indent=2))
    else:
        _print_findings(findings, fix)

    worst = _worst(findings)
    return 1 if worst in (_WARN, _FAIL) else 0


def _print_findings(findings, fixed_run):
    print("aim doctor\n")
    w = max((len(f.scope) for f in findings), default=0)
    for f in findings:
        line = f"  [{_GLYPH[f.level]}] {f.scope:<{w}}  {f.message}"
        print(line)
        if f.fix_note:
            print(f"          → {f.fix_note}")
    worst = _worst(findings)
    print()
    if worst == _OK:
        print("all clear — hooks in place, spool draining, service running.")
    elif not fixed_run:
        print("issues found. Re-run `aim doctor --fix` to repair what's fixable.")
    else:
        print("repair complete; some items still need attention (see WARN/FAIL "
              "above — typically enrollment or a currently-unreachable ingest).")

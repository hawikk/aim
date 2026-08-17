"""Per-user auto-start registration for the `aim watch` loop (AIM-139).

The single security-relevant promise here: the watcher survives a reboot
*without ever touching a system/root scope*. Every mechanism below registers
the loop **for the current user only** —

  * Linux   — a systemd **user** unit  (~/.config/systemd/user/aim-watch.service)
  * macOS   — a launchd **LaunchAgent** (~/Library/LaunchAgents/…plist)
  * Windows — a per-user **Scheduled Task** (schtasks, current user, LIMITED)

None of these write `/etc`, `/Library/LaunchDaemons`, `%ProgramData%`, or a
system scheduled task, and `install()` refuses outright if invoked as root
(uid 0). That is the least-privilege lens made executable: a single
engineer's `aim join` can register durable background telemetry for *their*
account and nothing wider. Fleet-wide managed deployment (Intune / MDM /
config-management) is a separate, admin-authorized surface — out of scope
here by construction, not by convention.

The command the service runs is ``<sys.executable> -m aim watch`` — pinned to
the exact interpreter that installed it, so it resolves under the minimal
PATH a service manager hands a unit.

Everything is overridable by env for testing (and for unusual layouts):
``AIM_SERVICE_PLATFORM`` forces the mechanism, the ``AIM_*_DIR`` vars redirect
where unit/plist files land, and ``AIM_SERVICE_NO_ACTIVATE=1`` writes the
artifact but skips the ``systemctl``/``launchctl``/``schtasks`` activation
call (so unit files for all three OSes can be generated and asserted on one
Linux CI box).
"""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

SERVICE_ID = "aim-watch"                    # systemd unit / schtasks task name
LABEL = "com.aimonitoring.aim-watch"        # launchd label
DEFAULT_INTERVAL = 30


# --- platform + command -----------------------------------------------------

def current_platform() -> str:
    """'linux' | 'darwin' | 'windows' | 'unsupported'. AIM_SERVICE_PLATFORM
    overrides so all three artifact generators are unit-testable on one host."""
    forced = os.environ.get("AIM_SERVICE_PLATFORM")
    if forced:
        return forced
    sysname = platform.system().lower()
    if sysname.startswith("linux"):
        return "linux"
    if sysname == "darwin":
        return "darwin"
    if sysname.startswith("win"):
        return "windows"
    return "unsupported"


def mechanism_label(plat: str | None = None) -> str:
    return {
        "linux": "systemd user unit",
        "darwin": "launchd LaunchAgent",
        "windows": "per-user Scheduled Task",
    }.get(plat or current_platform(), "unsupported platform")


def watch_command() -> list[str]:
    exe = sys.executable or "python3"
    return [exe, "-m", "aim", "watch", "--interval", str(DEFAULT_INTERVAL)]


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0  # POSIX only


def _activate() -> bool:
    """False when AIM_SERVICE_NO_ACTIVATE is set — write the artifact but skip
    the OS activation call (for artifact-shape unit tests on any host)."""
    return os.environ.get("AIM_SERVICE_NO_ACTIVATE") not in ("1", "true", "yes")


def _run(cmd) -> tuple[int, str]:
    """Run a service-manager command. Returns (returncode, combined output).
    A missing binary is (127, ...), never an exception — status/install must
    degrade, never crash."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"{cmd[0]}: not found"
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)


# --- Linux: systemd user unit -----------------------------------------------

def _linux_unit_dir() -> Path:
    return Path(os.environ.get(
        "AIM_SYSTEMD_USER_DIR", "~/.config/systemd/user")).expanduser()


def _linux_unit_path() -> Path:
    return _linux_unit_dir() / f"{SERVICE_ID}.service"


def _linux_unit_text() -> str:
    exec_start = " ".join(_quote(a) for a in watch_command())
    return (
        "[Unit]\n"
        "Description=AI Monitoring watcher (per-user AI-tool telemetry flush loop)\n"
        "Documentation=https://github.com/hawikk/aim\n"
        "After=default.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={exec_start}\n"
        "Restart=on-failure\n"
        "RestartSec=10\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def _linux_install() -> dict:
    unit = _linux_unit_path()
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text(_linux_unit_text())
    res = {"ok": True, "mechanism": mechanism_label("linux"),
           "artifact": str(unit), "activated": False, "linger": None,
           "detail": "unit written (not activated)"}
    if not _activate():
        return res
    _run(["systemctl", "--user", "daemon-reload"])
    rc, out = _run(["systemctl", "--user", "enable", "--now",
                    f"{SERVICE_ID}.service"])
    res["activated"] = rc == 0
    if rc != 0:
        res["ok"] = False
        res["detail"] = f"systemctl enable --now failed: {out.strip()}"
        return res
    # Best-effort: enable-linger so the unit runs across a full reboot without
    # an interactive login. This is a *per-user* action (set-self-linger), not
    # root; on a locked-down box polkit may deny it — then the watcher still
    # starts on next login, which we report honestly rather than failing.
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    lrc, _ = _run(["loginctl", "enable-linger"] + ([user] if user else []))
    res["linger"] = lrc == 0
    res["detail"] = ("running; starts on boot (linger enabled)"
                     if lrc == 0 else
                     "running; starts on next login (linger unavailable — "
                     "reboot-without-login coverage needs `loginctl enable-linger`)")
    return res


def _linux_uninstall() -> list[str]:
    removed = []
    if _activate():
        _run(["systemctl", "--user", "disable", "--now", f"{SERVICE_ID}.service"])
    unit = _linux_unit_path()
    if unit.exists():
        unit.unlink()
        removed.append(f"systemd user unit {unit}")
    if _activate():
        _run(["systemctl", "--user", "daemon-reload"])
    return removed


def _linux_status() -> dict:
    unit = _linux_unit_path()
    st = {"supported": True, "mechanism": mechanism_label("linux"),
          "artifact": str(unit), "installed": unit.exists(),
          "running": False, "enabled": False, "detail": ""}
    if _activate():
        rc_a, _ = _run(["systemctl", "--user", "is-active", f"{SERVICE_ID}.service"])
        rc_e, _ = _run(["systemctl", "--user", "is-enabled", f"{SERVICE_ID}.service"])
        st["running"] = rc_a == 0
        st["enabled"] = rc_e == 0
    return st


# --- macOS: launchd LaunchAgent ---------------------------------------------

def _darwin_agents_dir() -> Path:
    return Path(os.environ.get(
        "AIM_LAUNCH_AGENTS_DIR", "~/Library/LaunchAgents")).expanduser()


def _darwin_plist_path() -> Path:
    return _darwin_agents_dir() / f"{LABEL}.plist"


def _darwin_plist_text() -> str:
    args = "".join(f"    <string>{_xml_escape(a)}</string>\n"
                   for a in watch_command())
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        '<dict>\n'
        f'  <key>Label</key>\n  <string>{LABEL}</string>\n'
        '  <key>ProgramArguments</key>\n'
        f'  <array>\n{args}  </array>\n'
        '  <key>RunAtLoad</key>\n  <true/>\n'
        '  <key>KeepAlive</key>\n  <true/>\n'
        '  <key>ProcessType</key>\n  <string>Background</string>\n'
        '</dict>\n'
        '</plist>\n'
    )


def _darwin_install() -> dict:
    plist = _darwin_plist_path()
    plist.parent.mkdir(parents=True, exist_ok=True)
    plist.write_text(_darwin_plist_text())
    res = {"ok": True, "mechanism": mechanism_label("darwin"),
           "artifact": str(plist), "activated": False,
           "detail": "LaunchAgent written (not activated)"}
    if not _activate():
        return res
    _run(["launchctl", "unload", str(plist)])  # idempotent reload
    rc, out = _run(["launchctl", "load", "-w", str(plist)])
    res["activated"] = rc == 0
    res["ok"] = rc == 0
    res["detail"] = ("loaded; runs at login and is kept alive" if rc == 0
                     else f"launchctl load failed: {out.strip()}")
    return res


def _darwin_uninstall() -> list[str]:
    removed = []
    plist = _darwin_plist_path()
    if _activate():
        _run(["launchctl", "unload", "-w", str(plist)])
    if plist.exists():
        plist.unlink()
        removed.append(f"launchd LaunchAgent {plist}")
    return removed


def _darwin_status() -> dict:
    plist = _darwin_plist_path()
    st = {"supported": True, "mechanism": mechanism_label("darwin"),
          "artifact": str(plist), "installed": plist.exists(),
          "running": False, "enabled": plist.exists(), "detail": ""}
    if _activate() and plist.exists():
        rc, out = _run(["launchctl", "list"])
        st["running"] = rc == 0 and LABEL in out
    return st


# --- Windows: per-user Scheduled Task ---------------------------------------

def _windows_command_string() -> str:
    return " ".join(_quote(a) for a in watch_command())


def _windows_install() -> dict:
    res = {"ok": True, "mechanism": mechanism_label("windows"),
           "artifact": f"Scheduled Task \\{SERVICE_ID}", "activated": False,
           "detail": "task definition prepared (not activated)"}
    if not _activate():
        return res
    # /sc onlogon + no /ru → registers under the CURRENT user; /rl LIMITED
    # keeps it at the user's own privilege (never elevated). /f overwrites,
    # so re-running is idempotent.
    rc, out = _run(["schtasks", "/create", "/tn", SERVICE_ID,
                    "/tr", _windows_command_string(),
                    "/sc", "onlogon", "/rl", "LIMITED", "/f"])
    res["activated"] = rc == 0
    res["ok"] = rc == 0
    if rc == 0:
        _run(["schtasks", "/run", "/tn", SERVICE_ID])  # start now, best-effort
        res["detail"] = "registered; runs at every user logon"
    else:
        res["detail"] = f"schtasks /create failed: {out.strip()}"
    return res


def _windows_uninstall() -> list[str]:
    removed = []
    if _activate():
        rc, _ = _run(["schtasks", "/delete", "/tn", SERVICE_ID, "/f"])
        if rc == 0:
            removed.append(f"scheduled task \\{SERVICE_ID}")
    return removed


def _windows_status() -> dict:
    st = {"supported": True, "mechanism": mechanism_label("windows"),
          "artifact": f"Scheduled Task \\{SERVICE_ID}", "installed": False,
          "running": False, "enabled": False, "detail": ""}
    if _activate():
        rc, out = _run(["schtasks", "/query", "/tn", SERVICE_ID])
        st["installed"] = st["enabled"] = rc == 0
        st["running"] = rc == 0 and "Running" in out
    return st


# --- dispatch ---------------------------------------------------------------

_HANDLERS = {
    "linux": (_linux_install, _linux_uninstall, _linux_status),
    "darwin": (_darwin_install, _darwin_uninstall, _darwin_status),
    "windows": (_windows_install, _windows_uninstall, _windows_status),
}


def supported() -> bool:
    return current_platform() in _HANDLERS


def install() -> dict:
    """Register + start the per-user watcher service. Refuses root. Returns a
    result dict (always has 'ok'); never raises."""
    plat = current_platform()
    if _is_root():
        return {"ok": False, "mechanism": mechanism_label(plat), "activated": False,
                "detail": "refusing to install a root/system service — run `aim` "
                          "as your normal user (auto-start is per-user by design)"}
    if plat not in _HANDLERS:
        return {"ok": False, "mechanism": "unsupported platform", "activated": False,
                "detail": f"no per-user auto-start mechanism for {plat!r}; "
                          "run `aim watch` from your own startup items"}
    return _HANDLERS[plat][0]()


def uninstall() -> list[str]:
    """Remove the service registration. Idempotent; returns removals. Never
    raises. Root is fine here (cleanup should always be allowed)."""
    plat = current_platform()
    if plat not in _HANDLERS:
        return []
    try:
        return _HANDLERS[plat][1]()
    except Exception:  # noqa: BLE001 — cleanup is best-effort
        return []


def status() -> dict:
    """Report install/running state without changing anything. Never raises."""
    plat = current_platform()
    if plat not in _HANDLERS:
        return {"supported": False, "mechanism": "unsupported platform",
                "installed": False, "running": False, "enabled": False,
                "detail": f"no auto-start mechanism for {plat!r}"}
    try:
        return _HANDLERS[plat][2]()
    except Exception as e:  # noqa: BLE001
        return {"supported": True, "mechanism": mechanism_label(plat),
                "installed": False, "running": False, "enabled": False,
                "detail": f"status probe failed: {e}"}


# --- small text helpers -----------------------------------------------------

def _quote(arg: str) -> str:
    """Quote an arg that contains spaces for a unit ExecStart / task /tr."""
    return f'"{arg}"' if " " in arg else arg


def _xml_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

#!/usr/bin/env python3
"""End-to-end doctor + auto-start, no real AI tool needed.

Drives the two acceptance criteria that don't require a live OS service
manager, against a stub ingest that also counts events:

  1. Hand-delete a hook from a tool's settings file  → `aim doctor` flags it as
     a *clobber* (settings survived, hook gone), `aim doctor --fix` restores it
     WITHOUT losing spooled data, and events reach the ingest again.
  2. `aim uninstall` leaves no service / hook / spool residue and `aim doctor`
     on the now-clean machine says so.

Auto-start registration runs with AIM_SERVICE_NO_ACTIVATE=1 so this script
touches no real systemd/launchd/Task Scheduler state — the *live* systemd
reboot-survival proof is a separate manual run recorded on the issue. Stdlib
only; run from a checkout:

    python3 scripts/doctor-e2e.py
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "packaging" / "aim-cli" / "src"
DEVICE_TOKEN = "dev-tok-stub"


class _Ingest(BaseHTTPRequestHandler):
    events_seen = 0
    enrolls = 0

    def _token(self):
        return (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()

    def do_POST(self):  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == "/v1/enroll":
            type(self).enrolls += 1
            return self._send(201, {"device_token": DEVICE_TOKEN,
                                    "device_id": "dev-stub-1",
                                    "already_enrolled": False,
                                    "heartbeat_interval_sec": 300})
        if self.path == "/v1/heartbeat":
            return self._send(200, {"heartbeat_interval_sec": 300})
        if self.path == "/v1/events":
            try:
                body = json.loads(raw or b"{}")
                type(self).events_seen += len(body.get("events", []))
            except ValueError:
                pass
            return self._send(202, {"accepted": True})
        self._send(404, {"error": "not found"})

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _run(cmd, home, extra_env=None):
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["PYTHONPATH"] = str(SRC)
    env["AIM_SERVICE_NO_ACTIVATE"] = "1"      # don't touch real service managers
    env["AIM_COLLECTOR_TOKEN"] = "events-tok"  # events auth for the stub
    if extra_env:
        env.update(extra_env)
    p = subprocess.run([sys.executable, "-m", "aim"] + cmd,
                       cwd=str(REPO), env=env, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def _first_registered_command(settings_path):
    """Pull one hook command string our installer wrote into settings.json."""
    cfg = json.loads(settings_path.read_text())
    for groups in cfg.get("hooks", {}).values():
        for g in groups if isinstance(groups, list) else []:
            for h in g.get("hooks", []) if isinstance(g, dict) else []:
                cmd = str(h.get("command", ""))
                if "aim hook" in cmd:
                    return cmd
    return None


def _fire_registered_hook(settings_path, home, env):
    """Run the exact command from settings.json with a PostToolUse payload,
    the way Claude Code would. Returns the process exit code (or -1 if no
    command was found)."""
    cmd = _first_registered_command(settings_path)
    if not cmd:
        return -1
    run_env = dict(os.environ)
    run_env["HOME"] = str(home)
    run_env["PYTHONPATH"] = str(SRC)
    if env:
        run_env.update(env)
    payload = ('{"hook_event_name":"PostToolUse","session_id":"e2e-fire-1",'
               '"cwd":"/tmp","tool_name":"Bash"}')
    p = subprocess.run(cmd, shell=True, input=payload, text=True,
                       capture_output=True, cwd=str(REPO), env=run_env)
    return p.returncode


def _check(cond, msg):
    mark = "ok  " if cond else "FAIL"
    print(f"  [{mark}] {msg}")
    if not cond:
        raise SystemExit(f"assertion failed: {msg}")


def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Ingest)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}"

    tmp = Path(tempfile.mkdtemp(prefix="aim139-"))
    home = tmp / "home"
    # Make Claude Code look "installed": its settings dir must exist.
    (home / ".claude" / "projects" / "demo").mkdir(parents=True)
    # A transcript so `watch`/`doctor --fix` has real events to scan + flush.
    # The network path only emits on a usage/tool-call delta, so the assistant
    # line must carry token usage.
    (home / ".claude" / "projects" / "demo" / "s.jsonl").write_text(
        '{"type":"user","timestamp":"2026-01-01T00:00:00Z",'
        '"message":{"role":"user","content":"hello from aim-139 e2e"}}\n'
        '{"type":"assistant","timestamp":"2026-01-01T00:00:01Z",'
        '"message":{"role":"assistant","model":"claude-opus-4",'
        '"usage":{"input_tokens":12,"output_tokens":34}}}\n')
    projects = home / ".claude" / "projects"
    env = {"AIM_CLAUDE_PROJECTS_DIR": str(projects)}

    print(f"stub ingest on {url}; HOME={home}\n")

    print("1. join (hooks Claude Code, enrolls, registers auto-start)")
    rc, out = _run(["join", url, "--token", "good"], home, env)
    _check(rc == 0, "join exits 0")
    settings = home / ".claude" / "settings.json"
    _check(settings.exists() and "aim hook" in settings.read_text(),
           "hook present in settings.json after join (routed through `aim hook`)")
    _check("auto-start:" in out, "join reports auto-start registration")

    # The registered command must actually EXECUTE — a wheel install vendors the
    # collector under aim._vendor, so the earlier `-m aim_collector hook`
    # form failed ModuleNotFoundError at fire time and the hook silently no-oped.
    # Fire the exact command from settings.json with a PostToolUse payload.
    fired = _fire_registered_hook(settings, home, env)
    _check(fired == 0, f"registered hook command executes cleanly (exit {fired})")
    breadcrumb = home / ".aim-collector" / "hooked_tools.json"
    _check(breadcrumb.exists() and "claude-code" in breadcrumb.read_text(),
           "hook breadcrumb recorded for clobber detection")

    print("\n2. hand-delete the hook (simulate a tool update rewriting settings)")
    cfg = json.loads(settings.read_text())
    cfg["hooks"] = {}                              # tool update wiped our hook, kept the file
    cfg["theme"] = "dark"                          # ...and left its own settings
    settings.write_text(json.dumps(cfg, indent=2))
    _check("aim hook" not in settings.read_text(), "hook removed, settings file intact")

    print("\n3. doctor flags the clobber specifically")
    rc, out = _run(["doctor"], home, env)
    _check(rc == 1, "doctor exits non-zero on a broken hook")
    _check("clobber" in out.lower() or "rewrote settings" in out.lower(),
           "doctor names the tool-update clobber case")

    print("\n4. doctor --fix restores the hook (loss-free) and events flow")
    before = _Ingest.events_seen
    rc, out = _run(["doctor", "--fix"], home, env)
    _check("aim hook" in settings.read_text(), "hook re-installed by --fix")
    _check("theme" in settings.read_text(), "tool's own settings preserved (theme kept)")
    time.sleep(0.3)
    _check(_Ingest.events_seen > before, "events reached ingest after repair "
           f"({_Ingest.events_seen - before} received)")

    print("\n5. doctor now reports healthy hooks")
    rc, out = _run(["doctor"], home, env)
    _check("[ok  ] Claude Code  hooked" in out, "doctor shows Claude Code hooked")

    print("\n6. uninstall removes hook + state + service registration")
    rc, out = _run(["uninstall"], home, env)
    _check(rc == 0, "uninstall exits 0")
    _check(not (home / ".aim-collector").exists(), "state dir gone")
    _check("aim hook" not in settings.read_text(), "hook removed from settings")

    print("\n7. doctor on the clean machine says so")
    rc, out = _run(["doctor"], home, env)
    _check("not enrolled" in out.lower(), "doctor reports the box is unenrolled/clean")

    srv.shutdown()
    print("\nDoctor e2e: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

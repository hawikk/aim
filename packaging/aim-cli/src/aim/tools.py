"""Registry of the AI tools `aim` can hook, enroll, and inspect.

`aim join` / `aim status` / `aim uninstall` all iterate this one table so
adding a fifth tool is a single entry, not four call sites. Each `Tool`
knows how to import its vendored collector package, detect whether the tool
is installed on this machine, and (for hook-capable tools) find + read its
hook registration file.

Two collector shapes exist and both are first-class here:

  * hook-based  (Claude Code, Cursor, Copilot, Kimi, Grok): register a
    command hook in the tool's own settings file; telemetry + enforcement
    fire on tool events.
  * scan-based  (Kilo Code): no hook API, so there is nothing to register —
    coverage comes from enrollment + the periodic scan. `join` still
    configures + enrolls it; `status` reports it as scan-based rather than
    "unhooked/broken".

Device identity: Claude/Kilo/Kimi collectors default to the same state dir
(`~/.aim-collector`), so they share one host id + device token — one device
record. Cursor uses its own state dir; `join` bridges the shared identity
into it (see `aim.join`) so one physical machine stays one device.
"""

import contextlib
from pathlib import Path
import importlib
import os
import shlex
import shutil
import sys

from . import _bootstrap


class Tool:
    def __init__(self, key, label, subdir, pkg, hooks, detect, scan_mod):
        self.key = key          # stable slug, e.g. "cursor"
        self.label = label      # human label, e.g. "Cursor"
        self.subdir = subdir    # dir under _vendor/collectors, e.g. "cursor"
        self.pkg = pkg          # importable package, e.g. "cursor_collector"
        self.hooks = hooks      # True if it registers a command hook
        self._detect = detect   # detect(tool) -> bool
        self.scan_mod = scan_mod  # submodule exposing scan_once() for `aim watch`

    def module(self, name):
        """Import a submodule of this collector (e.g. install/state/paths).

        The vendored collectors live under _vendor/collectors/<subdir>/<pkg>;
        putting <subdir> on sys.path makes `import <pkg>` resolve, matching
        how the collectors discover each other in a git clone."""
        d = str(_bootstrap.VENDOR / "collectors" / self.subdir)
        if d not in sys.path:
            sys.path.insert(0, d)
        return importlib.import_module(f"{self.pkg}.{name}")

    def installed(self) -> bool:
        """True when the tool appears to be present on this machine. Never
        raises — a detection error is treated as 'not installed'."""
        try:
            return bool(self._detect(self))
        except Exception:
            return False

    def state_dir(self):
        """This collector's per-user state dir (device token, spool, config)."""
        return self.module("state").state_dir()

    def hooks_registered(self) -> bool:
        """True when this tool's settings file carries a hook we installed.

        Marker-based and shape-agnostic: our command line always contains the
        collector's package name (e.g. `python -m cursor_collector hook ...`),
        which appears nowhere else in a settings file. Returns False when the
        file is gone or the entry was removed by hand — that's exactly the
        'deliberately broken' state `aim status` must surface."""
        if not self.hooks:
            return False
        inst = self.module("install")
        path = inst.settings_path()
        try:
            text = path.read_text()
        except OSError:
            return False
        # Prefer the multi-marker check (recognizes both the standalone
        # `-m <pkg> hook` default and the packaged `aim hook` form); fall back
        # to the legacy single marker for any collector not yet updated.
        matcher = getattr(inst, "contains_our_hook", None)
        return matcher(text) if matcher else inst._MARKER in text


def _detect_claude(tool) -> bool:
    inst = tool.module("install")
    if inst.settings_path().parent.exists():
        return True
    return shutil.which("claude") is not None


def _detect_cursor(tool) -> bool:
    paths = tool.module("paths")
    if paths.cursor_home().exists() or paths.cursor_user_dir().exists():
        return True
    return shutil.which("cursor") is not None


def _detect_kilo(tool) -> bool:
    # IDE globalStorage and/or standalone CLI (AIM-647 dual surface)
    paths = tool.module("paths")
    if hasattr(paths, "any_surface_present"):
        return bool(paths.any_surface_present())
    return bool(paths.storage_dirs())


def _detect_kimi(tool) -> bool:
    return tool.module("paths").kimi_home().exists()


def _detect_copilot(tool) -> bool:
    paths = tool.module("paths")
    if hasattr(paths, "any_surface_present"):
        return bool(paths.any_surface_present())
    return False


def _detect_grok(tool) -> bool:
    """Grok Build grok_local is active when Grok CLI is installed
    or an agent-runner heartbeat is currently running (PAPERCLIP_RUN_ID)."""
    if shutil.which("grok") is not None:
        return True
    if os.environ.get("PAPERCLIP_RUN_ID"):
        return True
    # Also detect if the local Grok or agent-runner home exists.
    home = Path.home()
    if (home / ".grok").exists() or (home / ".paperclip").exists():
        return True
    return False



# Order is the display order in `join` / `status` output. `scan_mod` names the
# collector submodule whose `scan_once()` feeds the spool for `aim watch`:
# hook tools scan the tail their hook can miss (transcripts / vscdb), scan-only
# tools poll their logs. All four then drain via their own `spool.flush()`.
TOOLS = [
    Tool("claude-code", "Claude Code", "claude-code", "aim_collector",
         hooks=True, detect=_detect_claude, scan_mod="transcript"),
    Tool("cursor", "Cursor", "cursor", "cursor_collector",
         hooks=True, detect=_detect_cursor, scan_mod="vscdb"),
    Tool("kilo-code", "Kilo Code", "kilo-code", "kilo_collector",
         hooks=False, detect=_detect_kilo, scan_mod="watch"),
    Tool("kimi-code", "Kimi Code", "kimi-code", "kimi_collector",
         hooks=True, detect=_detect_kimi, scan_mod="watch"),
    Tool("grok-build", "Grok Build", "grok-build", "grok_collector",
         hooks=True, detect=_detect_grok, scan_mod="emit"),
    Tool("github-copilot", "GitHub Copilot", "github-copilot", "copilot_collector",
         hooks=True, detect=_detect_copilot, scan_mod="watch"),
]


def hook_command(tool) -> str:
    """The command string to register in a tool's settings file so its hook
    fires *this* `aim` install.

    Uses ``<interpreter> -m aim hook <key>`` — the same module form the
    auto-start service uses for ``-m aim watch`` (see aim.__main__), and for the
    same reason: it resolves against the exact interpreter that owns this
    install even from a minimal PATH. Critically, a wheel vendors the collectors
    under ``aim._vendor`` where they are NOT importable as top-level modules, so
    install.py's own default (``<interpreter> -m aim_collector hook``) raises
    ModuleNotFoundError at hook-fire time and the hook silently no-ops (the hook
    contract is fail-open). Routing through ``aim hook`` runs the vendor
    bootstrap first, so a wheel-installed collector actually services its hook.
    An explicit operator ``AIM_HOOK_COMMAND`` still wins (see hook_command_env).
    """
    return f"{shlex.quote(sys.executable)} -m aim hook {tool.key}"


@contextlib.contextmanager
def hook_command_env(tool):
    """Register hooks with :func:`hook_command` for the duration of an
    ``install()`` call, unless the operator set ``AIM_HOOK_COMMAND`` themselves
    (in which case their override is left untouched and restored after)."""
    prev = os.environ.get("AIM_HOOK_COMMAND")
    if prev is None:
        os.environ["AIM_HOOK_COMMAND"] = hook_command(tool)
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop("AIM_HOOK_COMMAND", None)


def by_key(key):
    """The Tool with this stable slug, or None."""
    return next((t for t in TOOLS if t.key == key), None)


def canonical_state_dir():
    """The state dir holding the machine's single device identity. This is
    the Claude Code collector's dir (`~/.aim-collector`), which Kilo and Kimi
    share by default; `join` enrolls here once and bridges the identity into
    any tool whose state dir differs (Cursor)."""
    from aim_collector import state  # noqa: on path via _bootstrap
    return state.state_dir()

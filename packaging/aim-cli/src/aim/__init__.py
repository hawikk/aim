"""aim — one installable artifact for AI Monitoring's endpoint collectors.

This package bundles the existing per-tool collectors (Claude Code, Cursor,
Kilo Code, Kimi Code) and the local dashboard behind a single `aim` CLI, so
an engineer can `pipx install aimonitoring-security` and run `aim personal`
with no repo clone and no infrastructure.

The distribution name on PyPI / GitHub Releases is ``aimonitoring-security``;
the ``aim`` name on PyPI is an unrelated AimStack project. The
import package and console script remain ``aim``. Runtime is stdlib-only; the
collector source is vendored verbatim (no binaries) under `aim/_vendor/`.

The version here is the single source of truth for the packaged artifact and
is what `aim version` reports for the CLI itself. It is kept in sync with
`packaging/aim-cli/pyproject.toml` by the build script.

Runtime floor is **Python 3.11+** (matches ``requires-python``). An early
import/CLI guard fails with a human message rather than a mid-command
``TypeError`` from 3.10+ typing syntax used in the CLI modules.
"""

import sys

__version__ = "0.1.2"

# Keep this block free of 3.10+ syntax so the message can still render on older
# interpreters that somehow imported the package (editable / force installs).
MIN_PYTHON = (3, 11)
INSTALL_DOCS_URL = (
    "https://github.com/hawikk/aim"
    "#2-personal-mode--your-own-ai-usage-in-60-seconds"
)


def unsupported_python_message(version_info=None):
    """Return a human stderr message when *version_info* is below the floor.

    Returns ``None`` when the interpreter is supported. Pure function so unit
    tests can pass synthetic version tuples without touching the real runtime.
    """
    vi = sys.version_info if version_info is None else version_info
    if vi[:2] >= MIN_PYTHON:
        return None
    micro = vi[2] if len(vi) > 2 else 0
    running = "%d.%d.%d" % (vi[0], vi[1], micro)
    return (
        "aim requires Python 3.11 or newer (this interpreter is %s).\n"
        "See install docs: %s\n" % (running, INSTALL_DOCS_URL)
    )


def ensure_supported_python(version_info=None):
    """Abort with a clear message (and non-zero exit) below Python 3.11."""
    msg = unsupported_python_message(version_info)
    if msg is None:
        return
    sys.stderr.write(msg)
    raise SystemExit(1)


# Fail at import time on older interpreters (before any 3.10+ typing is loaded).
ensure_supported_python()

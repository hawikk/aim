"""Locate the vendored collector trees and put them on sys.path.

The collectors ship as ordinary Python source vendored under
``aim/_vendor/`` in the exact repo-relative layout they have in the
monorepo::

    aim/_vendor/
      collectors/
        claude-code/aim_collector/...
        cursor/cursor_collector/...
        kilo-code/kilo_collector/...
        kimi-code/kimi_collector/...
        grok-build/grok_collector/...
        github-copilot/copilot_collector/...
      apps/web/public/...

Preserving that layout is deliberate: the collectors already discover their
siblings and the dashboard static root by walking up from ``__file__`` looking
for ``collectors/cursor/cursor_collector`` and ``apps/web/public``. By keeping
the same relative shape under ``_vendor/`` the collector source runs
byte-for-byte unchanged whether it's a git clone or an installed wheel — no
import shims, no path patches in the collector code.

We add only ``collectors/claude-code`` to ``sys.path`` (so ``import
aim_collector`` resolves); the sibling collectors are imported lazily by
``aim_collector.personal`` via its own walk-up + ``sys.path`` insertion, which
finds them under the same ``_vendor/collectors`` root.
"""

import sys
from pathlib import Path

VENDOR = Path(__file__).resolve().parent / "_vendor"
CLAUDE_PKG_DIR = VENDOR / "collectors" / "claude-code"


def vendored() -> bool:
    """True when the vendored collector tree is present (built wheel/sdist)."""
    return (CLAUDE_PKG_DIR / "aim_collector" / "__init__.py").is_file()


def ensure_on_path() -> None:
    """Put the vendored Claude Code collector dir on sys.path (idempotent)."""
    d = str(CLAUDE_PKG_DIR)
    if d not in sys.path:
        sys.path.insert(0, d)

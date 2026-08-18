"""Grok Build hook: deny tool calls via official PreToolUse contract.

xAI documents PreToolUse as the only blocking event
(``{"decision":"deny","reason":"..."}`` + exit 2). UserPromptSubmit is
observe-only. Fail-open on missing policy or collector errors.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _aim():
    try:
        from aim_collector import generic_hook
        return generic_hook
    except ImportError:
        collectors = Path(__file__).resolve().parents[2]
        claude = collectors / "claude-code"
        if claude.is_dir() and str(claude) not in sys.path:
            sys.path.insert(0, str(claude))
        from aim_collector import generic_hook
        return generic_hook


def run(raw: bytes) -> tuple[int, str, str]:
    try:
        return _aim().run("grok", raw)
    except Exception:
        return 0, "", ""


def main(argv=None) -> int:
    try:
        raw = sys.stdin.buffer.read(1 * 1024 * 1024)
        code, out, err = run(raw)
        if out:
            sys.stdout.write(out)
        if err:
            sys.stderr.write(err)
        return code
    except Exception:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

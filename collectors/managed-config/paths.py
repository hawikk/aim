"""Platform managed-config directories (AIM-36 / AIM-1170).

Search order for a managed file (first existing wins), after ``AIM_*_FILE``:

Windows
  ``%ProgramData%\\AI-Monitoring\\collector\\<name>``

macOS (first-class; Darwin must not fall through to Linux ``/etc`` only)
  1. ``/Library/Application Support/AI-Monitoring/collector/<name>``
     (MDM / admin drop; IT can push this without our installer running as root)
  2. ``~/Library/Application Support/AI-Monitoring/collector/<name>``
     (per-user managed path written by ``deploy/macos/managed-user/install.sh``)
  3. ``/etc/aim-collector/<name>``
     (legacy AIM-743 Jamf LaunchDaemon layout — compatibility only)

Linux / WSL
  ``/etc/aim-collector/<name>``

Collectors ship standalone, so each package inlines this list. Keep those
copies in lockstep with this module (tests assert the Darwin constants).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

LINUX_MANAGED_DIR = "/etc/aim-collector"
DARWIN_MANAGED_DIR = "/Library/Application Support/AI-Monitoring/collector"
DARWIN_USER_MANAGED_DIR = "~/Library/Application Support/AI-Monitoring/collector"
WINDOWS_MANAGED_DIRNAME = ("AI-Monitoring", "collector")


def managed_dirs(
    plat: str | None = None,
    *,
    home: Path | str | None = None,
    programdata: str | None = None,
) -> list[Path]:
    """Managed directories for ``plat`` (``sys.platform`` shape), first-class first."""
    p = plat if plat is not None else sys.platform
    if p.startswith("win"):
        base = programdata if programdata is not None else os.environ.get(
            "ProgramData", r"C:\ProgramData"
        )
        return [Path(base).joinpath(*WINDOWS_MANAGED_DIRNAME)]
    if p == "darwin" or p.startswith("darwin"):
        user_home = Path(home).expanduser() if home is not None else Path.home()
        return [
            Path(DARWIN_MANAGED_DIR),
            user_home / "Library" / "Application Support" / "AI-Monitoring" / "collector",
            Path(LINUX_MANAGED_DIR),  # AIM-743 legacy
        ]
    return [Path(LINUX_MANAGED_DIR)]


def managed_file_candidates(
    filename: str,
    plat: str | None = None,
    *,
    home: Path | str | None = None,
    programdata: str | None = None,
) -> list[Path]:
    """``managed_dirs`` with ``filename`` appended."""
    return [
        d / filename
        for d in managed_dirs(plat, home=home, programdata=programdata)
    ]

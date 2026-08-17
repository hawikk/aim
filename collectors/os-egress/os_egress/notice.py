"""Consent / notice gate (privacy bar).

Capture must not run until notice is acknowledged. See
.
"""

from __future__ import annotations

import os
from pathlib import Path


class NoticeNotAcknowledged(RuntimeError):
    """Raised when capture is attempted without notice acknowledgment."""


def state_dir() -> Path:
    override = os.environ.get("AIM_STATE_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".aim"


def notice_ack_path() -> Path:
    return state_dir() / "os_egress_notice_ack"


def is_notice_acknowledged(*, config: dict | None = None) -> bool:
    if os.environ.get("AIM_OS_EGRESS_NOTICE_ACK", "").strip() in ("1", "true", "yes"):
        return True
    if config and config.get("notice_ack") is True:
        return True
    path = notice_ack_path()
    try:
        text = path.read_text(encoding="utf-8").strip()
        return bool(text)
    except OSError:
        return False


def require_notice(*, config: dict | None = None) -> None:
    if not is_notice_acknowledged(config=config):
        raise NoticeNotAcknowledged(
            "OS egress capture is disabled until notice is acknowledged. "
            "(set AIM_OS_EGRESS_NOTICE_ACK=1 or drop "
            f"{notice_ack_path()} after notice publication)."
        )

"""Endpoint identity attestation (AIM-58). Same contract as other collectors."""

from __future__ import annotations

import getpass
import os
import re
import subprocess
import sys

from . import __version__, config, state
from .build_attestation import load_build_attestation

_DSREGCMD_DEVICE_ID_RE = re.compile(r"^\s*DeviceId\s*:\s*(\S+)\s*$", re.MULTILINE)


def _enrolled_device_id() -> str | None:
    try:
        return (state.state_dir() / "device_id").read_text().strip() or None
    except OSError:
        return None


def _device_id() -> str | None:
    env = os.environ.get("AIM_DEVICE_ID")
    if env and env.strip():
        return env.strip()
    cfg = config.load().get("device_id")
    if isinstance(cfg, str) and cfg.strip():
        return cfg.strip()
    enrolled = _enrolled_device_id()
    if enrolled:
        return enrolled
    if sys.platform.startswith("win"):
        return _dsregcmd_device_id()
    return None


def _dsregcmd_device_id() -> str | None:
    try:
        proc = subprocess.run(
            ["dsregcmd", "/status"], capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    m = _DSREGCMD_DEVICE_ID_RE.search(proc.stdout or "")
    return m.group(1) if m else None


def _os_user() -> str | None:
    try:
        return getpass.getuser() or None
    except Exception:
        return None


def collector_identity() -> dict:
    identity = {}
    device_id = _device_id()
    if device_id:
        identity["device_id"] = device_id
    os_user = _os_user()
    if os_user:
        identity["os_user"] = os_user
    identity["build"] = load_build_attestation(
        tool="github-copilot",
        version=__version__,
        module_file=__file__,
    )
    return identity

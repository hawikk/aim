"""Endpoint identity attestation (AIM-58).

The collector attests its endpoint identity once per batch: ingest resolves
it to a user_pseudonym + team via identity-sync POST /resolve (AIM-49). The
block travels in the batch envelope only — never inside event payloads
(metadata-only contract).

device_id resolution order (first hit wins):

1. ``AIM_DEVICE_ID`` env var (dev/test override)
2. ``device_id`` in the managed config file — the pilot path: the Intune/SCCM
   install drops the enrolled Intune device id alongside config.json
   (see docs/deployment/enrollment-and-heartbeat.md, AIM-28)
3. ``device_id`` written into the state dir by ``aim join`` — the platform's own
   enrollment id (AIM-149). Without this an enrolled Linux/WSL host attests
   only its OS login, so resolution falls through to the weakest rule (the
   bare-username heuristic) even though the device is enrolled and known.
4. Windows: ``dsregcmd /status`` DeviceId — the Entra/Intune device id of the
   enrolled device. Best-effort; absent on unmanaged, WSL, and Linux hosts.

os_user: the OS login name (USER/USERNAME/LOGNAME env, then the password
database). Covers WSL/Linux where no Intune id exists; identity-sync falls
back to os_user mapping and the bare-username heuristic (AIM-24 ADR-001).

build (AIM-646): signed package/version/tool identity embedded at release;
see docs/security/collector-build-attestation.md.
"""

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
    """Device id stored by ``aim join`` (AIM-149). Best-effort file read."""
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
    """Intune/Entra device id of the enrolled Windows device, or None."""
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
    except Exception:  # no env vars and no pwd entry (e.g. minimal containers)
        return None


def collector_identity() -> dict:
    """Identity block for the batch envelope; {} when nothing is attestable.

    Empty means "omit the block" — ingest rejects an empty collector object.

    Always includes a ``build`` sub-object (AIM-646): signed at release when
    ``build_attestation.json`` is present; unsigned package/version/tool in
    source checkouts. Ingest rejects unsigned only when
    ``INGEST_ATTESTATION_MODE=enforce``.
    """
    identity = {}
    device_id = _device_id()
    if device_id:
        identity["device_id"] = device_id
    os_user = _os_user()
    if os_user:
        identity["os_user"] = os_user
    identity["build"] = load_build_attestation(
        tool="kilo-code",
        version=__version__,
        module_file=__file__,
    )
    return identity

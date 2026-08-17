"""Managed configuration resolution (AIM-36). Identical contract to the
Claude Code collector: a managed JSON file dropped by endpoint tooling,
with env overrides for dev.

Search order (first existing wins):

1. ``AIM_CONFIG_FILE`` env var (explicit override, used by tests/dev)
2. platform managed path:
   - Windows: ``%ProgramData%\\AI-Monitoring\\collector\\config.json``
   - Linux/WSL: ``/etc/aim-collector/config.json``
3. ``<state dir>/config.json`` (per-user fallback, dev default)

Recognized keys: ``ingest_url``, ``token_file``, ``token`` (dev only),
``hash_salt`` (must match ingestion side).
"""

import json
import os
import sys
from pathlib import Path

from . import state

MANAGED_PATH_WINDOWS = r"C:\ProgramData\AI-Monitoring\collector\config.json"
MANAGED_PATH_LINUX = "/etc/aim-collector/config.json"


def _managed_default() -> Path:
    if sys.platform.startswith("win"):
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(base) / "AI-Monitoring" / "collector" / "config.json"
    return Path(MANAGED_PATH_LINUX)


def config_path() -> Path | None:
    """First config file that exists, in search order; None if none."""
    candidates = []
    if os.environ.get("AIM_CONFIG_FILE"):
        candidates.append(Path(os.environ["AIM_CONFIG_FILE"]).expanduser())
    candidates.append(_managed_default())
    candidates.append(state.state_dir() / "config.json")
    for c in candidates:
        if c.is_file():
            return c
    return None


def load() -> dict:
    """Parsed config dict; {} if no file or unreadable/invalid.

    AIM-749: prefer signed/harden load when ``collectors.integrity`` is
    importable; fall back to bare JSON so pilot hooks never hard-fail.
    """
    p = config_path()
    if p is None:
        return {}
    try:
        from collectors.integrity.harden import load_managed_config  # type: ignore

        return load_managed_config(p, state_dir=state.state_dir())
    except Exception:
        try:
            root = Path(__file__).resolve().parents[2]
            if (root / "integrity").is_dir() and str(root.parent) not in sys.path:
                sys.path.insert(0, str(root.parent))
            from collectors.integrity.harden import load_managed_config  # type: ignore

            return load_managed_config(p, state_dir=state.state_dir())
        except Exception:
            try:
                cfg = json.loads(p.read_text())
            except (OSError, json.JSONDecodeError):
                return {}
            return cfg if isinstance(cfg, dict) else {}


def ingest_url() -> str | None:
    return os.environ.get("AIM_INGEST_URL") or load().get("ingest_url")



def token() -> str | None:
    """Resolve the events bearer for spool flush.

    Order (AIM-443 / AIM-319):
      1. ``AIM_COLLECTOR_TOKEN`` env — explicit operator override
      2. ``<state dir>/device_token`` — enrollment-issued per-device bearer
      3. ``token_file`` from managed config
      4. inline ``token`` field (dev only)

    Heartbeat already uses the device token. Preferring it for events too
    means re-enrollment cannot leave the event path on a stale shared
    bearer while liveness stays green (the AIM-443 dogfood failure mode:
    141k events lost to ``auth_rejected: HTTP 401`` with a healthy device).
    """
    env = os.environ.get("AIM_COLLECTOR_TOKEN")
    if env:
        return env
    try:
        dt = (state.state_dir() / "device_token").read_text().strip()
        if dt:
            return dt
    except OSError:
        pass
    cfg = load()
    token_file = cfg.get("token_file")
    if token_file:
        try:
            t = Path(token_file).expanduser().read_text().strip()
            if t:
                return t
        except OSError:
            pass
    inline = cfg.get("token")
    if inline:
        return inline
    return None



def hash_salt() -> str | None:
    return os.environ.get("AIM_HASH_SALT") or load().get("hash_salt")

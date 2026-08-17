"""Managed configuration resolution.

The collector is configured by a managed JSON file that endpoint tooling
(Intune/SCCM on Windows, Jamf on macOS, config-management on Linux/WSL) drops at a
machine-wide path. Per-user or per-run env vars override file values, which
keeps local development easy while the fleet runs on the managed file.

Search order for the config file (first existing wins):

1. ``AIM_CONFIG_FILE`` env var (explicit override, used by tests/dev)
2. platform managed path:
   - Windows: ``%ProgramData%\\AI-Monitoring\\collector\\config.json``
   - macOS: ``/Library/Application Support/AI-Monitoring/collector/config.json``
     then ``~/Library/Application Support/AI-Monitoring/collector/config.json``
     then legacy ``/etc/aim-collector/config.json``
   - Linux/WSL: ``/etc/aim-collector/config.json``
3. ``<state dir>/config.json`` (per-user fallback, dev default)

Recognized keys::

    {
      "ingest_url":     "https://ingest.corp.example",
      "token_file":     "C:/ProgramData/AI-Monitoring/collector/token",
      "token":          null,              // dev only; prefer token_file
      "hash_salt":      "org-wide-salt",   // HMAC pseudonymization salt;
                                           // must match ingestion side
      "ca_bundle": "/path/to/ca.pem", // private ingest CA;
                                           // alias key: ca_cert
      "resolve":        ["host:port:ip"]   // curl-style split-horizon
                                           // overrides
    }

Token resolution order: ``AIM_COLLECTOR_TOKEN`` env > ``device_token`` (enrolled) > ``token_file`` contents
> ``token`` field. In managed deployments the token lives in a file deployed
and ACL-protected by endpoint tooling (v1 secure-store handoff: the file is
readable only by the service account / SYSTEM; a DPAPI or OS keychain
integration is the post-pilot hardening path). A plaintext ``token`` key in
the config file is accepted for local development only.
"""

import json
import os
import sys
from pathlib import Path

from . import state

MANAGED_PATH_WINDOWS = r"C:\ProgramData\AI-Monitoring\collector\config.json"
MANAGED_PATH_LINUX = "/etc/aim-collector/config.json"
# first-class Darwin paths (do not fall through to Linux /etc only).
MANAGED_PATH_DARWIN = "/Library/Application Support/AI-Monitoring/collector/config.json"
MANAGED_PATH_DARWIN_USER = "~/Library/Application Support/AI-Monitoring/collector/config.json"


def _managed_candidates() -> list[Path]:
    """Platform managed config files; Darwin is first-class."""
    plat = sys.platform
    if plat.startswith("win"):
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return [Path(base) / "AI-Monitoring" / "collector" / "config.json"]
    if plat == "darwin":
        return [
            Path(MANAGED_PATH_DARWIN),
            Path(MANAGED_PATH_DARWIN_USER).expanduser(),
            Path(MANAGED_PATH_LINUX), # legacy Jamf layout
        ]
    return [Path(MANAGED_PATH_LINUX)]


def _managed_default() -> Path:
    return _managed_candidates()[0]


def config_path() -> Path | None:
    """First config file that exists, in search order; None if none."""
    candidates = []
    if os.environ.get("AIM_CONFIG_FILE"):
        candidates.append(Path(os.environ["AIM_CONFIG_FILE"]).expanduser())
    candidates.extend(_managed_candidates())
    candidates.append(state.state_dir() / "config.json")
    for c in candidates:
        if c.is_file():
            return c
    return None


def load() -> dict:
    """Parsed config dict; {} if no file or unreadable/invalid.

    when harden mode is on (``AIM_HARDEN=1`` / ``harden:
    true``) and the integrity package is importable, refuse unsigned or
    tampered signed envelopes. Tamper events are appended under the state
    dir. Without the integrity package (stdlib-only endpoint installs that
    have not yet pulled the optional dep) behavior is unchanged — bare JSON
    load — so pilot hooks never hard-fail on a missing optional module.
    """
    p = config_path()
    if p is None:
        return {}
    try:
        from collectors.integrity.harden import load_managed_config  # type: ignore

        return load_managed_config(p, state_dir=state.state_dir())
    except Exception:
        try:
            root = Path(__file__).resolve().parents[2]  # collectors/
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

    Order:
      1. ``AIM_COLLECTOR_TOKEN`` env — explicit operator override
      2. ``<state dir>/device_token`` — enrollment-issued per-device bearer
      3. ``token_file`` from managed config
      4. inline ``token`` field (dev only)

    Heartbeat already uses the device token. Preferring it for events too
    means re-enrollment cannot leave the event path on a stale shared
    bearer while liveness stays green (the dogfood failure mode:
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

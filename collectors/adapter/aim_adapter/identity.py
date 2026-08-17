"""Identity / device attribution for adapter-emitted events.

Same HMAC-SHA256 pseudonymization contract as the hand-written collectors
(host_ref / user_ref / repo_ref). Salt: AIM_HASH_SALT → explicit arg →
deterministic dev fallback (not for production).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import platform
from dataclasses import dataclass


@dataclass(frozen=True)
class IdentityContext:
    host_key: str
    user_key: str | None = None
    repo_key: str | None = None


class Pseudonymizer:
    def __init__(self, salt: bytes | str | None = None):
        if salt is None:
            env = os.environ.get("AIM_HASH_SALT")
            salt = env.encode() if env else b"aim-adapter-dev-salt-not-for-production"
        elif isinstance(salt, str):
            salt = salt.encode()
        self._salt = salt

    def hmac64(self, value: str) -> str:
        return hmac.new(self._salt, value.encode(), hashlib.sha256).hexdigest()

    def host_ref(self, host_key: str | None = None) -> str:
        key = (host_key or platform.node() or "unknown-host").strip() or "unknown-host"
        return self.hmac64(key)

    def user_ref(self, user_key: str | None) -> str | None:
        if not user_key or not str(user_key).strip():
            return None
        return self.hmac64(str(user_key).strip())

    def repo_ref(self, repo_key: str | None) -> str | None:
        if not repo_key or not str(repo_key).strip():
            return None
        norm = os.path.normpath(str(repo_key)).lower().replace("\\", "/")
        return self.hmac64(norm)

    def daily_session_id(self, raw_session_id: str, utc_date: str) -> str:
        """Re-hash stable session ids per UTC day (schema session_id rule)."""
        return self.hmac64(f"{utc_date}|{raw_session_id}")


def default_identity(
    *,
    host_key: str | None = None,
    user_key: str | None = None,
    repo_key: str | None = None,
) -> IdentityContext:
    return IdentityContext(
        host_key=host_key or os.environ.get("AIM_DEVICE_ID") or platform.node() or "unknown-host",
        user_key=user_key or os.environ.get("AIM_USER_ID"),
        repo_key=repo_key,
    )

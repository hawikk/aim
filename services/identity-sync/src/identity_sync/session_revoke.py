"""AIM API session-revoke client.

When directory sync marks a user suspended (leaver / IdP disable), call the
platform API so live HMAC sessions are force-denied before AIM_SESSION_TTL_HOURS.

Opt-in: both IDENTITY_SYNC_AIM_API_URL and IDENTITY_SYNC_SESSION_REVOKE_TOKEN
must be set. Failures are logged and returned; they never roll back the
directory upsert (attribution still lands).
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Callable

logger = logging.getLogger(__name__)

# Default reason string written into the revoke watermark + audit trail.
DEFAULT_REASON = "identity-sync:directory-deprovision"


def revoke_sessions(
    emails: list[str],
    *,
    api_url: str,
    token: str,
    reason: str = DEFAULT_REASON,
    timeout_sec: float = 5.0,
    opener: Callable[..., object] | None = None,
) -> dict:
    """POST /api/admin/sessions/revoke for each email.

    Returns a summary dict suitable for merging into the sync result:
      sessions_revoked, sessions_revoke_failed, session_revoke_errors
    """
    base = (api_url or "").rstrip("/")
    bearer = (token or "").strip()
    unique = []
    seen: set[str] = set()
    for raw in emails:
        email = str(raw or "").strip().lower()
        if not email or "@" not in email or email in seen:
            continue
        seen.add(email)
        unique.append(email)

    if not unique:
        return {
            "sessions_revoked": 0,
            "sessions_revoke_failed": 0,
            "session_revoke_errors": [],
        }
    if not base or not bearer:
        return {
            "sessions_revoked": 0,
            "sessions_revoke_failed": len(unique),
            "session_revoke_errors": [
                "session revoke skipped: IDENTITY_SYNC_AIM_API_URL and "
                "IDENTITY_SYNC_SESSION_REVOKE_TOKEN must both be set"
            ],
        }

    url = f"{base}/api/admin/sessions/revoke"
    revoked = 0
    failed = 0
    errors: list[str] = []
    do_open = opener or urllib.request.urlopen

    for email in unique:
        body = json.dumps({"email": email, "reason": reason}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with do_open(req, timeout=timeout_sec) as resp:  # type: ignore[arg-type]
                status = getattr(resp, "status", None) or resp.getcode()
                raw = resp.read()
            if int(status) >= 400:
                failed += 1
                detail = raw.decode("utf-8", errors="replace")[:200]
                errors.append(f"{email}: HTTP {status} {detail}")
                logger.warning("session revoke failed for %s: HTTP %s", email, status)
            else:
                revoked += 1
        except urllib.error.HTTPError as err:
            failed += 1
            detail = err.read().decode("utf-8", errors="replace")[:200] if err.fp else str(err)
            errors.append(f"{email}: HTTP {err.code} {detail}")
            logger.warning("session revoke failed for %s: HTTP %s", email, err.code)
        except Exception as err:  # noqa: BLE001 — best-effort automation path
            failed += 1
            errors.append(f"{email}: {type(err).__name__}: {err}")
            logger.warning("session revoke failed for %s: %s", email, err)

    return {
        "sessions_revoked": revoked,
        "sessions_revoke_failed": failed,
        "session_revoke_errors": errors,
    }

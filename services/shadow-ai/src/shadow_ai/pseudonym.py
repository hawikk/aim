"""Pseudonymization: HMAC-SHA256 over the lowercase primary email.

Byte-identical to services/identity-sync pseudonym.py so OAuth-grant rows join
with the rest of the platform (events.user_pseudonym, /reveal audit path).
The secret MUST be the same value as IDENTITY_SYNC_PSEUDONYM_SECRET in prod.
"""

from __future__ import annotations

import hashlib
import hmac

PSEUDONYM_PREFIX = "u_"


def pseudonymize(email: str, secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        email.strip().lower().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{PSEUDONYM_PREFIX}{digest[:32]}"


def is_pseudonym(value: str) -> bool:
    return value.startswith(PSEUDONYM_PREFIX)

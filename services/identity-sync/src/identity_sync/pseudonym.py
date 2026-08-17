"""Pseudonymization: HMAC-SHA256 over the lowercase primary email.

Properties we rely on:
- Deterministic: all events for one user share one pseudonym, so usage can be
  aggregated per-user without storing the email in the event store.
- Keyed: without the secret, pseudonyms can't be reversed to emails by anyone
  holding only the event store. The key lives in a secret manager in prod.
- Key rotation = deliberate re-key event: old and new pseudonyms stop joining.
  Documented tradeoff; historical dashboards are re-computed at team level only.

Format: "u_" + 32 hex chars (128 bits of HMAC) — collision-safe at our scale and
clearly distinguishable from raw identifiers in logs and dashboards.
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

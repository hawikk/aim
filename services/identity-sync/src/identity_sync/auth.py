"""Caller authentication for the gated endpoints.

The bug this replaces: ``POST /reveal`` and ``POST /service-identities`` used
to derive the authorisation decision and the audit actor from the
client-supplied ``X-AIM-Role`` / ``X-AIM-Actor`` headers. Anything on the
compose network could mint those, which meant full de-pseudonymisation plus an
audit trail authored by the attacker. Headers are gone; the caller now proves
identity with a bearer JWT the service verifies itself:

- **Prod path** — RS/ES against the platform IdP's JWKS
  (``IDENTITY_SYNC_JWT_JWKS_URL``), the "gateway-validated JWT claim" design in
  docs/identity-mapping-design.md.
- **In-network path** — HS256 with a shared secret
  (``IDENTITY_SYNC_JWT_HS256_SECRET``) for service-to-service calls and the dev
  stack. The secret lives only in server-side env, so a caller cannot mint a
  token without a credential leak. This is the "service-token identity for
  in-network callers" the design allows.

Fail closed: with neither verifier configured, every gated call is denied and
the service says so loudly at startup. A verifier that is present but rejects
the token is a 403, never a silent fall-through.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import lru_cache

import jwt
from jwt import PyJWKClient

from .config import Settings

log = logging.getLogger(__name__)

#: Written to audit_log.actor when no verifiable principal exists. Deliberately
#: not an email shape, so an unauthenticated attempt can never impersonate one.
ANONYMOUS_ACTOR = "anonymous"


class AuthError(Exception):
    """Authentication failed. The message is audit-safe (no token material)."""


@dataclass(frozen=True)
class Principal:
    """A verified caller. Constructed ONLY from validated JWT claims."""

    actor: str  # email claim, falling back to sub
    groups: tuple[str, ...] = field(default_factory=tuple)

    @property
    def role_for_audit(self) -> str:
        """What the audit log records as actor_role: the caller's real groups."""
        return ",".join(self.groups)[:128]


@lru_cache(maxsize=4)
def _jwk_client(jwks_url: str) -> PyJWKClient:
    return PyJWKClient(jwks_url)


def verifier_configured(settings: Settings) -> bool:
    return bool(settings.jwt_hs256_secret or settings.jwt_jwks_url)


def _decode(token: str, settings: Settings) -> dict:
    """Verify signature + expiry (+ iss/aud when configured) and return claims."""
    kwargs = {
        "issuer": settings.jwt_issuer or None,
        "audience": settings.jwt_audience or None,
        "options": {"require": ["exp"]},
    }
    if settings.jwt_hs256_secret:
        return jwt.decode(token, settings.jwt_hs256_secret, algorithms=["HS256"], **kwargs)
    signing_key = _jwk_client(settings.jwt_jwks_url).get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
        **kwargs,
    )


def authenticate(token: str | None, settings: Settings) -> Principal:
    """Resolve a bearer token to a verified Principal, or raise AuthError."""
    if not token:
        raise AuthError("missing bearer token")
    if not verifier_configured(settings):
        # Misconfiguration must look like an outage, not like an open door.
        raise AuthError(
            "no JWT verifier configured "
            "(set IDENTITY_SYNC_JWT_HS256_SECRET or IDENTITY_SYNC_JWT_JWKS_URL)"
        )
    try:
        claims = _decode(token, settings)
    except jwt.PyJWTError as exc:
        raise AuthError(f"token rejected: {exc.__class__.__name__}") from exc
    actor = claims.get("email") or claims.get("sub") or ""
    if not isinstance(actor, str) or not actor:
        raise AuthError("token has no email/sub claim")
    groups = claims.get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    verified_groups = tuple(g for g in groups if isinstance(g, str) and g)
    return Principal(actor=actor, groups=verified_groups)

"""Ed25519 signed bundles for collector config and enforcement policy.

Envelope shape (version 1)::

    {
      "schema": "aim.signed-bundle/v1",
      "alg": "Ed25519",
      "key_id": "aim-config-prod-2026",
      "signed_at": "2026-08-01T12:00:00Z",
      "payload": { ... arbitrary JSON object ... },
      "signature": "<base64 raw 64-byte Ed25519 signature over canonical payload>"
    }

The signature covers the UTF-8 bytes of ``canonical_json(payload)`` only —
not the envelope metadata — so ``signed_at`` can be rewritten without
invalidating a legitimate payload, but any payload mutation fails verify.

Public keys are loaded from:

1. ``AIM_CONFIG_PUBKEY`` env (base64 raw 32-byte public key)
2. ``AIM_CONFIG_PUBKEY_FILE`` path
3. managed path:
   Linux ``/etc/aim-collector/config-pubkey.b64`` /
   macOS ``/Library/Application Support/AI-Monitoring/collector/config-pubkey.b64``
   (then user Application Support, then legacy ``/etc/aim-collector``) /
   Windows ``%ProgramData%\\AI-Monitoring\\collector\\config-pubkey.b64``
4. explicit argument to ``verify_payload`` / ``load_public_key``

Private keys are **never** read from managed fleet paths by the collector —
signing is an ops/CI action via ``scripts/sign_collector_bundle.py``.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

SCHEMA = "aim.signed-bundle/v1"
ALG = "Ed25519"
MANAGED_PUBKEY_LINUX = "/etc/aim-collector/config-pubkey.b64"
MANAGED_PUBKEY_DARWIN = "/Library/Application Support/AI-Monitoring/collector/config-pubkey.b64"
MANAGED_PUBKEY_DARWIN_USER = "~/Library/Application Support/AI-Monitoring/collector/config-pubkey.b64"
MANAGED_PUBKEY_WINDOWS = r"C:\ProgramData\AI-Monitoring\collector\config-pubkey.b64"


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding for signing (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.strip().encode("ascii"), validate=False)


def generate_keypair() -> tuple[bytes, bytes]:
    """Return ``(private_raw_32, public_raw_32)`` for tests / offline keygen."""
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_raw, pub_raw


def load_private_key(raw_or_b64: bytes | str) -> Ed25519PrivateKey:
    if isinstance(raw_or_b64, str):
        raw = _b64d(raw_or_b64)
    else:
        raw = raw_or_b64
    if len(raw) != 32:
        raise ValueError(f"Ed25519 private key must be 32 bytes, got {len(raw)}")
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_public_key(raw_or_b64: bytes | str | None = None) -> Ed25519PublicKey | None:
    """Resolve a public key from arg / env / managed path. None if unavailable."""
    if raw_or_b64 is not None:
        raw = _b64d(raw_or_b64) if isinstance(raw_or_b64, str) else raw_or_b64
        if len(raw) != 32:
            raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
        return Ed25519PublicKey.from_public_bytes(raw)

    env = os.environ.get("AIM_CONFIG_PUBKEY")
    if env:
        return load_public_key(env)

    env_file = os.environ.get("AIM_CONFIG_PUBKEY_FILE")
    candidates: list[Path] = []
    if env_file:
        candidates.append(Path(env_file).expanduser())
    if sys.platform.startswith("win"):
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        candidates.append(Path(base) / "AI-Monitoring" / "collector" / "config-pubkey.b64")
    elif sys.platform == "darwin":
        candidates.append(Path(MANAGED_PUBKEY_DARWIN))
        candidates.append(Path(MANAGED_PUBKEY_DARWIN_USER).expanduser())
        candidates.append(Path(MANAGED_PUBKEY_LINUX))
    else:
        candidates.append(Path(MANAGED_PUBKEY_LINUX))

    for c in candidates:
        try:
            if c.is_file():
                return load_public_key(c.read_text())
        except (OSError, ValueError):
            continue
    return None


@dataclass(frozen=True)
class SignedBundle:
    payload: dict
    signature: str
    key_id: str
    signed_at: str
    alg: str = ALG
    schema: str = SCHEMA

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "alg": self.alg,
            "key_id": self.key_id,
            "signed_at": self.signed_at,
            "payload": self.payload,
            "signature": self.signature,
        }


def sign_payload(
    payload: dict,
    private_key: Ed25519PrivateKey | bytes | str,
    *,
    key_id: str,
    signed_at: str | None = None,
) -> SignedBundle:
    if not isinstance(payload, dict):
        raise TypeError("payload must be a JSON object")
    if isinstance(private_key, (bytes, str)):
        private_key = load_private_key(private_key)
    sig = private_key.sign(canonical_json(payload))
    return SignedBundle(
        payload=payload,
        signature=_b64e(sig),
        key_id=key_id,
        signed_at=signed_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def is_signed_envelope(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and obj.get("schema") == SCHEMA
        and isinstance(obj.get("payload"), dict)
        and isinstance(obj.get("signature"), str)
    )


def verify_payload(
    envelope: dict | SignedBundle,
    public_key: Ed25519PublicKey | bytes | str | None = None,
    *,
    expected_key_id: str | None = None,
) -> tuple[bool, dict | None, str]:
    """Verify a signed envelope.

    Returns ``(ok, payload_or_None, reason)``.
    ``reason`` is ``"ok"`` on success, otherwise a short machine-readable code.
    """
    if isinstance(envelope, SignedBundle):
        envelope = envelope.to_dict()
    if not isinstance(envelope, dict):
        return False, None, "not_a_dict"
    if envelope.get("schema") != SCHEMA:
        return False, None, "unknown_schema"
    if envelope.get("alg") != ALG:
        return False, None, "unsupported_alg"
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return False, None, "missing_payload"
    sig_b64 = envelope.get("signature")
    if not isinstance(sig_b64, str) or not sig_b64:
        return False, None, "missing_signature"
    key_id = envelope.get("key_id")
    if expected_key_id is not None and key_id != expected_key_id:
        return False, None, "key_id_mismatch"

    try:
        pub = load_public_key(public_key) if not isinstance(public_key, Ed25519PublicKey) else public_key
    except ValueError:
        return False, None, "bad_public_key"
    if pub is None:
        return False, None, "no_public_key"

    try:
        sig = _b64d(sig_b64)
    except Exception:
        return False, None, "bad_signature_encoding"
    try:
        pub.verify(sig, canonical_json(payload))
    except InvalidSignature:
        return False, None, "invalid_signature"
    except Exception:
        return False, None, "verify_error"
    return True, payload, "ok"

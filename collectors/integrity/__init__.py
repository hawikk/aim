"""Independence / tamper-evidence controls for endpoint collectors.

This package is the reference implementation for Dimension 16 (independence
from the agent execution loop):

- **Signed updates** — Ed25519 envelopes over managed config + enforcement
  bundles so an agent process cannot rewrite policy without the ops key.
- **Harden mode** — refuse unsigned/tampered bundles; emit tamper events.
- **Out-of-band health** — host-level signal independent of the coding-agent
  process and of the per-user collector daemon.
- **Anti-bypass suite** — automated simulations of agent disable/spoof paths.
- **Continuous attestation** — architectural invariants that must hold in CI.

Collectors may import these modules directly (dev/CI) or vendor a subset.
Production fleet keys never live in this package — only the public key
material is deployed to endpoints; the private key stays offline / in ops.
"""

from .harden import (
    ALERTABLE_TAMPER_KINDS,
    HardenResult,
    TamperEvent,
    append_tamper_event,
    detect_and_alert,
    harden_enabled,
    load_managed_config,
    load_signed_json,
    tamper_to_alert_finding,
    verify_signed_artifact,
)
from .signing import (
    SignedBundle,
    sign_payload,
    verify_payload,
    canonical_json,
    load_public_key,
    load_private_key,
    generate_keypair,
)
from .oob_health import (
    write_oob_heartbeat,
    oob_heartbeat_stale,
    OOB_HEARTBEAT_DEFAULT,
)
from .attestation import run_attestation

__all__ = [
    "ALERTABLE_TAMPER_KINDS",
    "HardenResult",
    "load_signed_json",
    "load_managed_config",
    "verify_signed_artifact",
    "harden_enabled",
    "TamperEvent",
    "append_tamper_event",
    "tamper_to_alert_finding",
    "detect_and_alert",
    "SignedBundle",
    "sign_payload",
    "verify_payload",
    "canonical_json",
    "load_public_key",
    "load_private_key",
    "generate_keypair",
    "write_oob_heartbeat",
    "oob_heartbeat_stale",
    "OOB_HEARTBEAT_DEFAULT",
    "run_attestation",
]

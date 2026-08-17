"""Harden-mode load path for signed collector config / enforcement (AIM-639).

In harden mode the collector refuses to apply unsigned or tampered managed
JSON. This is the control that makes independence *provable*: an agent
running as the engineer cannot silently flip ``mode: enforce`` → ``shadow``
or point ingest at an attacker by rewriting a local config file.

Fail-open vs fail-closed:

- **Policy decisions** (block a prompt): still fail-open on internal errors
  (existing AIM-110 contract — never break the tool on our outage).
- **Config *updates* and harden loads**: fail-closed. A tampered signed
  bundle yields an empty payload + a ``TamperEvent``; the previous good
  config (if any) is retained by the caller. Unsigned bare JSON is only
  accepted when harden mode is off (dev / pre-pilot).

Harden mode is on when any of:

1. ``AIM_HARDEN=1`` / ``true`` / ``yes``
2. payload or bare config has ``"harden": true``
3. a public key is resolvable **and** the file is a signed envelope
   (signed files always verify; unsigned still allowed unless 1/2)
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .signing import (
    is_signed_envelope,
    load_public_key,
    verify_payload,
)


def harden_enabled(env: dict[str, str] | None = None, cfg_hint: dict | None = None) -> bool:
    env = env if env is not None else os.environ
    raw = (env.get("AIM_HARDEN") or "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if isinstance(cfg_hint, dict) and cfg_hint.get("harden") is True:
        return True
    return False


@dataclass
class TamperEvent:
    """Metadata-only tamper signal — no file contents, no secrets."""

    kind: str  # unsigned_in_harden | invalid_signature | unreadable | not_object
    path: str
    reason: str
    ts: float = field(default_factory=lambda: time.time())
    key_id: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HardenResult:
    ok: bool
    payload: dict
    path: Path | None
    tamper: TamperEvent | None = None
    signed: bool = False
    key_id: str | None = None
    verify_reason: str = "n/a"

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "ok": self.ok,
            "signed": self.signed,
            "key_id": self.key_id,
            "verify_reason": self.verify_reason,
            "path": str(self.path) if self.path else None,
            "payload_keys": sorted(self.payload.keys()) if self.payload else [],
        }
        if self.tamper:
            d["tamper"] = self.tamper.to_dict()
        return d


def load_signed_json(
    path: Path | str | None,
    *,
    public_key=None,
    harden: bool | None = None,
    expected_key_id: str | None = None,
    env: dict[str, str] | None = None,
) -> HardenResult:
    """Load a JSON file, verifying signature when present or when harden is on.

    Parameters
    ----------
    path:
        File path, or None (treated as missing → empty ok when not harden).
    public_key:
        Optional explicit key material (bytes/b64/key object).
    harden:
        Force harden on/off; None → auto via ``harden_enabled``.
    """
    env = env if env is not None else os.environ
    if path is None:
        forced = bool(harden) if harden is not None else harden_enabled(env)
        if forced:
            return HardenResult(
                ok=False,
                payload={},
                path=None,
                tamper=TamperEvent(kind="missing", path="", reason="no_config_path"),
            )
        return HardenResult(ok=True, payload={}, path=None, verify_reason="no_file")

    p = Path(path)
    try:
        raw_text = p.read_text(encoding="utf-8")
        obj = json.loads(raw_text)
    except OSError as e:
        return HardenResult(
            ok=False,
            payload={},
            path=p,
            tamper=TamperEvent(kind="unreadable", path=str(p), reason=type(e).__name__),
        )
    except json.JSONDecodeError:
        return HardenResult(
            ok=False,
            payload={},
            path=p,
            tamper=TamperEvent(kind="unreadable", path=str(p), reason="json_decode"),
        )

    if not isinstance(obj, dict):
        return HardenResult(
            ok=False,
            payload={},
            path=p,
            tamper=TamperEvent(kind="not_object", path=str(p), reason="root_not_object"),
        )

    # Hint harden from payload if auto
    if harden is None:
        hint = obj.get("payload") if is_signed_envelope(obj) else obj
        harden = harden_enabled(env, hint if isinstance(hint, dict) else None)

    if is_signed_envelope(obj):
        pub = public_key
        if pub is None:
            pub = load_public_key()
        ok, payload, reason = verify_payload(obj, pub, expected_key_id=expected_key_id)
        if not ok or payload is None:
            return HardenResult(
                ok=False,
                payload={},
                path=p,
                signed=True,
                key_id=obj.get("key_id") if isinstance(obj.get("key_id"), str) else None,
                verify_reason=reason,
                tamper=TamperEvent(
                    kind="invalid_signature",
                    path=str(p),
                    reason=reason,
                    key_id=obj.get("key_id") if isinstance(obj.get("key_id"), str) else None,
                ),
            )
        return HardenResult(
            ok=True,
            payload=payload,
            path=p,
            signed=True,
            key_id=obj.get("key_id") if isinstance(obj.get("key_id"), str) else None,
            verify_reason="ok",
        )

    # Bare (unsigned) JSON
    if harden:
        return HardenResult(
            ok=False,
            payload={},
            path=p,
            signed=False,
            verify_reason="unsigned_in_harden",
            tamper=TamperEvent(
                kind="unsigned_in_harden",
                path=str(p),
                reason="unsigned_in_harden",
            ),
        )

    return HardenResult(
        ok=True,
        payload=obj,
        path=p,
        signed=False,
        verify_reason="unsigned_allowed",
    )


def load_managed_config(
    path: Path | str | None,
    *,
    state_dir: Path | str | None = None,
    public_key=None,
    harden: bool | None = None,
    expected_key_id: str | None = None,
    env: dict[str, str] | None = None,
) -> dict:
    """Collector-facing load helper (AIM-749).

    Returns the config payload dict, or ``{}`` when the file is missing or
    refused under harden. On tamper, optionally appends a metadata-only
    event under ``state_dir``. Callers that lack the integrity package should
    fall back to bare ``json.loads`` so pilot hooks never hard-fail.
    """
    res = load_signed_json(
        path,
        public_key=public_key,
        harden=harden,
        expected_key_id=expected_key_id,
        env=env,
    )
    if res.tamper is not None and state_dir is not None:
        append_tamper_event(state_dir, res.tamper)
    if not res.ok:
        return {}
    return res.payload if isinstance(res.payload, dict) else {}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_signed_artifact(
    artifact_path: Path | str,
    *,
    manifest_path: Path | str | None = None,
    expected_sha256: str | None = None,
    public_key=None,
    harden: bool | None = None,
    env: dict[str, str] | None = None,
    state_dir: Path | str | None = None,
) -> HardenResult:
    """Refuse unsigned/mismatched binary (or any file) updates in harden mode.

    Two equivalent proof paths (AIM-749 acceptance — config **and** binary):

    1. ``expected_sha256`` — direct digest check of ``artifact_path``.
    2. ``manifest_path`` — signed envelope whose payload lists digests::

           {
             "artifacts": [
               {"name": "aim-collector.tgz", "sha256": "<hex>"}
             ]
           }

       Match is by basename of ``artifact_path``.

    In harden mode, a missing expected digest, digest mismatch, or unsigned
    manifest yields a ``TamperEvent`` and ``ok=False``. When harden is off,
    digest mismatches still fail closed if an expected digest is provided
    (tamper evidence), but unsigned manifests are allowed only as advisory.
    """
    env = env if env is not None else os.environ
    art = Path(artifact_path)
    if harden is None:
        harden = harden_enabled(env)

    if not art.is_file():
        tamper = TamperEvent(kind="missing", path=str(art), reason="artifact_missing")
        if state_dir is not None:
            append_tamper_event(state_dir, tamper)
        return HardenResult(ok=False, payload={}, path=art, tamper=tamper, verify_reason="artifact_missing")

    try:
        digest = _sha256_file(art)
    except OSError as e:
        tamper = TamperEvent(kind="unreadable", path=str(art), reason=type(e).__name__)
        if state_dir is not None:
            append_tamper_event(state_dir, tamper)
        return HardenResult(ok=False, payload={}, path=art, tamper=tamper, verify_reason="unreadable")

    expected = (expected_sha256 or "").strip().lower() or None
    manifest_payload: dict = {}
    signed = False
    key_id: str | None = None

    if manifest_path is not None:
        mres = load_signed_json(
            manifest_path,
            public_key=public_key,
            harden=harden,
            env=env,
        )
        if not mres.ok:
            # Propagate unsigned/tampered manifest refusal.
            if state_dir is not None and mres.tamper is not None:
                append_tamper_event(state_dir, mres.tamper)
            return mres
        signed = mres.signed
        key_id = mres.key_id
        manifest_payload = mres.payload
        if expected is None:
            name = art.name
            arts = manifest_payload.get("artifacts")
            if isinstance(arts, list):
                for entry in arts:
                    if not isinstance(entry, dict):
                        continue
                    if entry.get("name") == name or entry.get("path") == name:
                        exp = entry.get("sha256") or entry.get("digest")
                        if isinstance(exp, str) and exp.strip():
                            expected = exp.strip().lower()
                            break
            # also allow single-file form
            if expected is None:
                exp = manifest_payload.get("sha256") or manifest_payload.get("digest")
                if isinstance(exp, str) and exp.strip():
                    expected = exp.strip().lower()

    if expected is None:
        if harden:
            tamper = TamperEvent(
                kind="unsigned_in_harden",
                path=str(art),
                reason="no_expected_digest",
            )
            if state_dir is not None:
                append_tamper_event(state_dir, tamper)
            return HardenResult(
                ok=False,
                payload={},
                path=art,
                signed=signed,
                key_id=key_id,
                verify_reason="no_expected_digest",
                tamper=tamper,
            )
        return HardenResult(
            ok=True,
            payload={"sha256": digest, "path": str(art), **manifest_payload},
            path=art,
            signed=signed,
            key_id=key_id,
            verify_reason="digest_not_required",
        )

    if digest != expected:
        tamper = TamperEvent(
            kind="digest_mismatch",
            path=str(art),
            reason="sha256_mismatch",
            key_id=key_id,
        )
        if state_dir is not None:
            append_tamper_event(state_dir, tamper)
        return HardenResult(
            ok=False,
            payload={},
            path=art,
            signed=signed,
            key_id=key_id,
            verify_reason="sha256_mismatch",
            tamper=tamper,
        )

    return HardenResult(
        ok=True,
        payload={"sha256": digest, "path": str(art), "name": art.name, **manifest_payload},
        path=art,
        signed=signed,
        key_id=key_id,
        verify_reason="ok",
    )


def append_tamper_event(state_dir: Path | str, event: TamperEvent) -> Path | None:
    """Append a metadata-only tamper event to ``<state>/tamper-events.jsonl``."""
    try:
        d = Path(state_dir)
        d.mkdir(parents=True, exist_ok=True)
        out = d / "tamper-events.jsonl"
        with out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
        return out
    except OSError:
        return None


# Kinds that mean an agent (or local rewrite) tried to disable/spoof controls.
# Used by the anti-bypass suite and by collectors when raising SOC-facing alerts.
ALERTABLE_TAMPER_KINDS = frozenset(
    {
        "unsigned_in_harden",
        "invalid_signature",
        "missing",
        "unreadable",
        "not_object",
        "digest_mismatch",
    }
)


def tamper_to_alert_finding(
    event: TamperEvent,
    *,
    host_id: str | None = None,
    user_id: str = "local-endpoint",
    tool: str = "aim-collector",
    finding_id: str | None = None,
) -> dict[str, Any]:
    """Map a tamper event to a metadata-only alert finding (AIM-750).

    Shape matches ``packages/alerting`` Finding fields so a future spool
    forwarder can hand these to Sentinel without re-encoding. No file
    contents, no secrets — only kind / reason / key_id / basename path.

    ``findingType`` is ``policy_violation`` (approved High taxonomy entry)
    because rewrite of signed enforce/config is a deliberate policy-control
    breach, not a weak anomaly.
    """
    from datetime import datetime, timezone

    basename = Path(event.path).name if event.path else ""
    flags = [event.kind]
    if event.reason and event.reason != event.kind:
        flags.append(event.reason)
    if event.key_id:
        flags.append(f"key_id={event.key_id}")
    if basename:
        flags.append(f"file={basename}")
    ts = datetime.fromtimestamp(event.ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    fid = finding_id or f"tamper-{event.kind}-{int(event.ts)}"
    return {
        "findingId": fid,
        "findingType": "policy_violation",
        "title": f"Collector integrity tamper: {event.kind}",
        "timestamp": ts,
        "userId": user_id,
        "tool": tool,
        "hostId": host_id,
        "matchFlags": ",".join(flags),
        "source": "collector.integrity",
        "alert": True,
        "severityHint": "High",
    }


def detect_and_alert(
    path: Path | str | None,
    *,
    public_key=None,
    harden: bool | None = None,
    expected_key_id: str | None = None,
    env: dict[str, str] | None = None,
    state_dir: Path | str | None = None,
    host_id: str | None = None,
) -> tuple[HardenResult, dict[str, Any] | None]:
    """Load path; on tamper, record event and return an alert finding.

    Returns ``(HardenResult, alert_finding_or_None)``. Used by the anti-bypass
    suite as the single "detect/alert" contract under test.
    """
    res = load_signed_json(
        path,
        public_key=public_key,
        harden=harden,
        expected_key_id=expected_key_id,
        env=env,
    )
    alert: dict[str, Any] | None = None
    if res.tamper is not None and res.tamper.kind in ALERTABLE_TAMPER_KINDS:
        if state_dir is not None:
            append_tamper_event(state_dir, res.tamper)
        alert = tamper_to_alert_finding(res.tamper, host_id=host_id)
    return res, alert

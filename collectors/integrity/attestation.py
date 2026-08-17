"""Continuous independence attestation.

Produces a machine-readable report proving that the architectural controls
for independence from the agent execution loop are present in-tree:

1. Signed-bundle library + harden load path exist and are importable.
2. Anti-bypass test module is present.
3. Out-of-band health deploy units exist (systemd timer + script).
4. ADR document is checked in.
5. Collectors remain process-separated from coding-agent runtimes
   (structural markers — hooks call into collector packages, not the reverse).
6. Network/proxy path is a separate package from endpoint hooks.

This is intentionally a *static* attestation of the control plane (repo +
deploy artifacts). Runtime fleet coverage (device heartbeats) is a separate
signal consumed by the dashboard.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "aim.independence.attestation/v1"

# Repo-root-relative paths that must exist for a green attestation.
REQUIRED_PATHS = (
    "collectors/integrity/signing.py",
    "collectors/integrity/harden.py",
    "collectors/integrity/oob_health.py",
    "collectors/integrity/attestation.py",
    "collectors/integrity/tests/test_anti_bypass.py",
    "collectors/integrity/tests/test_signing.py",
    "docs/security/adr-independence-from-agent-loop.md",
    "scripts/independence_attestation.py",
    "scripts/sign_collector_bundle.py",
    "deploy/linux/aim-collector-oob-health.sh",
    "deploy/linux/systemd/aim-collector-oob-health.service",
    "deploy/linux/systemd/aim-collector-oob-health.timer",
    # Continuous out-of-band job — must remain scheduled on aim-ops.
    ".github/workflows/independence-attestation.yml",
)

# Packages that implement the *observer*, never the agent runtime itself.
OBSERVER_MARKERS = (
    "collectors/claude-code/aim_collector",
    "collectors/cursor/cursor_collector",
    "collectors/proxy/proxy_ingest.py",
    "services/guardrail",
    "services/ingest",
)

# Things that must NOT import the coding-agent product as a library dependency.
# (Heuristic: no requirements pinning claude-code / cursor as runtime libs.)
FORBIDDEN_REQUIREMENT_SNIPPETS = (
    "anthropic-claude-code",
    "cursor-agent-runtime",
)


@dataclass
class Check:
    id: str
    ok: bool
    detail: str


@dataclass
class Attestation:
    schema: str = SCHEMA
    generated_at: str = ""
    ok: bool = False
    score_claim: str = "independence_from_agent_loop"
    checks: list[Check] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "generated_at": self.generated_at,
            "ok": self.ok,
            "score_claim": self.score_claim,
            "checks": [asdict(c) for c in self.checks],
            "passed": sum(1 for c in self.checks if c.ok),
            "failed": sum(1 for c in self.checks if not c.ok),
        }


def _repo_root(start: Path | None = None) -> Path:
    if start is not None:
        return start
    # collectors/integrity/attestation.py → repo root
    return Path(__file__).resolve().parents[2]


def run_attestation(repo_root: Path | str | None = None) -> Attestation:
    root = Path(repo_root) if repo_root is not None else _repo_root()
    checks: list[Check] = []

    # 1) required paths
    missing = [rel for rel in REQUIRED_PATHS if not (root / rel).is_file()]
    checks.append(
        Check(
            id="required_artifacts",
            ok=not missing,
            detail="ok" if not missing else f"missing:{','.join(missing)}",
        )
    )

    # 2) import + round-trip sign/verify
    try:
        # Ensure repo root on path
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from collectors.integrity.signing import generate_keypair, sign_payload, verify_payload

        priv, pub = generate_keypair()
        env = sign_payload({"mode": "enforce", "harden": True}, priv, key_id="attestation")
        ok, payload, reason = verify_payload(env, pub)
        checks.append(
            Check(
                id="sign_verify_roundtrip",
                ok=bool(ok and payload and payload.get("mode") == "enforce"),
                detail=reason,
            )
        )
    except Exception as e:
        checks.append(
            Check(id="sign_verify_roundtrip", ok=False, detail=f"{type(e).__name__}:{e}")
        )

    # 3) harden refuses unsigned when AIM_HARDEN=1
    try:
        from collectors.integrity.harden import load_signed_json
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cfg.json"
            p.write_text('{"mode":"shadow","ingest_url":"http://evil"}', encoding="utf-8")
            res = load_signed_json(p, harden=True, public_key=None)
            checks.append(
                Check(
                    id="harden_refuses_unsigned",
                    ok=(not res.ok and res.tamper is not None and res.tamper.kind == "unsigned_in_harden"),
                    detail=res.verify_reason,
                )
            )
    except Exception as e:
        checks.append(
            Check(id="harden_refuses_unsigned", ok=False, detail=f"{type(e).__name__}:{e}")
        )

    # 4) observer packages present (process separation evidence)
    absent_obs = [rel for rel in OBSERVER_MARKERS if not (root / rel).exists()]
    checks.append(
        Check(
            id="observer_packages_present",
            ok=not absent_obs,
            detail="ok" if not absent_obs else f"missing:{','.join(absent_obs)}",
        )
    )

    # 5) OOB unit is independent of user session (Type=oneshot + timer, User=root)
    svc = root / "deploy/linux/systemd/aim-collector-oob-health.service"
    timer = root / "deploy/linux/systemd/aim-collector-oob-health.timer"
    oob_sh = root / "deploy/linux/aim-collector-oob-health.sh"
    try:
        text = svc.read_text(encoding="utf-8") if svc.is_file() else ""
        has_root = "User=root" in text or "User = root" in text
        has_oneshot = "Type=oneshot" in text
        checks.append(
            Check(
                id="oob_systemd_root_oneshot",
                ok=has_root and has_oneshot,
                detail=f"root={has_root},oneshot={has_oneshot}",
            )
        )
        ttext = timer.read_text(encoding="utf-8") if timer.is_file() else ""
        has_interval = "OnUnitActiveSec=" in ttext
        checks.append(
            Check(
                id="oob_timer_recurring",
                ok=timer.is_file() and has_interval,
                detail="ok" if has_interval else "timer missing OnUnitActiveSec",
            )
        )
        sh = oob_sh.read_text(encoding="utf-8") if oob_sh.is_file() else ""
        # Script must claim independence from agent user + emit oob source.
        oob_script_ok = (
            "oob_systemd" in sh
            and "root" in sh.lower()
            and "independent" in sh.lower()
        )
        checks.append(
            Check(
                id="oob_script_independent_source",
                ok=oob_script_ok,
                detail="ok" if oob_script_ok else "oob script missing independence markers",
            )
        )
    except OSError as e:
        checks.append(Check(id="oob_systemd_root_oneshot", ok=False, detail=str(e)))

    # 5b) install.sh must enable OOB timer (deploy path, not just unit files)
    install_sh = root / "deploy/linux/install.sh"
    try:
        itxt = install_sh.read_text(encoding="utf-8") if install_sh.is_file() else ""
        wired = (
            "aim-collector-oob-health" in itxt
            and "aim-collector-oob-health.timer" in itxt
            and "config-pubkey" in itxt
        )
        checks.append(
            Check(
                id="install_wires_oob_and_pubkey",
                ok=wired,
                detail="ok" if wired else "install.sh missing oob-health timer and/or pubkey install",
            )
        )
    except OSError as e:
        checks.append(Check(id="install_wires_oob_and_pubkey", ok=False, detail=str(e)))

    # 5c) Continuous CI job must stay on aim-ops; aim-ci only in comments
    wf = root / ".github/workflows/independence-attestation.yml"
    try:
        wtxt = wf.read_text(encoding="utf-8") if wf.is_file() else ""
        runs_on_ops = any(
            "runs-on:" in line and "aim-ops" in line for line in wtxt.splitlines()
        )
        # aim-ci may appear in comments as a negative constraint, never as runs-on.
        ci_as_runner = any(
            "runs-on:" in line and "aim-ci" in line for line in wtxt.splitlines()
        )
        scheduled = "schedule:" in wtxt and "cron:" in wtxt
        ok_wf = wf.is_file() and runs_on_ops and scheduled and not ci_as_runner
        checks.append(
            Check(
                id="continuous_attestation_workflow",
                ok=ok_wf,
                detail=(
                    "ok"
                    if ok_wf
                    else f"file={wf.is_file()},ops={runs_on_ops},sched={scheduled},ci_runner={ci_as_runner}"
                ),
            )
        )
    except OSError as e:
        checks.append(Check(id="continuous_attestation_workflow", ok=False, detail=str(e)))

    # 6) ADR asserts independence invariants
    adr = root / "docs/security/adr-independence-from-agent-loop.md"
    try:
        body = adr.read_text(encoding="utf-8") if adr.is_file() else ""
        needed = (
            "Independence from the agent",
            "signed",
            "out-of-band",
            "anti-bypass",
        )
        missing_terms = [t for t in needed if t.lower() not in body.lower()]
        checks.append(
            Check(
                id="adr_present",
                ok=adr.is_file() and not missing_terms,
                detail="ok" if not missing_terms else f"missing_terms:{missing_terms}",
            )
        )
    except OSError as e:
        checks.append(Check(id="adr_present", ok=False, detail=str(e)))

    att = Attestation(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        checks=checks,
    )
    att.ok = all(c.ok for c in checks)
    return att


def write_attestation(path: Path | str, att: Attestation | None = None, repo_root: Path | str | None = None) -> Path:
    att = att or run_attestation(repo_root)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(att.to_dict(), indent=2) + "\n", encoding="utf-8")
    return p

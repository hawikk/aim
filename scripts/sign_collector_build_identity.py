#!/usr/bin/env python3
"""Sign collector build identity blobs for release embeds.

Produces ``build_attestation.json`` files that collectors load at runtime.
Signing uses OpenSSL Ed25519 (no Python crypto deps) so air-gapped / CI
builders with a bare OpenSSL work.

Canonical message (must match ingest ``canonicalBuildMessage``)::

    AIM-BUILD-ATTEST-V1
    package=<package>
    version=<version>
    tool=<tool>
    git_sha=<git_sha|->
    built_at=<built_at|->

Usage (release)::

    openssl genpkey -algorithm Ed25519 -out release-ed25519.pem
    openssl pkey -in release-ed25519.pem -pubout -out release-ed25519.pub.pem

    python3 scripts/sign_collector_build_identity.py \\
      --private-key path/to/release-ed25519.pem \\
      --key-id aim-release-ed25519-v1 \\
      --version 0.1.0 \\
      --git-sha \"$GITHUB_SHA\" \\
      --write-collectors

    python3 scripts/sign_collector_build_identity.py \\
      --public-key path/to/release-ed25519.pub.pem \\
      --key-id aim-release-ed25519-v1 \\
      --print-ingest-env

    python3 scripts/sign_collector_build_identity.py --self-test
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "collectors" / "build-identity"))
from build_attestation import canonical_message  # noqa: E402

COLLECTOR_TOOLS = [
    ("claude-code", ROOT / "collectors" / "claude-code" / "aim_collector"),
    ("cursor", ROOT / "collectors" / "cursor" / "cursor_collector"),
    ("kilo-code", ROOT / "collectors" / "kilo-code" / "kilo_collector"),
    ("kimi-code", ROOT / "collectors" / "kimi-code" / "kimi_collector"),
    ("grok-build", ROOT / "collectors" / "grok-build" / "grok_collector"),
    ("github-copilot", ROOT / "collectors" / "github-copilot" / "copilot_collector"),
]

DEFAULT_PACKAGE = "aimonitoring-security"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _pub_raw_from_pem(pub_pem: Path) -> bytes:
    der = subprocess.check_output(
        ["openssl", "pkey", "-in", str(pub_pem), "-pubin", "-outform", "DER"],
    )
    if len(der) < 32:
        raise SystemExit(f"public key DER too short: {len(der)}")
    return der[-32:]


def _sign(private_key: Path, message: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as msg_f:
        msg_path = Path(msg_f.name)
        msg_f.write(message)
    sig_path = msg_path.with_suffix(".sig")
    try:
        subprocess.check_call(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(private_key),
                "-rawin",
                "-in",
                str(msg_path),
                "-out",
                str(sig_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        return sig_path.read_bytes()
    finally:
        msg_path.unlink(missing_ok=True)
        sig_path.unlink(missing_ok=True)


def build_attestation(
    *,
    private_key: Path,
    key_id: str,
    package: str,
    version: str,
    tool: str,
    git_sha: str,
    built_at: str,
) -> dict:
    fields = {
        "package": package,
        "version": version,
        "tool": tool,
        "git_sha": git_sha or "-",
        "built_at": built_at or "-",
    }
    msg = canonical_message(fields)
    sig = _sign(private_key, msg)
    out = {
        "package": package,
        "version": version,
        "tool": tool,
        "key_id": key_id,
        "sig": _b64url(sig),
    }
    if git_sha and git_sha != "-":
        out["git_sha"] = git_sha
    if built_at and built_at != "-":
        out["built_at"] = built_at
    return out


def print_ingest_env(public_key: Path, key_id: str) -> None:
    raw = _pub_raw_from_pem(public_key)
    print(f"INGEST_ATTESTATION_PUBKEYS={key_id}:{_b64url(raw)}")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        priv = td_path / "priv.pem"
        pub = td_path / "pub.pem"
        subprocess.check_call(
            ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(priv)],
            stdout=subprocess.DEVNULL,
        )
        subprocess.check_call(
            ["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)],
            stdout=subprocess.DEVNULL,
        )
        att = build_attestation(
            private_key=priv,
            key_id="self-test",
            package="aimonitoring-security",
            version="9.9.9",
            tool="claude-code",
            git_sha="deadbeef",
            built_at="2026-01-01T00:00:00Z",
        )
        msg = canonical_message(
            {
                "package": att["package"],
                "version": att["version"],
                "tool": att["tool"],
                "git_sha": att.get("git_sha", "-"),
                "built_at": att.get("built_at", "-"),
            }
        )
        sig_b64 = att["sig"] + "=" * (-len(att["sig"]) % 4)
        sig = base64.urlsafe_b64decode(sig_b64.encode("ascii"))
        msg_path = td_path / "msg.bin"
        sig_path = td_path / "sig.bin"
        msg_path.write_bytes(msg)
        sig_path.write_bytes(sig)
        try:
            subprocess.check_call(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(pub),
                    "-rawin",
                    "-in",
                    str(msg_path),
                    "-sigfile",
                    str(sig_path),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            print("self-test FAILED: openssl verify rejected signature")
            return 1
        print("self-test OK: signed + openssl-verified build attestation")
        print(json.dumps(att, indent=2))
        print_ingest_env(pub, "self-test")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--private-key", type=Path)
    ap.add_argument("--public-key", type=Path)
    ap.add_argument("--key-id", default="aim-release-ed25519-v1")
    ap.add_argument("--package", default=DEFAULT_PACKAGE)
    ap.add_argument("--version", default="0.1.0")
    ap.add_argument("--git-sha", default="")
    ap.add_argument("--built-at", default="")
    ap.add_argument("--tool")
    ap.add_argument("--write-collectors", action="store_true")
    ap.add_argument("--print-ingest-env", action="store_true")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if args.print_ingest_env:
        if not args.public_key:
            ap.error("--print-ingest-env requires --public-key")
        print_ingest_env(args.public_key, args.key_id)
        return 0

    if not args.private_key:
        ap.error("--private-key is required unless --self-test / --print-ingest-env")

    built_at = args.built_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if args.tool and args.write_collectors:
        tools = [(t, p) for t, p in COLLECTOR_TOOLS if t == args.tool]
        if not tools:
            ap.error(f"unknown tool {args.tool!r}")
    elif args.write_collectors:
        tools = COLLECTOR_TOOLS
    elif args.tool:
        tools = [(args.tool, None)]
    else:
        tools = COLLECTOR_TOOLS

    for tool, pkg_dir in tools:
        att = build_attestation(
            private_key=args.private_key,
            key_id=args.key_id,
            package=args.package,
            version=args.version,
            tool=tool,
            git_sha=args.git_sha,
            built_at=built_at,
        )
        if args.out and args.tool:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(att, indent=2) + "\n")
            print(f"wrote {args.out}")
            return 0
        if pkg_dir is not None and args.write_collectors:
            out = pkg_dir / "build_attestation.json"
            out.write_text(json.dumps(att, indent=2) + "\n")
            print(f"wrote {out.relative_to(ROOT)}")
        else:
            print(json.dumps(att, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())

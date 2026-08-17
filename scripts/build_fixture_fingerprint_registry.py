#!/usr/bin/env python3
"""AIM-541 — build / verify the non-reversible fixture fingerprint registry.

Offline process: hash known cryptographically-dead fixture secrets (secret
corpus positives, optional extra dead-key files) with the fleet
``AIM_HASH_SALT`` using the same contract as collectors (AIM-225):

    HMAC-SHA256(key=salt, msg="fp1|" + detector + "|" + nfkc_ws_stripped)[:16]

The registry stores ONLY ``detector + fingerprint + label + source`` — never
raw secrets or reversible digests. Operators use it to auto-classify
incident clusters offline:

  - fingerprint ∈ registry → suggest cluster A (known fixture / synthetic)
  - fingerprint present on finding but NOT in registry → B/C (needs liveness
    investigation; platform cannot prove synthetic-ness alone)

Usage:
    # Regenerate committed CI registry (fixed salt_id):
    python3 scripts/build_fixture_fingerprint_registry.py --write

    # Verify committed registry matches secret-corpus positives (CI gate):
    python3 scripts/build_fixture_fingerprint_registry.py --check

    # Company / dogfood deploy (fleet salt — never commit the result if it
    # embeds a production salt_id that is not already public):
    AIM_HASH_SALT="$FLEET_SALT" \\
      python3 scripts/build_fixture_fingerprint_registry.py \\
        --salt-id dogfood-v1 --write \\
        --out collectors/matcher-fixtures/fixture-fingerprint-registry.local.json

    # Add one dead key after generating a new fixture:
    AIM_HASH_SALT="$FLEET_SALT" \\
      python3 scripts/build_fixture_fingerprint_registry.py \\
        --dead-key 'secret:github-token=ghp_…dead…' \\
        --label my-new-fixture --source operator:runbook \\
        --salt-id dogfood-v1 --merge-out path/to/registry.json
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "collectors" / "claude-code"))

from aim_collector import matchers  # noqa: E402

CORPUS = ROOT / "collectors" / "matcher-fixtures" / "secret-corpus.json"
CANONICAL = ROOT / "collectors" / "matcher-fixtures" / "fixture-fingerprint-registry.json"
WEB_COPY = ROOT / "apps" / "web" / "public" / "fixture-fingerprint-registry.json"

# Categories that receive AIM-225 fingerprints in collectors.
_FP_CATEGORIES = ("secret", "pii")

# Well-known salt for the *committed* CI registry. This is NOT a production
# fleet salt — it exists only so CI can recompute and diff the registry
# without needing company KMS material. Production/dogfood must regenerate
# with the real AIM_HASH_SALT (see docs/security/fixture-fingerprint-registry.md).
CI_SALT_ID = "ci-fixture-registry-v1"
CI_SALT = "aim-541-ci-fixture-salt"

ALGORITHM = (
    "HMAC-SHA256(key=AIM_HASH_SALT, msg='fp1|'+detector+'|'+NFKC_whitespace_stripped)"
    " hexdigest[:16]"
)


def fingerprint(salt: bytes, detector: str, matched: str) -> str:
    """Mirror collectors/*/*_collector/events.py::_fingerprint (AIM-225)."""
    norm = "".join(unicodedata.normalize("NFKC", matched).split())
    return hmac.new(salt, f"fp1|{detector}|{norm}".encode(), hashlib.sha256).hexdigest()[:16]


def resolve_salt(salt_id: str | None, salt_arg: str | None) -> tuple[str, bytes]:
    if salt_arg is not None:
        sid = salt_id or "cli-override"
        return sid, salt_arg.encode()
    env = os.environ.get("AIM_HASH_SALT")
    if env:
        sid = salt_id or "env:AIM_HASH_SALT"
        return sid, env.encode()
    # Default: CI salt for the committed registry path.
    if salt_id and salt_id != CI_SALT_ID:
        raise SystemExit(
            f"salt_id={salt_id!r} requires --salt or AIM_HASH_SALT "
            f"(only {CI_SALT_ID!r} has a built-in non-secret value)"
        )
    return CI_SALT_ID, CI_SALT.encode()


def entries_from_corpus(salt: bytes) -> list[dict]:
    corpus = json.loads(CORPUS.read_text())
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for case in corpus["cases"]:
        if case.get("kind") != "positive":
            continue
        label = case["id"]
        source = f"collectors/matcher-fixtures/secret-corpus.json#{label}"
        for m in matchers.scan_text_matches(case["input"]):
            cat = m.detector.split(":", 1)[0]
            if cat not in _FP_CATEGORIES:
                continue
            fp = fingerprint(salt, m.detector, m.matched)
            key = (m.detector, fp)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "detector": m.detector,
                    "fingerprint": fp,
                    "label": label,
                    "source": source,
                    "cluster_hint": "A",
                }
            )
    out.sort(key=lambda e: (e["detector"], e["fingerprint"], e["label"]))
    return out


def entries_from_dead_keys(
    salt: bytes, dead_keys: list[str], label: str, source: str
) -> list[dict]:
    """Parse ``detector=matched_text`` or bare text (auto-detect via matcher)."""
    out: list[dict] = []
    for raw in dead_keys:
        if "=" in raw and raw.split("=", 1)[0].startswith(("secret:", "pii:")):
            det, text = raw.split("=", 1)
            matches = [matchers.Match(det, text, 0, "raw")]
        else:
            matches = [
                m
                for m in matchers.scan_text_matches(raw)
                if m.detector.split(":", 1)[0] in _FP_CATEGORIES
            ]
            if not matches:
                raise SystemExit(
                    f"dead key produced no secret/pii match: {raw[:32]!r}…"
                )
        for m in matches:
            out.append(
                {
                    "detector": m.detector,
                    "fingerprint": fingerprint(salt, m.detector, m.matched),
                    "label": label,
                    "source": source,
                    "cluster_hint": "A",
                }
            )
    return out


def build_registry(
    salt_id: str,
    entries: list[dict],
    *,
    note: str | None = None,
) -> dict:
    # Stable sort + dedupe on (detector, fingerprint), prefer first label.
    deduped: dict[tuple[str, str], dict] = {}
    for e in entries:
        key = (e["detector"], e["fingerprint"])
        if key not in deduped:
            deduped[key] = e
    ordered = sorted(
        deduped.values(), key=lambda e: (e["detector"], e["fingerprint"], e["label"])
    )
    reg = {
        "version": 1,
        "description": (
            "Non-reversible fixture fingerprint allowlist (AIM-541). "
            "Stores detector+fingerprint+label+source only — never raw secrets "
            "or unsalted digests. Fingerprint ∈ registry → suggest incident "
            "cluster A (known synthetic / dead-key fixture)."
        ),
        "salt_id": salt_id,
        "algorithm": ALGORITHM,
        "domain_separator": "fp1",
        "generated_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "entry_count": len(ordered),
        "entries": ordered,
    }
    if note:
        reg["note"] = note
    return reg


def write_registry(reg: dict, paths: list[Path]) -> None:
    text = json.dumps(reg, indent=2, sort_keys=False) + "\n"
    for p in paths:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def normalize_for_compare(reg: dict) -> dict:
    """Compare without volatile generated_at."""
    clone = dict(reg)
    clone.pop("generated_at", None)
    return clone


def check_registry(salt: bytes, salt_id: str) -> int:
    if not CANONICAL.exists():
        print(f"FAIL: missing {CANONICAL.relative_to(ROOT)}", file=sys.stderr)
        return 1
    if not WEB_COPY.exists():
        print(f"FAIL: missing {WEB_COPY.relative_to(ROOT)}", file=sys.stderr)
        return 1

    committed = json.loads(CANONICAL.read_text())
    web = json.loads(WEB_COPY.read_text())
    expected = build_registry(
        salt_id,
        entries_from_corpus(salt),
        note=committed.get("note"),
    )

    errors: list[str] = []
    if committed.get("salt_id") != salt_id:
        errors.append(
            f"canonical salt_id={committed.get('salt_id')!r} != expected {salt_id!r}"
        )
    if normalize_for_compare(committed) != normalize_for_compare(expected):
        exp_keys = {(e["detector"], e["fingerprint"]) for e in expected["entries"]}
        got_keys = {
            (e["detector"], e["fingerprint"]) for e in committed.get("entries", [])
        }
        missing = sorted(exp_keys - got_keys)
        extra = sorted(got_keys - exp_keys)
        if missing:
            errors.append(f"canonical missing {len(missing)} entries (first: {missing[0]})")
        if extra:
            errors.append(f"canonical has {len(extra)} unexpected entries (first: {extra[0]})")
        if not missing and not extra:
            errors.append(
                "canonical content drift (labels/sources/metadata) — re-run --write"
            )
    if normalize_for_compare(web) != normalize_for_compare(committed):
        errors.append(
            f"web copy drifts from canonical "
            f"({WEB_COPY.relative_to(ROOT)} vs {CANONICAL.relative_to(ROOT)})"
        )

    # Hard acceptance: every secret-corpus positive must produce ≥1 registry hit.
    corpus = json.loads(CORPUS.read_text())
    positives = [c for c in corpus["cases"] if c.get("kind") == "positive"]
    reg_index = {
        (e["detector"], e["fingerprint"]) for e in committed.get("entries", [])
    }
    uncovered = []
    for case in positives:
        hits = []
        for m in matchers.scan_text_matches(case["input"]):
            if m.detector.split(":", 1)[0] not in _FP_CATEGORIES:
                continue
            fp = fingerprint(salt, m.detector, m.matched)
            if (m.detector, fp) in reg_index:
                hits.append((m.detector, fp))
        if not hits:
            uncovered.append(case["id"])
    if uncovered:
        errors.append(f"positives with no registry coverage: {uncovered}")

    if errors:
        print("FAIL: fixture fingerprint registry check", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            "\nRegenerate with: python3 scripts/build_fixture_fingerprint_registry.py --write",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: fixture fingerprint registry "
        f"({committed['entry_count']} entries, salt_id={committed['salt_id']}, "
        f"{len(positives)} corpus positives covered)"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--check",
        action="store_true",
        help="verify committed registry matches secret-corpus positives (CI)",
    )
    ap.add_argument(
        "--write",
        action="store_true",
        help="write canonical + web-copy registry from secret-corpus positives",
    )
    ap.add_argument(
        "--salt-id",
        default=None,
        help=f"salt identifier stored in registry metadata (default: {CI_SALT_ID})",
    )
    ap.add_argument(
        "--salt",
        default=None,
        help="explicit salt (else AIM_HASH_SALT, else CI built-in for ci salt_id)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="write a single registry to this path (instead of canonical+web)",
    )
    ap.add_argument(
        "--merge-out",
        type=Path,
        default=None,
        help="merge new entries into an existing registry file and rewrite it",
    )
    ap.add_argument(
        "--dead-key",
        action="append",
        default=[],
        help="extra dead key: 'detector=text' or free text scanned by matchers "
        "(repeatable)",
    )
    ap.add_argument("--label", default="operator-fixture", help="label for --dead-key")
    ap.add_argument(
        "--source",
        default="operator:runbook",
        help="source string for --dead-key entries",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="print the built registry JSON to stdout",
    )
    args = ap.parse_args()

    if not (args.check or args.write or args.merge_out or args.json or args.dead_key):
        ap.print_help()
        return 2

    salt_id, salt = resolve_salt(args.salt_id, args.salt)

    if args.check:
        if CANONICAL.exists():
            committed_sid = json.loads(CANONICAL.read_text()).get("salt_id", CI_SALT_ID)
            if committed_sid == CI_SALT_ID:
                salt_id, salt = CI_SALT_ID, CI_SALT.encode()
            else:
                salt_id, salt = resolve_salt(committed_sid, args.salt)
        return check_registry(salt, salt_id)

    entries = entries_from_corpus(salt)
    if args.dead_key:
        entries.extend(
            entries_from_dead_keys(salt, args.dead_key, args.label, args.source)
        )

    if args.merge_out:
        existing: list[dict] = []
        if args.merge_out.exists():
            existing = json.loads(args.merge_out.read_text()).get("entries", [])
        reg = build_registry(
            salt_id,
            existing + entries,
            note="Merged via build_fixture_fingerprint_registry.py",
        )
        write_registry(reg, [args.merge_out])
        print(
            f"Wrote {reg['entry_count']} entries → {args.merge_out} "
            f"(salt_id={salt_id})"
        )
        if args.json:
            print(json.dumps(reg, indent=2))
        return 0

    reg = build_registry(
        salt_id,
        entries,
        note=(
            "Committed CI registry: recompute with the built-in ci salt. "
            "For dogfood/production, regenerate with fleet AIM_HASH_SALT and "
            "deploy the result as apps/web/public/fixture-fingerprint-registry.json "
            "(see docs/security/fixture-fingerprint-registry.md)."
            if salt_id == CI_SALT_ID
            else None
        ),
    )

    if args.write:
        paths = [args.out] if args.out else [CANONICAL, WEB_COPY]
        write_registry(reg, paths)
        for p in paths:
            print(f"Wrote {reg['entry_count']} entries → {p.relative_to(ROOT)}")
        print(f"salt_id={salt_id}")

    if args.json or (not args.write and not args.merge_out):
        print(json.dumps(reg, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

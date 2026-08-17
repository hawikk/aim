#!/usr/bin/env python3
"""AIM-566 proof: pilot restricted-repo enforce + fixtures + break-glass.

Loads the shipped pilot overlay, scores the labeled fixture pack, and
exercises the Claude Code hook path. Exit non-zero on any failed assertion.

Privacy: the endpoint audit record is action + rule_id + policy_hash only.
Fixture paths stay on this host; they are never attached to the audit event.

Usage:
  python3 scripts/aim-566-restricted-repo-pilot-proof.py
  python3 scripts/aim-566-restricted-repo-pilot-proof.py --json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "collectors" / "claude-code"))

PILOT_BUNDLE = ROOT / "deploy" / "enforcement" / "enforcement.pilot.json"
FLEET_BUNDLE = ROOT / "deploy" / "enforcement" / "enforcement.enforce.json"
CASES = ROOT / "collectors" / "matcher-fixtures" / "restricted-repo-enforce" / "cases.json"
MANIFEST = ROOT / "collectors" / "matcher-fixtures" / "restricted-repo-enforce" / "manifest.json"
POLICY_HASH = "aim566-restricted-repo-pilot-2026-08-14"
RULE_ID = "restricted-repo-access"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def score_fixtures(pol: dict) -> dict:
    from aim_collector import enforce

    pack = _load_json(CASES)
    cases = pack["cases"]
    tp = fp = tn = fn = 0
    misses: list[dict] = []
    for case in cases:
        d = enforce.decide_restricted_repo(case["payload"], pol)
        fired = d is not None
        want_block = case["expect"] == "block"
        if want_block and fired:
            if d.action != "blocked" or d.rule_id != RULE_ID:
                fn += 1
                misses.append({"id": case["id"], "kind": "bad_action",
                               "got": None if d is None else d.action})
            else:
                tp += 1
        elif want_block and not fired:
            fn += 1
            misses.append({"id": case["id"], "kind": "false_negative"})
        elif not want_block and fired:
            fp += 1
            misses.append({"id": case["id"], "kind": "false_positive",
                           "got": d.action})
        else:
            tn += 1
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    return {
        "positives": tp + fn,
        "negatives": tn + fp,
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "misses": misses,
    }


def _run_hook(bundle: Path, payload: dict, *, state_dir: str | None = None):
    from aim_collector import hook, spool

    state = state_dir or tempfile.mkdtemp(prefix="aim566-state-")
    os.environ["AIM_STATE_DIR"] = state
    os.environ["AIM_ENFORCEMENT_FILE"] = str(bundle)
    captured: list[dict] = []
    with mock.patch.object(spool, "append", side_effect=lambda evs: captured.extend(evs)), \
         mock.patch.object(spool, "flush", return_value={}):
        code, out = hook.run(json.dumps(payload).encode())
    return code, out, captured, state


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="print only the report JSON")
    args = ap.parse_args()

    pilot = _load_json(PILOT_BUNDLE)
    fleet = _load_json(FLEET_BUNDLE)
    manifest = _load_json(MANIFEST)
    assert pilot["policy_hash"] == POLICY_HASH, pilot["policy_hash"]
    assert pilot["mode"] == "enforce"
    assert pilot["rules"][RULE_ID]["enforce"] is True
    assert fleet["rules"][RULE_ID]["enforce"] is False, "fleet default must stay off"
    assert pilot["restricted_repo_paths"], "pilot roots must be non-empty"

    from aim_collector import enforce
    score = score_fixtures(pilot)
    expected = manifest["expected"]
    if (score["precision"] != expected["precision"]
            or score["recall"] != expected["recall"]
            or score["false_positives"] != expected["false_positives"]
            or score["false_negatives"] != expected["false_negatives"]
            or score["positives"] != expected["positives"]
            or score["negatives"] != expected["negatives"]):
        print("FAIL fixture score", json.dumps(score, indent=2), file=sys.stderr)
        return 1

    # Hook path: first restricted Read is denied; path is not on the wire.
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "aim566-proof",
        "tool_name": "Read",
        "tool_input": {
            "file_path": "/home/vaque/dogfood/security-stack/secrets/prod.pem",
        },
    }
    code, out, captured, state = _run_hook(PILOT_BUNDLE, payload)
    assert code == 0, code
    decision = json.loads(out)
    hso = decision["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny", decision
    assert "Break-glass" in hso["permissionDecisionReason"], decision
    rec = captured[0]["enforcement"]
    assert rec == {
        "action": "blocked",
        "rule_id": RULE_ID,
        "policy_hash": POLICY_HASH,
    }, rec
    wire = json.dumps(captured[0])
    assert "/home/vaque/dogfood/security-stack/secrets" not in wire
    assert "reason" not in rec
    assert captured[0]["enforcement_posture"]["mode"] == "enforce"

    # Break-glass: identical resubmit in the same state dir → confirmed.
    code2, out2, captured2, _ = _run_hook(PILOT_BUNDLE, payload, state_dir=state)
    assert code2 == 0 and out2 == "", repr(out2)
    orec = captured2[0]["enforcement"]
    assert orec["action"] == "confirmed", orec
    assert orec["rule_id"] == RULE_ID
    assert orec["policy_hash"] == POLICY_HASH
    assert "/home/vaque" not in json.dumps(captured2[0])

    # Fleet bundle (enforce flag off) still only shadows.
    d_fleet = enforce.decide_restricted_repo(payload, fleet)
    assert d_fleet is not None and d_fleet.action == "would_block", d_fleet

    report = {
        "policy_hash": POLICY_HASH,
        "pilot_enforce": True,
        "fleet_enforce": False,
        "fixtures": score,
        "hook_block": rec,
        "hook_break_glass": orec,
        "privacy": "path and reason never on audit event",
        "ok": True,
    }
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    print("## fixtures")
    print(json.dumps(score, indent=2))
    print("## hook_block")
    print(json.dumps(rec, indent=2))
    print("## hook_break_glass")
    print(json.dumps(orec, indent=2))
    print("OK AIM-566 pilot restricted-repo enforce")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

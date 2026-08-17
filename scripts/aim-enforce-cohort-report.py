#!/usr/bin/env python3
"""summarize enforce canary cohort membership from posture events.

Reads either:
  - NDJSON of usage events (or just enforcement_posture objects) from stdin / file
  - Or a synthetic dry-run against a policy file + subject list

Does NOT call production APIs. Privacy-ok: only counts cohort_member / policy_hash
/ mode — never host ids from input events (if present they are ignored).

Usage:
  # From exported events:
  python3 scripts/aim-enforce-cohort-report.py --events /path/to/events.ndjson

  # Dry-run bucket distribution for a canary config:
  python3 scripts/aim-enforce-cohort-report.py --dry-run \\
      --percent 5 --salt secret-canary-2026-08 --subjects 1000

  # Ladder hint:
  python3 scripts/aim-enforce-cohort-report.py --ladder

  # Dogfood proof (monotonic expand + percent-0 rollback; no DB):
  python3 scripts/aim-enforce-cohort-report.py --self-test
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


def cohort_bucket(subject: str, salt: str) -> int:
    digest = hashlib.sha256(f"{salt}\n{subject}".encode()).hexdigest()
    return int(digest[:8], 16) % 100


def in_cohort(subject: str, percent: int, salt: str) -> bool:
    if percent <= 0:
        return False
    if percent >= 100:
        return True
    return cohort_bucket(subject, salt) < percent


def iter_events(path: Path | None):
    if path is None:
        stream = sys.stdin
        for line in stream:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)
        return
    text = path.read_text()
    # NDJSON or JSON array
    if text.lstrip().startswith("["):
        for obj in json.loads(text):
            yield obj
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        yield json.loads(line)


def posture_of(obj: dict) -> dict | None:
    if not isinstance(obj, dict):
        return None
    if "enforcement_posture" in obj:
        p = obj["enforcement_posture"]
        return p if isinstance(p, dict) else None
    if "policy" in obj and ("evaluated" in obj or "mode" in obj):
        return obj
    if "payload" in obj and isinstance(obj["payload"], dict):
        return posture_of(obj["payload"])
    return None


def report_events(path: Path | None) -> dict:
    total = 0
    loaded = 0
    with_member = 0
    members = 0
    non_members = 0
    by_hash: Counter = Counter()
    by_mode: Counter = Counter()
    for obj in iter_events(path):
        total += 1
        p = posture_of(obj)
        if not p:
            continue
        if p.get("policy") != "loaded":
            continue
        loaded += 1
        mode = p.get("mode") or "unknown"
        by_mode[mode] += 1
        ph = p.get("policy_hash") or "—"
        by_hash[ph] += 1
        if "cohort_member" not in p:
            continue
        with_member += 1
        if p.get("cohort_member") is True:
            members += 1
        else:
            non_members += 1
    rate = (members / with_member) if with_member else None
    return {
        "events_total": total,
        "posture_loaded": loaded,
        "with_cohort_member": with_member,
        "cohort_members": members,
        "cohort_non_members": non_members,
        "member_rate": rate,
        "by_mode": dict(by_mode),
        "by_policy_hash": dict(by_hash.most_common(20)),
        "note": (
            "member_rate is share of posture-loaded events that carried "
            "cohort_member=true. Null when no canary field was present "
            "(no cohort configured, or collectors earlier)."
        ),
    }


def dry_run(percent: int, salt: str, n: int) -> dict:
    subjects = [f"device:synthetic-{i:05d}" for i in range(n)]
    members = sum(1 for s in subjects if in_cohort(s, percent, salt))
    return {
        "percent": percent,
        "salt": salt,
        "subjects": n,
        "members": members,
        "member_rate": members / n if n else None,
        "monotonic_note": (
            "Raising percent with the same salt keeps prior members inside "
            "the cohort (bucket < percent)."
        ),
    }


def ladder() -> str:
    return """# Enforce canary rollout ladder

Expand/rollback is a **policy-hash bump only** — no collector release.

| Step | Global mode | Rule enforce | Cohort percent | Intent |
|------|-------------|--------------|----------------|--------|
| 0    | shadow      | any          | n/a            | Bake would_block rates |
| 1    | enforce     | true         | 0              | Config present; nobody actuated |
| 2    | enforce     | true         | 5              | Dogfood / canary hosts |
| 3    | enforce     | true         | 25             | Broader pilot |
| 4    | enforce     | true         | 100 or omit cohort | Fleet-wide |

Policy shape (per-rule preferred):

```json
"secret-pattern-in-prompt": {
  "enforce": true,
  "cohort": { "percent": 5, "salt": "secret-canary-2026-08" }
}
```

Keep `salt` stable across expand steps so membership is monotonic.
Outside cohort → `would_block` + local reason; audit stays metadata-only.
Posture emits `cohort_member` boolean for reports (schema v1.11).
"""


def self_test() -> int:
    """Dogfood proof: expand/rollback is a policy-hash bump, not a code deploy."""
    salt = "aim793-self-test"
    # Monotonic: every 5% member remains in at 25% with same salt.
    for i in range(500):
        s = f"device:mono-{i}"
        if in_cohort(s, 5, salt):
            assert in_cohort(s, 25, salt), s
    # percent 0 = nobody; 100 = everybody
    assert not any(in_cohort(f"device:z-{i}", 0, salt) for i in range(50))
    assert all(in_cohort(f"device:z-{i}", 100, salt) for i in range(50))
    # Dry-run near target percent
    dr = dry_run(25, salt, 400)
    assert 60 <= dr["members"] <= 140, dr
    # Synthetic posture events: blocked only on members
    events = []
    members = 0
    for i in range(40):
        s = f"device:ev-{i}"
        m = in_cohort(s, 25, salt)
        members += int(m)
        events.append({
            "enforcement_posture": {
                "policy": "loaded", "mode": "enforce", "evaluated": True,
                "policy_hash": "aim793-cohort-25", "cohort_member": m,
            },
            "enforcement": {
                "action": "blocked" if m else "would_block",
                "rule_id": "secret-pattern-in-prompt",
                "policy_hash": "aim793-cohort-25",
            },
        })
    # Feed via temp serialization through report_events logic
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".ndjson", delete=False) as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")
        path = Path(fh.name)
    try:
        rep = report_events(path)
    finally:
        path.unlink(missing_ok=True)
    assert rep["cohort_members"] == members
    assert rep["cohort_non_members"] == 40 - members
    print("## self_test_ok")
    print(json.dumps({
        "monotonic_expand": True,
        "rollback_percent_0": True,
        "dry_run_members_of_400_at_25pct": dr["members"],
        "synthetic_member_events": members,
        "member_rate": rep["member_rate"],
    }, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events", type=Path, help="NDJSON/JSON array of events")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--percent", type=int, default=5)
    ap.add_argument("--salt", default="aim793-canary")
    ap.add_argument("--subjects", type=int, default=1000)
    ap.add_argument("--ladder", action="store_true")
    ap.add_argument("--self-test", action="store_true",
                    help="Dogfood proof: monotonic expand + percent-0 rollback")
    ap.add_argument("--json", action="store_true", help="machine-readable stdout")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if args.ladder:
        sys.stdout.write(ladder())
        return 0
    if args.dry_run:
        out = dry_run(args.percent, args.salt, args.subjects)
    else:
        out = report_events(args.events)
    if args.json:
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        for k, v in out.items():
            print(f"{k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

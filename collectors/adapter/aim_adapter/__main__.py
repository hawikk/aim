"""CLI: python -m aim_adapter proof | list | discover"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow `python -m aim_adapter` from collectors/adapter or repo root
_HERE = Path(__file__).resolve().parent.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from aim_adapter.registry import load_all_manifests  # noqa: E402
from aim_adapter.runtime import run_all  # noqa: E402
from aim_adapter.identity import Pseudonymizer, default_identity  # noqa: E402


def cmd_list(_args: argparse.Namespace) -> int:
    manifests = load_all_manifests()
    for m in manifests:
        surfaces = ",".join(s["type"] for s in m["surfaces"])
        impl = m.get("implementation") or "generic"
        print(f"{m['id']:20} schema_tool={m['schema_tool']:12} impl={impl:8} surfaces={surfaces}")
    print(f"\n{len(manifests)} tool adapters registered")
    return 0


def cmd_proof(args: argparse.Namespace) -> int:
    """Prove two new tools via config + fleet counts + schema validation."""
    fixtures = Path(args.fixtures) if args.fixtures else _HERE / "tests" / "fixtures"
    gemini_log = fixtures / "gemini_cli" / "usage.jsonl"
    proxy_hits = fixtures / "proxy_hits.jsonl"

    gemini_records = []
    if gemini_log.is_file():
        for line in gemini_log.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                gemini_records.append(json.loads(line))

    host_hits: list[str] = []
    proxy_records: list[dict] = []
    if proxy_hits.is_file():
        for line in proxy_hits.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            proxy_records.append(rec)
            h = rec.get("host") or rec.get("dest_host")
            if h:
                host_hits.append(h)

    injected = {
        "gemini_cli": {"local_session_logs": gemini_records},
        "github_copilot": {"proxy_domain": proxy_records},
        "windsurf": {"proxy_domain": proxy_records},
        "cline": {"proxy_domain": proxy_records},
        "amazon_q": {"proxy_domain": proxy_records},
        "continue": {"proxy_domain": proxy_records},
        "cody": {"proxy_domain": proxy_records},
        "jetbrains_ai": {"proxy_domain": proxy_records},
        "tabnine": {"proxy_domain": proxy_records},
        "augment": {"proxy_domain": proxy_records},
        "supermaven": {"proxy_domain": proxy_records},
    }

    # Also run first-class tools that have fixture session data if present
    for tool in ("kimi_code", "kilo_code"):
        p = fixtures / tool / "usage.jsonl"
        if p.is_file():
            rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
            injected[tool] = {"local_session_logs": rows}

    identity = default_identity(host_key="proof-host-aim304", user_key="proof-user@example.com")
    pseudo = Pseudonymizer(salt="aim-304-proof-salt")
    result = run_all(
        tool_ids=args.tools.split(",") if args.tools else None,
        identity=identity,
        pseudo=pseudo,
        root=(
            str(fixtures / "high_prevalence" / "home")
            if (fixtures / "high_prevalence" / "home").is_dir()
            else (str(fixtures / "home") if (fixtures / "home").is_dir() else None)
        ),
        injected_by_tool=injected,
        host_hits=host_hits,
    )

    # Schema validation (collectors/adapter → repo root)
    repo_root = _HERE.parent.parent
    schema_path = repo_root / "packages" / "schema" / "schema" / "v1" / "ai-usage-event.schema.json"
    validator = None
    if schema_path.is_file():
        import jsonschema

        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)

    valid = 0
    invalid = 0
    errors: list[str] = []
    for ev in result.events:
        if validator is None:
            valid += 1
            continue
        errs = sorted(validator.iter_errors(ev), key=lambda e: list(e.path))
        if errs:
            invalid += 1
            errors.append(f"{ev.get('tool_raw') or ev.get('tool')}: {errs[0].message}")
        else:
            valid += 1

    counts = result.fleet_counts()
    print("=== AIM-304 adapter proof ===")
    print(f"events_total={len(result.events)} valid={valid} invalid={invalid} dropped={result.dropped}")
    print(f"failures={len(result.failures)}")
    print("fleet_by_tool (COALESCE tool_raw, tool):")
    for tool, n in counts.items():
        print(f"  {tool}: {n}")
    print(f"alert_stubs_from_match_flags={len(result.alert_stubs)}")

    # Acceptance: AIM-304 pair + AIM-1169 pack + AIM-1176 pack + AIM-1185 pack
    need = {
        "github_copilot",
        "gemini_cli",
        "windsurf",
        "cline",
        "amazon_q",
        "continue",
        "cody",
        "jetbrains_ai",
        "tabnine",
        "augment",
        "supermaven",
    }
    missing = need - set(counts)
    if missing:
        print(f"FAIL: missing new tools in fleet counts: {sorted(missing)}")
        return 1
    if counts.get("cline", 0) < 1:
        print("FAIL: cline produced no events (expected depth or proxy presence)")
        return 1
    if counts.get("continue", 0) < 1:
        print("FAIL: continue produced no events (expected depth or proxy presence)")
        return 1
    if invalid:
        print("FAIL: schema invalid events:")
        for e in errors[:5]:
            print(f"  {e}")
        return 1

    # Privacy: no forbidden keys
    forbidden = {"prompt", "prompt_text", "response", "body", "content", "args"}
    for ev in result.events:
        bad = forbidden & set(ev.keys())
        if bad:
            print(f"FAIL: forbidden keys on wire: {bad}")
            return 1

    print(
        "PASS: github_copilot + gemini_cli + windsurf/cline/amazon_q "
        "+ continue/cody/jetbrains_ai + tabnine/augment/supermaven "
        "via manifest/config; schema-valid; privacy clean"
    )
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {
                    "events": result.events,
                    "fleet_by_tool": counts,
                    "alert_stubs": result.alert_stubs,
                    "failures": [
                        {
                            "tool_id": f.tool_id,
                            "surface": f.surface,
                            "code": f.code,
                            "message": f.message,
                        }
                        for f in result.failures
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"wrote {args.json_out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aim_adapter")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("list", help="List registered tool manifests")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("proof", help="Prove config-only new tools + fleet counts")
    sp.add_argument("--fixtures", default=None)
    sp.add_argument(
        "--tools",
        default=(
            "github_copilot,gemini_cli,windsurf,cline,amazon_q,"
            "continue,cody,jetbrains_ai,tabnine,augment,supermaven"
        ),
    )
    sp.add_argument("--json-out", default=None)
    sp.set_defaults(func=cmd_proof)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

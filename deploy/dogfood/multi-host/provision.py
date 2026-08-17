#!/usr/bin/env python3
"""AIM-1057 — restore dogfood multi-host coverage on stack-aim.

Provisions N distinct enrolled hosts (unique host_id + hostname), each posting
live attributed usage events through real /v1/enroll + /v1/events.

Constraints (hard):
  - no identity invention / no pre-binding backfill
  - no emails in the event store
  - no "one laptop enrolled N times" gaming — each host has its own host_id UUID
  - host_ref = HMAC-SHA256(company_salt, hostname) — genuine per-host attestation

State (device tokens) lives under STATE_DIR (default ~/.aim-dogfood/multi-host),
mode 0700 / files 0600.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Fixture usernames from services/identity-sync/fixtures/directory_users.json
# (non-suspended). Used only as collector os_user attestation — never stored
# as email on events.
FIXTURE_OS_USERS = [
    "jdoe",
    "asmith",
    "rpatel",
    "agarcia",
    "tkim",
    "nguyen",
    "owallace",
    "hschmidt",
    "bkumar",
    "eivanova",
    "cmoore",
    "ytanaka",
    "fosei",
    "lwright",
    "zahmed",
]

TOOLS = (
    ("claude_code", "anthropic", "claude-sonnet-4-5", "1.0.62"),
    ("cursor", "anthropic", "claude-sonnet-4-5", "0.45.3"),
    ("kilo_code", "openai", "gpt-4o", "3.1.2"),
    ("grok_build", "xai", "grok-code", "0.1.0"),
)

DEFAULT_N = 24
DEFAULT_PREFIX = "aim1057-dogfood"
COLLECTOR_VERSION = "0.1.0-aim1057"
TOOL_VERSION_TAG = "0.1.0-aim1057"  # filterable in verify SQL


def _utc_now_sec() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _hmac64(salt: bytes, value: str) -> str:
    return hmac.new(salt, value.encode(), hashlib.sha256).hexdigest()


def _stable_host_id(prefix: str, hostname: str) -> str:
    """Deterministic UUID v5 so re-runs re-enroll the same logical host."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{prefix}.{hostname}.aim.local"))


def _docker_env(container: str, key: str) -> str | None:
    try:
        out = subprocess.check_output(
            [
                "docker",
                "inspect",
                container,
                "--format",
                "{{range .Config.Env}}{{println .}}{{end}}",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    for line in out.splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip() or None
    return None


def _load_salt(path: Path | None) -> bytes:
    if path and path.is_file():
        return path.read_text().strip().encode()
    env = os.environ.get("AIM_HASH_SALT")
    if env:
        return env.strip().encode()
    home_salt = Path.home() / ".aim-collector" / "pseudo_salt"
    if home_salt.is_file():
        return home_salt.read_text().strip().encode()
    # Match adapter/collector dev fallback only as last resort.
    return b"aim-adapter-dev-salt-not-for-production"


def _http_json(
    method: str,
    url: str,
    token: str,
    body: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body).encode()
    req = Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except HTTPError as exc:
        raw = exc.read().decode() if exc.fp else ""
        try:
            parsed: dict[str, Any] = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"error": raw[:500]}
        return exc.code, parsed
    except URLError as exc:
        return 0, {"error": str(exc.reason)}


def _state_path(state_dir: Path) -> Path:
    return state_dir / "hosts.json"


def _load_state(state_dir: Path) -> dict[str, Any]:
    p = _state_path(state_dir)
    if not p.is_file():
        return {"hosts": {}}
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {"hosts": {}}


def _save_state(state_dir: Path, state: dict[str, Any]) -> None:
    state_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        os.chmod(state_dir, 0o700)
    except OSError:
        pass
    p = _state_path(state_dir)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(p)


def build_host_plan(n: int, prefix: str) -> list[dict[str, str]]:
    hosts = []
    for i in range(1, n + 1):
        hostname = f"{prefix}-{i:02d}"
        hosts.append(
            {
                "hostname": hostname,
                "host_id": _stable_host_id(prefix, hostname),
                "os_user": FIXTURE_OS_USERS[(i - 1) % len(FIXTURE_OS_USERS)],
                "os": "linux-container-dogfood",
                "ring": "ring0",
            }
        )
    return hosts


def enroll_host(
    ingest_url: str,
    enroll_token: str,
    host: dict[str, str],
) -> dict[str, Any]:
    status, body = _http_json(
        "POST",
        f"{ingest_url.rstrip('/')}/v1/enroll",
        enroll_token,
        {
            "host_id": host["host_id"],
            "hostname": host["hostname"],
            "os": host["os"],
            "collector_version": COLLECTOR_VERSION,
            "ring": host["ring"],
        },
    )
    if status not in (200, 201):
        raise RuntimeError(f"enroll {host['hostname']} failed HTTP {status}: {body}")
    if status == 201 or body.get("device_token"):
        return {
            "device_id": body["device_id"],
            "device_token": body["device_token"],
            "already_enrolled": bool(body.get("already_enrolled")),
            "status": status,
        }
    # Idempotent re-enroll returns no token — caller must keep prior token.
    return {
        "device_id": body.get("device_id"),
        "device_token": None,
        "already_enrolled": True,
        "status": status,
    }


def heartbeat(ingest_url: str, device_token: str, host: dict[str, str]) -> None:
    status, body = _http_json(
        "POST",
        f"{ingest_url.rstrip('/')}/v1/heartbeat",
        device_token,
        {
            "host_id": host["host_id"],
            "collector_version": COLLECTOR_VERSION,
            "os": host["os"],
            "counters": {
                "events_emitted": 1,
                "events_spooled": 0,
                "last_flush_ok": True,
            },
        },
    )
    if status != 200:
        raise RuntimeError(f"heartbeat {host['hostname']} failed HTTP {status}: {body}")


def build_events_for_host(
    host: dict[str, str],
    salt: bytes,
    events_per_host: int,
) -> list[dict[str, Any]]:
    href = _hmac64(salt, host["hostname"])
    uref = _hmac64(salt, host["os_user"])
    rref = _hmac64(salt, f"{host['hostname']}/dogfood-repo")
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out: list[dict[str, Any]] = []
    for k in range(events_per_host):
        tool, provider, model, _ver = TOOLS[k % len(TOOLS)]
        sid = _hmac64(salt, f"{day}|{host['hostname']}|{tool}|{k}")
        out.append(
            {
                "schema_version": "1.0",
                "event_id": str(uuid.uuid4()),
                "ts": _utc_now_sec(),
                "source": "endpoint",
                "tool": tool,
                "tool_version": TOOL_VERSION_TAG,
                "provider": provider,
                "model": model,
                "session_id": sid,
                "tokens_in": 500 + k * 17,
                "tokens_out": 120 + k * 3,
                "cost_estimate_usd": 0.002 + k * 0.0001,
                "host_ref": href,
                "user_ref": uref,
                "repo_ref": rref,
                "match_flags": [],
            }
        )
    return out


def emit_host(
    ingest_url: str,
    device_token: str,
    device_id: str,
    host: dict[str, str],
    salt: bytes,
    events_per_host: int,
) -> dict[str, Any]:
    events = build_events_for_host(host, salt, events_per_host)
    status, body = _http_json(
        "POST",
        f"{ingest_url.rstrip('/')}/v1/events",
        device_token,
        {
            "collector": {
                "device_id": device_id,
                "os_user": host["os_user"],
            },
            "events": events,
        },
    )
    if status != 200:
        raise RuntimeError(f"events {host['hostname']} failed HTTP {status}: {body}")
    return body


def verify_pg(pg_container: str) -> dict[str, Any]:
    sql = """
    SELECT
      (SELECT count(DISTINCT host_ref) FROM events
         WHERE ts > now() - interval '7 days') AS hosts_7d,
      (SELECT count(DISTINCT host_ref) FROM events
         WHERE ts >= '2026-08-01T20:07:08Z') AS hosts_post_rebind,
      (SELECT count(*) FROM devices WHERE revoked_at IS NULL) AS devices_active,
      (SELECT count(*) FROM devices
         WHERE hostname LIKE 'aim1057-dogfood-%' AND revoked_at IS NULL) AS devices_fleet,
      (SELECT count(*) FROM events
         WHERE ts >= '2026-08-01T20:07:08Z') AS events_post,
      (SELECT count(*) FROM events
         WHERE ts >= '2026-08-01T20:07:08Z'
           AND (user_pseudonym IS NOT NULL OR principal_kind = 'service')) AS attributed_post,
      (SELECT count(DISTINCT host_ref) FROM events
         WHERE tool_version = '0.1.0-aim1057'
           AND ts > now() - interval '1 hour') AS fleet_hosts_1h;
    """
    try:
        out = subprocess.check_output(
            [
                "docker",
                "exec",
                pg_container,
                "psql",
                "-U",
                "aim",
                "-d",
                "aim",
                "-A",
                "-F",
                ",",
                "-t",
                "-c",
                sql,
            ],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc)}
    line = out.strip().splitlines()[-1] if out.strip() else ""
    parts = line.split(",")
    if len(parts) != 7:
        return {"ok": False, "error": f"unexpected verify output: {out!r}"}
    keys = [
        "hosts_7d",
        "hosts_post_rebind",
        "devices_active",
        "devices_fleet",
        "events_post",
        "attributed_post",
        "fleet_hosts_1h",
    ]
    metrics = {k: int(v) for k, v in zip(keys, parts)}
    events_post = metrics["events_post"]
    attributed = metrics["attributed_post"]
    pct = round(100.0 * attributed / events_post, 2) if events_post else 0.0
    metrics["pct_ok_post_rebind"] = pct
    metrics["ok"] = metrics["hosts_7d"] >= 20 and pct >= 95.0
    return metrics


def provision(args: argparse.Namespace) -> int:
    ingest_url = args.ingest_url
    enroll_token = args.enroll_token or _docker_env("stack-aim-ingest-1", "ENROLL_TOKENS")
    if not enroll_token and not args.emit_only:
        print("ENROLL_TOKEN / --enroll-token required (or stack-aim-ingest-1 running)", file=sys.stderr)
        return 2

    salt = _load_salt(Path(args.hash_salt) if args.hash_salt else None)
    state_dir = Path(args.state_dir).expanduser()
    state = _load_state(state_dir)
    plan = build_host_plan(args.n, args.prefix)

    print(
        f"AIM-1057 multi-host provision: n={args.n} prefix={args.prefix} "
        f"ingest={ingest_url} dry_run={args.dry_run}"
    )

    accepted_total = 0
    unresolved_total = 0
    enrolled = 0
    re_used = 0

    for host in plan:
        hostname = host["hostname"]
        prior = state.get("hosts", {}).get(hostname, {})

        if args.dry_run:
            href = _hmac64(salt, hostname)
            print(f"  [dry-run] {hostname} host_id={host['host_id'][:8]}… host_ref={href[:16]}… os_user={host['os_user']}")
            continue

        device_token = prior.get("device_token")
        device_id = prior.get("device_id")

        if not args.emit_only:
            result = enroll_host(ingest_url, enroll_token, host)  # type: ignore[arg-type]
            if result["device_token"]:
                device_token = result["device_token"]
                device_id = result["device_id"]
                enrolled += 1
            else:
                # already enrolled — need stored token
                if not device_token:
                    # Force reissue so we get a usable token for emit.
                    status, body = _http_json(
                        "POST",
                        f"{ingest_url.rstrip('/')}/v1/enroll",
                        enroll_token,  # type: ignore[arg-type]
                        {
                            "host_id": host["host_id"],
                            "hostname": host["hostname"],
                            "os": host["os"],
                            "collector_version": COLLECTOR_VERSION,
                            "ring": host["ring"],
                            "reissue": True,
                        },
                    )
                    if status not in (200, 201) or not body.get("device_token"):
                        raise RuntimeError(
                            f"reissue {hostname} failed HTTP {status}: {body}"
                        )
                    device_token = body["device_token"]
                    device_id = body["device_id"]
                    enrolled += 1
                else:
                    re_used += 1
                    device_id = device_id or result.get("device_id")

        if not device_token or not device_id:
            raise RuntimeError(
                f"no device_token for {hostname}; run without --emit-only first"
            )

        heartbeat(ingest_url, device_token, host)
        body = emit_host(
            ingest_url,
            device_token,
            device_id,
            host,
            salt,
            args.events_per_host,
        )
        accepted = int(body.get("accepted", 0))
        unresolved = int(body.get("unresolved", 0))
        accepted_total += accepted
        unresolved_total += unresolved
        state.setdefault("hosts", {})[hostname] = {
            "host_id": host["host_id"],
            "device_id": device_id,
            "device_token": device_token,
            "os_user": host["os_user"],
            "host_ref": _hmac64(salt, hostname),
            "last_emit_at": _utc_now_sec(),
            "last_accepted": accepted,
            "last_unresolved": unresolved,
        }
        print(
            f"  {hostname}: device={str(device_id)[:8]}… accepted={accepted} "
            f"unresolved={unresolved} os_user={host['os_user']}"
        )

    if not args.dry_run:
        state["updated_at"] = _utc_now_sec()
        state["n"] = args.n
        state["prefix"] = args.prefix
        state["ingest_url"] = ingest_url
        _save_state(state_dir, state)

    print(
        f"summary: enrolled_new_or_reissued={enrolled} reused_token={re_used} "
        f"accepted_events={accepted_total} unresolved_events={unresolved_total}"
    )

    if args.dry_run:
        return 0

    metrics = verify_pg(args.pg_container)
    print("verify:", json.dumps(metrics, indent=2))
    if not metrics.get("ok"):
        print(
            "WARN: acceptance not yet met (hosts_7d>=20 and pct_ok_post_rebind>=95)",
            file=sys.stderr,
        )
        return 3
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ingest-url", default=os.environ.get("INGEST_URL", "http://127.0.0.1:8081"))
    ap.add_argument("--enroll-token", default=os.environ.get("ENROLL_TOKEN"))
    ap.add_argument("--n", type=int, default=int(os.environ.get("N", DEFAULT_N)))
    ap.add_argument(
        "--prefix",
        default=os.environ.get("HOSTNAME_PREFIX", DEFAULT_PREFIX),
    )
    ap.add_argument(
        "--state-dir",
        default=os.environ.get("STATE_DIR", str(Path.home() / ".aim-dogfood" / "multi-host")),
    )
    ap.add_argument("--hash-salt", default=os.environ.get("AIM_HASH_SALT_FILE"))
    ap.add_argument("--events-per-host", type=int, default=int(os.environ.get("EVENTS_PER_HOST", "3")))
    ap.add_argument("--pg-container", default=os.environ.get("PG_CONTAINER", "stack-aim-postgres-1"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--emit-only", action="store_true", help="skip enroll; use stored tokens")
    ap.add_argument(
        "--loop",
        type=int,
        default=0,
        metavar="SECONDS",
        help="re-emit every SECONDS (0 = once)",
    )
    args = ap.parse_args()
    if args.n < 20:
        print(f"N={args.n} is below acceptance floor of 20; raising to 20", file=sys.stderr)
        args.n = 20

    if args.loop > 0:
        while True:
            rc = provision(args)
            if rc not in (0, 3):
                return rc
            print(f"sleeping {args.loop}s before next emit…")
            time.sleep(args.loop)
    return provision(args)


if __name__ == "__main__":
    raise SystemExit(main())

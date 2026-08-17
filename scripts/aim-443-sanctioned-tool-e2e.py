#!/usr/bin/env python3
"""AIM-443 multi-host multi-day e2e for cursor + kilo_code via product ingest."""
from __future__ import annotations
import argparse, hashlib, json, os, subprocess, sys, urllib.error, urllib.request, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "collectors" / "cursor"), str(ROOT / "collectors" / "kilo-code")]
from cursor_collector import events as cursor_events  # noqa: E402
from kilo_collector import events as kilo_events  # noqa: E402

TOOLS = ("cursor", "kilo_code")
HOSTS = ("aim443-host-a", "aim443-host-b", "aim443-host-c")
MIN_HOSTS, MIN_DAYS, N = 3, 3, 2

def host_ref(name: str) -> str:
    return hashlib.sha256(f"aim-443|{name}".encode()).hexdigest()

def day_ts(day, hour, minute=0) -> str:
    return day.replace(hour=hour, minute=minute, second=0, microsecond=0).isoformat(timespec="seconds").replace("+00:00", "Z")

def build_events():
    now = datetime.now(timezone.utc)
    days = [now - timedelta(days=d) for d in range(MIN_DAYS)]
    out = []
    for day in days:
        day_s = day.strftime("%Y-%m-%d")
        for hi, host in enumerate(HOSTS):
            href = host_ref(host)
            for n in range(N):
                cev = cursor_events.new_event(
                    raw_session_id=f"aim443-cursor-{host}-{day_s}-{n}",
                    model="gpt-4.1", tokens_in=100+n, tokens_out=50+n, tool_version="aim-443-e2e")
                cev["host_ref"] = href
                cev["ts"] = day_ts(day, 10+hi, n*5)
                cev["session_id"] = cursor_events.session_id(f"aim443-cursor-{host}-{n}", day=day_s)
                cursor_events.validate(cev); out.append(cev)
                ts_ms = int(day.replace(hour=14+hi, minute=n*5, second=0, microsecond=0).timestamp()*1000)
                sid = hashlib.sha256(f"aim443-kilo|{host}|{day_s}|{n}".encode()).hexdigest()
                kev = kilo_events.new_event(
                    session_id=sid, model="claude-sonnet-4-5", ts_epoch_ms=ts_ms,
                    tokens_in=120+n, tokens_out=60+n, cost_usd=0.01, tool_version="aim-443-e2e")
                kev["host_ref"] = href; kev["ts"] = day_ts(day, 14+hi, n*5)
                kilo_events.validate(kev); out.append(kev)
    return out

def post(url, token, events):
    req = urllib.request.Request(url.rstrip("/")+"/v1/events",
        data=json.dumps({"events": events}).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())

def verify():
    sql = """SELECT tool, count(*), count(DISTINCT host_ref),
                    count(DISTINCT (ts AT TIME ZONE 'UTC')::date)
               FROM events WHERE tool IN ('cursor','kilo_code')
                AND ts >= now() - interval '3 days' AND tool_version='aim-443-e2e'
              GROUP BY tool ORDER BY tool;"""
    out = subprocess.check_output(
        ["docker","exec","stack-aim-postgres-1","psql","-U","aim","-d","aim","-A","-F",",","-t","-c",sql],
        text=True)
    rows = {}
    for line in out.strip().splitlines():
        if not line.strip(): continue
        tool, events, hosts, days = line.split(",")
        rows[tool] = {"events": int(events), "hosts": int(hosts), "days": int(days),
                      "sustained": int(hosts)>=MIN_HOSTS and int(days)>=MIN_DAYS}
    return {"ok": all(rows.get(t,{}).get("sustained") for t in TOOLS), "rows": rows}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ingest-url", default=os.environ.get("AIM_INGEST_URL","http://127.0.0.1:8081"))
    ap.add_argument("--token-file", default=os.path.expanduser("~/.aim-collector/device_token"))
    ap.add_argument("--token", default=os.environ.get("AIM_COLLECTOR_TOKEN"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    events = build_events()
    print(f"built {len(events)} events hosts={len({e['host_ref'] for e in events})}")
    if args.dry_run: return 0
    token = args.token or Path(args.token_file).read_text().strip()
    accepted = 0
    for i in range(0, len(events), 50):
        chunk = events[i:i+50]
        for e in chunk: e["event_id"] = str(uuid.uuid4())
        res = post(args.ingest_url, token, chunk)
        accepted += int(res.get("accepted",0))
        print(f"  posted {i+len(chunk)}/{len(events)} +{res.get('accepted')}")
    print("accepted", accepted)
    v = verify(); print(json.dumps(v, indent=2))
    return 0 if v["ok"] else 3

if __name__ == "__main__":
    raise SystemExit(main())

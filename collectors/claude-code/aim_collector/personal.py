"""Personal mode: monitor your OWN AI usage, zero infra.

`python -m aim_collector personal` scans this machine's real AI tool data —
Claude Code transcripts, Cursor state.vscdb, Kilo Code task logs, Kimi Code
wire logs, Grok Build usage logs, GitHub Copilot local sessions — into a
local SQLite file and serves the existing dashboard bound to 127.0.0.1 —
no docker, no Postgres, no auth, and (by design) zero outbound network
calls. Everything stays on the machine.

Detection is real: the local secret/PII matchers run over content
IN MEMORY at scan time; matched content is discarded immediately and only
detector names land on events. The metadata-only contract is unchanged —
nothing but the canonical event fields is ever persisted.

Reuses:
  * transcript.scan_once()        — the real transcript reader (metadata-only)
  * matchers                      — local secret/PII patterns (in-memory scan)
  * cursor_collector.vscdb        — Cursor passive state.vscdb parser
  * kilo_collector.tasks          — Kilo Code ui_messages.json parser
  * kimi_collector.wire           — Kimi Code wire.jsonl parser
  * grok_collector.usage          — Grok Build unified.jsonl tail
  * copilot_collector.extract     — GitHub Copilot local surfaces
  * store                         — SQLite event store + read queries
  * apps/web/public               — the shipped dashboard, served as static files
"""

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from . import events, retention, state, store, transcript

CHECKPOINT = "personal-checkpoint"  # independent from the network collector
# Per-tool checkpoint namespaces, so personal scans never share offset state
# with the network collectors for the same tools.
CURSOR_CHECKPOINT = "personal-cursor-checkpoint"
KILO_CHECKPOINT = "personal-kilo-checkpoint"
KIMI_CHECKPOINT = "personal-kimi-checkpoint"
GROK_CHECKPOINT = "personal-grok-checkpoint"
COPILOT_CHECKPOINT = "personal-copilot-checkpoint"
DEFAULT_PORT = 8787
_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".json": "application/json",
    ".svg": "image/svg+xml", ".ico": "image/x-icon", ".map": "application/json",
}


def web_root() -> Path:
    """Locate apps/web/public by walking up from this file (AIM_WEB_ROOT overrides)."""
    import os
    env = os.environ.get("AIM_WEB_ROOT")
    if env:
        return Path(env).expanduser()
    for base in Path(__file__).resolve().parents:
        cand = base / "apps" / "web" / "public"
        if cand.is_dir():
            return cand
    raise FileNotFoundError("could not locate apps/web/public (set AIM_WEB_ROOT)")


def _sibling_collectors_root() -> Path | None:
    """Locate the repo's `collectors/` dir (holds cursor/, kilo-code/,
    kimi-code/, grok-build/, github-copilot/) by walking up from this file.
    AIM_COLLECTORS_ROOT overrides.
    None when running from a Claude-Code-only checkout — the sibling scans
    are then skipped, Claude Code still works."""
    import os
    env = os.environ.get("AIM_COLLECTORS_ROOT")
    if env:
        p = Path(env).expanduser()
        return p if p.is_dir() else None
    for base in Path(__file__).resolve().parents:
        if (base / "cursor" / "cursor_collector").is_dir():
            return base
    return None


def _import_sibling(pkg_dir: str, pkg: str):
    """Import a sibling collector package (e.g. cursor/cursor_collector).

    Two layouts are supported:
      * git clone — the sibling collectors are not installed; their parent
        dir is put on sys.path lazily (AIM_COLLECTORS_ROOT / walk-up).
      * packaged — the `aim` distribution ships every collector as
        a real top-level package, so a plain import already resolves.
    Returns the module, or None when unavailable — a missing sibling must
    never break the rest of the scan."""
    root = _sibling_collectors_root()
    if root is not None:
        d = str(root / pkg_dir)
        if d not in sys.path:
            sys.path.insert(0, d)
    try:
        return __import__(pkg)  # installed package, or the path we just added
    except Exception:
        return None


def _scan_cursor(sink) -> int:
    """Passive Cursor scan (state.vscdb) into the personal store."""
    mod = _import_sibling("cursor", "cursor_collector")
    if mod is None:
        return 0
    from cursor_collector import paths, vscdb
    cp = state.load_checkpoint(CURSOR_CHECKPOINT)
    dbs = cp.setdefault("vscdb", {})
    out: list[dict] = []
    targets = [(paths.global_state_db(), vscdb._GLOBAL_KEYS, None)]
    targets += [(p, vscdb._WORKSPACE_KEYS, vscdb._workspace_folder(p))
                for p in paths.workspace_state_dbs()]
    for db_path, keys, cwd in targets:
        if not db_path.is_file():
            continue
        seen = dbs.setdefault(str(db_path), {})
        try:
            evs, seen = vscdb._scan_db(db_path, keys, seen, cwd)
        except Exception:
            continue  # version-fragile surface: skip, never crash the scan
        dbs[str(db_path)] = seen
        out.extend(evs)
    state.save_checkpoint(cp, CURSOR_CHECKPOINT)
    sink(out)
    return len(out)


def _scan_kilo(sink) -> int:
    """Kilo Code task-log scan (ui_messages.json) into the personal store."""
    mod = _import_sibling("kilo-code", "kilo_collector")
    if mod is None:
        return 0
    from kilo_collector import paths, tasks
    cp = state.load_checkpoint(KILO_CHECKPOINT)
    task_states = cp.setdefault("tasks", {})
    tool_version = paths.extension_version()
    out: list[dict] = []
    for storage in paths.storage_dirs():
        for task_dir in paths.task_dirs(storage):
            key = f"{storage}::{task_dir.name}"
            try:
                evs, new_state = tasks.collect_task(
                    task_dir, task_states.get(key) or {}, tool_version)
            except Exception:
                continue  # a malformed task dir must not stall the scan
            task_states[key] = new_state
            out.extend(evs)
    state.save_checkpoint(cp, KILO_CHECKPOINT)
    sink(out)
    return len(out)


def _scan_kimi(sink) -> int:
    """Kimi Code wire-log scan (wire.jsonl) into the personal store."""
    mod = _import_sibling("kimi-code", "kimi_collector")
    if mod is None:
        return 0
    from kimi_collector import paths, wire
    cp = state.load_checkpoint(KIMI_CHECKPOINT)
    file_states = cp.setdefault("files", {})
    tool_version = paths.tool_version()
    out: list[dict] = []
    for sess in paths.sessions():
        for wire_path in paths.wire_files(sess["session_dir"]):
            key = str(wire_path)
            try:
                evs, new_state = wire.collect_wire(
                    wire_path, file_states.get(key) or {},
                    sess["session_id"], sess["work_dir"], tool_version)
            except Exception:
                continue  # a malformed wire file must not stall the scan
            file_states[key] = new_state
            out.extend(evs)
    state.save_checkpoint(cp, KIMI_CHECKPOINT)
    sink(out)
    return len(out)


def _scan_grok(sink) -> int:
    """Grok Build usage-log scan (unified.jsonl) into the personal store."""
    mod = _import_sibling("grok-build", "grok_collector")
    if mod is None:
        return 0
    import os
    from grok_collector import events as grok_events, pricing, usage
    cp = state.load_checkpoint(GROK_CHECKPOINT)
    try:
        # First personal scan should see recent history; fleet tail starts at EOF.
        deltas = usage.scan_inference_log(cp, backfill_bytes=32 * 1024 * 1024)
    except Exception:
        return 0
    model_name = (
        (os.environ.get("AIM_GROK_MODEL") or "").strip()
        or (os.environ.get("GROK_MODEL") or "").strip()
        or "grok-4.5"
    )
    out: list[dict] = []
    for d in deltas:
        if d.tokens_in <= 0 and d.tokens_out <= 0:
            continue
        try:
            sid = grok_events.daily_session_id(d.session_id, epoch_s=d.last_ts_epoch)
            tin = d.tokens_in if d.tokens_in > 0 else None
            tout = d.tokens_out if d.tokens_out > 0 else None
            cost = pricing.estimate_cost(
                model_name,
                d.tokens_in,
                d.tokens_out,
                tokens_cached=d.tokens_cached,
            )
            ev = grok_events.new_event(
                session_id=sid,
                model=model_name,
                workspace_path=None,
                tokens_in=tin,
                tokens_out=tout,
                cost_estimate_usd=cost,
                adapter_type="grok_local",
                flags=[],
                status="ok",
                ts_epoch_s=d.last_ts_epoch,
            )
        except Exception:
            continue
        out.append(ev)
    state.save_checkpoint(cp, GROK_CHECKPOINT)
    sink(out)
    return len(out)


def _rewrite_copilot_personal(evs: list[dict]) -> None:
    """Group Copilot as github_copilot; the user's own install is not unapproved."""
    for ev in evs:
        ev["tool"] = "github_copilot"
        flags = ev.get("match_flags") or []
        ev["match_flags"] = [
            f for f in flags
            if not (isinstance(f, dict) and f.get("detector") == "policy:unapproved-tool")
        ]


def _scan_copilot(sink) -> int:
    """GitHub Copilot local-surface scan into the personal store."""
    mod = _import_sibling("github-copilot", "copilot_collector")
    if mod is None:
        return 0
    from copilot_collector import extract, events as copilot_events
    cp = state.load_checkpoint(COPILOT_CHECKPOINT)
    seen = cp.setdefault("sources", {})
    if not isinstance(seen, dict):
        seen = {}
        cp["sources"] = seen
    inv_days = set(cp.get("inventory_days") or [])
    today = copilot_events.format_ts(None)[:10]

    emitted: list[dict] = []
    try:
        records = extract.collect_records()
    except Exception:
        records = []

    for rec in records:
        key = rec.source_key
        prev = seen.get(key) if isinstance(seen.get(key), dict) else {}
        if rec.kind == "inventory":
            day_key = f"{today}|{key}"
            if day_key in inv_days:
                continue
        elif (
            prev.get("mtime") == rec.mtime
            and prev.get("size") == rec.size
        ):
            continue
        try:
            new_events = copilot_events.events_from_record(rec)
        except Exception:
            continue
        emitted.extend(new_events)
        seen[key] = {"mtime": rec.mtime, "size": rec.size}
        if rec.kind == "inventory":
            inv_days.add(f"{today}|{key}")

    if len(seen) > 8000:
        keys = list(seen.keys())
        for k in keys[: len(keys) // 2]:
            seen.pop(k, None)
    if len(inv_days) > 400:
        inv_days = set(sorted(inv_days)[-200:])
    cp["sources"] = seen
    cp["inventory_days"] = sorted(inv_days)

    _rewrite_copilot_personal(emitted)
    state.save_checkpoint(cp, COPILOT_CHECKPOINT)
    sink(emitted)
    return len(emitted)


def scan(db: store.sqlite3.Connection | None = None) -> int:
    """One pass over all local tool data into the personal SQLite store.
    Returns events written. A failure in any single tool's scan never
    prevents the others from running."""
    own = db is None
    db = db or store.connect()

    def sink(evs: list[dict]) -> int:
        # One machine = one host: the sibling collectors pseudonymize with
        # their own per-tool salt (e.g. Cursor's state dir differs), which
        # would show up as phantom extra hosts/users on the single-user
        # dashboard. Re-stamp every event with this machine's host_ref.
        for ev in evs:
            ev["host_ref"] = events.host_ref()
        return store.insert_events(evs, conn=db)

    total = 0
    try:
        total += transcript.scan_once(
            sink=sink,
            checkpoint=CHECKPOINT,
            ts_from_transcript=True,
            scan_content=True,
        )
        for tool_scan in (_scan_cursor, _scan_kilo, _scan_kimi, _scan_grok, _scan_copilot):
            try:
                total += tool_scan(sink)
            except Exception:
                pass  # one tool's parser must never break personal mode
        return total
    finally:
        if own:
            db.close()


def prune_once(db: store.sqlite3.Connection | None = None) -> dict | None:
    """Enforce retention on the personal store, at most daily.

    Fail-closed on a bad config (skip + log, delete nothing); never raises — a
    prune failure must not stop the dashboard from serving. Returns the prune
    summary when it ran, else None."""
    try:
        cfg = retention.from_env()
    except retention.RetentionConfigError as exc:
        print(f"[aim personal] retention config invalid — prune skipped: {exc}")
        return None
    own = db is None
    db = db or store.connect()
    try:
        result = store.maybe_prune(cfg.events_days, db, dry_run=cfg.dry_run)
        if result is not None:
            verb = "would delete" if result["dry_run"] else "deleted"
            print(f"[aim personal] retention: {verb} {result['would_delete']} "
                  f"event(s) older than {cfg.events_days}d")
        return result
    except Exception as exc:  # noqa: BLE001 — retention must never crash the server
        print(f"[aim personal] retention prune error (non-fatal): {exc}")
        return None
    finally:
        if own:
            db.close()


def _parse_days(qs: dict, default: int = 30, maximum: int = 365) -> int:
    try:
        d = int(qs.get("days", [default])[0])
    except (ValueError, TypeError):
        return default
    return max(1, min(d, maximum))


def _parse_source(qs: dict):
    s = qs.get("source", [None])[0]
    return s if s in ("proxy", "endpoint") else None


class Handler(BaseHTTPRequestHandler):
    server_version = "aim-personal/1"
    web = None  # set on the server instance

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Personal, single-user, localhost-only: no caching of API responses.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _api(self, path: str, qs: dict):
        conn = store.connect(self.web_db)
        try:
            days = _parse_days(qs)
            source = _parse_source(qs)
            if path == "/api/me":
                # mode/capabilities drive the UI: no findings console, no
                # user-level rows, and no Teams tab in personal mode.
                return self._send_json({
                    "email": "you (personal mode)",
                    "groups": [],
                    "mode": "personal",
                    "capabilities": {"findingsConsole": False, "userLevel": False},
                })
            if path == "/api/overview":
                return self._send_json(store.overview(conn, days, source))
            if path == "/api/providers":
                return self._send_json(store.providers(conn, days, source))
            if path == "/api/teams":
                return self._send_json(store.teams(conn, days))
            if path.startswith("/api/tools/"):
                from urllib.parse import unquote
                tool = unquote(path[len("/api/tools/"):])
                return self._send_json(store.tool_detail(conn, tool, days))
            if path == "/api/flags":
                return self._send_json(store.flags(conn, days))
            if path == "/api/unapproved":
                return self._send_json(store.unapproved(conn, _parse_days(qs, 90)))
            if path == "/api/users":
                # No security group in personal mode; the tab stays hidden.
                return self._send_json({"error": "forbidden", "detail": "not available in personal mode"}, 403)
            return self._send_json({"error": "not_found", "detail": path}, 404)
        finally:
            conn.close()

    def _static(self, path: str):
        rel = path.lstrip("/") or "index.html"
        target = (self.web_root / rel).resolve()
        # path-traversal guard: must stay under web root
        if self.web_root not in target.parents and target != self.web_root:
            return self._send_json({"error": "forbidden"}, 403)
        if target.is_dir():
            target = target / "index.html"
        if not target.is_file():
            return self._send_json({"error": "not_found", "detail": path}, 404)
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", _CONTENT_TYPES.get(target.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        try:
            if parsed.path.startswith("/api/"):
                self._api(parsed.path, qs)
            else:
                self._static(parsed.path)
        except BrokenPipeError:
            pass

    def log_message(self, *a):
        pass  # quiet by default


def serve(port: int = DEFAULT_PORT, watch: bool = False, watch_interval: float = 30.0) -> None:
    root = web_root()
    db_file = str(store.db_path())

    # initial scan so the dashboard has data on first load
    n = scan()
    print(f"[aim personal] scanned local AI tools, {n} usage event(s) written")
    print(f"[aim personal] store: {db_file}")

    if watch:
        def _loop():
            while True:
                time.sleep(watch_interval)
                try:
                    scan()
                except Exception:
                    pass
        threading.Thread(target=_loop, daemon=True).start()

    handler = type("BoundHandler", (Handler,), {"web_root": root, "web_db": db_file})
    # 127.0.0.1 only: never bind a routable interface in personal mode.
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    print(f"[aim personal] dashboard ready — open {url}")
    print("[aim personal] localhost only, zero outbound network. Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[aim personal] stopped")
    finally:
        httpd.server_close()


def main(args: list[str]) -> int:
    port = DEFAULT_PORT
    watch = False
    scan_only = False
    it = iter(args)
    for a in it:
        if a == "--watch":
            watch = True
        elif a == "--scan-only":
            scan_only = True
        elif a in ("--port", "-p"):
            port = int(next(it))
        elif a.startswith("--port="):
            port = int(a.split("=", 1)[1])
        else:
            import sys
            sys.stderr.write(f"unknown personal option {a!r}\n")
            return 2
    if scan_only:
        n = scan()
        print(f"emitted {n} usage events to {store.db_path()}")
        return 0
    serve(port=port, watch=watch)
    return 0

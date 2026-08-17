"""Fleet enrollment + heartbeat client.

One-line install (``python -m <collector> install --ingest-url URL
--enroll-token TOKEN``) enrolls the device with the ingestion service and
stores the issued per-device token at ``<state dir>/device_token`` (mode
0600). The watch daemon and the ``heartbeat`` command then POST liveness
to ``/v1/heartbeat`` so the fleet coverage view can tell healthy devices
from stale ones.

Protocol: docs/deployment/enrollment-and-heartbeat.md. Metadata only:
host identity is the random UUID from ``state.host_id()``, never a
hardware fingerprint. Every network function here fails closed into a
result dict — a collector must never crash the engineer's tool.
"""

import http.client
import json
import os
import platform
import socket
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__, config, state

_TIMEOUT = 10
DEFAULT_INTERVAL = 300  # matches the ingest default heartbeat_interval_sec


# --- TLS + split-horizon transport --------------------------------
#
# Fleet enroll/heartbeat talk to an ingest URL that may present a private CA
# (stack gateway) and may not resolve on the collector host (*.localhost is
# only a SHOULD under RFC 6761). Operators pass --ca-bundle / --resolve on
# `aim join`; those land in config.json so the watch daemon reuses them.


def _ca_bundle_path() -> str | None:
    """Path to a PEM trust bundle, or None for the process default store.

    Order: AIM_CA_BUNDLE env > config.ca_bundle/ca_cert > SSL_CERT_FILE.
    SSL_CERT_FILE is last so an explicit flag/config wins over ambient env,
    but still works when the launcher only sets the OpenSSL-standard var.
    """
    for key in ("AIM_CA_BUNDLE",):
        val = os.environ.get(key)
        if val:
            return val
    cfg = config.load()
    for key in ("ca_bundle", "ca_cert"):
        val = cfg.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return os.environ.get("SSL_CERT_FILE") or None


def _resolve_entries() -> list[str]:
    """curl-style ``host:port:ip`` entries from env or config."""
    env = os.environ.get("AIM_RESOLVE")
    if env:
        return [e.strip() for e in env.split(",") if e.strip()]
    cfg = config.load()
    raw = cfg.get("resolve")
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    if isinstance(raw, list):
        return [str(e).strip() for e in raw if str(e).strip()]
    return []


def _parse_resolve(entries: list[str]) -> dict[tuple[str, int], str]:
    """Parse ``host:port:ip`` (IPv6 address as ``host:port:[::1]``) → map."""
    out: dict[tuple[str, int], str] = {}
    for entry in entries:
        # Split from the right so an IPv6 address keeps its colons.
        host, sep, rest = entry.partition(":")
        if not sep or not host:
            continue
        port_s, sep2, ip = rest.partition(":")
        if not sep2 or not port_s or not ip:
            continue
        try:
            port = int(port_s)
        except ValueError:
            continue
        out[(host.lower(), port)] = ip.strip().strip("[]")
    return out


def _ssl_context() -> ssl.SSLContext:
    ca = _ca_bundle_path()
    if ca:
        return ssl.create_default_context(cafile=ca)
    return ssl.create_default_context()


class _ResolvedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that dials a fixed IP while keeping Host as the URL host."""

    resolve_map: dict[tuple[str, int], str] = {}

    def connect(self):
        ip = self.resolve_map.get((self.host.lower(), self.port))
        if not ip:
            return super().connect()
        self.sock = socket.create_connection(
            (ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()


class _ResolvedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection with curl-style --resolve: dial IP, SNI stays the name."""

    resolve_map: dict[tuple[str, int], str] = {}

    def connect(self):
        ip = self.resolve_map.get((self.host.lower(), self.port))
        if not ip:
            return super().connect()
        self.sock = socket.create_connection(
            (ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()
        # Keep SNI + cert hostname as the URL host, not the resolved IP —
        # that is the whole point of --resolve vs rewriting the URL.
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=self.host)


def _urlopen(req: urllib.request.Request, timeout: float = _TIMEOUT):
    """urlopen with optional private CA and curl-style --resolve overrides."""
    ctx = _ssl_context()
    rmap = _parse_resolve(_resolve_entries())
    if not rmap:
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)

    class _HTTPConn(_ResolvedHTTPConnection):
        resolve_map = rmap

    class _HTTPSConn(_ResolvedHTTPSConnection):
        resolve_map = rmap

    class _HTTP(urllib.request.HTTPHandler):
        def http_open(self, request):
            return self.do_open(_HTTPConn, request)

    class _HTTPS(urllib.request.HTTPSHandler):
        def __init__(self):
            super().__init__(context=ctx)

        def https_open(self, request):
            return self.do_open(_HTTPSConn, request)

    return urllib.request.build_opener(_HTTP, _HTTPS).open(req, timeout=timeout)


def device_token_path() -> Path:
    return state.state_dir() / "device_token"


def device_token() -> str | None:
    try:
        return device_token_path().read_text().strip() or None
    except OSError:
        return None


def device_id_path() -> Path:
    return state.state_dir() / "device_id"


def device_id() -> str | None:
    try:
        return device_id_path().read_text().strip() or None
    except OSError:
        return None


def store_device_id(device_id: str) -> None:
    try:
        device_id_path().write_text(device_id + "\n")
    except OSError:
        pass


def last_heartbeat_path() -> Path:
    return state.state_dir() / "last_heartbeat"


def last_heartbeat_at() -> float | None:
    """Epoch seconds of the most recent accepted heartbeat, or None."""
    try:
        return float(last_heartbeat_path().read_text().strip())
    except (OSError, ValueError):
        return None


def _record_heartbeat() -> None:
    try:
        last_heartbeat_path().write_text(f"{int(time.time())}\n")
    except OSError:
        pass


def store_device_token(token: str) -> Path:
    p = device_token_path()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token + "\n")
    os.chmod(p, 0o600)  # explicit: also fixes a pre-existing loose file
    return p


def clear_device_token() -> None:
    device_token_path().unlink(missing_ok=True)
    device_id_path().unlink(missing_ok=True)
    last_heartbeat_path().unlink(missing_ok=True)


def os_string() -> str:
    return f"{platform.system().lower()}-{platform.release()}"


def _post(url: str, token: str, path: str, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        url.rstrip("/") + path,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with _urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ssl.SSLError):
        return 0, {}


def enroll(ingest_url: str, enroll_token: str, ring: str | None = None) -> dict:
    """Enroll this device and store the issued per-device token.

    Idempotent server-side: a re-enroll (HTTP 200) carries no new token when
    the local device_token is already present. If the local token is missing
    (host wipe, deleted state dir) we ask the server to rotate via
    ``reissue: true`` using the same enroll bearer — that is the deliberate
    admin-equivalent recovery path (dogfood).
    """
    payload = {
        "host_id": state.host_id(),
        "hostname": socket.gethostname(),
        "os": os_string(),
        "collector_version": __version__,
    }
    if ring:
        payload["ring"] = ring
    # when the local state still knows a previous enrollment id but
    # the server mints a new one (devices table recreated, host_id row lost),
    # ingest rebinds identity-sync join keys so service_identity / mapping
    # rows are not left pointing at the obsolete device_id.
    previous = device_id()
    if previous:
        payload["previous_device_id"] = previous
    # Request a fresh device token when we have none locally. First enroll
    # ignores reissue; live hosts rotate; revoked hosts are revived by the
    # server even without the flag.
    if not device_token():
        payload["reissue"] = True
    status, body = _post(ingest_url, enroll_token, "/v1/enroll", payload)
    if status in (200, 201):
        token = body.get("device_token")
        if token:
            store_device_token(token)
        elif not device_token():
            return {"ok": False, "status": status,
                    "error": "device already enrolled and no local device "
                             "token; server refused reissue"}
        if body.get("device_id"):
            store_device_id(body["device_id"])
        return {"ok": True, "status": status,
                "already_enrolled": bool(body.get("already_enrolled")),
                "device_id": body.get("device_id"),
                "heartbeat_interval_sec": body.get("heartbeat_interval_sec",
                                                   DEFAULT_INTERVAL)}
    if status == 0:
        return {"ok": False, "status": status, "error": "ingest unreachable"}
    return {"ok": False, "status": status,
            "error": body.get("error") or f"enroll rejected (HTTP {status})"}


def heartbeat() -> dict:
    """Single liveness POST using the stored per-device token.

    On 401 the token is revoked/unknown server-side: the local copy is
    deleted so a decommissioned device stops cleanly instead of retrying
    forever.
    """
    url = config.ingest_url()
    token = device_token()
    if not url or not token:
        return {"ok": False, "error": "not enrolled"}
    status, body = _post(url, token, "/v1/heartbeat", {
        "host_id": state.host_id(),
        "collector_version": __version__,
        "os": os_string(),
        "counters": _counters(),
    })
    if 200 <= status < 300:
        _record_heartbeat()
        # heal a missing local device_id from the heartbeat response.
        # clear_device_token() wipes device_id with the token; if only the token
        # is restored (or the file is lost), batches fall back to os_user-only
        # and device_id-keyed service_identities resolve as principal_kind=unknown.
        server_device_id = body.get("device_id")
        if isinstance(server_device_id, str) and server_device_id.strip():
            if device_id() != server_device_id.strip():
                store_device_id(server_device_id.strip())
        return {"ok": True, "status": status,
                "device_id": body.get("device_id") or device_id(),
                "heartbeat_interval_sec": body.get("heartbeat_interval_sec",
                                                   DEFAULT_INTERVAL)}
    if status == 401:
        clear_device_token()
        return {"ok": False, "status": status,
                "error": "device token rejected (revoked?)"}
    if status == 0:
        return {"ok": False, "status": status, "error": "ingest unreachable"}
    return {"ok": False, "status": status,
            "error": body.get("error") or f"heartbeat failed (HTTP {status})"}


def maybe_heartbeat(last_sent: float, interval: float = DEFAULT_INTERVAL) -> float:
    """Heartbeat-when-due helper for watch daemons. Send on first call and
    every ``interval`` seconds after; no-op when not enrolled. Returns the
    monotonic timestamp of the last attempt (``last_sent`` if skipped).

    ``last_sent <= 0`` is the "never sent" sentinel and is always due — a
    collector starting soon after boot must emit its first liveness heartbeat
    immediately, not wait for ``time.monotonic()`` (uptime) to reach
    ``interval``."""
    if not device_token():
        return last_sent
    now = time.monotonic()
    if last_sent > 0 and now - last_sent < interval:
        return last_sent
    heartbeat()
    return now


def _counters() -> dict:
    spooled = 0
    p = state.spool_path()
    if p.exists():
        try:
            spooled = sum(1 for l in p.read_text().splitlines() if l.strip())
        except OSError:
            pass
    c = {"events_spooled": spooled}
    # Events ingest refused inside a 2xx. Reported on every
    # heartbeat so the fleet view can attribute a rejection spike to this
    # device and build — the server-side `rejected_events` table knows the
    # count but not who lost them.
    led = _rejection_ledger()
    c["events_rejected"] = int(led.get("events") or 0)
    c["batches_fully_rejected"] = int(led.get("batches_fully_rejected") or 0)
    if led.get("last_at"):
        c["last_rejection_at"] = int(led["last_at"])
    return c


def _rejection_ledger() -> dict:
    """spool's local rejection ledger. Imported lazily and defensively: the
    heartbeat is liveness and must never fail because the ledger is absent."""
    try:
        from . import spool
        return spool.rejections()
    except Exception:  # noqa: BLE001
        return {}


_INSTALL_FLAGS = {
    "--ingest-url": "ingest_url",
    "--enroll-token": "enroll_token",
    "--token": "token",
    "--ring": "ring",
}

INSTALL_USAGE = ("install [--ingest-url URL] [--enroll-token TOKEN] "
                 "[--token EVENTS_TOKEN] [--ring RING]")


def parse_install_args(args: list) -> dict | None:
    """Hand-rolled flag parse (no argparse, matching the rest of the CLI).
    Returns None on unknown/malformed flags."""
    opts = {"ingest_url": None, "enroll_token": None, "token": None, "ring": None}
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _INSTALL_FLAGS and i + 1 < len(args):
            opts[_INSTALL_FLAGS[arg]] = args[i + 1]
            i += 2
        elif arg.startswith("--") and "=" in arg:
            key, _, val = arg.partition("=")
            if key not in _INSTALL_FLAGS:
                return None
            opts[_INSTALL_FLAGS[key]] = val
            i += 1
        else:
            return None
    return opts


def write_config(
    ingest_url: str | None = None,
    token: str | None = None,
    *,
    ca_bundle: str | None = None,
    resolve: list[str] | None = None,
) -> Path:
    """Merge connection settings into the resolved config file.

    Target: ``AIM_CONFIG_FILE`` when set, else the first existing config in
    the managed search order, else the per-user state-dir config. The events
    token goes to a 0600 file referenced by ``token_file`` — never plaintext
    in the JSON we write.

    ``ca_bundle`` and ``resolve`` are persisted so the watch
    daemon reuses the same private-CA / split-horizon settings that made
    ``aim join`` work — without requiring ambient SSL_CERT_FILE forever.
    """
    explicit = os.environ.get("AIM_CONFIG_FILE")
    if explicit:
        path = Path(explicit).expanduser()
    else:
        path = config.config_path() or (state.state_dir() / "config.json")
    cfg = {}
    if path.exists():
        try:
            parsed = json.loads(path.read_text())
            cfg = parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            cfg = {}
    if ingest_url:
        cfg["ingest_url"] = ingest_url
    if ca_bundle:
        # Absolute so a later watch started from another cwd still finds it.
        cfg["ca_bundle"] = str(Path(ca_bundle).expanduser().resolve())
    if resolve is not None:
        cleaned = [str(e).strip() for e in resolve if str(e).strip()]
        if cleaned:
            cfg["resolve"] = cleaned
        else:
            cfg.pop("resolve", None)
    if token is not None:
        token_file = state.state_dir() / "token"
        fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(token + "\n")
        os.chmod(token_file, 0o600)
        cfg["token_file"] = str(token_file)
        cfg.pop("token", None)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cfg, indent=2) + "\n")
    return path


def setup(opts: dict) -> int:
    """Shared one-line-install flow: write config, enroll, verify
    connectivity end-to-end with a first heartbeat. Returns an exit code."""
    if opts.get("ingest_url") or opts.get("token") is not None:
        print(f"config written to {write_config(opts['ingest_url'], opts['token'])}")
    enroll_token = opts.get("enroll_token")
    if not enroll_token:
        if not opts.get("ingest_url"):
            print("tip: " + INSTALL_USAGE + " also writes config and enrolls "
                  "the device for fleet coverage")
        return 0
    url = opts.get("ingest_url") or config.ingest_url()
    if not url:
        print("error: --enroll-token needs an ingest URL "
              "(--ingest-url or managed config)")
        return 1
    res = enroll(url, enroll_token, ring=opts.get("ring"))
    if not res.get("ok"):
        print(f"error: enrollment failed: {res.get('error')}")
        return 1
    verb = "already enrolled" if res.get("already_enrolled") else "enrolled"
    print(f"{verb} as device {res.get('device_id')} "
          f"(device token stored at {device_token_path()}, mode 0600)")
    hb = heartbeat()
    if hb.get("ok"):
        print("connectivity verified: first heartbeat accepted")
        return 0
    print(f"error: enrolled but heartbeat verification failed: {hb.get('error')}")
    return 1

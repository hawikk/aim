"""Fleet enrollment + heartbeat client (event-auth).

One-line install (``python -m <collector> install --ingest-url URL
--enroll-token TOKEN``) enrolls the device with the ingestion service and
stores the issued per-device token at ``<state dir>/device_token`` (mode
0600). The watch daemon and the ``heartbeat`` command then POST liveness
to ``/v1/heartbeat`` so the fleet coverage view can tell healthy devices
from stale ones.

The same per-device token authorizes ``POST /v1/events``, so
``aim join`` / enroll alone is enough for spool flush — a separate shared
ingest bearer is optional for managed fleets. Join/install verification
probes event auth, not only heartbeat, so a collector that cannot send
events fails loudly instead of reporting green.

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
from pathlib import Path
from urllib.parse import urlparse

from . import __version__, config, state

_TIMEOUT = 10
DEFAULT_INTERVAL = 300  # matches the ingest default heartbeat_interval_sec


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


def unenroll() -> dict:
    """Revoke this device server-side, then clear local enrollment state.

    Called by ``aim uninstall`` so a clean exit does not leave a zombie
    coverage row. Best-effort network: if the endpoint is
    unreachable we still wipe local state and report the network error —
    the engineer is entitled to a local clean slate even offline. Idempotent
    on the server (unknown/already-revoked tokens return 200).
    """
    url = config.ingest_url()
    token = device_token()
    if not token:
        clear_device_token()
        return {"ok": True, "status": "not_enrolled"}
    if not url:
        clear_device_token()
        return {"ok": True, "status": "local_only",
                "error": "ingest_url not configured; local state cleared only"}
    status, body = _post(url, token, "/v1/unenroll", {})
    clear_device_token()
    if status == 0:
        return {"ok": True, "status": "local_cleared",
                "error": "ingest unreachable; local state cleared, "
                         "server-side revoke may still be needed"}
    if 200 <= status < 300:
        return {"ok": True, "status": body.get("status") or "revoked",
                "device_id": body.get("device_id")}
    # 401 means the token was already unknown/revoked — local wipe is enough.
    if status == 401:
        return {"ok": True, "status": "already_revoked"}
    return {"ok": True, "status": "local_cleared",
            "error": body.get("error") or f"unenroll HTTP {status}; "
                     "local state cleared"}


def os_string() -> str:
    return f"{platform.system().lower()}-{platform.release()}"


def _ca_cert_path() -> str | None:
    """Path to an extra CA bundle for the ingest endpoint.

    Order: AIM_CA_CERT env, SSL_CERT_FILE (stdlib openssl default), then
    ``ca_cert`` in the managed/user config written by ``aim join --ca-cert``.
    """
    for key in ("AIM_CA_CERT", "SSL_CERT_FILE"):
        val = os.environ.get(key)
        if val:
            return val
    cfg_val = config.load().get("ca_cert")
    return str(cfg_val) if cfg_val else None


def _resolve_map() -> dict[str, str]:
    """Hostname → connect-IP map for split-horizon / no-DNS pilots.

    ``AIM_RESOLVE`` is a comma-separated list of ``host:ip`` or curl-style
    ``host:port:ip`` entries (port is ignored for the map key). Config key
    ``resolve`` is a JSON object of the same shape.
    """
    out: dict[str, str] = {}
    cfg_val = config.load().get("resolve")
    if isinstance(cfg_val, dict):
        for host, ip in cfg_val.items():
            if host and ip:
                out[str(host)] = str(ip)
    env = os.environ.get("AIM_RESOLVE") or ""
    for part in env.split(","):
        part = part.strip()
        if not part:
            continue
        bits = part.split(":")
        if len(bits) == 2:
            host, ip = bits
        elif len(bits) == 3:
            host, _port, ip = bits
        else:
            continue
        if host and ip:
            out[host] = ip
    return out


def parse_resolve_arg(spec: str) -> tuple[str, str] | None:
    """Parse one ``host:ip`` or ``host:port:ip`` flag value → (host, ip)."""
    bits = (spec or "").strip().split(":")
    if len(bits) == 2 and bits[0] and bits[1]:
        return bits[0], bits[1]
    if len(bits) == 3 and bits[0] and bits[2]:
        return bits[0], bits[2]
    return None


def _ssl_context(ca_cert: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if ca_cert:
        ctx.load_verify_locations(cafile=ca_cert)
    return ctx


def _diagnose_network_error(exc: BaseException, url: str) -> str:
    """Human-readable remedy for a network-layer failure."""
    msg = str(exc) or exc.__class__.__name__
    low = msg.lower()
    if isinstance(exc, ssl.SSLError) or "certificate" in low or "ssl" in low:
        return (
            f"TLS/certificate error talking to {url}: {msg}. "
            "If this is a pilot with an internal CA, re-run with "
            "`--ca-cert /path/to/ca.pem` (or set SSL_CERT_FILE / AIM_CA_CERT)."
        )
    if isinstance(exc, socket.gaierror) or "name or service not known" in low \
            or "nodename nor servname" in low or "getaddrinfo" in low:
        return (
            f"DNS resolution failed for {url}: {msg}. "
            "Check the ingest hostname, or for single-VM pilots use "
            "`--resolve HOST:IP` so the collector connects without root DNS."
        )
    if "connection refused" in low:
        return (
            f"Connection refused to {url}: is the ingest service up and "
            "reachable from this network? Check VPN / firewall / port."
        )
    if "timed out" in low or "timeout" in low:
        return (
            f"Timed out reaching {url}: network path may be blocked, or "
            "ingest is overloaded. Retry once connectivity is confirmed."
        )
    if "permission" in low:
        return f"Permission error reaching {url}: {msg}."
    return f"ingest unreachable ({url}): {msg}"


def _post(url: str, token: str, path: str, payload: dict) -> tuple[int, dict]:
    """POST JSON to the ingest endpoint, honouring ca_cert + resolve.

    ``--resolve`` / config ``resolve`` connects to an alternate IP while keeping
    the original Host header and TLS SNI so a gateway vhost (e.g.
    ``ingest.localhost``) works without DNS or root. ``--ca-cert`` /
    SSL_CERT_FILE trusts the stack's internal CA for the same reason.
    """
    full = url.rstrip("/") + path
    parsed = urlparse(full)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return 0, {}
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    connect_host = _resolve_map().get(hostname, hostname)
    request_path = parsed.path or "/"
    if parsed.query:
        request_path = f"{request_path}?{parsed.query}"
    host_header = hostname if parsed.port is None else f"{hostname}:{port}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "Host": host_header,
    }
    body = json.dumps(payload).encode()
    try:
        if parsed.scheme == "https":
            ctx = _ssl_context(_ca_cert_path())
            # Connect to connect_host but present SNI for the vhost name so
            # Caddy's internal cert for ingest.<host> still verifies.
            class _SNIConn(http.client.HTTPSConnection):
                def connect(self_inner):  # noqa: N805 — bound method
                    sock = socket.create_connection(
                        (self_inner.host, self_inner.port),
                        self_inner.timeout,
                        self_inner.source_address,
                    )
                    self_inner.sock = ctx.wrap_socket(
                        sock, server_hostname=hostname
                    )

            conn: http.client.HTTPConnection = _SNIConn(
                connect_host, port, timeout=_TIMEOUT, context=ctx
            )
        else:
            conn = http.client.HTTPConnection(
                connect_host, port, timeout=_TIMEOUT
            )
        try:
            conn.request("POST", request_path, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read() or b"{}"
            try:
                parsed_body = json.loads(raw)
            except json.JSONDecodeError:
                parsed_body = {}
            if not isinstance(parsed_body, dict):
                parsed_body = {}
            return resp.status, parsed_body
        finally:
            conn.close()
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        return 0, {"error": _diagnose_network_error(exc, url)}


def enroll(ingest_url: str, enroll_token: str, ring: str | None = None) -> dict:
    """Enroll this device and store the issued per-device token.

    Idempotent server-side: a re-enroll (HTTP 200) carries no new token when
    the local device_token is already present. If the local token is missing
    we ask the server to rotate via ``reissue: true`` using the enroll bearer
    (dogfood recovery path).
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
    if not device_token():
        payload["reissue"] = True
    status, body = _post(ingest_url, enroll_token, "/v1/enroll", payload)
    if status in (200, 201):
        token = body.get("device_token")
        if token:
            store_device_token(token)
        elif not device_token():
            return {"ok": False, "status": status,
                    "error": "device already enrolled server-side but this "
                             "machine has no local device_token and the "
                             "server refused reissue. Fix: confirm the "
                             "enroll token is valid, or ask a security-admin "
                             "to revoke the device in the fleet view."}
        if body.get("device_id"):
            store_device_id(body["device_id"])
        return {"ok": True, "status": status,
                "already_enrolled": bool(body.get("already_enrolled")),
                "device_id": body.get("device_id"),
                "heartbeat_interval_sec": body.get("heartbeat_interval_sec",
                                                   DEFAULT_INTERVAL)}
    if status == 0:
        return {"ok": False, "status": status,
                "error": body.get("error") or "ingest unreachable"}
    if status == 401:
        return {"ok": False, "status": status,
                "error": "enrollment token rejected (invalid, revoked, "
                         "expired, or exhausted). Mint a fresh token from "
                         "the Onboarding view and re-run `aim join`."}
    if status == 400:
        return {"ok": False, "status": status,
                "error": body.get("error") or "enroll request rejected "
                         "(check host_id / payload)."}
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
                "error": "device token rejected (revoked or unknown). "
                         "Re-run `aim join` with a fresh enrollment token."}
    if status == 0:
        return {"ok": False, "status": status,
                "error": body.get("error") or "ingest unreachable"}
    return {"ok": False, "status": status,
            "error": body.get("error") or f"heartbeat failed (HTTP {status})"}


def verify_event_auth() -> dict:
    """Prove the events credential can authorize ``POST /v1/events``.

    Heartbeat success only proves the device token works for liveness. Spool
    flush uses ``config.token()`` (shared bearer or device_token fallback) on
    ``/v1/events``. Before those were different credentials and join
    reported green while never being able to send an event.

    Probes with an empty batch: auth is checked first, then the server returns
    400 for the empty body. ``400`` (or any non-401 4xx/2xx) means the bearer
    is accepted for events. ``401`` means this collector cannot flush.
    """
    url = config.ingest_url()
    token = config.token()
    if not url:
        return {"ok": False, "error": "ingest_url not configured"}
    if not token:
        return {
            "ok": False,
            "error": (
                "no event credential: enroll (device_token) or set "
                "AIM_COLLECTOR_TOKEN / token_file"
            ),
        }
    status, body = _post(url, token, "/v1/events", {"events": []})
    if status == 401:
        return {
            "ok": False,
            "status": status,
            "error": (
                "event credential rejected by /v1/events (device token or "
                "shared ingest token not accepted)"
            ),
        }
    if status == 0:
        return {"ok": False, "status": status, "error": "ingest unreachable"}
    # 400 empty-batch (or any other non-401) means auth passed.
    if 200 <= status < 500:
        return {"ok": True, "status": status}
    return {
        "ok": False,
        "status": status,
        "error": body.get("error") or f"event auth probe failed (HTTP {status})",
    }


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
    "--ca-cert": "ca_cert",
    "--ca-bundle": "ca_cert",  # curl-shaped alias
    "--resolve": "resolve",
}

INSTALL_USAGE = (
    "install [--ingest-url URL] [--enroll-token TOKEN] "
    "[--token EVENTS_TOKEN] [--ring RING] "
    "[--ca-cert PATH] [--resolve HOST:IP]"
)


def parse_install_args(args: list) -> dict | None:
    """Hand-rolled flag parse (no argparse, matching the rest of the CLI).
    Returns None on unknown/malformed flags."""
    opts = {
        "ingest_url": None,
        "enroll_token": None,
        "token": None,
        "ring": None,
        "ca_cert": None,
        "resolve": None,
    }
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
    ca_cert: str | None = None,
    resolve: dict | str | None = None,
) -> Path:
    """Merge connection settings into the resolved config file.

    Target: ``AIM_CONFIG_FILE`` when set, else the first existing config in
    the managed search order, else the per-user state-dir config. The events
    token goes to a 0600 file referenced by ``token_file`` — never plaintext
    in the JSON we write.

    ``ca_cert`` / ``resolve`` let a single-VM pilot enroll against
    ``ingest.<host>`` without root DNS or system trust store changes; they
    persist so heartbeats and spool flush keep working after join.
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
    if ca_cert:
        cfg["ca_cert"] = str(Path(ca_cert).expanduser())
    if resolve is not None:
        merged = (
            dict(cfg.get("resolve") or {})
            if isinstance(cfg.get("resolve"), dict)
            else {}
        )
        if isinstance(resolve, dict):
            merged.update({str(k): str(v) for k, v in resolve.items() if k and v})
        elif isinstance(resolve, str):
            parsed_r = parse_resolve_arg(resolve)
            if parsed_r:
                merged[parsed_r[0]] = parsed_r[1]
        if merged:
            cfg["resolve"] = merged
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
    heartbeat *and* event auth end-to-end. Returns an exit code."""
    should_write = any(
        opts.get(k) is not None
        for k in ("ingest_url", "token", "ca_cert", "resolve")
    )
    if should_write:
        path = write_config(
            opts.get("ingest_url"),
            opts.get("token"),
            ca_cert=opts.get("ca_cert"),
            resolve=opts.get("resolve"),
        )
        print(f"config written to {path}")
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
    if not hb.get("ok"):
        print(f"error: enrolled but heartbeat verification failed: {hb.get('error')}")
        return 1
    ev = verify_event_auth()
    if not ev.get("ok"):
        print(f"error: enrolled but event delivery auth failed: {ev.get('error')}")
        print("heartbeat works but this collector cannot flush events — "
              "ingest must accept the device token on /v1/events")
        return 1
    print("connectivity verified: heartbeat + event auth accepted")
    return 0

"""Local spool + flush to the ingestion API — canonical shared client (AIM-200).

Every endpoint collector ships as a standalone package and vendors a
byte-identical copy of this file (see scripts/sync_spool_client.py). It
depends only on each package's ``config``, ``identity`` and ``state``
modules, whose interfaces are identical across collectors.

Events are appended to spool.jsonl before any network attempt, so the
collector is safe offline and across reboots. flush() drains the spool in
batches; on failure the unacked remainder is kept for the next run.

HTTP 200 is *not* full acceptance. The ingest API answers a batch with
``{accepted, duplicates, unresolved, rejected: [{index, error}]}`` and
rejects individual schema-invalid events inside a 2xx response. Before
AIM-200 this client read only the status line, so rejected events were
dropped from the spool and counted as sent — a silent data-path loss that
went fleet-wide whenever a producer was deployed ahead of its ingest
(``additionalProperties: false`` means one unknown field rejects the whole
event). Rejections are now parsed, persisted locally, and surfaced by
``aim status`` / ``aim doctor`` and the heartbeat counters.
"""

import http.client
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import config, identity, state

_BATCH = 200
_TIMEOUT = 10
_MAX_SPOOL_BYTES = 50 * 1024 * 1024  # drop-oldest guard against disk bloat
_MAX_KEPT_REASONS = 5


# --- TLS + split-horizon transport (AIM-238) --------------------------------
# Mirrors collectors/enroll-client/enroll.py so spool + enroll honour the
# same ca_bundle / resolve keys the join line wrote into config.json.


def _ca_bundle_path() -> str | None:
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
    out: dict[tuple[str, int], str] = {}
    for entry in entries:
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
    resolve_map: dict[tuple[str, int], str] = {}

    def connect(self):
        ip = self.resolve_map.get((self.host.lower(), self.port))
        if not ip:
            return super().connect()
        self.sock = socket.create_connection(
            (ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=self.host)


def _urlopen(req: urllib.request.Request, timeout: float = _TIMEOUT):
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


def append(events: list[dict]) -> None:
    if not events:
        return
    p = state.spool_path()
    with p.open("a", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, separators=(",", ":")) + "\n")
    _enforce_cap(p)


def _enforce_cap(p: Path) -> None:
    try:
        if p.stat().st_size <= _MAX_SPOOL_BYTES:
            return
        lines = p.read_text().splitlines()
        keep = lines[-(len(lines) // 2):]  # drop oldest half
        p.write_text("\n".join(keep) + "\n")
    except OSError:
        pass


# --- local rejection ledger -------------------------------------------------
#
# Rejected events can never validate, so retrying them forever is its own
# outage: the cursor advances and they leave the spool. That makes the local
# ledger the *only* endpoint-side record that telemetry was lost, which is
# why it is persisted rather than kept in memory. Server-side counters exist
# (`rejected_events`), but nothing there ties a spike back to this device and
# build — and the endpoint itself must be able to say "I am losing events".


def rejections_path() -> Path:
    return state.state_dir() / "rejections.json"


def rejections() -> dict:
    """The persisted rejection ledger, or an empty ledger.

    Keys: events (total rejected), batches_fully_rejected, last_at (epoch),
    last_error, last_full_rejection_at, reasons (recent distinct errors).
    """
    try:
        data = json.loads(rejections_path().read_text())
        return data if isinstance(data, dict) else _empty_ledger()
    except (OSError, ValueError):
        return _empty_ledger()


def _empty_ledger() -> dict:
    return {"events": 0, "batches_fully_rejected": 0, "last_at": None,
            "last_error": None, "last_full_rejection_at": None, "reasons": []}


def clear_rejections() -> None:
    """Drop the ledger — used by uninstall and after an operator acks."""
    try:
        rejections_path().unlink(missing_ok=True)
    except OSError:
        pass


def _record_rejections(rejected: list[dict], full_batch: bool) -> None:
    if not rejected:
        return
    led = rejections()
    led["events"] = int(led.get("events") or 0) + len(rejected)
    led["last_at"] = int(time.time())
    errors = [str(r.get("error") or "unspecified") for r in rejected]
    led["last_error"] = errors[0]
    if full_batch:
        led["batches_fully_rejected"] = int(led.get("batches_fully_rejected") or 0) + 1
        led["last_full_rejection_at"] = led["last_at"]
    # Keep a few *distinct* reasons: one contract mismatch repeated 200 times
    # is one fact, and the ledger must not grow without bound.
    reasons = list(led.get("reasons") or [])
    for e in errors:
        if e not in reasons:
            reasons.append(e)
    led["reasons"] = reasons[-_MAX_KEPT_REASONS:]
    try:
        dest = rejections_path()
        tmp = dest.with_suffix(".tmp")
        tmp.write_text(json.dumps(led))
        tmp.replace(dest)  # atomic
    except OSError:
        pass


class _PostResult:
    """Outcome of one batch POST.

    ok           2xx — the batch reached ingest and the cursor may advance.
                 NOTE: ok does not mean every event was stored; see rejected.
    accepted     events ingest stored (excludes duplicates), when reported.
    rejected     per-event [{index, error}] ingest refused inside a 2xx.
    backpressure ingest signalled overload (429/503, AIM-127). Stop draining
                 and retain the spool; retry_after carries the server's
                 Retry-After hint (seconds) when present.
    """

    __slots__ = ("ok", "backpressure", "retry_after", "accepted", "rejected")

    def __init__(self, ok: bool, backpressure: bool = False, retry_after: float | None = None,
                 accepted: int | None = None, rejected: list[dict] | None = None):
        self.ok = ok
        self.backpressure = backpressure
        self.retry_after = retry_after
        self.accepted = accepted
        self.rejected = rejected or []


def _parse_retry_after(value: str | None) -> float | None:
    """Retry-After is delta-seconds or an HTTP-date. We honour the numeric form
    (what the ingest service sends) and ignore dates — a missing/odd value just
    means 'back off for the normal flush interval'."""
    if not value:
        return None
    try:
        secs = float(value.strip())
        return secs if secs >= 0 else None
    except ValueError:
        return None


def _parse_ack(raw: bytes) -> tuple[int | None, list[dict]]:
    """Read (accepted, rejected[]) out of an ingest 2xx body.

    An unparseable or bodyless 2xx is treated as "accepted, nothing rejected"
    — 202 with no body is a legitimate ack (the older ingest, and test
    doubles, answer that way) and must not be misreported as a rejection.
    """
    if not raw:
        return None, []
    try:
        body = json.loads(raw)
    except ValueError:
        return None, []
    if not isinstance(body, dict):
        return None, []
    accepted = body.get("accepted")
    if not isinstance(accepted, int):
        accepted = None
    rejected = body.get("rejected")
    if not isinstance(rejected, list):
        return accepted, []
    return accepted, [r for r in rejected if isinstance(r, dict)]


def _post_batch(url: str, token: str, events: list[dict], collector: dict) -> _PostResult:
    # Identity is attested once per batch in the envelope — never inside
    # event payloads (metadata-only contract, AIM-58).
    body_dict: dict = {"events": events}
    if collector:
        body_dict["collector"] = collector
    body = json.dumps(body_dict).encode()
    req = urllib.request.Request(
        url.rstrip("/") + "/v1/events",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with _urlopen(req, timeout=_TIMEOUT) as resp:
            ok = 200 <= resp.status < 300
            if not ok:
                return _PostResult(ok=False)
            try:
                raw = resp.read()
            except OSError:
                raw = b""
            accepted, rejected = _parse_ack(raw)
            return _PostResult(ok=True, accepted=accepted, rejected=rejected)
    except urllib.error.HTTPError as e:
        # 429/503 = ingest admission control shedding under overload (AIM-127).
        # Treat as backpressure: stop draining, keep the spool, honour
        # Retry-After. Any other HTTP error is a normal failure (retain + retry).
        if e.code in (429, 503):
            return _PostResult(
                ok=False,
                backpressure=True,
                retry_after=_parse_retry_after(e.headers.get("Retry-After")),
            )
        return _PostResult(ok=False)
    except (urllib.error.URLError, OSError):
        return _PostResult(ok=False)


def flush() -> dict:
    """Drain the spool. Returns {sent, rejected, remaining, error[, retry_after]}.

    ``sent`` counts events the cursor advanced past; ``rejected`` is how many
    of those ingest refused (they left the spool but were never stored). A
    clean flush is ``rejected == 0 and error is None`` — callers that treat a
    2xx as success must check ``rejected``.

    On ingest backpressure (429/503, AIM-127) the drain stops and the unsent
    remainder is retained for the next flush — the collector never piles on
    under overload. retry_after (when the server sends it) tells the daemon how
    long to wait before the next attempt; watch() honours it.

    On a *fully* rejected batch the drain also stops (AIM-200). Every
    following batch would fail the same way, so continuing would empty the
    whole spool into a contract mismatch; stopping bounds the loss to the one
    batch that already cannot be retried, and leaves the remainder for a
    flush after ingest catches up.
    """
    url = config.ingest_url()
    token = config.token()
    if not url or not token:
        return {"sent": 0, "rejected": 0, "remaining": _count(),
                "error": "ingest not configured (managed config file or AIM_INGEST_URL/AIM_COLLECTOR_TOKEN)"}

    p = state.spool_path()
    if not p.exists():
        return {"sent": 0, "rejected": 0, "remaining": 0, "error": None}

    lines = [l for l in p.read_text().splitlines() if l.strip()]
    collector = identity.collector_identity()
    sent = 0
    rejected_total = 0
    i = 0
    backpressure = False
    full_rejection = False
    retry_after: float | None = None
    while i < len(lines):
        chunk = [json.loads(l) for l in lines[i:i + _BATCH]]
        res = _post_batch(url, token, chunk, collector)
        if not res.ok:
            backpressure = res.backpressure
            retry_after = res.retry_after
            break
        if res.rejected:
            full_rejection = len(res.rejected) >= len(chunk)
            _record_rejections(res.rejected, full_rejection)
            rejected_total += len(res.rejected)
        sent += len(chunk)
        i += _BATCH
        if full_rejection:
            break

    remaining = lines[i:]
    if remaining:
        p.write_text("\n".join(remaining) + "\n")
    else:
        p.unlink(missing_ok=True)

    if full_rejection:
        # Loudest case: ingest stored nothing. That is a contract mismatch
        # (producer ahead of ingest schema), not bad data, and it must be
        # visible at the endpoint rather than only in a server-side table.
        error = ("ingest REJECTED an entire batch — schema contract mismatch, "
                 "telemetry is being lost; run `aim doctor`")
    elif rejected_total and sent == len(lines):
        error = f"ingest rejected {rejected_total} event(s) as invalid (dropped)"
    elif sent == len(lines):
        error = None
    elif backpressure:
        error = "ingest overloaded (backpressure); retained for retry"
    else:
        error = "ingest unreachable"
    result = {"sent": sent, "rejected": rejected_total,
              "remaining": len(remaining), "error": error}
    if backpressure and retry_after is not None:
        result["retry_after"] = retry_after
    return result


def _count() -> int:
    p = state.spool_path()
    if not p.exists():
        return 0
    return sum(1 for l in p.read_text().splitlines() if l.strip())

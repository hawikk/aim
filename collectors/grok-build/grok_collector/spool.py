"""Local spool + flush to the ingestion API — canonical shared client.

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
this client read only the status line, so rejected events were
dropped from the spool and counted as sent — a silent data-path loss that
went fleet-wide whenever a producer was deployed ahead of its ingest
(``additionalProperties: false`` means one unknown field rejects the whole
event). Rejections are now parsed, written to a local DLQ with the reason,
and surfaced by ``aim status`` / ``aim doctor`` and the heartbeat counters.

Delivery integrity contract:

* Only events ingest explicitly accepted (or already stored as duplicates)
  leave the spool as "delivered".
* Transport failures and 429/503 keep the whole batch on the spool for
  backoff retry.
* Schema / permanent rejections leave the spool *and* land in ``dlq.jsonl``
  with the rejection reason so every loss is attributable and re-sendable
  after a collector or ingest fix.
"""

import http.client
import json
import os
import socket
import ssl
import time
from pathlib import Path
from urllib.parse import urlparse

from . import config, identity, state

_BATCH = 200
_TIMEOUT = 10
_MAX_SPOOL_BYTES = 50 * 1024 * 1024  # drop-oldest guard against disk bloat
_MAX_DLQ_BYTES = 25 * 1024 * 1024    # drop-oldest on the permanent-rejection DLQ
_MAX_KEPT_REASONS = 5


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


# --- local rejection ledger + permanent-rejection DLQ -----------------------
#
# Schema-invalid events can never validate against *this* ingest image, so
# retrying them forever is its own outage: the cursor advances and they leave
# the spool. Two local records then become the endpoint-side proof that
# telemetry was lost:
#
#   * rejections.json  — counters + recent distinct reasons (cheap, for doctor
#                        and heartbeat counters)
#   * dlq.jsonl        — each permanently rejected event + its reason
#                        (attributable, re-sendable after a fix)
#
# Server-side `rejected_events` is the fleet audit trail, but it stores no
# payload and does not name this device. The endpoint itself must be able to
# say "I am losing events" and hold the loss until an operator acts.


def rejections_path() -> Path:
    return state.state_dir() / "rejections.json"


def dlq_path() -> Path:
    """Permanent-rejection dead-letter file. One JSON object per line."""
    return state.state_dir() / "dlq.jsonl"


def rejections() -> dict:
    """The persisted rejection ledger, or an empty ledger.

    Keys: events (total rejected), batches_fully_rejected, last_at (epoch),
    last_error, last_full_rejection_at, reasons (recent distinct errors),
    dlq_events (count of rows currently in the local DLQ file).
    """
    try:
        data = json.loads(rejections_path().read_text())
        if not isinstance(data, dict):
            return _empty_ledger()
        # Always surface the live DLQ size so doctor/status stay honest even
        # when the ledger file was written by an older client.
        data["dlq_events"] = dlq_count()
        return data
    except (OSError, ValueError):
        return _empty_ledger()


def _empty_ledger() -> dict:
    return {"events": 0, "batches_fully_rejected": 0, "last_at": None,
            "last_error": None, "last_full_rejection_at": None, "reasons": [],
            "dlq_events": 0}


def clear_rejections() -> None:
    """Drop the ledger — used by uninstall and after an operator acks."""
    try:
        rejections_path().unlink(missing_ok=True)
    except OSError:
        pass


def clear_dlq() -> None:
    """Drop the local DLQ file — operator ack after re-send or deliberate discard."""
    try:
        dlq_path().unlink(missing_ok=True)
    except OSError:
        pass


def dlq_count() -> int:
    p = dlq_path()
    if not p.exists():
        return 0
    try:
        return sum(1 for line in p.read_text().splitlines() if line.strip())
    except OSError:
        return 0


def _enforce_dlq_cap(p: Path) -> None:
    try:
        if p.stat().st_size <= _MAX_DLQ_BYTES:
            return
        lines = [l for l in p.read_text().splitlines() if l.strip()]
        keep = lines[-(len(lines) // 2):]
        p.write_text("\n".join(keep) + "\n")
    except OSError:
        pass


def _append_dlq(chunk: list[dict], rejected: list[dict]) -> int:
    """Persist permanently rejected events with their reasons.

    Returns how many DLQ rows were written. Never raises — a DLQ write
    failure must not re-introduce silent loss of the *ledger* counters, and
    the rejected events have already left the server-side spool path.
    """
    if not rejected:
        return 0
    now = int(time.time())
    rows = []
    for r in rejected:
        if not isinstance(r, dict):
            continue
        try:
            idx = int(r.get("index"))
        except (TypeError, ValueError):
            continue
        if idx < 0 or idx >= len(chunk):
            continue
        event = chunk[idx]
        event_id = event.get("event_id") if isinstance(event, dict) else None
        rows.append({
            "rejected_at": now,
            "error": str(r.get("error") or "unspecified"),
            "event_id": event_id if isinstance(event_id, str) else None,
            "event": event,
            "permanent": True,
        })
    if not rows:
        return 0
    try:
        p = dlq_path()
        with p.open("a", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, separators=(",", ":")) + "\n")
        _enforce_dlq_cap(p)
    except OSError:
        # Still count them as rejected; the ledger is the floor of observability.
        pass
    return len(rows)


def _record_rejections(rejected: list[dict], full_batch: bool, dlq_written: int = 0) -> None:
    if not rejected:
        return
    led = rejections()
    # rejections() injects live dlq_events; strip so we write a clean ledger.
    led.pop("dlq_events", None)
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
    if dlq_written:
        led["dlq_events"] = dlq_count()
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
    backpressure ingest signalled overload (429/503). Stop draining
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


def _ca_cert_path() -> str | None:
    """Same resolution order as enroll-client."""
    for key in ("AIM_CA_CERT", "SSL_CERT_FILE"):
        val = os.environ.get(key)
        if val:
            return val
    cfg_val = config.load().get("ca_cert")
    return str(cfg_val) if cfg_val else None


def _resolve_map() -> dict:
    """Hostname → connect-IP map. Mirrors enroll-client."""
    out = {}
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


def _post_batch(url: str, token: str, events: list[dict], collector: dict) -> _PostResult:
    # Identity is attested once per batch in the envelope — never inside
    # event payloads (metadata-only contract).
    # Transport honours ca_cert + resolve from config/env so a
    # single-VM join that needed --resolve/--ca-cert keeps flushing after.
    body_dict: dict = {"events": events}
    if collector:
        body_dict["collector"] = collector
    body = json.dumps(body_dict).encode()
    full = url.rstrip("/") + "/v1/events"
    parsed = urlparse(full)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return _PostResult(ok=False)
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
    try:
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            ca = _ca_cert_path()
            if ca:
                ctx.load_verify_locations(cafile=ca)

            class _SNIConn(http.client.HTTPSConnection):
                def connect(self_inner):  # noqa: N805
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
            status = resp.status
            # 429/503 = ingest admission control shedding under overload.
            if status in (429, 503):
                retry = _parse_retry_after(resp.getheader("Retry-After"))
                return _PostResult(ok=False, backpressure=True, retry_after=retry)
            if not (200 <= status < 300):
                return _PostResult(ok=False)
            try:
                raw = resp.read()
            except OSError:
                raw = b""
            accepted, rejected = _parse_ack(raw)
            return _PostResult(ok=True, accepted=accepted, rejected=rejected)
        finally:
            conn.close()
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
        return _PostResult(ok=False)


def flush() -> dict:
    """Drain the spool. Returns {sent, rejected, dlq, remaining, error[, retry_after]}.

    ``sent`` counts events the cursor advanced past (accepted + permanently
    rejected). ``rejected`` is how many of those ingest refused; those rows
    also land in the local DLQ (``dlq`` count) with the rejection reason. A
    clean flush is ``rejected == 0 and error is None`` — callers that treat a
    2xx as success must check ``rejected``.

    On ingest backpressure (429/503) the drain stops and the unsent
    remainder is retained for the next flush — the collector never piles on
    under overload. retry_after (when the server sends it) tells the daemon how
    long to wait before the next attempt; watch() honours it.

    On a *fully* rejected batch the drain also stops. Every
    following batch would fail the same way, so continuing would empty the
    whole spool into a contract mismatch; stopping bounds the loss to the one
    batch that already cannot be retried, and leaves the remainder for a
    flush after ingest catches up. The rejected batch is still written to the
    local DLQ so the loss is attributable.
    """
    url = config.ingest_url()
    token = config.token()
    if not url or not token:
        return {"sent": 0, "rejected": 0, "dlq": 0, "remaining": _count(),
                "error": "ingest not configured (managed config, AIM_INGEST_URL/AIM_COLLECTOR_TOKEN, or enroll via aim join)"}

    p = state.spool_path()
    if not p.exists():
        return {"sent": 0, "rejected": 0, "dlq": 0, "remaining": 0, "error": None}

    lines = [l for l in p.read_text().splitlines() if l.strip()]
    collector = identity.collector_identity()
    sent = 0
    rejected_total = 0
    dlq_total = 0
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
            written = _append_dlq(chunk, res.rejected)
            _record_rejections(res.rejected, full_rejection, dlq_written=written)
            rejected_total += len(res.rejected)
            dlq_total += written
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
                 "telemetry is being lost (see local DLQ); run `aim doctor`")
    elif rejected_total and sent == len(lines):
        error = (f"ingest rejected {rejected_total} event(s) as invalid "
                 f"(retained in local DLQ)")
    elif sent == len(lines):
        error = None
    elif backpressure:
        error = "ingest overloaded (backpressure); retained for retry"
    else:
        error = "ingest unreachable"
    result = {"sent": sent, "rejected": rejected_total, "dlq": dlq_total,
              "remaining": len(remaining), "error": error}
    if backpressure and retry_after is not None:
        result["retry_after"] = retry_after
    return result


def _count() -> int:
    p = state.spool_path()
    if not p.exists():
        return 0
    return sum(1 for l in p.read_text().splitlines() if l.strip())

#!/usr/bin/env python3
"""Proxy/network log ingestion connector for AI tool detection (AIM-19).

Reads existing network telemetry (no endpoint agent required), detects AI
coding tool usage via the endpoint detection database, normalizes hits into
the canonical AI Usage Event schema
(packages/schema/schema/v1/ai-usage-event.schema.json, AIM-34), and
forwards to the AIM-23 ingestion API (POST /v1/events, bearer auth).

Privacy posture (per AIM-16 locked decisions):
  - Metadata only. We extract the destination hostname and immediately
    discard URL paths, query strings, and credentials. Hostnames only, ever.
  - No payload or TLS content is touched.
  - Identity is pseudonymized: host_ref is HMAC-SHA256 of the most stable
    host identifier the source provides (src_ip for proxy logs; the schema
    field is named for hostname — the endpoint hostname is not visible at
    the proxy). user_ref stays null until identity mapping (AIM-24/38).
    Salt comes from AIM_HASH_SALT (KMS-distributed in production) or a
    local 0600 state file in dev/pilot, same pattern as the Claude Code
    endpoint collector.

Source-class attribution (AIM-103): each event's src_ip is classified
BEFORE pseudonymization against the subnet inventory (subnets.json) into
'application' (server/DC + CI-runner ranges), 'employee' (endpoint ranges),
or 'unknown'. Application traffic on provider-api rules (direct LLM APIs:
OpenAI, Anthropic, Azure OpenAI, OpenRouter) does not inherit the
employee-tool unapproved verdict; 'unknown' fails safe toward flagging.

Supported input formats:
  - squid_native : standard Squid access.log
  - jsonl        : one JSON object per line with at least a host-bearing
                   field (host/url/domain/urlhost/…). Accepts common
                   enterprise aliases (Zscaler NSS JSON field names,
                   identity-bearing login/user fields, DNS/firewall
                   exports converted upstream).
  - zscaler_nss  : explicit pin for Zscaler Nanolog Streaming Service
                   JSON lines (same parser as jsonl; vendor field aliases).
  - paloalto_csv : Palo Alto URL-filtering / traffic CSV export
                   (headered or fixed-column synthetic subset).
  - bluecoat_main: Blue Coat / Symantec ProxySG bcreportermain_v1-style
                   space-separated access log (quoted fields via shlex).
  - umbrella_csv : Cisco Umbrella proxy/DNS CSV export
                   (headered or fixed-column synthetic subset).
  - auto         : sniff each line (default). Used for replaying unknown
                   samples from IT; production instances should pin an
                   explicit format once confirmed.

Sinks: stdout (default), file, or http (batched POST {"events": [...]} to
the ingestion API with retry/backoff).

Usage:
  python3 proxy_ingest.py --collector proxy-squid-dc1 --format squid_native \
      --input access.log --sink stdout --coverage --expected-fleet 700
"""

import argparse
import csv
import hashlib
import hmac
import ipaddress
import json
import os
import shlex
import sys
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from io import StringIO

SCHEMA_VERSION = "1.8"
SOURCE = "proxy"
USER_AGENT = "aim-proxy-ingest/0.5"

# Policy-approved tools (CEO AIM-16). Separate from the schema enum: a tool
# can be first-class (named in events) without being policy-approved.
SANCTIONED_TOOLS = {"claude_code", "cursor", "kilo_code"}

# First-class schema enum values that proxy may emit as `tool` rather than
# collapsing to other/tool_raw. Keep in sync with packages/schema tool enum
# (minus genai_app — otel-only — and other itself).
FIRST_CLASS_TOOLS = {
    "claude_code", "cursor", "kilo_code", "kimi_code", "grok_build",
}

# Detector name fired on unapproved-tool traffic (guardrail engine may
# re-derive severity; this is the collector-side statement).
UNAPPROVED_DETECTOR = "policy:unapproved-tool"


# ---------------------------------------------------------------- rules ----

class Rule:
    __slots__ = ("id", "provider", "tool", "category", "sanctioned", "domains")

    def __init__(self, d):
        self.id = d["id"]
        self.provider = d["provider"]
        self.tool = d.get("tool")
        self.category = d.get("category")
        self.sanctioned = bool(d["sanctioned"])
        self.domains = [x.lower() for x in d["domains"]]

    def matches(self, host):
        for dom in self.domains:
            if host == dom or host.endswith("." + dom):
                return True
        return False


def load_rules(path):
    with open(path, "r", encoding="utf-8") as f:
        db = json.load(f)
    rules = [Rule(r) for r in db["rules"]]
    return rules, db


def match_rule(rules, host):
    """Most specific (longest) matching domain wins."""
    best = None
    best_len = -1
    for rule in rules:
        for dom in rule.domains:
            if (host == dom or host.endswith("." + dom)) and len(dom) > best_len:
                best = rule
                best_len = len(dom)
    return best


# --------------------------------------------------- source-class attribution ----

TRAFFIC_CLASSES = ("application", "employee", "unknown")


class SourceClassifier:
    """Classify a src_ip into a source class (AIM-103) from the subnet
    inventory (subnets.json): server/DC + CI-runner ranges → 'application'
    (company-built software); endpoint ranges → 'employee'; anything else
    → 'unknown'.

    Runs BEFORE pseudonymization; only the class label crosses the wire.
    Fail-safe direction: 'unknown' keeps the employee-tool verdict behavior,
    and on overlapping ranges of equal specificity 'employee' wins — a
    mis-listed segment can never shed the unapproved verdict by accident."""

    def __init__(self, path):
        self._nets = []  # (network, class)
        if not path or not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            inv = json.load(f)
        for key, cls in (("server", "application"), ("ci", "application"),
                         ("endpoint", "employee")):
            for cidr in inv.get(key, []):
                self._nets.append((ipaddress.ip_network(cidr), cls))

    def classify(self, src_ip):
        try:
            ip = ipaddress.ip_address(src_ip)
        except ValueError:
            return "unknown"
        best_cls = None
        best_prefix = -1
        for net, cls in self._nets:
            if ip in net and net.prefixlen > best_prefix:
                best_cls, best_prefix = cls, net.prefixlen
            elif ip in net and net.prefixlen == best_prefix and cls == "employee":
                best_cls = "employee"  # equal-specificity tie: fail toward flagging
        return best_cls or "unknown"


# --------------------------------------------------------------- parsing ----

def extract_host(url_or_authority):
    """Return (lowercase hostname, port) from a URL or CONNECT authority.

    Never returns path, query, or credentials. Returns (None, None) if
    unusable.
    """
    s = url_or_authority.strip()
    if not s or s == "-":
        return None, None
    port = None
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]          # drop path+query in one cut
    s = s.rsplit("@", 1)[-1]        # drop any userinfo
    if s.startswith("["):           # IPv6 literal
        end = s.find("]")
        host = s[1:end] if end != -1 else None
        rest = s[end + 1:] if end != -1 else ""
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
    else:
        if ":" in s:
            h, p = s.rsplit(":", 1)
            host = h
            if p.isdigit():
                port = int(p)
        else:
            host = s
    if not host:
        return None, None
    return host.lower().rstrip("."), port


def _iso_z(dt):
    # Canonical schema (AIM-34) enforces second-level precision, no
    # fractional seconds — same as the Claude Code endpoint collector.
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def _first(rec, *keys):
    """Return the first present non-empty value for any of keys (dict)."""
    for k in keys:
        if k in rec and rec[k] is not None and rec[k] != "":
            return rec[k]
    return None


def _normalize_ts(ts):
    """Coerce vendor timestamps to schema RFC 3339 second-precision UTC.

    Accepts epoch seconds/ms, ISO-8601, Zscaler ``YYYY-MM-DD HH:MM:SS``,
    and Palo Alto ``YYYY/MM/DD HH:MM:SS`` shapes. Falls back to now only
    when the source provided nothing usable.
    """
    if ts is None or ts == "":
        return _iso_z(datetime.now(timezone.utc))
    if isinstance(ts, (int, float)):
        # Zscaler occasionally emits ms epochs; treat large values as ms.
        v = float(ts)
        if v > 1e12:
            v = v / 1000.0
        return _iso_z(datetime.fromtimestamp(v, tz=timezone.utc))
    s = str(ts).strip()
    if not s:
        return _iso_z(datetime.now(timezone.utc))
    # Already close to RFC 3339 — normalize fractional seconds away.
    if "T" in s or s.endswith("Z") or (len(s) > 10 and s[10] == " " and "T" not in s and "-" in s[:10]):
        candidate = s
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        # Zscaler-style space separator → ISO T
        if len(candidate) >= 19 and candidate[10] == " " and "T" not in candidate:
            candidate = candidate[:10] + "T" + candidate[11:]
        # Strip fractional seconds before timezone if present
        try:
            # fromisoformat handles "+00:00" and bare naive
            if candidate.endswith("Z"):
                candidate = candidate[:-1] + "+00:00"
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return _iso_z(dt.astimezone(timezone.utc))
        except ValueError:
            pass
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S%z",
    ):
        try:
            dt = datetime.strptime(s.replace("Z", "+0000") if fmt.endswith("%z") else s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return _iso_z(dt.astimezone(timezone.utc))
        except ValueError:
            continue
    # Last resort: leave as-is only if it already matches the schema
    # pattern; otherwise stamp now so emit path still validates.
    import re
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})", s):
        return s
    return _iso_z(datetime.now(timezone.utc))


def _as_int(value):
    if value is None or value == "" or value == "-":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def parse_squid_native(line):
    """Squid access.log: ts elapsed client code/status bytes method URL rfc931 peer hier mime"""
    parts = line.split()
    if len(parts) < 8:
        return None
    try:
        ts_epoch = float(parts[0])
        duration_ms = int(float(parts[1]))
    except ValueError:
        return None
    src_ip = parts[2]
    status_field = parts[3]
    try:
        http_status = int(status_field.split("/", 1)[1])
    except (IndexError, ValueError):
        http_status = None
    try:
        bytes_down = int(parts[4])
    except ValueError:
        bytes_down = None
    action = parts[5]
    host, port = extract_host(parts[6])
    user = parts[7] if parts[7] != "-" else None
    if host is None:
        return None
    return {
        "ts": _iso_z(datetime.fromtimestamp(ts_epoch, tz=timezone.utc)),
        "src_ip": src_ip,
        "user": user,
        "host": host,
        "port": port,
        "action": action,
        "http_status": http_status,
        "bytes_up": None,  # Squid access.log carries reply size only
        "bytes_down": bytes_down,
        "duration_ms": duration_ms,
    }


def parse_jsonl(line):
    """Generic JSON-lines adapter + enterprise field aliases.

    Host-bearing keys (first match wins): host, urlhost, url, domain,
    hostname, dest_host, destination, server_ip (last-resort).
    Client IP aliases: src_ip, client, client_ip, clientip, cip, csip,
    srcip, sourceip, source_ip.
    Identity-bearing user aliases (coverage / future mapping only;
    user_ref stays null until AIM-24/38): user, login, username,
    user_name, authenticated_user, srcuser, useremail, email.
    Timestamp aliases: ts, timestamp, datetime, time, stime, eventtime,
    event_time, logtime.
    """
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(rec, dict):
        return None
    raw = _first(rec, "host", "urlhost", "url", "domain", "hostname",
                 "dest_host", "destination", "server_ip")
    if not raw:
        # Nested Zscaler-ish envelopes occasionally wrap the record.
        for nest_key in ("event", "record", "message"):
            nested = rec.get(nest_key)
            if isinstance(nested, dict):
                return parse_jsonl(json.dumps(nested))
        return None
    host, port = extract_host(str(raw))
    if host is None:
        return None
    src = _first(rec, "src_ip", "client", "client_ip", "clientip", "cip",
                 "csip", "srcip", "sourceip", "source_ip")
    user = _first(rec, "user", "login", "username", "user_name",
                  "authenticated_user", "srcuser", "useremail", "email")
    # Nested identity block (identity-bearing JSONL variant): take UPN/email
    # for coverage reporting only — never forwarded as cleartext identity.
    if user is None and isinstance(rec.get("identity"), dict):
        user = _first(rec["identity"], "upn", "email", "user", "login", "sam")
    ts = _normalize_ts(_first(rec, "ts", "timestamp", "datetime", "time",
                              "stime", "eventtime", "event_time", "logtime"))
    status = _first(rec, "status", "http_status", "respcode", "response_code",
                    "status_code")
    action = _first(rec, "action", "reqmethod", "method", "http_method")
    bytes_up = _as_int(_first(rec, "bytes_up", "reqsize", "request_size",
                              "requestsize", "sent_bytes"))
    bytes_down = _as_int(_first(rec, "bytes_down", "respsize", "response_size",
                                "responsesize", "received_bytes"))
    duration_ms = _as_int(_first(rec, "duration_ms", "duration", "elapsed_ms",
                                 "elapsed", "ttime"))
    port = port or _as_int(rec.get("port"))
    return {
        "ts": ts,
        "src_ip": str(src) if src is not None else "unknown",
        "user": str(user) if user is not None else None,
        "host": host,
        "port": port,
        "action": str(action) if action is not None else None,
        "http_status": _as_int(status),
        "bytes_up": bytes_up,
        "bytes_down": bytes_down,
        "duration_ms": duration_ms,
    }


# Explicit production pin for Zscaler NSS JSON — same code path as jsonl
# after alias expansion; kept as a named format so IT can pin without
# relying on auto-sniff once the live export is confirmed (AIM-50).
parse_zscaler_nss = parse_jsonl


# Palo Alto URL-filtering / traffic CSV — fixed column order used by the
# synthetic sample and by the common "custom syslog/CSV export" subset.
# Full PAN-OS LEHF dumps have 40–60 fields; when IT delivers a full export,
# either map to this subset or convert upstream to jsonl. Column names in
# the optional header row are matched case-insensitively.
_PA_DEFAULT_COLS = (
    "receive_time", "src", "srcuser", "dst", "url", "category", "action",
    "bytes_sent", "bytes_received", "http_method", "response_code",
    "elapsed_sec",
)
_PA_HOST_KEYS = ("url", "misc", "host", "destination", "fqdn", "uri")
_PA_SRC_KEYS = ("src", "src_ip", "source", "source_ip", "sourceaddress")
_PA_USER_KEYS = ("srcuser", "user", "sourceuser", "source_user")
_PA_TS_KEYS = ("receive_time", "time_generated", "generate_time", "time")
_PA_ACTION_KEYS = ("http_method", "action", "app", "method")
_PA_STATUS_KEYS = ("response_code", "http_status", "status")
_PA_UP_KEYS = ("bytes_sent", "bytes_up", "sent")
_PA_DOWN_KEYS = ("bytes_received", "bytes_down", "received")
_PA_DUR_KEYS = ("elapsed_sec", "elapsed", "duration", "session_end_reason")


def _pa_header_map(header_line):
    cols = [c.strip().lower() for c in header_line.split(",")]
    return {name: idx for idx, name in enumerate(cols) if name}


def _pa_pick(fields, colmap, keys):
    for k in keys:
        idx = colmap.get(k)
        if idx is not None and idx < len(fields):
            val = fields[idx].strip().strip('"')
            if val and val != "-":
                return val
    return None


def parse_paloalto_csv(line):
    """Palo Alto URL-filtering / traffic CSV line.

    Accepts either:
      - a header row (returns None; skipped by the main loop), or
      - a data row. When a header was not provided, uses the fixed
        ``_PA_DEFAULT_COLS`` order from the synthetic sample.
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    # Header row — names, no leading date
    lower = s.lower()
    if "receive_time" in lower and ("url" in lower or "src" in lower) and \
            not s[0].isdigit():
        return None
    fields = [f.strip().strip('"') for f in s.split(",")]
    if len(fields) < 5:
        return None
    # Prefer name-based mapping when the line count matches a known header
    # length; otherwise assume default synthetic column order.
    if len(fields) == len(_PA_DEFAULT_COLS) or fields[0][:4].isdigit():
        colmap = {name: idx for idx, name in enumerate(_PA_DEFAULT_COLS)
                  if idx < len(fields)}
        # If first field is not a date-like token, try header-style map on
        # the default names only (already done).
    else:
        colmap = {name: idx for idx, name in enumerate(_PA_DEFAULT_COLS)
                  if idx < len(fields)}

    # If the first field looks nothing like a timestamp and contains a
    # non-date word, treat as an unrecognized header / junk.
    ts_raw = _pa_pick(fields, colmap, _PA_TS_KEYS) or fields[0]
    if not ts_raw or not any(ch.isdigit() for ch in ts_raw):
        return None
    raw_host = _pa_pick(fields, colmap, _PA_HOST_KEYS)
    if not raw_host:
        return None
    host, port = extract_host(raw_host)
    if host is None:
        return None
    src = _pa_pick(fields, colmap, _PA_SRC_KEYS) or "unknown"
    user = _pa_pick(fields, colmap, _PA_USER_KEYS)
    # Domain-qualified user (corp\jsmith or jsmith@corp) — keep as coverage label
    action = _pa_pick(fields, colmap, _PA_ACTION_KEYS)
    status = _as_int(_pa_pick(fields, colmap, _PA_STATUS_KEYS))
    bytes_up = _as_int(_pa_pick(fields, colmap, _PA_UP_KEYS))
    bytes_down = _as_int(_pa_pick(fields, colmap, _PA_DOWN_KEYS))
    dur_raw = _pa_pick(fields, colmap, _PA_DUR_KEYS)
    duration_ms = None
    if dur_raw is not None:
        # elapsed_sec in the synthetic subset; convert to ms when small.
        n = _as_int(dur_raw)
        if n is not None:
            duration_ms = n * 1000 if n < 10000 else n
    return {
        "ts": _normalize_ts(ts_raw),
        "src_ip": src,
        "user": user,
        "host": host,
        "port": port,
        "action": action,
        "http_status": status,
        "bytes_up": bytes_up,
        "bytes_down": bytes_down,
        "duration_ms": duration_ms,
    }


# Blue Coat / Symantec ProxySG main access log (bcreportermain_v1 subset).
# Space-separated with optional quoted multi-token fields (shlex). Full
# vendor exports can include more columns; when IT delivers a full dump,
# either map to this subset or convert upstream to jsonl.
_BC_DEFAULT_COLS = (
    "date", "time", "time-taken", "c-ip", "cs-username", "cs-auth-group",
    "x-exception-id", "sc-filter-result", "cs-categories", "cs-referer",
    "sc-status", "s-action", "cs-method", "rs-content-type", "cs-uri-scheme",
    "cs-host", "cs-uri-port", "cs-uri-path", "cs-uri-query", "cs-uri-extension",
    "cs-user-agent", "s-ip", "sc-bytes", "cs-bytes", "x-virus-id",
    "x-bluecoat-application-name", "x-bluecoat-application-operation",
)
_BC_HOST_KEYS = ("cs-host", "cs_host", "host", "c-uri-host")
_BC_SRC_KEYS = ("c-ip", "c_ip", "src_ip", "clientip")
_BC_USER_KEYS = ("cs-username", "cs_username", "username", "user")
_BC_STATUS_KEYS = ("sc-status", "sc_status", "status")
_BC_ACTION_KEYS = ("cs-method", "cs_method", "s-action", "method")
_BC_UP_KEYS = ("cs-bytes", "cs_bytes", "bytes_up")
_BC_DOWN_KEYS = ("sc-bytes", "sc_bytes", "bytes_down")
_BC_DUR_KEYS = ("time-taken", "time_taken", "duration")


def _bc_pick(fields, colmap, keys):
    for k in keys:
        idx = colmap.get(k)
        if idx is not None and idx < len(fields):
            val = fields[idx].strip()
            if val and val != "-":
                return val
    return None


def parse_bluecoat_main(line):
    """Blue Coat / Symantec ProxySG bcreportermain_v1-style access line.

    Accepts W3C-style ``#Fields:`` header rows (skipped) and data rows in the
    synthetic fixed column order (``_BC_DEFAULT_COLS``). Quoted multi-token
    fields (categories, user-agent) are split with ``shlex``.
    """
    s = line.strip()
    if not s:
        return None
    low = s.lower()
    # W3C / ProxySG preamble
    if s.startswith("#"):
        return None
    # Header without leading '#': "date time time-taken c-ip …"
    if low.startswith("date ") and "cs-host" in low and "c-ip" in low:
        return None
    try:
        fields = shlex.split(s)
    except ValueError:
        return None
    if len(fields) < 12:
        return None
    # Require a date-like first token so we don't swallow squid/garbage.
    if not (len(fields[0]) >= 8 and fields[0][0:4].isdigit() and
            ("-" in fields[0] or "/" in fields[0])):
        return None
    colmap = {name: idx for idx, name in enumerate(_BC_DEFAULT_COLS)
              if idx < len(fields)}
    # date + time → single timestamp when both present
    date_part = _bc_pick(fields, colmap, ("date",)) or fields[0]
    time_part = _bc_pick(fields, colmap, ("time",))
    ts_raw = f"{date_part} {time_part}" if time_part else date_part
    raw_host = _bc_pick(fields, colmap, _BC_HOST_KEYS)
    if not raw_host:
        # Some exports put authority in cs-uri (scheme-relative); try late fields.
        for cand in fields[14:18]:
            if "." in cand and not cand.startswith("/") and "://" not in cand:
                raw_host = cand
                break
    if not raw_host:
        return None
    host, port = extract_host(raw_host)
    if host is None:
        return None
    port = port or _as_int(_bc_pick(fields, colmap, ("cs-uri-port", "cs_uri_port", "port")))
    src = _bc_pick(fields, colmap, _BC_SRC_KEYS) or "unknown"
    user = _bc_pick(fields, colmap, _BC_USER_KEYS)
    action = _bc_pick(fields, colmap, _BC_ACTION_KEYS)
    status = _as_int(_bc_pick(fields, colmap, _BC_STATUS_KEYS))
    bytes_up = _as_int(_bc_pick(fields, colmap, _BC_UP_KEYS))
    bytes_down = _as_int(_bc_pick(fields, colmap, _BC_DOWN_KEYS))
    duration_ms = _as_int(_bc_pick(fields, colmap, _BC_DUR_KEYS))
    return {
        "ts": _normalize_ts(ts_raw),
        "src_ip": src,
        "user": user,
        "host": host,
        "port": port,
        "action": action,
        "http_status": status,
        "bytes_up": bytes_up,
        "bytes_down": bytes_down,
        "duration_ms": duration_ms,
    }


# Cisco Umbrella proxy CSV — synthetic fixed column order matching the common
# "proxy" export (not the DNS-only export). DNS exports can map Domain → host
# via the same column layout with empty URL/HTTP columns, or convert to jsonl.
_UM_DEFAULT_COLS = (
    "timestamp", "identities", "internal_ip", "external_ip", "destination_ip",
    "content_type", "action", "url", "hostname", "categories", "http_method",
    "status_code",
)
_UM_HOST_KEYS = ("hostname", "domain", "url", "host")
_UM_SRC_KEYS = ("internal_ip", "internal ip", "client_ip", "src_ip")
_UM_USER_KEYS = ("identities", "most_granular_identity",
                 "most granular identity", "identity", "user")
_UM_TS_KEYS = ("timestamp", "datetime", "time")
_UM_ACTION_KEYS = ("http_method", "http method", "action", "method")
_UM_STATUS_KEYS = ("status_code", "status code", "response_code", "status")


def _csv_fields(line):
    """Split a single CSV line, preserving quoted commas."""
    try:
        row = next(csv.reader(StringIO(line)))
    except Exception:  # noqa: BLE001 — fall back to naive split
        row = [c.strip() for c in line.split(",")]
    return [c.strip() for c in row]


def _um_header_map(fields):
    return {name.strip().lower().replace(" ", "_"): idx
            for idx, name in enumerate(fields) if name and name.strip()}


def _um_pick(fields, colmap, keys):
    for k in keys:
        idx = colmap.get(k) if k in colmap else colmap.get(k.replace(" ", "_"))
        if idx is None:
            idx = colmap.get(k.replace("_", " "))
        if idx is not None and idx < len(fields):
            val = fields[idx].strip().strip('"')
            if val and val != "-":
                return val
    return None


def parse_umbrella_csv(line):
    """Cisco Umbrella proxy (or DNS-compatible) CSV line.

    Header rows are skipped. Data rows use either a recognized header layout
    when the line count matches, or the synthetic ``_UM_DEFAULT_COLS`` order.
    Identity is taken from ``Identities`` / ``Most Granular Identity`` when
    present (coverage only; never emitted as cleartext).
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    fields = _csv_fields(s)
    if len(fields) < 6:
        return None
    # Header rows (no leading digit in Timestamp column) — skip.
    if not any(ch.isdigit() for ch in fields[0]):
        return None

    # Prefer default synthetic layout when first field is a timestamp-like value.
    if fields[0][:4].isdigit() or (fields[0].startswith('"') and
                                   len(fields[0]) > 5 and fields[0][1:5].isdigit()):
        colmap = {name: idx for idx, name in enumerate(_UM_DEFAULT_COLS)
                  if idx < len(fields)}
    else:
        colmap = _um_header_map(fields)

    ts_raw = _um_pick(fields, colmap, _UM_TS_KEYS) or fields[0]
    if not ts_raw or not any(ch.isdigit() for ch in ts_raw):
        return None
    # Strip trailing timezone tokens Umbrella often appends (" UTC")
    ts_raw = ts_raw.replace(" UTC", "").replace(" GMT", "").strip()
    raw_host = _um_pick(fields, colmap, _UM_HOST_KEYS)
    if not raw_host:
        return None
    host, port = extract_host(raw_host)
    if host is None:
        return None
    src = _um_pick(fields, colmap, _UM_SRC_KEYS) or "unknown"
    user = _um_pick(fields, colmap, _UM_USER_KEYS)
    # Umbrella Identities can be a comma-joined list inside one CSV field —
    # take the first token as the coverage label.
    if user and "," in user:
        user = user.split(",", 1)[0].strip()
    action = _um_pick(fields, colmap, _UM_ACTION_KEYS)
    # Prefer HTTP method over allow/block action when both exist
    if action and action.lower() in ("allowed", "blocked", "proxied"):
        method = _um_pick(fields, colmap, ("http_method", "http method", "method"))
        if method:
            action = method
    status = _as_int(_um_pick(fields, colmap, _UM_STATUS_KEYS))
    return {
        "ts": _normalize_ts(ts_raw),
        "src_ip": src,
        "user": user,
        "host": host,
        "port": port,
        "action": action,
        "http_status": status,
        "bytes_up": None,   # Umbrella proxy export typically omits byte counts
        "bytes_down": None,
        "duration_ms": None,
    }


PARSERS = {
    "squid_native": parse_squid_native,
    "jsonl": parse_jsonl,
    "zscaler_nss": parse_zscaler_nss,
    "paloalto_csv": parse_paloalto_csv,
    "bluecoat_main": parse_bluecoat_main,
    "umbrella_csv": parse_umbrella_csv,
}


def detect_format(line):
    """Sniff a single log line. Returns a PARSERS key or None.

    Deliberately conservative: a wrong guess wastes one line, a crash is
    worse, so anything ambiguous returns None and is skipped.
    """
    s = line.lstrip()
    if not s or s.startswith("#"):
        # Blue Coat W3C Fields preamble is format-signal but not a data row.
        low = s.lower()
        if low.startswith("#fields:") and ("cs-host" in low or "c-ip" in low):
            return "bluecoat_main"
        return None
    if s.startswith("{"):
        try:
            rec = json.loads(s)
        except json.JSONDecodeError:
            return None
        # Prefer explicit Zscaler pin when NSS-specific keys are present so
        # production configs can be mirrored in auto-replay evidence.
        if isinstance(rec, dict) and any(k in rec for k in (
                "urlhost", "cip", "csip", "respcode", "reqsize", "respsize")):
            return "zscaler_nss"
        return "jsonl"
    # CSV family: Umbrella vs Palo Alto — disambiguate by header keywords and
    # date separator (PAN samples use YYYY/MM/DD; Umbrella uses YYYY-MM-DD).
    if "," in s and len(s) > 20:
        low = s.lower()
        if (("identities" in low or "most granular identity" in low) and
                ("hostname" in low or "domain" in low or "internal ip" in low)):
            return "umbrella_csv"
        if "receive_time" in low and ("url" in low or "srcuser" in low):
            return "paloalto_csv"
        head = s.split(",", 1)[0].strip().strip('"')
        if len(head) >= 10 and head[0:4].isdigit():
            # Slash-date → Palo Alto LEHF/URL subset (synthetic + common export)
            if head[4] == "/" and head[7] == "/":
                return "paloalto_csv"
            # Dash-date with enough columns → Umbrella-style proxy CSV
            if head[4] == "-" and head[7] == "-" and s.count(",") >= 7:
                return "umbrella_csv"
            # Remaining dash-date CSV: prefer Palo when column count matches
            # the synthetic PAN subset, else umbrella if wider.
            if head[4] == "-" and head[7] == "-":
                nfields = len(_csv_fields(s))
                if nfields >= len(_UM_DEFAULT_COLS) - 1:
                    return "umbrella_csv"
                return "paloalto_csv"
    # Blue Coat: leading calendar date, space-separated, has host-ish tokens
    parts = s.split()
    if len(parts) >= 12:
        head = parts[0]
        if (len(head) >= 10 and head[0:4].isdigit() and
                head[4] in "-/" and head[7] in "-/"):
            # Not squid (epoch) and not pure CSV
            if "," not in s[:40]:
                return "bluecoat_main"
    if len(parts) >= 8:
        try:
            float(parts[0])            # epoch seconds
            float(parts[1])            # elapsed ms
        except ValueError:
            return None
        if "/" in parts[3] and parts[4].lstrip("-").isdigit():
            return "squid_native"      # TCP_MISS/200 15234 ...
    return None


def parse_auto(line):
    fmt = detect_format(line)
    if fmt is None:
        return None
    return PARSERS[fmt](line)


PARSERS["auto"] = parse_auto


# ------------------------------------------------------- pseudonymization ----

class Pseudonymizer:
    """HMAC-SHA256 with a company salt (AIM_HASH_SALT) or a dev/pilot
    per-install salt file. Mirrors collectors/claude-code/aim_collector/
    events.py so proxy and endpoint refs join on the same pseudonyms once
    the real KMS-distributed salt is in place (tracked on AIM-23)."""

    def __init__(self, salt_file):
        s = os.environ.get("AIM_HASH_SALT")
        if s:
            self._salt = s.encode()
            return
        f = os.path.expanduser(salt_file)
        if not os.path.exists(f):
            os.makedirs(os.path.dirname(f), exist_ok=True)
            with open(f, "w") as fh:
                fh.write(uuid.uuid4().hex)
            os.chmod(f, 0o600)
        with open(f) as fh:
            self._salt = fh.read().strip().encode()

    def hmac64(self, value):
        return hmac.new(self._salt, value.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- events ----

def to_event(rec, rule, pseudo, traffic_class="unknown"):
    """Build a canonical AI Usage Event (v1) from a parsed record + rule.

    traffic_class (AIM-103): source-class attribution of the src_ip —
    'application' (server/DC/CI subnet), 'employee' (endpoint subnet), or
    'unknown' (no inventory match). Application traffic on provider-api rules
    (direct LLM APIs used by both employee tools and company-built software)
    does NOT inherit the employee-tool unapproved verdict; employee and
    unknown sources are unchanged."""
    # Deterministic, uuid-format id so re-ingestion is idempotent.
    seed = f"{rec['ts']}|{rec['src_ip']}|{rec['host']}|{rec.get('action')}"
    event_id = str(uuid.UUID(bytes=hashlib.sha256(seed.encode()).digest()[:16], version=5))

    if rule.tool in FIRST_CLASS_TOOLS:
        # First-class schema tools keep their name even when not policy-
        # approved (AIM-271: grok_build is reportable without being sanctioned).
        tool, tool_raw = rule.tool, None
    else:
        # Unknown tool: tool='other', name it in tool_raw.
        tool = "other"
        tool_raw = (rule.tool or rule.provider)[:64]

    flags = []
    if not rule.sanctioned and not (rule.category == "provider-api"
                                    and traffic_class == "application"):
        flags.append({
            "detector": UNAPPROVED_DETECTOR,
            "category": "policy",
            "severity": "medium",
        })

    # Proxy sources see no endpoint hostname; src_ip is the most stable
    # host identifier available (schema field documented for hostname).
    host_ref = pseudo.hmac64(rec["src_ip"])

    # Synthetic daily correlation id: groups one source's activity per UTC
    # day. Not a tool session; not stable across days (documented on AIM-19).
    day = rec["ts"][:10]
    session_id = pseudo.hmac64(f"proxy|{rec['src_ip']}|{rec.get('user')}|{day}")[:32]

    ev = {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id,
        "ts": rec["ts"],
        "host_ref": host_ref,
        "user_ref": None,  # identity mapping lands with AIM-24/38
        "tool": tool,
        "model": None,     # not observable at network level
        "provider": rule.provider[:64],
        "session_id": session_id,
        "match_flags": flags,
        "source": SOURCE,
        "traffic_class": traffic_class,
        "bytes_up": rec.get("bytes_up"),
        "bytes_down": rec.get("bytes_down"),
        "http_status": rec.get("http_status"),
    }
    # duration_ms is non-nullable integer in schema v1.3 — omit when the
    # source didn't report it rather than emitting null.
    if rec.get("duration_ms") is not None:
        ev["duration_ms"] = rec["duration_ms"]
    if tool_raw is not None:
        ev["tool_raw"] = tool_raw
    validate(ev)
    return ev


_ALLOWED = {"schema_version", "event_id", "ts", "host_ref", "user_ref",
            "tool", "tool_raw", "tool_version", "model", "provider",
            "session_id", "tokens_in", "tokens_out", "cost_estimate_usd",
            "repo_ref", "cwd_hash", "match_flags", "source",
            "traffic_class", "bytes_up", "bytes_down", "duration_ms",
            "http_status"}


def validate(event):
    """Local conformance check against the canonical schema's hard
    constraints. Ingest-side JSON Schema validation remains authoritative."""
    import re
    required = ("schema_version", "event_id", "ts", "host_ref", "tool",
                "session_id", "source", "match_flags")
    missing = [k for k in required if k not in event]
    if missing:
        raise ValueError(f"event missing required fields: {missing}")
    extra = set(event) - _ALLOWED
    if extra:
        raise ValueError(f"out-of-schema fields (ingest would reject): {sorted(extra)}")
    if not re.fullmatch(r"1\.[0-9]+", event["schema_version"]):
        raise ValueError("bad schema_version")
    for k in ("host_ref", "user_ref", "repo_ref", "cwd_hash"):
        v = event.get(k)
        if v is not None and not re.fullmatch(r"[0-9a-f]{64}", str(v)):
            raise ValueError(f"{k} must be 64 lowercase hex chars")
    if event["tool"] == "other" and not event.get("tool_raw"):
        raise ValueError("tool='other' requires tool_raw")
    if event["source"] not in ("proxy", "endpoint"):
        raise ValueError("bad source")
    if event.get("traffic_class") is not None and \
            event["traffic_class"] not in TRAFFIC_CLASSES:
        raise ValueError("bad traffic_class")
    for k in ("bytes_up", "bytes_down", "duration_ms", "http_status"):
        v = event.get(k)
        if v is not None and not isinstance(v, int):
            raise ValueError(f"{k} must be an integer or null")
    json.dumps(event)  # must be serializable


# ------------------------------------------------------------------ sink ----

class HttpSink:
    """Batch POST {"events": [...]} to the AIM-23 ingestion API
    (/v1/events). Bearer auth, 3 retries with backoff."""

    def __init__(self, url, token, batch_size=500):
        self.url = url
        self.token = token
        self.batch_size = batch_size
        self.buf = []

    def write(self, event):
        self.buf.append(event)
        if len(self.buf) >= self.batch_size:
            self.flush()

    def flush(self):
        if not self.buf:
            return
        payload = json.dumps({"events": self.buf}).encode()
        req = urllib.request.Request(
            self.url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )
        last_err = None
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    if resp.status >= 400:
                        raise RuntimeError(f"ingest API returned {resp.status}")
                self.buf = []
                return
            except Exception as e:  # noqa: BLE001 - retry any transient failure
                last_err = e
                time.sleep(2 ** attempt)
        raise RuntimeError(f"failed to deliver batch after 3 attempts: {last_err}")


class StreamSink:
    def __init__(self, fp):
        self.fp = fp

    def write(self, event):
        self.fp.write(json.dumps(event) + "\n")

    def flush(self):
        self.fp.flush()


# -------------------------------------------------------------- coverage ----

class Coverage:
    """Fleet coverage + provider/tool stats, computed from parsed records
    (pseudonymized events intentionally do not carry src_ip)."""

    def __init__(self):
        self.src_ips = set()
        self.users = set()
        self.events = 0
        self.by_provider = {}
        self.by_class = {}
        self.unsanctioned = {}
        self.ts_min = None
        self.ts_max = None

    def add(self, rec, rule, traffic_class="unknown"):
        self.events += 1
        self.src_ips.add(rec["src_ip"])
        if rec.get("user"):
            self.users.add(rec["user"])
        self.by_provider[rule.provider] = self.by_provider.get(rule.provider, 0) + 1
        self.by_class[traffic_class] = self.by_class.get(traffic_class, 0) + 1
        if not rule.sanctioned:
            k = rule.tool or rule.provider
            self.unsanctioned[k] = self.unsanctioned.get(k, 0) + 1
        ts = rec["ts"]
        self.ts_min = ts if self.ts_min is None else min(self.ts_min, ts)
        self.ts_max = ts if self.ts_max is None else max(self.ts_max, ts)

    def report(self, expected_fleet):
        seen = len(self.src_ips)
        pct = (100.0 * seen / expected_fleet) if expected_fleet else 0.0
        lines = [
            "=== Coverage report (network path, AIM-19) ===",
            f"window:            {self.ts_min} .. {self.ts_max}",
            f"distinct sources:  {seen} / {expected_fleet} endpoints ({pct:.1f}%)",
            f"distinct users:    {len(self.users)}",
            f"AI events:         {self.events}",
            "",
            "by provider:",
        ]
        for prov, n in sorted(self.by_provider.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {prov:<18} {n}")
        lines.append("")
        lines.append("by source class (AIM-103; 'unknown' = no subnet inventory match):")
        if self.by_class:
            for cls, n in sorted(self.by_class.items(), key=lambda kv: -kv[1]):
                lines.append(f"  {cls:<18} {n}")
        else:
            lines.append("  none")
        lines.append("")
        lines.append("unsanctioned tools observed (policy: Claude Code, Cursor, Kilo Code only):")
        if self.unsanctioned:
            for tool, n in sorted(self.unsanctioned.items(), key=lambda kv: -kv[1]):
                lines.append(f"  {tool:<18} {n}")
        else:
            lines.append("  none")
        return "\n".join(lines)


# ------------------------------------------------------------------ main ----

def build_sink(args):
    if args.sink == "stdout":
        return StreamSink(sys.stdout)
    if args.sink == "file":
        return StreamSink(open(args.output, "a", encoding="utf-8"))
    if args.sink == "http":
        if not args.ingest_url or not args.ingest_token:
            raise SystemExit("--sink http requires --ingest-url and --ingest-token")
        return HttpSink(args.ingest_url, args.ingest_token)
    raise SystemExit(f"unknown sink: {args.sink}")


def main(argv=None):
    p = argparse.ArgumentParser(description="AI tool detection from proxy/network logs")
    p.add_argument("--collector", required=True, help="collector instance id, e.g. proxy-squid-dc1")
    p.add_argument("--source-kind", default="proxy", choices=["proxy", "dns", "firewall"],
                   help="input telemetry kind (events are always emitted with source='proxy')")
    p.add_argument("--format", default="auto", choices=sorted(PARSERS),
                   help="input log format (default: auto — sniff each line; pin explicitly in production)")
    p.add_argument("--input", default="-", help="log file path, or - for stdin")
    p.add_argument("--detections",
                   default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "endpoints.json"),
                   help="endpoint detection DB (default: endpoints.json next to this script)")
    p.add_argument("--subnets",
                   default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "subnets.json"),
                   help="source-class subnet inventory (default: subnets.json next to this script; "
                        "missing/empty = every source classifies 'unknown', verdicts unchanged)")
    p.add_argument("--sink", default="stdout", choices=["stdout", "file", "http"])
    p.add_argument("--output", help="output file (sink=file)")
    p.add_argument("--ingest-url", help="ingestion API URL, e.g. https://ingest.aim.internal/v1/events")
    p.add_argument("--ingest-token", help="ingestion API bearer token (or AIM_INGEST_TOKEN env)")
    p.add_argument("--salt-file", default="~/.aim/proxy_pseudo_salt",
                   help="dev/pilot pseudonymization salt file (AIM_HASH_SALT env takes precedence)")
    p.add_argument("--coverage", action="store_true", help="print coverage report to stderr")
    p.add_argument("--expected-fleet", type=int, default=700)
    args = p.parse_args(argv)

    rules, db = load_rules(args.detections)
    parse = PARSERS[args.format]
    pseudo = Pseudonymizer(args.salt_file)
    classifier = SourceClassifier(args.subnets)
    if not classifier._nets:
        print(f"note: no subnet inventory at {args.subnets} — all sources classify "
              f"'unknown' and verdicts are unchanged (AIM-103 prerequisite: "
              f"network-team subnet list)", file=sys.stderr)
    token = args.ingest_token or os.environ.get("AIM_INGEST_TOKEN")
    if args.sink == "http" and not token:
        raise SystemExit("--sink http requires --ingest-token or AIM_INGEST_TOKEN")
    args.ingest_token = token
    sink = build_sink(args)
    cov = Coverage() if args.coverage else None

    in_f = sys.stdin if args.input == "-" else open(args.input, "r", encoding="utf-8", errors="replace")
    n_lines = n_matched = 0
    try:
        for line in in_f:
            line = line.strip()
            if not line:
                continue
            n_lines += 1
            rec = parse(line)
            if rec is None:
                continue
            rule = match_rule(rules, rec["host"])
            if rule is None:
                continue
            traffic_class = classifier.classify(rec["src_ip"])
            event = to_event(rec, rule, pseudo, traffic_class)
            sink.write(event)
            n_matched += 1
            if cov:
                cov.add(rec, rule, traffic_class)
    finally:
        sink.flush()
        if in_f is not sys.stdin:
            in_f.close()

    if cov:
        print(cov.report(args.expected_fleet), file=sys.stderr)
        print(f"(detection DB v{db['version']} updated {db['updated']}; "
              f"{n_lines} lines read, {n_matched} AI events emitted)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

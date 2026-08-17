"""Is the leaked credential still live? — the question that turns a report line
into a page.

A history scan finds every secret ever committed. Most of them were rotated
years ago, and a pillar that pages on all of them gets muted in a week. The
severity difference between "a key was once committed" and "a key that is in a
public-ish repo still authenticates right now" is the difference between a
ticket and an incident, so this module exists to establish exactly that.

**The safety rule, and it is not negotiable.** A probe may only call an endpoint
that (a) is read-only, (b) exists to describe the *caller's own identity*, and
(c) is the documented way to answer "is this credential valid". Never a write.
Never a list of the account's resources. `sts:GetCallerIdentity` is the model:
it takes no parameters, touches no resource, is granted implicitly to every
principal, and cannot be denied by IAM policy. `GET /user` is GitHub's
equivalent.

That rule is enforced structurally, not by convention: a probe is a `Probe`
record in `_PROBES`, and `verify()` will not call anything that is not one.
There is no generic "try the credential" path to reach for, because the moment
one exists someone adds `s3:ListBuckets` to it and we are enumerating a
customer's data with a credential we found on the floor.

**The credential does leave the box — to its own issuer, and nowhere else.**
This is the one deliberate exception to "secrets never leave the machine", and
it is unavoidable: the only party who can say whether a key is live is the party
who issued it. It is sent over TLS, to a pinned hostname allowlist, with no
retries, and never to an AI Monitoring endpoint. Operators who consider that
trade wrong set `liveness.enabled: false` and get `unknown` instead of `live`.

**`unknown` is a real answer and is never rendered as "fine".** A probe that
times out, hits a proxy, or has no implementation for its issuer returns
`unknown` with a reason. Treating "could not check" as "not live" would
downgrade exactly the finding most likely to matter.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

# Every host a credential may be sent to. Belt and braces alongside `_PROBES`:
# if a probe URL is ever edited to point somewhere else, the send is refused.
ALLOWED_HOSTS = frozenset({
    "sts.amazonaws.com", "api.github.com", "slack.com", "oauth2.googleapis.com",
})

DEFAULT_TIMEOUT = 8


@dataclass(frozen=True)
class Result:
    """`state` is one of live/dead/unknown. `detail` names the *identity* the
    credential resolves to (an ARN, a login) — never the credential, and never
    a full API response, which for some issuers carries account metadata we
    have no business persisting."""

    state: str
    detail: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        if self.state not in ("live", "dead", "unknown"):
            raise ValueError(f"bad liveness state: {self.state!r}")


@dataclass(frozen=True)
class Probe:
    """One issuer's identity endpoint. `needs_pair` marks issuers whose
    credential is two halves (AWS: key id + secret) and therefore cannot be
    probed from a single finding."""

    issuer: str
    description: str
    call: Callable[..., Result]
    needs_pair: bool = False


def _http(url: str, *, headers: dict[str, str], data: bytes | None = None,
          timeout: int = DEFAULT_TIMEOUT) -> tuple[int, str]:
    """One request, no retries, host-allowlisted.

    No retries on purpose: a retry loop against an auth endpoint with a
    credential we do not own is how you trip an issuer's brute-force lockout
    and turn our scan into someone else's outage.
    """
    host = urllib.parse.urlparse(url).hostname or ""
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"refusing to send a credential to non-allowlisted host {host!r}")
    request = urllib.request.Request(url, data=data, headers=headers,
                                     method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(4096).decode("utf-8", "replace")


# --------------------------------------------------------------------------
# AWS — sts:GetCallerIdentity, signed with SigV4.
# --------------------------------------------------------------------------

def _sigv4(key_id: str, secret: str, *, region: str = "us-east-1") -> tuple[str, dict[str, str]]:
    """Sign the GetCallerIdentity POST. Implemented on the stdlib rather than
    pulling in botocore: this service's whole job is credential hygiene, and a
    transitive dependency tree that large is a poor look on the box that holds
    every secret we found."""
    service, host = "sts", "sts.amazonaws.com"
    body = "Action=GetCallerIdentity&Version=2011-06-15"
    now = datetime.datetime.now(datetime.timezone.utc)
    stamp, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body.encode()).hexdigest()

    canonical = (f"POST\n/\n\ncontent-type:application/x-www-form-urlencoded\n"
                 f"host:{host}\nx-amz-date:{stamp}\n\n"
                 f"content-type;host;x-amz-date\n{payload_hash}")
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = (f"AWS4-HMAC-SHA256\n{stamp}\n{scope}\n"
               f"{hashlib.sha256(canonical.encode()).hexdigest()}")

    def sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    signing_key = sign(sign(sign(sign(f"AWS4{secret}".encode(), date), region),
                            service), "aws4_request")
    signature = hmac.new(signing_key, to_sign.encode(), hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Amz-Date": stamp,
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={key_id}/{scope}, "
                          f"SignedHeaders=content-type;host;x-amz-date, "
                          f"Signature={signature}"),
    }
    return body, headers


_ARN = re.compile(r"<Arn>([^<]{1,256})</Arn>")


def probe_aws(*, key_id: str, secret: str, http=_http, **_: object) -> Result:
    """`sts:GetCallerIdentity` — takes no parameters, reads no resource, and is
    allowed for every principal regardless of policy. The canonical safe probe."""
    if not (key_id and secret):
        return Result("unknown", reason="AWS needs both the key id and the secret; "
                                        "only one half was recovered from history")
    try:
        body, headers = _sigv4(key_id, secret)
        status, text = http("https://sts.amazonaws.com/", headers=headers, data=body.encode())
    except Exception as exc:  # noqa: BLE001 — a failed probe is `unknown`, never `dead`
        return Result("unknown", reason=f"{type(exc).__name__}: {str(exc)[:120]}")
    if status == 200:
        arn = _ARN.search(text)
        return Result("live", detail=arn.group(1) if arn else "identity confirmed")
    # 403 with these codes is AWS positively asserting the credential is not
    # usable. Any other status is an inconclusive probe, not a dead key.
    if status == 403 and ("InvalidClientTokenId" in text or "SignatureDoesNotMatch" in text):
        return Result("dead", reason="STS rejected the credential")
    return Result("unknown", reason=f"STS returned {status}")


# --------------------------------------------------------------------------
# GitHub — GET /user.
# --------------------------------------------------------------------------

def probe_github(*, secret: str, http=_http, **_: object) -> Result:
    """`GET /user` returns the authenticated identity and nothing else. Its
    response headers also carry `x-oauth-scopes`, which is what check 3 audits —
    see `checks/tokens.py`, which calls this same endpoint for that reason."""
    if not secret:
        return Result("unknown", reason="no token value")
    try:
        status, text = http("https://api.github.com/user", headers={
            "Authorization": f"Bearer {secret}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "aim-hygiene/0.1",
        })
    except Exception as exc:  # noqa: BLE001
        return Result("unknown", reason=f"{type(exc).__name__}: {str(exc)[:120]}")
    if status == 200:
        try:
            login = (json.loads(text) or {}).get("login", "")
        except json.JSONDecodeError:
            login = ""
        return Result("live", detail=f"github:{login}" if login else "identity confirmed")
    if status == 401:
        return Result("dead", reason="GitHub rejected the token (401)")
    return Result("unknown", reason=f"GitHub returned {status}")


# --------------------------------------------------------------------------
# Slack — auth.test.
# --------------------------------------------------------------------------

def probe_slack(*, secret: str, http=_http, **_: object) -> Result:
    """`auth.test` is Slack's documented "is this token valid" call. It returns
    the bot's own identity and requires no scope."""
    if not secret:
        return Result("unknown", reason="no token value")
    try:
        status, text = http("https://slack.com/api/auth.test",
                            headers={"Authorization": f"Bearer {secret}",
                                     "Content-Type": "application/x-www-form-urlencoded"},
                            data=b"")
    except Exception as exc:  # noqa: BLE001
        return Result("unknown", reason=f"{type(exc).__name__}: {str(exc)[:120]}")
    if status != 200:
        return Result("unknown", reason=f"Slack returned {status}")
    try:
        payload = json.loads(text) or {}
    except json.JSONDecodeError:
        return Result("unknown", reason="Slack returned unparseable JSON")
    if payload.get("ok"):
        return Result("live", detail=f"slack:{payload.get('team', '')}/{payload.get('user', '')}"[:200])
    # Slack answers 200 with ok:false for a revoked token — the HTTP status
    # alone would have said "fine", which is why this branch reads the body.
    if payload.get("error") in ("invalid_auth", "token_revoked", "account_inactive"):
        return Result("dead", reason=f"Slack: {payload['error']}")
    return Result("unknown", reason=f"Slack: {payload.get('error', 'unknown')}")


_PROBES: dict[str, Probe] = {
    "aws": Probe("aws", "sts:GetCallerIdentity", probe_aws, needs_pair=True),
    "github": Probe("github", "GET /user", probe_github),
    "slack": Probe("slack", "auth.test", probe_slack),
}


def probe_for(issuer: str) -> Probe | None:
    return _PROBES.get(issuer)


def enabled(env: dict | None = None) -> bool:
    """Off switch that does not require editing config. `HYGIENE_LIVENESS=off`
    is honoured everywhere, including in tests, so a developer running the CLI
    on a laptop cannot accidentally transmit a customer's leaked key."""
    env = os.environ if env is None else env
    return str(env.get("HYGIENE_LIVENESS", "on")).lower() not in ("off", "0", "false", "no")


def verify(issuer: str, *, secret: str, key_id: str = "", http=_http,
           env: dict | None = None) -> Result:
    """The only entry point. Returns `unknown` for every case we cannot or must
    not check, and never raises — a liveness failure must not lose the
    underlying leak finding, which stands on its own."""
    if not enabled(env):
        return Result("unknown", reason="liveness verification disabled by configuration")
    probe = probe_for(issuer)
    if probe is None:
        return Result("unknown",
                      reason=f"no read-only identity probe exists for {issuer!r}; "
                             "not attempting one")
    try:
        return probe.call(secret=secret, key_id=key_id, http=http)
    except Exception as exc:  # noqa: BLE001 — see docstring
        return Result("unknown", reason=f"probe crashed: {type(exc).__name__}: {str(exc)[:120]}")


# --------------------------------------------------------------------------
# Pairing AWS halves.
# --------------------------------------------------------------------------

_AWS_KEY_ID = re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b")


def looks_like_aws_key_id(value: str) -> bool:
    """AWS access key ids are base32 after the prefix — `[A-Z2-7]`, no 0/1/8/9.

    Written out because the obvious `[A-Z0-9]` is wrong and fails open: it
    accepts strings AWS never issues while still matching real ones, so a
    fixture or a heuristic built on it appears to work. gitleaks' own
    `aws-access-token` rule encodes the same alphabet.
    """
    return bool(_AWS_KEY_ID.fullmatch((value or "").strip()))

"""Check 3 — what the token can actually do, versus what it was supposed to do.

A token that is not leaked is still a liability if it holds `admin:org` in
order to read a repo's status checks. This check closes the gap between the
scopes a token was *documented* to need and the scopes it was *granted*, which
in practice is where most of the standing blast radius in an org lives.

**The trap this module is built around: fine-grained PATs.**

Classic PATs report their grants in the `x-oauth-scopes` response header.
Fine-grained PATs, GitHub Apps and Actions' `GITHUB_TOKEN` do not — they return
that header *empty or absent*, because their permissions are per-resource and
are not expressible as OAuth scopes. Read naively, an empty header parses to
"zero scopes", which sorts as the least privileged token possible. A
fine-grained PAT with admin write on every repo in the org would audit as
*cleaner than a read-only classic token*.

So an absent header is reported as `unknown` and carries its own finding.
"Could not determine" and "determined to be fine" are different answers, and
collapsing them is precisely the silent pass this product exists to prevent.

**Cloud principals are deep-linked, not re-derived (D2).** Enumerating what an
IAM principal can do is CIEM, and a CNAPP already does it. Rebuilding a
policy evaluator here would produce a second, worse answer that disagrees with
the first. When a leaked AWS key is verified live, STS hands back the caller's
ARN — this module turns that ARN into a link to the CNAPP's CIEM view for
that exact principal, so "what could the finder have done with this key?" is one
click away and answered by the component that owns the question.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from dataclasses import dataclass, field

from ..models import Finding, safe_label
from . import liveness

OVERSCOPED_TOKEN = "secrets_hygiene.overscoped_token"
UNKNOWN_SCOPES = "secrets_hygiene.unauditable_token"
OVERSCOPED_PRINCIPAL = "secrets_hygiene.overscoped_principal"

# Scopes ranked by what they let a holder do that they cannot undo. The number
# is the severity floor for a token that holds the scope without documenting it.
_SCOPE_RISK: dict[str, tuple[str, str]] = {
    "delete_repo":       ("critical", "delete any repository the user can administer"),
    "admin:org":         ("critical", "add/remove org members and change org settings"),
    "admin:enterprise":  ("critical", "administer the enterprise account"),
    "site_admin":        ("critical", "GitHub Enterprise site administration"),
    "admin:org_hook":    ("high", "add org webhooks — an exfiltration path for every event"),
    "admin:repo_hook":   ("high", "add repo webhooks — an exfiltration path for every push"),
    "admin:public_key":  ("high", "add SSH keys to the account"),
    "admin:gpg_key":     ("high", "add GPG signing keys, enabling forged signed commits"),
    "workflow":          ("high", "modify Actions workflows — arbitrary code with CI's secrets"),
    "write:packages":    ("high", "publish packages consumers already trust"),
    "repo":              ("high", "full read/write on every private repo the user can reach"),
    "user":              ("medium", "read and write the user's profile and email addresses"),
    "gist":              ("medium", "create gists as the user — a quiet exfiltration channel"),
    "write:org":         ("medium", "change team membership"),
    "write:discussion":  ("low", "write discussions"),
    "read:org":          ("low", "read org membership"),
    "repo:status":       ("low", "read and write commit statuses"),
    "read:packages":     ("low", "read packages"),
    "notifications":     ("low", "read notifications"),
}

_ORDER = ["critical", "high", "medium", "low", "informational"]


@dataclass(frozen=True)
class TokenAudit:
    """The raw answer from the issuer, before it becomes findings."""

    identity: str = ""
    granted: tuple[str, ...] = ()
    # None means "the issuer did not tell us" — distinct from an empty tuple,
    # which means "the issuer told us there are none".
    enumerable: bool = True
    token_kind: str = "classic"
    reason: str = ""
    labels: dict[str, str] = field(default_factory=dict)


def classify(scope: str) -> tuple[str, str]:
    """Severity floor and plain-English capability for one scope.

    Unknown scopes are `medium`, never `low`: GitHub adds scopes over time and
    a scope we have never heard of is more likely to be new-and-powerful than
    harmless. Failing quiet on an unrecognized grant is how an audit rots.
    """
    if scope in _SCOPE_RISK:
        return _SCOPE_RISK[scope]
    parent = scope.split(":", 1)[0]
    if parent in ("admin",):
        return "critical", f"administrative access ({scope})"
    if parent in ("write", "delete"):
        return "high", f"write access ({scope})"
    if parent in ("read",):
        return "low", f"read access ({scope})"
    return "medium", f"undocumented scope ({scope})"


def token_kind(token: str) -> str:
    """Which GitHub credential shape this is. Drives whether scopes are
    enumerable at all."""
    if token.startswith("github_pat_"):
        return "fine-grained"
    if token.startswith(("ghs_", "ghu_")):
        return "app-installation"
    if token.startswith(("ghp_", "gho_", "ghr_")):
        return "classic"
    return "unknown"


def audit_github(token: str, *, http=liveness._http) -> TokenAudit:
    """Ask GitHub what this token is and what it may do.

    `GET /user` is the same read-only identity call the liveness probe makes;
    the scopes ride along in the response headers, so auditing a token costs no
    additional request and no additional permission.
    """
    kind = token_kind(token)
    if not token:
        return TokenAudit(enumerable=False, token_kind=kind, reason="no token configured")
    try:
        status, text, headers = _get_user(token, http=http)
    except Exception as exc:  # noqa: BLE001
        return TokenAudit(enumerable=False, token_kind=kind,
                          reason=f"{type(exc).__name__}: {str(exc)[:120]}")
    if status == 401:
        return TokenAudit(enumerable=False, token_kind=kind,
                          reason="GitHub rejected the token (401) — it is revoked or invalid")
    if status != 200:
        return TokenAudit(enumerable=False, token_kind=kind,
                          reason=f"GitHub returned {status}")
    try:
        login = (json.loads(text) or {}).get("login", "")
    except json.JSONDecodeError:
        login = ""

    # Header names are case-insensitive on the wire; normalize rather than
    # trusting the client library to preserve GitHub's casing.
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    raw = lowered.get("x-oauth-scopes")
    if raw is None:
        # THE trap. See the module docstring: absent is not empty.
        return TokenAudit(
            identity=login, enumerable=False, token_kind=kind,
            reason=("GitHub returned no x-oauth-scopes header. Fine-grained PATs, GitHub "
                    "App installation tokens and Actions' GITHUB_TOKEN carry per-resource "
                    "permissions that are not OAuth scopes and cannot be read from this "
                    "endpoint."))
    granted = tuple(sorted(s.strip() for s in raw.split(",") if s.strip()))
    return TokenAudit(identity=login, granted=granted, enumerable=True, token_kind=kind)


def _get_user(token: str, *, http) -> tuple[int, str, dict]:
    """`GET /user`, returning headers too.

    Uses urllib directly rather than `liveness._http` when it can, because the
    scopes live in the headers and that helper deliberately returns only the
    body. `http` stays injectable so tests never touch the network.
    """
    import urllib.request

    if http is not liveness._http:  # a test double
        result = http("https://api.github.com/user",
                      headers={"Authorization": f"Bearer {token}"})
        # Doubles may return (status, body) or (status, body, headers).
        if len(result) == 3:
            return result  # type: ignore[return-value]
        status, body = result  # type: ignore[misc]
        return status, body, {}
    request = urllib.request.Request("https://api.github.com/user", headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "aim-hygiene/0.1",
    })
    try:
        with urllib.request.urlopen(request, timeout=liveness.DEFAULT_TIMEOUT) as response:
            return response.status, response.read(4096).decode("utf-8", "replace"), \
                dict(response.headers)
    except urllib.error.HTTPError as exc:  # type: ignore[name-defined]
        return exc.code, exc.read(4096).decode("utf-8", "replace"), dict(exc.headers or {})


def findings_for_token(audit: TokenAudit, *, repo: str, minimum: list[str],
                       label: str = "the configured GitHub token") -> list[Finding]:
    """Compare granted against documented-minimum and produce findings."""
    if not audit.enumerable:
        return [Finding(
            check="tokens",
            rule_id="token-scopes-unauditable",
            finding_type=UNKNOWN_SCOPES,
            # Deliberately not `low`. An unauditable token is an unbounded one
            # until a human looks; ranking it below a token we *did* audit and
            # found over-scoped would invert the queue.
            severity="medium",
            title=f"Cannot enumerate the scopes of {label} ({audit.token_kind})",
            repo=repo,
            message=(f"{audit.reason} Because the grants could not be read, this token is "
                     "unaudited — not clean. An empty scope list from this endpoint must "
                     "never be read as 'no permissions'."),
            remediation=(
                "Read the permissions where they actually live:\n"
                "  fine-grained PAT: https://github.com/settings/personal-access-tokens — "
                "open the token and compare its repository access and permission list "
                "against the documented minimum.\n"
                "  App installation: gh api /installation/repositories, and the App's "
                "permissions at https://github.com/settings/apps/<app>/permissions\n"
                "  Actions GITHUB_TOKEN: the `permissions:` block in the workflow; default to\n"
                "    permissions: {contents: read}\n"
                "  and raise individual permissions only where a job needs them."),
            labels={"token_kind": safe_label(audit.token_kind, 32),
                    "identity": safe_label(audit.identity, 60)},
        )]

    allowed = set(minimum)
    # `repo` implies its children; a token holding `repo` also holds
    # `repo:status`, so a documented minimum of `repo` must not flag them.
    extra = sorted(s for s in audit.granted
                   if s not in allowed and not _implied_by(s, allowed))
    if not extra:
        return []
    worst = min((classify(s)[0] for s in extra), key=_ORDER.index)
    lines = "\n".join(f"  - {s}: {classify(s)[1]}" for s in extra)
    return [Finding(
        check="tokens",
        rule_id="token-over-scoped",
        finding_type=OVERSCOPED_TOKEN,
        severity=worst,
        title=f"{label} holds {len(extra)} scope(s) beyond its documented minimum",
        repo=repo,
        message=(f"Granted: {', '.join(audit.granted) or '(none)'}. "
                 f"Documented minimum: {', '.join(sorted(allowed)) or '(none)'}. "
                 f"Beyond the minimum:\n{lines}\n"
                 "Anyone who obtains this token obtains all of it, so the extra scopes are "
                 "standing blast radius rather than convenience."),
        remediation=(
            "GitHub cannot narrow an existing token's scopes — a replacement is the only fix:\n"
            "1. Mint a replacement at https://github.com/settings/tokens with only:\n"
            f"     {', '.join(sorted(allowed)) or '(define the minimum first)'}\n"
            "2. Prefer a fine-grained PAT scoped to the specific repositories, or a GitHub\n"
            "   App installation, over a classic PAT — classic scopes are account-wide and\n"
            "   cannot be limited to one repo.\n"
            "3. Roll the new token into the secret store, verify the dependent job, then\n"
            "   delete the old token from the tokens page.\n"
            "4. If this token was ever committed anywhere, treat it as leaked and check the\n"
            "   org audit log for use you did not authorize."),
        labels={"granted": safe_label(",".join(audit.granted), 128),
                "extra": safe_label(",".join(extra), 128),
                "identity": safe_label(audit.identity, 60),
                "token_kind": safe_label(audit.token_kind, 32)},
    )]


def _implied_by(scope: str, allowed: set[str]) -> bool:
    """`repo` implies `repo:*`; `admin:x` implies `write:x` implies `read:x`."""
    if ":" in scope and scope.split(":", 1)[0] in allowed:
        return True
    verb, _, noun = scope.partition(":")
    if not noun:
        return False
    ladder = {"read": ("read", "write", "admin"), "write": ("write", "admin"),
              "admin": ("admin",)}
    return any(f"{v}:{noun}" in allowed for v in ladder.get(verb, ()))


# --------------------------------------------------------------------------
# Cloud principals — deep link into the CNAPP CIEM (D2).
# --------------------------------------------------------------------------

DEFAULT_CIEM_BASE = os.environ.get("CIEM_BASE_URL", "https://cnapp.internal")


def ciem_link(principal: str, *, base: str = "") -> str:
    """A deep link to the CNAPP's CIEM view for one principal.

    The path is configurable because it belongs to another service's routing
    table, and hardcoding another team's URL shape is how a link rots silently.
    An operator who changes it changes one setting; the default documents the
    shape we integrate against.
    """
    root = (base or DEFAULT_CIEM_BASE).rstrip("/")
    return f"{root}/ciem/principals?ref={urllib.parse.quote(principal, safe='')}"


def principal_finding(principal: str, *, repo: str, fingerprint_: str = "",
                      ciem_base: str = "", source: str = "a credential leaked in git history",
                      ) -> Finding:
    """Raised when a live leaked cloud credential resolves to a real principal.

    This is the finding that answers "so what?" — the leak is the event, the
    principal's effective permissions are the impact, and the CNAPP owns
    that computation.
    """
    link = ciem_link(principal, base=ciem_base)
    return Finding(
        check="tokens",
        rule_id="cloud-principal-exposed",
        finding_type=OVERSCOPED_PRINCIPAL,
        severity="high",
        title=f"Review the effective permissions of {principal[:80]}",
        repo=repo,
        fingerprint=fingerprint_,
        message=(f"{source} authenticates as {principal}. The impact of this leak is whatever "
                 "that principal is entitled to do, which is a CIEM question — the CNAPP "
                 "computes it from the live policy graph rather than this pillar guessing "
                 "from the credential's shape."),
        remediation=(
            f"1. OPEN the principal's effective-permissions view:\n     {link}\n"
            "2. SCOPE the incident from what it shows: any data that principal can read "
            "should be assumed read, and any action it can take should be assumed taken, "
            "until the audit log says otherwise.\n"
            "3. ROTATE first if you have not already — the CIEM review does not revoke "
            "anything.\n"
            "4. RIGHT-SIZE the principal after the rotation. A leaked credential for a "
            "least-privileged role is a much smaller incident next time."),
        labels={"principal": safe_label(principal, 128), "ciem": "cnapp-scanner"},
    )

"""Non-secret health/self-check for gatehouse PAT consumers (AIM-1090).

Purpose: make the cutover from interim OAuth (`gho_*`) / classic PATs to
repo-scoped fine-grained PATs a one-step swap with a fail-closed probe that
never prints secret material.

Why capability probes (not `x-oauth-scopes`):

* Classic / OAuth tokens report grants in the `x-oauth-scopes` response header.
* Fine-grained PATs (`github_pat_…`), App installation tokens, and Actions'
  `GITHUB_TOKEN` leave that header empty/absent — reading it as "zero scopes"
  would sort as least-privileged and pass incorrectly.
* So this module classifies shape by prefix and proves access with real,
  non-mutating GitHub calls (GraphQL `viewerPermission` + read REST probes).

Never log, print, or return the token value. Reports use only: env var name,
kind, presence, permission rank, and plain-English fail reasons.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

API_ROOT = os.environ.get("GATEHOUSE_GITHUB_API", "https://api.github.com")
USER_AGENT = "gatehouse-token-check/0.1 (+ai-monitoring AIM-1090)"

# Ranked permission from GraphQL repository.viewerPermission.
_PERM_RANK = {
    "NONE": 0,
    "READ": 1,
    "TRIAGE": 2,
    "WRITE": 3,
    "MAINTAIN": 4,
    "ADMIN": 5,
}

# Documented least-privilege matrix (must match the cutover runbook).
# Issues: Read is enough for list_issue_comments; AIM-419 may still mint Issues
# Read/Write for future issue-filing — either satisfies the current probe.
READ_ROLE = "read"
WRITE_ROLE = "write"

HttpFn = Callable[[str, str, str, dict | None, dict[str, str] | None], tuple[int, str, dict[str, str]]]


@dataclass
class TokenIdentity:
    """Shape + presence only — never the secret."""

    env_var: str
    present: bool
    kind: str  # fine-grained | oauth | classic-pat | app-installation | user-to-server | refresh | unknown | missing
    length: int = 0
    preferred: bool = False  # True when kind is fine-grained (cutover target)


@dataclass
class ProbeResult:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class RoleReport:
    role: str  # read | write
    env_var: str
    identity: TokenIdentity
    ok: bool
    probes: list[ProbeResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "env_var": self.env_var,
            "ok": self.ok,
            "identity": asdict(self.identity),
            "probes": [asdict(p) for p in self.probes],
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


@dataclass
class CheckReport:
    ok: bool
    roles: list[RoleReport] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "roles": [r.to_dict() for r in self.roles],
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


def classify_token(token: str) -> str:
    """Which GitHub credential shape this is. Prefix-only; no network."""
    if not token:
        return "missing"
    if token.startswith("github_pat_"):
        return "fine-grained"
    if token.startswith("gho_"):
        return "oauth"
    if token.startswith("ghp_"):
        return "classic-pat"
    if token.startswith("ghs_"):
        return "app-installation"
    if token.startswith("ghu_"):
        return "user-to-server"
    if token.startswith("ghr_"):
        return "refresh"
    return "unknown"


def identity_for(env_var: str, token: str) -> TokenIdentity:
    kind = classify_token(token)
    return TokenIdentity(
        env_var=env_var,
        present=bool(token),
        kind=kind,
        length=len(token) if token else 0,
        preferred=(kind == "fine-grained"),
    )


def _default_http(
    method: str,
    url: str,
    token: str,
    body: dict | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, str, dict[str, str]]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", USER_AGENT)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read(8192).decode("utf-8", "replace")
            headers = {k.lower(): v for k, v in dict(resp.headers).items()}
            return int(resp.status), raw, headers
    except urllib.error.HTTPError as exc:
        raw = exc.read(8192).decode("utf-8", "replace")
        headers = {k.lower(): v for k, v in dict(exc.headers or {}).items()}
        return int(exc.code), raw, headers
    except urllib.error.URLError as exc:
        return 0, f"network: {exc.reason}", {}


def _parse_scopes(headers: dict[str, str]) -> tuple[bool, tuple[str, ...]]:
    """Return (header_present, scopes). Absent ≠ empty (see hygiene tokens)."""
    if "x-oauth-scopes" not in headers:
        return False, ()
    raw = headers.get("x-oauth-scopes") or ""
    return True, tuple(sorted(s.strip() for s in raw.split(",") if s.strip()))


def probe_viewer_permission(
    token: str,
    repo: str,
    *,
    http: HttpFn = _default_http,
    api_root: str = API_ROOT,
) -> ProbeResult:
    """Non-mutating GraphQL: repository.viewerPermission for this token."""
    if "/" not in repo:
        return ProbeResult("viewerPermission", False, f"bad repo {repo!r}")
    owner, name = repo.split("/", 1)
    query = {
        "query": (
            "query($o:String!,$n:String!){"
            "repository(owner:$o,name:$n){viewerPermission}"
            "}"
        ),
        "variables": {"o": owner, "n": name},
    }
    status, text, _ = http("POST", f"{api_root.rstrip('/')}/graphql", token, query, None)
    if status == 401:
        return ProbeResult("viewerPermission", False, "GitHub rejected the token (401)")
    if status != 200:
        return ProbeResult("viewerPermission", False, f"GraphQL HTTP {status}")
    try:
        payload = json.loads(text or "{}")
    except json.JSONDecodeError:
        return ProbeResult("viewerPermission", False, "GraphQL body not JSON")
    if payload.get("errors"):
        msg = payload["errors"][0].get("message", "GraphQL error")[:160]
        return ProbeResult("viewerPermission", False, msg)
    perm = (
        ((payload.get("data") or {}).get("repository") or {}).get("viewerPermission")
        or "NONE"
    )
    return ProbeResult("viewerPermission", True, str(perm))


def probe_list_pulls(
    token: str,
    repo: str,
    *,
    http: HttpFn = _default_http,
    api_root: str = API_ROOT,
) -> ProbeResult:
    """Read path used by merge-audit: list closed PRs."""
    url = f"{api_root.rstrip('/')}/repos/{repo}/pulls?state=closed&per_page=1"
    status, text, _ = http("GET", url, token, None, None)
    if status == 200:
        return ProbeResult("list_pulls", True, "ok")
    if status == 401:
        return ProbeResult("list_pulls", False, "401 unauthorized")
    if status == 403:
        detail = text[:160].replace("\n", " ")
        return ProbeResult(
            "list_pulls",
            False,
            f"403 forbidden — need pull_requests:read on {repo} ({detail})",
        )
    if status == 404:
        return ProbeResult(
            "list_pulls",
            False,
            f"404 — token cannot see {repo} (metadata:read + repository access)",
        )
    return ProbeResult("list_pulls", False, f"HTTP {status}")


def probe_auth_and_scopes(
    token: str,
    *,
    http: HttpFn = _default_http,
    api_root: str = API_ROOT,
) -> tuple[ProbeResult, tuple[str, ...] | None]:
    """GET /user — proves the token authenticates; returns classic scopes if any."""
    status, text, headers = http("GET", f"{api_root.rstrip('/')}/user", token, None, None)
    if status == 401:
        return ProbeResult("authenticate", False, "401 unauthorized / revoked"), None
    if status != 200:
        return ProbeResult("authenticate", False, f"HTTP {status}"), None
    try:
        login = (json.loads(text) or {}).get("login") or ""
    except json.JSONDecodeError:
        login = ""
    present, scopes = _parse_scopes(headers)
    detail = f"login={login or '?'}"
    if present:
        detail += f"; classic_scopes={','.join(scopes) or '(none)'}"
    else:
        detail += "; classic_scopes=unauditable (fine-grained/App/Actions)"
    return ProbeResult("authenticate", True, detail), (scopes if present else None)


def _min_perm_ok(actual: str, required: str) -> bool:
    return _PERM_RANK.get(actual.upper(), -1) >= _PERM_RANK.get(required.upper(), 99)


def _classic_scopes_cover_read(scopes: tuple[str, ...]) -> bool:
    """Classic OAuth: `repo` covers read; finer read scopes also ok."""
    s = set(scopes)
    if "repo" in s:
        return True
    # Public-only classic scopes are not enough for private dogfood repos.
    needed_any = {"repo", "public_repo"}
    return bool(s & needed_any)


def _classic_scopes_cover_write(scopes: tuple[str, ...]) -> bool:
    return "repo" in set(scopes)


def check_read_token(
    token: str,
    repos: list[str],
    *,
    env_var: str = "GATEHOUSE_GITHUB_TOKEN",
    require_fine_grained: bool = False,
    http: HttpFn = _default_http,
    api_root: str = API_ROOT,
) -> RoleReport:
    ident = identity_for(env_var, token)
    report = RoleReport(role=READ_ROLE, env_var=env_var, identity=ident, ok=False)
    if not token:
        report.errors.append(
            f"{env_var} is unset — merge-audit cannot list PRs/check runs"
        )
        return report

    if require_fine_grained and ident.kind != "fine-grained":
        report.errors.append(
            f"{env_var} kind={ident.kind} — cutover requires fine-grained "
            f"(github_pat_*) read PAT; interim oauth/classic is not accepted "
            f"with --require-fine-grained"
        )
    elif ident.kind in ("oauth", "classic-pat"):
        report.warnings.append(
            f"{env_var} is still interim kind={ident.kind} (prefix "
            f"{'gho_' if ident.kind == 'oauth' else 'ghp_'}). Target is a "
            f"repo-scoped fine-grained PAT (AIM-419)."
        )
    elif ident.kind == "unknown":
        report.warnings.append(
            f"{env_var} has unrecognized shape — ensure it is a GitHub PAT, "
            f"not a GHCR password or unrelated secret"
        )

    auth, scopes = probe_auth_and_scopes(token, http=http, api_root=api_root)
    report.probes.append(auth)
    if not auth.ok:
        report.errors.append(f"authenticate failed: {auth.detail}")
        return report

    if scopes is not None and not _classic_scopes_cover_read(scopes):
        report.errors.append(
            f"classic scopes {list(scopes)} lack repo/public_repo — "
            f"merge-audit needs contents/PR/checks read on private repos"
        )
        report.ok = False
        return report

    for repo in repos:
        pulls = probe_list_pulls(token, repo, http=http, api_root=api_root)
        report.probes.append(probes_rename(pulls, repo))
        if not pulls.ok:
            report.errors.append(f"{repo}: {pulls.detail}")
            continue
        perm = probe_viewer_permission(token, repo, http=http, api_root=api_root)
        report.probes.append(probes_rename(perm, repo))
        if not perm.ok:
            report.errors.append(f"{repo}: viewerPermission {perm.detail}")
            continue
        if not _min_perm_ok(perm.detail, "READ"):
            report.errors.append(
                f"{repo}: viewerPermission={perm.detail} < READ — grant at least "
                f"Contents: Read, Pull requests: Read, Checks: Read, Metadata: Read"
            )

    # Interim oauth/classic can still be operationally ok (with warnings);
    # --require-fine-grained elevates shape into errors above.
    report.ok = not report.errors
    return report


def check_write_token(
    token: str,
    repos: list[str],
    *,
    env_var: str = "GATEHOUSE_REVERT_TOKEN",
    require_fine_grained: bool = False,
    http: HttpFn = _default_http,
    api_root: str = API_ROOT,
) -> RoleReport:
    """Write path for auto-revert. Non-mutating: auth + viewerPermission≥WRITE.

    Does **not** create branches or PRs. When the token is missing, report is
    not ok but callers can treat write as optional (detect-only mode).
    """
    ident = identity_for(env_var, token)
    report = RoleReport(role=WRITE_ROLE, env_var=env_var, identity=ident, ok=False)
    if not token:
        report.errors.append(
            f"{env_var} is unset — unauthorized bypasses alert but do not "
            f"open auto-revert PRs"
        )
        return report

    if require_fine_grained and ident.kind != "fine-grained":
        report.errors.append(
            f"{env_var} kind={ident.kind} — cutover requires fine-grained "
            f"write PAT (contents:write + pull_requests:write on audited repos only)"
        )
    elif ident.kind in ("oauth", "classic-pat"):
        report.warnings.append(
            f"{env_var} is still interim kind={ident.kind}. Target is a "
            f"repo-scoped fine-grained PAT (AIM-360 / AIM-361)."
        )

    auth, scopes = probe_auth_and_scopes(token, http=http, api_root=api_root)
    report.probes.append(auth)
    if not auth.ok:
        report.errors.append(f"authenticate failed: {auth.detail}")
        return report

    if scopes is not None and not _classic_scopes_cover_write(scopes):
        report.errors.append(
            f"classic scopes {list(scopes)} lack `repo` — auto-revert needs "
            f"contents:write + pull_requests:write"
        )
        report.ok = False
        return report

    for repo in repos:
        perm = probe_viewer_permission(token, repo, http=http, api_root=api_root)
        report.probes.append(probes_rename(perm, repo))
        if not perm.ok:
            report.errors.append(f"{repo}: viewerPermission {perm.detail}")
            continue
        if not _min_perm_ok(perm.detail, "WRITE"):
            report.errors.append(
                f"{repo}: viewerPermission={perm.detail} < WRITE — grant "
                f"Contents: Read and write + Pull requests: Read and write "
                f"(Metadata: Read) for auto-revert"
            )

    report.ok = not report.errors
    return report


def probes_rename(probe: ProbeResult, repo: str) -> ProbeResult:
    return ProbeResult(f"{probe.name}@{repo}", probe.ok, probe.detail)


def resolve_read_token(
    explicit: str | None = None,
) -> tuple[str, str]:
    """Return (token, env_var_name) for the merge-audit read path."""
    if explicit is not None and explicit != "":
        return explicit, "GATEHOUSE_GITHUB_TOKEN"
    if os.environ.get("GATEHOUSE_GITHUB_TOKEN"):
        return os.environ["GATEHOUSE_GITHUB_TOKEN"], "GATEHOUSE_GITHUB_TOKEN"
    if os.environ.get("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"], "GITHUB_TOKEN"
    return "", "GATEHOUSE_GITHUB_TOKEN"


def check_tokens(
    *,
    read_token: str | None = None,
    write_token: str | None = None,
    repos: list[str] | None = None,
    require_fine_grained: bool = False,
    require_write: bool = True,
    http: HttpFn = _default_http,
    api_root: str = API_ROOT,
) -> CheckReport:
    """Run the full cutover readiness check against configured env tokens."""
    repos = list(repos or _default_repos())
    read_value, read_var = resolve_read_token(read_token)
    if write_token is None:
        write_value = os.environ.get("GATEHOUSE_REVERT_TOKEN") or ""
    else:
        write_value = write_token

    report = CheckReport(ok=True)
    if not repos:
        report.ok = False
        report.errors.append("no repos configured — pass --repo OWNER/NAME")
        return report

    read_rep = check_read_token(
        read_value,
        repos,
        env_var=read_var,
        require_fine_grained=require_fine_grained,
        http=http,
        api_root=api_root,
    )
    report.roles.append(read_rep)
    report.warnings.extend(read_rep.warnings)
    report.errors.extend(read_rep.errors)
    if not read_rep.ok:
        report.ok = False

    write_rep = check_write_token(
        write_value,
        repos,
        env_var="GATEHOUSE_REVERT_TOKEN",
        require_fine_grained=require_fine_grained,
        http=http,
        api_root=api_root,
    )
    report.roles.append(write_rep)
    report.warnings.extend(write_rep.warnings)
    if require_write:
        report.errors.extend(write_rep.errors)
        if not write_rep.ok:
            report.ok = False
    elif write_rep.errors:
        report.warnings.append(
            "write token not required (--no-require-write); "
            + "; ".join(write_rep.errors)
        )

    # Shared credential warning (dogfood interim state: same gho_* in both vars).
    if read_value and write_value and read_value == write_value:
        msg = (
            "GATEHOUSE_GITHUB_TOKEN and GATEHOUSE_REVERT_TOKEN are the same "
            "credential — a read-path compromise is a write primitive. Prefer "
            "separate fine-grained PATs (AIM-419 read + AIM-360/361 write)."
        )
        report.warnings.append(msg)
        if require_fine_grained:
            report.errors.append(msg)
            report.ok = False

    return report


def _default_repos() -> list[str]:
    """Compose/systemd defaults for dogfood dual-repo audit."""
    primary = os.environ.get("GATEHOUSE_AUDIT_REPO", "hawikk/aim")
    twin = os.environ.get("GATEHOUSE_AUDIT_REPO_TWIN", "")
    # Strip optional :base-ref suffixes used by merge-audit CLI.
    out: list[str] = []
    for raw in (primary, twin):
        if not raw:
            continue
        name, sep, _ref = raw.rpartition(":")
        out.append(name if sep and "/" in name else raw)
    return out


def format_human(report: CheckReport) -> str:
    """Operator-facing summary; never includes secret values."""
    lines = [
        f"gatehouse check-tokens: {'OK' if report.ok else 'FAIL'}",
    ]
    for role in report.roles:
        ident = role.identity
        lines.append(
            f"  [{role.role}] {role.env_var}: "
            f"{'ok' if role.ok else 'FAIL'} "
            f"kind={ident.kind} present={ident.present} "
            f"preferred_shape={ident.preferred}"
        )
        for p in role.probes:
            mark = "pass" if p.ok else "fail"
            lines.append(f"    - {p.name}: {mark} ({p.detail})")
    for w in report.warnings:
        lines.append(f"  WARN: {w}")
    for e in report.errors:
        lines.append(f"  ERROR: {e}")
    if not report.ok:
        lines.append(
            "Fail-closed: fix token presence/shape/permissions before cutover. "
            "See docs/security/gatehouse-pat-cutover.md"
        )
    return "\n".join(lines)

"""GitHub App client — least privilege, on purpose, at every layer.

The acceptance criterion says "minimum permissions … no org-wide token". Three
separate mechanisms are needed to actually mean that, and only the first is the
one people usually implement:

1. **The App declares three permissions.** `contents:read`,
   `pull_requests:write`, `checks:write` — justified per permission in
   `docs/gatehouse-github-app.md` and in `app-manifest.yml`.
2. **The installation token is scoped down at mint time.** An installation
   access token defaults to *every repository the App is installed on*, which
   on a 700-engineer org is thousands of repos, held in memory by a service
   that runs other people's code through four scanners. Every token gatehouse
   mints names exactly one repository and re-states the three permissions, so a
   token stolen mid-scan opens one repo for at most an hour.
3. **Tokens are never persisted.** Cached in memory keyed by installation and
   repo, dropped 5 minutes before GitHub expires them, never written to disk,
   never logged, and handed to git through GIT_ASKPASS rather than a URL.

The private key is read from the environment (or a file path) and used only to
sign the 10-minute App JWT.
"""

from __future__ import annotations

import hmac
import json
import os
import time
import urllib.error
import urllib.request
from hashlib import sha256

API_ROOT = os.environ.get("GATEHOUSE_GITHUB_API", "https://api.github.com")
USER_AGENT = "gatehouse/0.1 (+ai-monitoring pillar 3)"

# Restated on every token mint. Must stay a subset of what the App declares —
# GitHub rejects a scope-down that asks for more than the installation has,
# which makes this a real assertion rather than a comment.
TOKEN_PERMISSIONS = {
    "contents": "read",
    "pull_requests": "write",
    "checks": "write",
}


class GitHubError(RuntimeError):
    pass


def verify_signature(body: bytes, header: str, secret: str) -> bool:
    """Constant-time check of `X-Hub-Signature-256`.

    An unsigned or wrongly-signed delivery is not a webhook, it is an attacker
    asking gatehouse to clone a repository of their choosing onto our runner
    and hand back an installation token's worth of access. Missing header,
    missing secret and bad digest are all one answer: no.
    """
    if not secret or not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, sha256).hexdigest()
    return hmac.compare_digest(expected, header[7:])


def app_jwt(app_id: str, private_key: str, *, now: int | None = None) -> str:
    """A 10-minute RS256 JWT identifying the App itself (GitHub's maximum).

    `iat` is backdated 60s because GitHub rejects a token whose `iat` is in the
    future by even a second, and container clocks drift.
    """
    import jwt  # PyJWT

    now = now or int(time.time())
    return jwt.encode(
        {"iat": now - 60, "exp": now + 570, "iss": app_id},
        private_key,
        algorithm="RS256",
    )


def _request(method: str, url: str, *, token: str, body: dict | None = None,
             accept: str = "application/vnd.github+json") -> dict | list:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", accept)
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    request.add_header("User-Agent", USER_AGENT)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        # The token is in a header, not the URL, so the URL is safe to log.
        raise GitHubError(f"{method} {url} -> {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise GitHubError(f"{method} {url} failed: {exc.reason}") from exc
    return json.loads(payload or b"{}")


class Client:
    """Authenticated GitHub calls for one App. Thread-safe enough for the
    webhook's one-thread-per-delivery model: the token cache is a dict of
    immutable tuples and a redundant mint is harmless."""

    def __init__(self, app_id: str = "", private_key: str = "",
                 api_root: str = API_ROOT, transport=None):
        self.app_id = app_id or os.environ.get("GATEHOUSE_APP_ID", "")
        self.private_key = private_key or _load_private_key()
        self.api_root = api_root.rstrip("/")
        # Injectable so every call below is asserted in unit tests against a
        # recorded transport instead of against a live GitHub.
        self._request = transport or _request
        self._tokens: dict[tuple[int, str], tuple[str, float]] = {}

    # ---- auth ------------------------------------------------------------

    def installation_token(self, installation_id: int, repo_full_name: str) -> str:
        """Mint (or reuse) a token scoped to ONE repo and three permissions."""
        key = (installation_id, repo_full_name)
        cached = self._tokens.get(key)
        if cached and cached[1] > time.time():
            return cached[0]
        payload = self._request(
            "POST",
            f"{self.api_root}/app/installations/{installation_id}/access_tokens",
            token=app_jwt(self.app_id, self.private_key),
            body={
                "repositories": [repo_full_name.split("/", 1)[-1]],
                "permissions": dict(TOKEN_PERMISSIONS),
            },
        )
        token = payload.get("token")
        if not token:
            raise GitHubError("installation token response had no token")
        # GitHub expires these at 60 minutes; drop ours at 55 so a long scan
        # cannot hand git a token that dies mid-clone.
        self._tokens[key] = (token, time.time() + 55 * 60)
        return token

    # ---- checks ----------------------------------------------------------

    def create_check_run(self, repo: str, *, head_sha: str, token: str,
                         name: str = "gatehouse") -> int:
        """Open an in-progress check immediately, before the scan starts.

        Posted first so the PR shows "gatehouse — running" within seconds. If
        the scan then crashes, the run has somewhere to report the crash to;
        creating the check only on success would leave a failed scan invisible.
        """
        payload = self._request(
            "POST", f"{self.api_root}/repos/{repo}/check-runs", token=token,
            body={"name": name, "head_sha": head_sha, "status": "in_progress",
                  "started_at": _now_iso()})
        return int(payload.get("id") or 0)

    def complete_check_run(self, repo: str, check_run_id: int, *, token: str,
                           conclusion: str, title: str, summary: str,
                           annotations: list[dict], name: str = "gatehouse") -> None:
        """Finish the check, sending annotations 50 at a time.

        The first request carries the conclusion so the PR stops spinning even
        if a later annotation batch fails; the remaining batches are additive
        updates. Ordering matters: a scan that reported 200 findings and then
        died on batch 2 must still be red, not stuck.
        """
        from .checkrun import batches

        pages = list(batches(annotations)) or [[]]
        self._request(
            "PATCH", f"{self.api_root}/repos/{repo}/check-runs/{check_run_id}", token=token,
            body={"name": name, "status": "completed", "conclusion": conclusion,
                  "completed_at": _now_iso(),
                  "output": {"title": title, "summary": summary, "annotations": pages[0]}})
        for page in pages[1:]:
            self._request(
                "PATCH", f"{self.api_root}/repos/{repo}/check-runs/{check_run_id}",
                token=token,
                body={"output": {"title": title, "summary": summary, "annotations": page}})

    # ---- the one comment -------------------------------------------------

    def upsert_comment(self, repo: str, pr_number: int, *, token: str, body: str,
                       marker: str) -> int:
        """Edit gatehouse's existing comment, or post the first one.

        Returns the comment id, or 0 when nothing was posted. Finding the old
        comment by marker rather than by author id means a re-installed App
        with a new bot user still edits in place instead of starting a second
        thread of comments on a long-lived PR.
        """
        existing = self.find_comment(repo, pr_number, token=token, marker=marker)
        if existing:
            self._request("PATCH", f"{self.api_root}/repos/{repo}/issues/comments/{existing}",
                          token=token, body={"body": body})
            return existing
        payload = self._request(
            "POST", f"{self.api_root}/repos/{repo}/issues/{pr_number}/comments",
            token=token, body={"body": body})
        return int(payload.get("id") or 0)

    def find_comment(self, repo: str, pr_number: int, *, token: str, marker: str) -> int:
        for page in range(1, 6):  # 500 comments is far past any real PR
            items = self._request(
                "GET",
                f"{self.api_root}/repos/{repo}/issues/{pr_number}/comments"
                f"?per_page=100&page={page}",
                token=token)
            if not items:
                return 0
            for item in items:
                if marker in (item.get("body") or ""):
                    return int(item.get("id") or 0)
            if len(items) < 100:
                return 0
        return 0

    def create_review_comment(self, repo: str, pr_number: int, *, token: str,
                              commit_id: str, path: str, body: str, line: int,
                              side: str = "RIGHT", start_line: int | None = None,
                              start_side: str | None = None) -> int:
        """Post one pull-request review comment (inline on Files changed).

        Used ```suggestion blocks. Failures are the caller's to
        handle: a missing line in the diff is a 422 and must not crash the
        whole report. Returns the comment id, or 0 when GitHub omits it.
        """
        payload: dict = {
            "body": body,
            "commit_id": commit_id,
            "path": path,
            "line": line,
            "side": side,
        }
        if start_line is not None and start_line < line:
            payload["start_line"] = start_line
            payload["start_side"] = start_side or side
        result = self._request(
            "POST", f"{self.api_root}/repos/{repo}/pulls/{pr_number}/comments",
            token=token, body=payload)
        return int(result.get("id") or 0)

    def file_at_ref(self, repo: str, path: str, ref: str, *, token: str) -> str:
        """Read one file at a ref without cloning. Used for `.gatehouse.yml`,
        which is deliberately read from the BASE branch — see suppress.py."""
        try:
            payload = self._request(
                "GET", f"{self.api_root}/repos/{repo}/contents/{path}?ref={ref}",
                token=token, accept="application/vnd.github.raw+json")
        except GitHubError:
            return ""
        return payload if isinstance(payload, str) else ""

    # ---- coverage ledger ---------------------------------------

    def list_installations(self) -> list[dict]:
        """Every installation of this App. App JWT, no installation token.

        Returns a thin list: id, account login, account type, repository_selection
        (all|selected). Used as the forge-side denominator for the coverage
        ledger — silence is not green.
        """
        items: list[dict] = []
        for page in range(1, 51):  # hard cap; 5000 installs is absurd for us
            batch = self._request(
                "GET",
                f"{self.api_root}/app/installations?per_page=100&page={page}",
                token=app_jwt(self.app_id, self.private_key),
            )
            if not isinstance(batch, list) or not batch:
                break
            for inst in batch:
                account = inst.get("account") or {}
                items.append({
                    "id": int(inst.get("id") or 0),
                    "account_login": account.get("login") or "",
                    "account_type": account.get("type") or "",
                    "repository_selection": inst.get("repository_selection") or "",
                    "suspended_at": inst.get("suspended_at"),
                })
            if len(batch) < 100:
                break
        return items

    def list_installation_repos(self, installation_id: int) -> list[dict]:
        """Repos this installation can see, via a short-lived installation token.

        This is the forge API enumeration path: every repo GitHub says the App
        is installed on, whether or not a gate has ever run. Pagination is
        capped so a misbehaving org cannot OOM the process.
        """
        if not installation_id:
            return []
        # Installation-wide token (no single-repo scope-down): listing needs
        # the full set. Permissions restated so a stolen list-token still
        # cannot escalate beyond what the App holds.
        payload = self._request(
            "POST",
            f"{self.api_root}/app/installations/{installation_id}/access_tokens",
            token=app_jwt(self.app_id, self.private_key),
            body={"permissions": dict(TOKEN_PERMISSIONS)},
        )
        token = payload.get("token") if isinstance(payload, dict) else None
        if not token:
            raise GitHubError(
                f"installation {installation_id}: token response had no token")
        repos: list[dict] = []
        for page in range(1, 101):  # 10k repos hard cap
            batch = self._request(
                "GET",
                f"{self.api_root}/installation/repositories?per_page=100&page={page}",
                token=token,
            )
            page_repos = (batch or {}).get("repositories") if isinstance(batch, dict) else None
            if not page_repos:
                break
            for r in page_repos:
                full = r.get("full_name") or ""
                if not full:
                    continue
                repos.append({
                    "full_name": full,
                    "private": bool(r.get("private")),
                    "archived": bool(r.get("archived")),
                    "disabled": bool(r.get("disabled")),
                    "default_branch": r.get("default_branch") or "",
                    "installation_id": installation_id,
                })
            if len(page_repos) < 100:
                break
        return repos

    def create_inline_review(self, repo: str, pr_number: int, *, token: str,
                             commit_id: str, comments: list[dict],
                             body: str = "") -> int:
        """Post one PR review with inline comments on the exact diff lines.

        Used SAST annotations (message + fix hint on the line) and
        ```suggestion blocks. Always `event: COMMENT` — never
        `REQUEST_CHANGES` or `APPROVE`. Returns the review id, or 0 when there
        is nothing to post.
        """
        if not comments or not commit_id:
            return 0
        payload = self._request(
            "POST", f"{self.api_root}/repos/{repo}/pulls/{pr_number}/reviews",
            token=token,
            body={
                "commit_id": commit_id,
                "event": "COMMENT",
                "body": body or (
                    "### 🛡️ gatehouse\n\n"
                    "Inline findings on the lines this pull request changed."
                ),
                "comments": comments,
            })
        return int(payload.get("id") or 0)

    def create_suggestion_review(self, repo: str, pr_number: int, *, token: str,
                                 commit_id: str, comments: list[dict],
                                 body: str = "") -> int:
        """Post one advisory PR review carrying committable ```suggestion blocks.

        Thin wrapper over `create_inline_review` with the default body.
        """
        return self.create_inline_review(
            repo, pr_number, token=token, commit_id=commit_id, comments=comments,
            body=body or (
                "### 🛡️ gatehouse suggested fixes\n\n"
                "Committable suggestions for corroborated scanner findings. "
                "**Advisory only** — they do not fail this check."
            ),
        )


def _load_private_key() -> str:
    """PEM from GATEHOUSE_PRIVATE_KEY, or from GATEHOUSE_PRIVATE_KEY_FILE.

    The file form is the one to use in production (a compose secret, a mounted
    file); the env form exists because it is what a container platform without
    file secrets can offer. `\\n` escaping is accepted because every secret
    manager mangles PEM newlines differently and a silently unusable key is a
    service that fails every scan with an auth error.
    """
    path = os.environ.get("GATEHOUSE_PRIVATE_KEY_FILE", "")
    if path and os.path.exists(path):
        with open(path) as fh:
            return fh.read()
    return os.environ.get("GATEHOUSE_PRIVATE_KEY", "").replace("\\n", "\n")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

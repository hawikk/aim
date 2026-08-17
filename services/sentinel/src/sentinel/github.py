"""GitHub App client for the draft-PR remediation path — a *second* App, on purpose.

Gatehouse already holds a GitHub App, and the obvious cheap move is to add
`contents: write` to it and reuse the credential. That would be a mistake, and
it is the mistake this module exists to avoid.

Gatehouse runs four scanners over other people's pull-request source on a
runner. Its App is `contents: read` so that a scanner escape, a malicious
`.semgrep.yml`, or a crafted dependency lockfile buys the attacker *reading* a
repo they could already read by opening the PR. Sentinel, meanwhile, consumes
the alert bus — an input any of the three pillars can write, and therefore an
input a compromised pillar can shape. Those two blast radii must not be joined
by a shared private key. One poisoned triage input should not reach a repo, and
one scanner escape should not be able to push a commit.

So: separate App, separate private key, separate env vars, and a permission set
(`contents: write`, `pull_requests: write`) that is never granted to gatehouse
and never installed org-wide.

Four narrowing layers, because "the App has two permissions" on its own is not
least privilege:

1. **The App declares two permissions**, justified per permission in
   `docs/sentinel-remediation-github-app.md` §2 and in
   `services/sentinel/app-manifest.yml`.
2. **Per-repo installation**, not org-wide. `installation_for` resolves the
   installation *through the repository*, so a repo the App was never installed
   on returns 404 and the caller degrades — the install itself is half the
   opt-in check (`draftpr.eligibility`).
3. **Every token names one repository** and re-states the two permissions.
   GitHub rejects a scope-down asking for more than the installation holds, so
   this is an assertion the server enforces, not a comment.
4. **Tokens are never persisted.** In-memory, keyed by (installation, repo),
   dropped 5 minutes before GitHub expires them, never logged.

This service still holds zero *cloud* write credentials (D4). A repo write
scope is the single documented exception; see the epic's decision record.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

API_ROOT = os.environ.get("SENTINEL_GITHUB_API", "https://api.github.com")
USER_AGENT = "sentinel/0.1 (+ai-monitoring remediation)"

# Restated on every mint. Deliberately *not* `checks`, `workflows`,
# `administration` or `members`: the only thing this credential may do is put a
# commit on a new branch and open a pull request against it.
TOKEN_PERMISSIONS = {
    "contents": "write",
    "pull_requests": "write",
}


class GitHubError(RuntimeError):
    """Any failure talking to GitHub. Always carries a reason string that is
    safe to put in a Slack message: the token lives in a header, never in a URL,
    and response bodies are truncated."""


class NotInstalled(GitHubError):
    """The App is not installed on this repository.

    A distinct type because it is not an outage — it is the operator half of
    the opt-in never having been done, and the ping says so in those words
    rather than reporting a generic API error.
    """


def app_jwt(app_id: str, private_key: str, *, now: int | None = None) -> str:
    """A 10-minute RS256 JWT identifying the App itself (GitHub's maximum).

    `iat` is backdated 60s: GitHub rejects a token whose `iat` is in the future
    by even a second, and container clocks drift.
    """
    import jwt  # PyJWT

    now = now or int(time.time())
    return jwt.encode({"iat": now - 60, "exp": now + 570, "iss": app_id},
                      private_key, algorithm="RS256")


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
        raise GitHubError(f"{method} {_scrub(url)} -> {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise GitHubError(f"{method} {_scrub(url)} failed: {exc.reason}") from exc
    return json.loads(payload or b"{}")


def _scrub(url: str) -> str:
    """Strip the query string before a URL goes into a log or a Slack message.

    Nothing secret is put in a query today, but `?head=owner:branch` is one
    refactor away from carrying something that is, and an error string from
    this module has a short path to a channel humans read.
    """
    return url.split("?", 1)[0]


class Client:
    """Authenticated GitHub calls for the remediation App.

    `transport` is injectable so every call below is asserted against a recorded
    transport in tests rather than against a live GitHub — the alternative is a
    push path whose only proof is that it did not crash in production.
    """

    def __init__(self, app_id: str = "", private_key: str = "",
                 api_root: str = API_ROOT, transport=None):
        self.app_id = app_id or os.environ.get("SENTINEL_GITHUB_APP_ID", "")
        self.private_key = private_key or load_private_key()
        self.api_root = api_root.rstrip("/")
        self._request = transport or _request
        self._tokens: dict[tuple[int, str], tuple[str, float]] = {}

    @property
    def configured(self) -> bool:
        return bool(self.app_id and self.private_key)

    # ---- auth -------------------------------------------------------------

    def installation_for(self, repo: str) -> int:
        """Installation id for one repo, or raise NotInstalled.

        Resolving *through the repository* rather than listing the App's
        installations is what makes this an authorization check and not just a
        lookup: GitHub answers 404 for a repo the App cannot see, which is the
        same answer it gives for a repo that does not exist. Both mean "not
        eligible", and neither leaks whether the repo is real.
        """
        try:
            payload = self._request("GET", f"{self.api_root}/repos/{repo}/installation",
                                    token=self._app_token())
        except GitHubError as err:
            if " -> 404:" in str(err):
                raise NotInstalled(
                    f"the sentinel remediation App is not installed on {repo}") from err
            raise
        installation_id = int(payload.get("id") or 0)
        if not installation_id:
            raise NotInstalled(f"no installation id returned for {repo}")
        return installation_id

    def installation_token(self, installation_id: int, repo: str) -> str:
        """Mint (or reuse) a token scoped to ONE repo and the two permissions."""
        key = (installation_id, repo)
        cached = self._tokens.get(key)
        if cached and cached[1] > time.time():
            return cached[0]
        payload = self._request(
            "POST", f"{self.api_root}/app/installations/{installation_id}/access_tokens",
            token=self._app_token(),
            body={"repositories": [repo.split("/", 1)[-1]],
                  "permissions": dict(TOKEN_PERMISSIONS)})
        token = payload.get("token")
        if not token:
            raise GitHubError("installation token response carried no token")
        self._tokens[key] = (token, time.time() + 55 * 60)
        return token

    def token_for(self, repo: str) -> str:
        return self.installation_token(self.installation_for(repo), repo)

    def _app_token(self) -> str:
        if not self.configured:
            raise GitHubError(
                "the remediation App credential is not available "
                "(SENTINEL_GITHUB_APP_ID / SENTINEL_GITHUB_PRIVATE_KEY[_FILE])")
        try:
            return app_jwt(self.app_id, self.private_key)
        except Exception as err:  # noqa: BLE001 — PyJWT raises several unrelated types
            raise GitHubError(f"could not sign the App JWT: {type(err).__name__}: {err}") from err

    # ---- reads ------------------------------------------------------------

    def repo_info(self, repo: str, *, token: str) -> dict:
        payload = self._request("GET", f"{self.api_root}/repos/{repo}", token=token)
        return payload if isinstance(payload, dict) else {}

    def ref_sha(self, repo: str, ref: str, *, token: str) -> str:
        payload = self._request(
            "GET", f"{self.api_root}/repos/{repo}/git/ref/{urllib.parse.quote(ref)}", token=token)
        return str(((payload or {}).get("object") or {}).get("sha") or "")

    def get_file(self, repo: str, path: str, ref: str, *, token: str) -> tuple[str, str]:
        """(content, blob_sha) for one file at a ref. Raises on anything that is
        not a plain UTF-8 file — a directory, a submodule or a binary blob is a
        refusal, not something to patch."""
        import base64

        payload = self._request(
            "GET",
            f"{self.api_root}/repos/{repo}/contents/{urllib.parse.quote(path)}"
            f"?ref={urllib.parse.quote(ref)}",
            token=token)
        if not isinstance(payload, dict) or payload.get("type") != "file":
            raise GitHubError(f"{path} is not a regular file in {repo}@{ref}")
        raw = base64.b64decode(payload.get("content") or "")
        try:
            return raw.decode("utf-8"), str(payload.get("sha") or "")
        except UnicodeDecodeError as err:
            raise GitHubError(f"{path} is not UTF-8 text; refusing to patch it") from err

    def pull_request(self, repo: str, number: int, *, token: str) -> dict:
        payload = self._request("GET", f"{self.api_root}/repos/{repo}/pulls/{int(number)}",
                                token=token)
        return payload if isinstance(payload, dict) else {}

    def open_pr_for_branch(self, repo: str, owner: str, branch: str, *, token: str) -> dict:
        """The open PR whose head is `branch`, or {}. Reused rather than
        duplicated: a recurring finding must not open its fifth PR."""
        payload = self._request(
            "GET",
            f"{self.api_root}/repos/{repo}/pulls"
            f"?state=open&head={urllib.parse.quote(f'{owner}:{branch}')}",
            token=token)
        items = payload if isinstance(payload, list) else []
        return items[0] if items else {}

    # ---- writes -----------------------------------------------------------

    def create_branch(self, repo: str, branch: str, sha: str, *, token: str) -> bool:
        """True if created, False if it already existed. Any other failure raises."""
        try:
            self._request("POST", f"{self.api_root}/repos/{repo}/git/refs", token=token,
                          body={"ref": f"refs/heads/{branch}", "sha": sha})
            return True
        except GitHubError as err:
            # 422 "Reference already exists" is the normal re-run path.
            if " -> 422:" in str(err):
                return False
            raise

    def put_file(self, repo: str, path: str, *, token: str, branch: str, content: str,
                 blob_sha: str, message: str) -> str:
        """Commit one file onto `branch`. `blob_sha` makes this a
        compare-and-swap: if the file moved under us since we read it, GitHub
        rejects the write instead of clobbering someone's commit."""
        import base64

        payload = self._request(
            "PUT", f"{self.api_root}/repos/{repo}/contents/{urllib.parse.quote(path)}",
            token=token,
            body={"message": message, "branch": branch, "sha": blob_sha,
                  "content": base64.b64encode(content.encode()).decode()})
        return str(((payload or {}).get("commit") or {}).get("sha") or "")

    def create_pull(self, repo: str, *, token: str, title: str, head: str, base: str,
                    body: str) -> dict:
        """Always `draft: true`. There is no non-draft path in this module, and
        no merge call anywhere in this service — a human opens the PR for
        review and a human merges it."""
        payload = self._request(
            "POST", f"{self.api_root}/repos/{repo}/pulls", token=token,
            body={"title": title, "head": head, "base": base, "body": body, "draft": True})
        return payload if isinstance(payload, dict) else {}

    def add_labels(self, repo: str, number: int, labels: list[str], *, token: str) -> None:
        """Label the PR machine-generated. Best-effort by design: a repo with
        label restrictions must not turn a successfully opened remediation PR
        into a reported failure."""
        self._request("POST", f"{self.api_root}/repos/{repo}/issues/{number}/labels",
                      token=token, body={"labels": labels})


def load_private_key() -> str:
    """PEM from SENTINEL_GITHUB_PRIVATE_KEY_FILE, else SENTINEL_GITHUB_PRIVATE_KEY.

    Deliberately different variable names from gatehouse's. Sharing a name is
    how two services end up sharing a key by accident on a host that runs both,
    which is precisely the coupling this module exists to prevent.
    """
    path = os.environ.get("SENTINEL_GITHUB_PRIVATE_KEY_FILE", "")
    if path and os.path.exists(path):
        with open(path) as fh:
            return fh.read()
    return os.environ.get("SENTINEL_GITHUB_PRIVATE_KEY", "").replace("\\n", "\n")

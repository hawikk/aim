"""The webhook. Small on purpose: this endpoint is internet-facing.

stdlib `ThreadingHTTPServer` rather than a framework. The service has exactly
two routes, and the stack has a 16 GB budget for five pillars (D6) — a web
framework here would buy nothing and add a dependency tree to a process that
clones untrusted repositories.

Request handling order is a security decision, not a style one:

  1. Cap the body size **before** reading it.
  2. Verify the HMAC signature **before** parsing JSON.
  3. Parse, and only then look at anything the sender said.

An attacker who can reach this port and is not holding the webhook secret must
not be able to make gatehouse clone a repo, mint a token, or allocate memory
proportional to their request. Steps 1–3 are what that means concretely.

The scan runs on a worker thread and GitHub gets its 204 immediately: GitHub
times a delivery out at 10 seconds, and a scan is allowed three minutes.
"""

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import bus, checkrun, coverage, orchestrator, suggest, suppress, telemetry
from .cache import Store
from .github import Client, GitHubError, verify_signature
from .models import ScanTarget
from .scanners.base import log
from .workspace import WorkspaceError, ephemeral_checkout

MAX_BODY = 5 * 1024 * 1024
ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}
CHECK_NAME = os.environ.get("GATEHOUSE_CHECK_NAME", "gatehouse")


def default_publisher() -> bus.Publisher | None:
    """Publisher for the webhook path.

    The historical bug: `serve()` constructed `Service()` with `publisher=None`,
    so every real PR scan produced check-run annotations and never touched
    `secstack:alerts:v1`. Live baseline was XLEN=10, all `cloud_posture`, zero
    `pr_security`. Compose always sets `ALERT_BUS_URL` for gatehouse; when it is
    set we publish. Opt out with `GATEHOUSE_PUBLISH_ALERTS=0` for a pure
    check-run install that has no bus.
    """
    if os.environ.get("GATEHOUSE_PUBLISH_ALERTS", "1").lower() in ("0", "false", "no"):
        return None
    if not os.environ.get("ALERT_BUS_URL"):
        return None
    return bus.Publisher()


class Service:
    """Everything the handler needs, injectable for tests."""

    def __init__(self, *, client: Client | None = None, store: Store | None = None,
                 publisher: bus.Publisher | None | object = bus.UNSET, secret: str = ""):
        self.client = client or Client()
        self.store = store if store is not None else Store()
        # UNSET → wire the default when the bus is configured. Explicit None
        # (tests that want "no bus") stays None and is not overridden.
        if publisher is bus.UNSET:
            self.publisher = default_publisher()
        else:
            self.publisher = publisher  # type: ignore[assignment]
        self.secret = secret or os.environ.get("GATEHOUSE_WEBHOOK_SECRET", "")
        # Delivery ids already handled. GitHub retries deliveries, and a retry
        # after a slow-but-successful scan would clone and scan the same commit
        # a second time for no new information.
        #
        # durable claim via Store (SQLite) so a process restart does
        # not forget a completed delivery. In-memory remains a fast path for
        # concurrent threads inside one process; the store is the authority.
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def already_handled(self, delivery_id: str) -> bool:
        if not delivery_id:
            return False
        with self._lock:
            now = time.time()
            for old in [k for k, ts in self._seen.items() if now - ts > 3600]:
                self._seen.pop(old, None)
            if delivery_id in self._seen:
                return True
            # Durable claim first — only one process/thread wins the INSERT.
            if not self.store.claim_delivery(delivery_id, now=int(now)):
                self._seen[delivery_id] = now
                return True
            self._seen[delivery_id] = now
        return False

    # ---- the scan --------------------------------------------------------

    def handle_pull_request(self, payload: dict) -> None:
        """Clone, scan, report. Runs on a worker thread; never raises upward."""
        pr = payload.get("pull_request") or {}
        repo = ((payload.get("repository") or {}).get("full_name") or "")
        installation_id = int(((payload.get("installation") or {}).get("id")) or 0)
        author = ((pr.get("user") or {}).get("login") or "")
        target = ScanTarget(
            repo_full_name=repo,
            pr_number=int(pr.get("number") or 0),
            base_sha=str(((pr.get("base") or {}).get("sha")) or ""),
            head_sha=str(((pr.get("head") or {}).get("sha")) or ""),
            installation_id=installation_id,
            head_ref=str(((pr.get("head") or {}).get("ref")) or ""),
            author_login=str(author),
        )
        check_run_id = 0
        token = ""
        try:
            token = self.client.installation_token(installation_id, repo)
            check_run_id = self.client.create_check_run(
                repo, head_sha=target.head_sha, token=token, name=CHECK_NAME)
        except GitHubError as exc:
            # No token, no check run, no scan. Loud and done — there is nowhere
            # to report to, so pretending to scan would only burn CPU.
            log({"event": "gatehouse.github.auth_failed", "repo": repo,
                 "pr": target.pr_number, "error": str(exc)[:300]})
            # Still record the attempt so coverage can distinguish "never
            # installed" from "installed but auth is broken".
            self._record_gate_run(
                repo, pr=target.pr_number, head_sha=target.head_sha,
                conclusion="neutral", mode="enforce", fail_on="",
                duration_ms=0, error=f"auth_failed: {exc}"[:300])
            return

        try:
            # Read from the BASE branch: a PR must not be able to introduce the
            # vulnerability and the suppression that hides it in one commit.
            config_text = self.client.file_at_ref(
                repo, suppress.CONFIG_NAME,
                str(((pr.get("base") or {}).get("ref")) or "HEAD"), token=token)
            with ephemeral_checkout(repo, pr_number=target.pr_number,
                                    base_sha=target.base_sha, head_sha=target.head_sha,
                                    token=token) as repo_dir:
                result = orchestrator.scan(
                    repo_dir, target, store=self.store, config_text=config_text,
                    publisher=self.publisher, check_run_id=check_run_id)
        except (WorkspaceError, Exception) as exc:  # noqa: BLE001 — reported below
            self._report_failure(repo, check_run_id, token, exc, target=target)
            return
        finally:
            # flush GenAI spans after each PR scan (no-op when unset).
            try:
                telemetry.flush()
            except Exception as flush_exc:  # noqa: BLE001
                log({"event": "gatehouse.telemetry.export_error",
                     "error": f"{type(flush_exc).__name__}: {flush_exc}"[:200]})

        self._report(repo, check_run_id, token, result)

    def _record_gate_run(
        self,
        repo: str,
        *,
        pr: int = 0,
        head_sha: str = "",
        conclusion: str,
        mode: str = "enforce",
        fail_on: str = "",
        duration_ms: int = 0,
        error: str = "",
    ) -> None:
        """Persist one ledger row. Failures here must never break the PR path."""
        try:
            self.store.record_gate_run(
                repo,
                pr=pr,
                head_sha=head_sha,
                conclusion=conclusion,
                mode=mode,
                fail_on=fail_on,
                duration_ms=duration_ms,
                error=error,
            )
        except Exception as exc:  # noqa: BLE001 — ledger is best-effort
            log({"event": "gatehouse.coverage.record_failed", "repo": repo,
                 "error": f"{type(exc).__name__}: {exc}"[:300]})

    def _report(self, repo: str, check_run_id: int, token: str,
                result: orchestrator.ScanResult) -> None:
        suggestions_md = suggest.summary_section(result.suggestions)
        body = checkrun.summary(
            result.findings, suppressed=result.suppressed, errors=result.errors,
            config_problems=result.config_problems, scanned_files=result.scanned_files,
            cached_files=result.cached_files, duration_ms=result.duration_ms,
            ai_stats=result.ai_stats, ai_blocking=result.ai_blocking,
            suggestions_md=suggestions_md)
        try:
            self.client.complete_check_run(
                repo, check_run_id, token=token, conclusion=result.conclusion,
                title=checkrun.title(result.findings, result.errors), summary=body,
                annotations=checkrun.annotations(result.findings), name=CHECK_NAME)
        except GitHubError as exc:
            log({"event": "gatehouse.check.update_failed", "repo": repo,
                 "error": str(exc)[:300]})

        # every completed scan lands in the coverage ledger so a
        # quiet gated repo can alarm as runner_offline rather than looking
        # green from absence.
        self._record_gate_run(
            repo,
            pr=result.target.pr_number,
            head_sha=result.target.head_sha,
            conclusion=result.conclusion,
            mode=coverage.mode_for(result.fail_on),
            fail_on=result.fail_on or "",
            duration_ms=result.duration_ms,
        )

        # The comment is edited when it exists and posted only when there is
        # something to say — but a PR that *was* dirty and is now clean gets its
        # existing comment updated to the all-clear rather than left stale.
        try:
            if checkrun.should_comment(result.findings, result.errors):
                self.client.upsert_comment(
                    repo, result.target.pr_number, token=token,
                    body=checkrun.comment_body(body), marker=checkrun.MARKER)
            elif self.client.find_comment(repo, result.target.pr_number, token=token,
                                          marker=checkrun.MARKER):
                self.client.upsert_comment(
                    repo, result.target.pr_number, token=token,
                    body=checkrun.comment_body(body), marker=checkrun.MARKER)
        except GitHubError as exc:
            log({"event": "gatehouse.comment.failed", "repo": repo,
                 "error": str(exc)[:300]})

        # inline PR review comments on the exact diff line (message +
        # fix hint). Check-run annotations already cover the same lines; leaders
        # still expect a conversation-thread annotation on Files changed, not
        # status-check-only noise. Failures here must not undo the check.
        suggest_comments = suggest.review_comments(result.suggestions)
        suggest_keys = {
            (c.get("path"), int(c.get("line") or 0))
            for c in suggest_comments
            if c.get("path") and c.get("line")
        }
        inline = checkrun.inline_review_comments(
            result.findings,
            scanners=frozenset({"semgrep"}),
            skip_paths_lines=suggest_keys,
        )
        if inline:
            try:
                review_id = self.client.create_inline_review(
                    repo, result.target.pr_number, token=token,
                    commit_id=result.target.head_sha, comments=inline,
                    body=(
                        "### 🛡️ gatehouse SAST findings\n\n"
                        "Inline annotations on the lines this pull request changed. "
                        "Full-repo noise is filtered by diff scope — only new lines."
                    ),
                )
                log({"event": "gatehouse.inline.posted", "repo": repo,
                     "pr": result.target.pr_number, "review_id": review_id,
                     "comments": len(inline)})
            except GitHubError as exc:
                log({"event": "gatehouse.inline.failed", "repo": repo,
                     "error": str(exc)[:300]})

        # advisory review with ```suggestion blocks. Failures here
        # must not undo a successful check — the summary already names the fixes.
        if suggest_comments:
            try:
                review_id = self.client.create_suggestion_review(
                    repo, result.target.pr_number, token=token,
                    commit_id=result.target.head_sha, comments=suggest_comments)
                log({"event": "gatehouse.suggest.posted", "repo": repo,
                     "pr": result.target.pr_number, "review_id": review_id,
                     "comments": len(suggest_comments)})
            except GitHubError as exc:
                log({"event": "gatehouse.suggest.failed", "repo": repo,
                     "error": str(exc)[:300]})

    def _report_failure(self, repo: str, check_run_id: int, token: str,
                        exc: Exception, *, target: ScanTarget | None = None) -> None:
        """A crashed scan is reported as a crashed scan.

        `neutral`, never `success` and never silence: the PR author has to be
        able to tell "gatehouse found nothing" from "gatehouse did not run".
        """
        err = f"{type(exc).__name__}: {exc}"[:300]
        log({"event": "gatehouse.scan.failed", "repo": repo, "error": err})
        self._record_gate_run(
            repo,
            pr=(target.pr_number if target else 0),
            head_sha=(target.head_sha if target else ""),
            conclusion="neutral",
            mode="enforce",
            fail_on="",
            duration_ms=0,
            error=err,
        )
        if not check_run_id:
            return
        try:
            self.client.complete_check_run(
                repo, check_run_id, token=token, conclusion="neutral",
                title="Scan did not complete",
                summary=("> [!WARNING]\n> gatehouse could not complete this scan: "
                         f"`{checkrun.md(str(exc), 300)}`.\n> This is **not** a clean "
                         "result — nothing was verified. Re-run the check or contact "
                         "the security team."),
                annotations=[], name=CHECK_NAME)
        except GitHubError:
            pass


def make_handler(service: Service):
    class Handler(BaseHTTPRequestHandler):
        server_version = "gatehouse"
        sys_version = ""  # do not advertise the Python version

        def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler's API
            # Strip query string; coverage is unauthenticated on the internal
            # network (compose binds 127.0.0.1). aim-api is the only consumer
            # and is itself role-gated (analyst+).
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                self._send(200, {"ok": True})
            elif path == "/coverage/repos":
                # forge-enumerated gated-vs-dark ledger. Hits GitHub
                # App APIs; keep the timeout budget honest by doing the work
                # inline (aim-api already times out at 5s and surfaces error).
                try:
                    report = coverage.coverage_report(
                        store=service.store, client=service.client)
                    self._send(200, report)
                except Exception as exc:  # noqa: BLE001 — never 500-crash the process
                    log({"event": "gatehouse.coverage.failed",
                         "error": f"{type(exc).__name__}: {exc}"[:300]})
                    self._send(500, {
                        "state": "error",
                        "error": f"{type(exc).__name__}: {exc}"[:300],
                        "repos_known": None,
                        "repos_covered": None,
                        "repos_dark": None,
                    })
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if self.path not in ("/webhook", "/"):
                return self._send(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                return self._send(413, {"error": "body missing or too large"})
            body = self.rfile.read(length)
            if not verify_signature(body, self.headers.get("X-Hub-Signature-256", ""),
                                    service.secret):
                # Deliberately uninformative: a probe learns only that it failed.
                return self._send(401, {"error": "bad signature"})
            event = self.headers.get("X-GitHub-Event", "")
            delivery = self.headers.get("X-GitHub-Delivery", "")
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                return self._send(400, {"error": "bad json"})
            if event == "ping":
                return self._send(200, {"pong": True})
            if event != "pull_request" or payload.get("action") not in ACTIONS:
                return self._send(204, None)
            if service.already_handled(delivery):
                return self._send(200, {"duplicate": True})
            self._send(202, {"accepted": True})
            threading.Thread(target=service.handle_pull_request, args=(payload,),
                             daemon=True).start()

        def _send(self, code: int, payload: dict | None):
            data = json.dumps(payload).encode() if payload is not None else b""
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if data:
                self.wfile.write(data)

        def log_message(self, fmt, *args):
            log({"event": "gatehouse.http", "message": fmt % args})

    return Handler


def serve(port: int = 8090, service: Service | None = None) -> None:
    service = service or Service()
    if not service.secret:
        raise SystemExit("GATEHOUSE_WEBHOOK_SECRET is required — refusing to accept "
                         "unauthenticated webhooks")
    telemetry.configure()
    httpd = ThreadingHTTPServer(("0.0.0.0", port), make_handler(service))
    log({
        "event": "gatehouse.listening",
        "port": port,
        # Loud on boot so "zero pr_security on the bus" is diagnosable without
        # waiting for a PR: publisher=null means ALERT_BUS_URL is unset or
        # GATEHOUSE_PUBLISH_ALERTS disabled — not a silent wiring miss.
        "publisher": "enabled" if service.publisher is not None else "disabled",
        "alert_bus_url_set": bool(os.environ.get("ALERT_BUS_URL")),
        "otel_genai": "enabled" if telemetry.enabled() else "disabled",
    })
    httpd.serve_forever()

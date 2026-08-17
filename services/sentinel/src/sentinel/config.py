"""Sentinel configuration — sentinel.yml plus env, with secrets only in env.

Shape mirrors the launcher's ``stack.yaml`` (``notifications.slack_webhook:
env:SLACK_WEBHOOK_URL``): a committable file that says *what* is on, and env
that carries *credentials*. A webhook URL is a bearer credential — anyone
holding it can post as the app — so the ``env:NAME`` indirection is the only
supported way to supply one, and a literal ``https://…`` in the YAML is a
config error rather than a convenience.

Two settings are load-bearing for the acceptance criteria and are therefore
validated here rather than at first use:

* ``page_from`` — the severity at which a human is interrupted. Everything
  below it rolls into the daily digest. Security owns this number; this file
  ships the proposal (high).
* ``remediation.draft_pr`` — off by default (board answer Q7). Turning it on
  requires *both* halves of the opt-in to be present at startup: the
  separately-scoped GitHub App credential, and a non-empty per-repo allowlist.
  Enabling the flag without either of those fails startup with a pointer,
  because the alternative — accept the flag and keep sending copy-paste-only
  proposals — is the silent-drop shape the whole stack is built to avoid.

  Note the deliberate asymmetry with runtime: a *missing* credential at startup
  is a configuration error and refuses to boot, while a credential that stops
  working later degrades to a copy-paste ping carrying an explicit "the PR could
  not be opened" line. The first is a human's mistake, caught before it can
  mislead anyone; the second is the world changing under a running service, and
  losing the page over it would be far worse than losing the PR.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace
from typing import Any

SEVERITIES = ("informational", "low", "medium", "high", "critical")
SEVERITY_ORDER = {name: i for i, name in enumerate(SEVERITIES)}

DEFAULT_STREAM = "secstack:alerts:v1"
ENV_REF = re.compile(r"^env:([A-Z][A-Z0-9_]*)$")


class ConfigError(Exception):
    """Raised for a configuration a human must fix before the service runs."""


@dataclass(frozen=True)
class Channel:
    """One notification destination."""

    kind: str                 # slack | webhook | email
    name: str
    target: str               # URL, or "to" address for email
    enabled: bool = True
    # Generic webhooks are signed with HMAC-SHA256 over the exact body bytes,
    # matching the guardrail notifier's X-AIM-Signature scheme so a receiver
    # already verifying AIM alerts needs no second code path.
    secret: str = ""
    # SMTP settings, email only.
    smtp_host: str = ""
    smtp_port: int = 25
    smtp_from: str = ""


@dataclass(frozen=True)
class LLMConfig:
    """Where triage reasoning comes from.

    ``endpoint`` is an OpenAI-compatible /chat/completions URL by default so a
    self-hosted vLLM/Ollama/LiteLLM box works with no code change (D5: the
    LLM hop is configurable and self-hostable, and it is documented as a trust
    boundary). ``anthropic`` speaks the Messages API instead.

    ``timeout_seconds`` is small on purpose. The 2-minute ping bar is the
    product promise; a hung LLM must cost seconds and degrade, not minutes and
    silence.
    """

    enabled: bool = True
    flavor: str = "openai"     # openai | anthropic
    endpoint: str = ""
    model: str = "claude-sonnet-5"
    api_key: str = ""
    timeout_seconds: float = 20.0
    max_output_tokens: int = 700


@dataclass(frozen=True)
class DraftPRConfig:
    """Opt-in, off by default, per repo (board answer Q7; AIM-185).

    ``repos`` is the half of the opt-in that lives in git. The other half — the
    App actually being installed on the repo — lives in GitHub and is checked at
    run time, because a repo admin can revoke it without touching this file.
    Requiring both means neither a config edit nor an install alone can start
    writing to a repository.
    """

    enabled: bool = False
    repos: tuple[str, ...] = ()
    app_id: str = ""
    private_key: str = ""

    @property
    def repo_set(self) -> frozenset[str]:
        """Lower-cased, because GitHub owner/repo comparison is case-insensitive
        and an allowlist that misses on `Hawikk/ai-monitoring` would fail open in
        the confusing direction: a repo the operator listed reads as not opted in."""
        return frozenset(r.lower() for r in self.repos)


@dataclass(frozen=True)
class Config:
    bus_url: str = "redis://redis-bus:6379/0"
    stream_key: str = DEFAULT_STREAM
    state_db: str = "/var/lib/sentinel/state.db"
    poll_interval_seconds: float = 2.0
    # Read cap per poll. Bounds memory and keeps one backlog burst from
    # blocking the loop for minutes on a 4-vCPU VM (D6).
    batch_size: int = 200

    page_from: str = "high"
    # Two alerts that share a correlation key inside this window collapse to
    # one parent incident with child links (AIM-700). Wide enough to swallow a
    # Terraform apply that turns 40 resources public, or the same secret
    # pattern across Claude Code and Cursor for two engineers; short enough
    # that tomorrow's recurrence pages again. Configurable via
    # sentinel.burst_window_seconds.
    burst_window_seconds: int = 900
    # An incident that already paged does not page again for this long, unless
    # its severity escalates. Precision over noise.
    renotify_cooldown_seconds: int = 3600
    # Fields whose values, taken together, identify one root cause. Order is
    # irrelevant; missing fields are treated as empty. Default intentionally
    # omits tool and user so findings correlate across tools and users; add
    # labels.tool or subject_ref.user_ref only when paging per-tool/per-user.
    correlate_on: tuple[str, ...] = ("pillar", "finding_type", "resource.account_ref")

    digest_hour_utc: int = 8
    # A failed digest is retried with exponential backoff from this base,
    # doubling per failure up to the max — not on every poll pass. Before
    # AIM-250 a misconfigured deployment (no channel) logged a
    # `degraded: delivery_failed` decision every ~2s, ~12k/day, drowning the
    # audit trail.
    digest_retry_base_seconds: float = 60.0
    digest_retry_max_seconds: float = 3600.0
    # Daily cap on digest delivery attempts. Reaching it gives up until the
    # next day (the queue is retained, not dropped) so a channel that stays
    # broken stops generating decision rows entirely.
    digest_retry_daily_cap: int = 12
    # A bus we have not been able to read for this long is itself an incident:
    # the operator is told the stack has gone quiet rather than reading silence
    # as "nothing is wrong".
    bus_stall_alert_seconds: int = 300

    channels: tuple[Channel, ...] = ()
    llm: LLMConfig = field(default_factory=LLMConfig)
    # Base for evidence links: `pillar:/path` refs from the bus are resolved
    # against this at render time (D3.1 §3.4 — the alert carries a relative
    # ref; only the renderer knows the deployment's hostname).
    gateway_base_url: str = "https://localhost:8443"
    draft_pr: DraftPRConfig = field(default_factory=DraftPRConfig)

    def pages(self, severity: str) -> bool:
        return SEVERITY_ORDER.get(severity, -1) >= SEVERITY_ORDER[self.page_from]


def _resolve(value: Any, *, env: dict[str, str], where: str) -> str:
    """`env:NAME` -> the env var. A literal secret in YAML is rejected."""
    if value in (None, ""):
        return ""
    text = str(value)
    match = ENV_REF.match(text)
    if match:
        return env.get(match.group(1), "")
    if text.startswith(("http://", "https://")) and "webhook" in where:
        raise ConfigError(
            f"{where}: webhook URLs are credentials and must not be committed. "
            f"Use env:NAME and put the value in .env")
    return text


def _channels_from(doc: dict, env: dict[str, str]) -> tuple[Channel, ...]:
    out: list[Channel] = []
    notif = doc.get("notifications") or {}

    slack = notif.get("slack_webhook")
    if slack:
        url = _resolve(slack, env=env, where="notifications.slack_webhook")
        # An enabled-but-unresolved channel is the dangerous state: the operator
        # believes Slack is wired and the service quietly posts nowhere. Keep it
        # in the list, disabled, so health and startup logs can name it.
        out.append(Channel(kind="slack", name="slack", target=url, enabled=bool(url)))

    for i, hook in enumerate(notif.get("webhooks") or []):
        url = _resolve(hook.get("url"), env=env, where=f"notifications.webhooks[{i}].url")
        out.append(Channel(
            kind="webhook",
            name=str(hook.get("name") or f"webhook-{i}"),
            target=url,
            enabled=bool(url) and hook.get("enabled", True),
            secret=_resolve(hook.get("secret"), env=env, where=f"notifications.webhooks[{i}].secret"),
        ))

    email = notif.get("email") or {}
    if email.get("to"):
        out.append(Channel(
            kind="email",
            name="email",
            target=str(email["to"]),
            enabled=bool(email.get("enabled", True) and email.get("smtp_host")),
            smtp_host=str(email.get("smtp_host") or ""),
            smtp_port=int(email.get("smtp_port") or 25),
            smtp_from=str(email.get("from") or "sentinel@localhost"),
        ))
    return tuple(out)


_REPO = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")


def _draft_pr_from(block: dict, env: dict[str, str]) -> DraftPRConfig:
    """The allowlist comes from YAML; the App credential only ever from env.

    A private key is the strongest secret this service can hold — it mints
    tokens that can push to a repo — so it gets the same treatment as a webhook
    URL, one level stricter: there is no YAML key for it at all, not even an
    ``env:NAME`` indirection, so there is no shape of config file that can leak
    it into git.
    """
    repos = []
    for entry in block.get("repos") or []:
        name = str(entry).strip()
        if not _REPO.match(name):
            raise ConfigError(
                f"remediation.draft_pr.repos: {name!r} is not an owner/repo name. "
                f"List full names, e.g. hawikk/aim — a bare repo name or a URL "
                f"would silently never match anything on the bus.")
        repos.append(name)
    return DraftPRConfig(
        enabled=bool(block.get("enabled", False)),
        repos=tuple(repos),
        app_id=env.get("SENTINEL_GITHUB_APP_ID", ""),
        private_key=_key_from(env),
    )


def _key_from(env: dict[str, str]) -> str:
    """Mirrors github.load_private_key, but reads the caller's env mapping so a
    test can exercise the real precedence without mutating os.environ."""
    path = env.get("SENTINEL_GITHUB_PRIVATE_KEY_FILE", "")
    if path and os.path.exists(path):
        with open(path) as fh:
            return fh.read()
    return env.get("SENTINEL_GITHUB_PRIVATE_KEY", "").replace("\\n", "\n")


def load(path: str | None = None, env: dict[str, str] | None = None) -> Config:
    """Read sentinel.yml (optional) and overlay env. Env always wins."""
    env = dict(os.environ if env is None else env)
    doc: dict = {}
    path = path or env.get("SENTINEL_CONFIG") or ""
    if path and os.path.exists(path):
        import yaml
        with open(path) as fh:
            doc = yaml.safe_load(fh) or {}
    elif path:
        raise ConfigError(f"config file not found: {path}")

    sentinel = doc.get("sentinel") or {}
    triage = sentinel.get("triage") or {}
    remediation = sentinel.get("remediation") or {}

    llm = LLMConfig(
        enabled=bool(triage.get("enabled", True)),
        flavor=str(triage.get("flavor") or env.get("SENTINEL_LLM_FLAVOR") or "openai"),
        endpoint=str(triage.get("endpoint") or env.get("SENTINEL_LLM_ENDPOINT") or ""),
        model=str(triage.get("model") or env.get("SENTINEL_LLM_MODEL") or "claude-sonnet-5"),
        api_key=env.get("SENTINEL_LLM_API_KEY", ""),
        timeout_seconds=float(triage.get("timeout_seconds") or env.get("SENTINEL_LLM_TIMEOUT") or 20.0),
    )

    cfg = Config(
        bus_url=env.get("ALERT_BUS_URL") or str(sentinel.get("bus_url") or Config.bus_url),
        stream_key=env.get("ALERT_BUS_STREAM") or str(sentinel.get("stream_key") or DEFAULT_STREAM),
        state_db=env.get("SENTINEL_STATE_DB") or str(sentinel.get("state_db") or Config.state_db),
        poll_interval_seconds=float(sentinel.get("poll_interval_seconds")
                                    or Config.poll_interval_seconds),
        batch_size=int(sentinel.get("batch_size") or Config.batch_size),
        bus_stall_alert_seconds=int(sentinel.get("bus_stall_alert_seconds",
                                                 Config.bus_stall_alert_seconds)),
        page_from=str(env.get("SENTINEL_PAGE_FROM") or sentinel.get("page_from") or Config.page_from),
        burst_window_seconds=int(sentinel.get("burst_window_seconds") or Config.burst_window_seconds),
        renotify_cooldown_seconds=int(
            sentinel.get("renotify_cooldown_seconds") or Config.renotify_cooldown_seconds),
        correlate_on=tuple(sentinel.get("correlate_on") or Config.correlate_on),
        digest_hour_utc=int(sentinel.get("digest_hour_utc", Config.digest_hour_utc)),
        digest_retry_base_seconds=float(sentinel.get("digest_retry_base_seconds")
                                        or Config.digest_retry_base_seconds),
        digest_retry_max_seconds=float(sentinel.get("digest_retry_max_seconds")
                                       or Config.digest_retry_max_seconds),
        digest_retry_daily_cap=int(sentinel.get("digest_retry_daily_cap")
                                   or Config.digest_retry_daily_cap),
        channels=_channels_from(doc, env),
        llm=llm,
        gateway_base_url=(env.get("SENTINEL_GATEWAY_URL")
                          or str(sentinel.get("gateway_base_url") or Config.gateway_base_url)).rstrip("/"),
        draft_pr=_draft_pr_from(remediation.get("draft_pr") or {}, env),
    )
    validate(cfg)
    return cfg


def validate(cfg: Config) -> None:
    if cfg.page_from not in SEVERITY_ORDER:
        raise ConfigError(f"page_from must be one of {SEVERITIES}, got {cfg.page_from!r}")
    if not 0 <= cfg.digest_hour_utc <= 23:
        raise ConfigError(f"digest_hour_utc must be 0-23, got {cfg.digest_hour_utc}")
    if cfg.digest_retry_base_seconds <= 0 or cfg.digest_retry_max_seconds < cfg.digest_retry_base_seconds:
        raise ConfigError(
            f"digest retry backoff must satisfy 0 < base <= max, got "
            f"base={cfg.digest_retry_base_seconds} max={cfg.digest_retry_max_seconds}")
    if cfg.digest_retry_daily_cap < 1:
        raise ConfigError(f"digest_retry_daily_cap must be >= 1, got {cfg.digest_retry_daily_cap}")
    if cfg.draft_pr.enabled:
        # Both halves are required before the service will claim it can open a
        # PR. Refusing to start is the honest failure; accepting the flag and
        # sending copy-paste-only proposals would leave the operator believing
        # PRs are being opened with no error anywhere.
        if not cfg.draft_pr.repos:
            raise ConfigError(
                "remediation.draft_pr.enabled is true but remediation.draft_pr.repos is empty. "
                "Draft PRs are opt-in per repository — with no repos listed, nothing would ever "
                "be opened and the flag would be a lie. List the repos or set enabled: false.")
        if not cfg.draft_pr.app_id or not cfg.draft_pr.private_key:
            raise ConfigError(
                "remediation.draft_pr.enabled is true but the remediation GitHub App credential "
                "is missing. Set SENTINEL_GITHUB_APP_ID and SENTINEL_GITHUB_PRIVATE_KEY_FILE "
                "(or SENTINEL_GITHUB_PRIVATE_KEY) in .env. This App is separate from "
                "gatehouse's on purpose — see docs/sentinel-remediation-github-app.md; do not "
                "point it at GATEHOUSE_* values.")
    for ch in cfg.channels:
        if ch.enabled and not ch.target:
            raise ConfigError(f"notification channel {ch.name!r} is enabled but has no target")
    if cfg.llm.enabled and not cfg.llm.endpoint:
        # Not fatal: no endpoint is a supported deployment (pass-through mode).
        # It must be visible, though, because "no explanation in the ping" would
        # otherwise look like an LLM bug rather than a missing setting.
        pass


def with_channels(cfg: Config, channels: tuple[Channel, ...]) -> Config:
    return replace(cfg, channels=channels)

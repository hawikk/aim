"""`.gatehouse.yml` — per-repo false-positive suppression.

The design constraint that shapes everything here: **a suppression must not be
able to make a finding disappear.** A suppressed finding is still counted, still
listed in the check summary, and still published to the alert bus with
`status: suppressed`. It stops *blocking the PR*; it does not stop existing.
Security keeps visibility into what teams are muting and why, which is the only
version of this feature that is safe to hand to 700 engineers.

Three rules follow from that:

1. **`reason` is required.** A suppression without one is refused and reported
   on the check. Unexplained suppressions are how a gate quietly rots.
2. **`expires` is honoured.** An expired entry stops applying and is reported,
   so "temporary" suppressions cannot become permanent by inattention.
3. **The file is untrusted input.** It comes from the PR's own branch, so it is
   parsed with `yaml.safe_load`, capped, and every path pattern is rejected if
   it escapes the repo root. A suppression file that could match `../` would
   let a PR mute findings in other repos on the same runner.

Note the ordering consequence: gatehouse reads `.gatehouse.yml` **from the base
branch**, not from the PR head. Reading it from the head would let a PR that
introduces a vulnerability also introduce the suppression that hides it, in the
same commit, and pass its own gate.
"""

from __future__ import annotations

import datetime
import fnmatch
from dataclasses import dataclass, field

import yaml

from .models import Finding

CONFIG_NAME = ".gatehouse.yml"
MAX_RULES = 200


@dataclass
class Suppression:
    rule: str
    path: str = "**"
    reason: str = ""
    expires: str = ""

    def matches(self, finding: Finding) -> bool:
        if not _rule_matches(self.rule, finding):
            return False
        return fnmatch.fnmatch(finding.path, self.path) or fnmatch.fnmatch(
            finding.path, self.path.rstrip("/") + "/**")

    def expired(self, today: datetime.date) -> bool:
        if not self.expires:
            return False
        try:
            return datetime.date.fromisoformat(str(self.expires)) < today
        except ValueError:
            # An unparseable date is treated as expired. Failing open would
            # make `expires: soon` a permanent suppression.
            return True


_VALID_BLOCK_ON = ("critical", "high", "medium", "low", "informational")


@dataclass
class Config:
    suppressions: list[Suppression] = field(default_factory=list)
    disabled_scanners: list[str] = field(default_factory=list)
    # `ai_review:` (AIM-162). None = no opinion (the environment decides);
    # False = this repo opts the AI reviewer out entirely. `ai_blocking` is the
    # one way AI findings may fail a check, and it is opt-in per repo.
    ai_enabled: bool | None = None
    ai_blocking: bool = False
    # `suggested_fixes:` (AIM-234). Default on — a repo opts out explicitly.
    # Draft-PR routing still requires the service-level allowlist (AIM-185 gate);
    # this flag only controls whether gatehouse posts ```suggestion comments.
    suggest_enabled: bool = True
    # `enforcement.block_on` (AIM-298). Per-repo severity threshold for which
    # findings fail the check. None = use service default (`GATEHOUSE_FAIL_ON`).
    # Security owns the value; engineering owns the mechanism.
    block_on: str | None = None
    # Problems with the file itself, surfaced on the check run so a broken
    # config is visible to the person who broke it rather than to a log.
    problems: list[str] = field(default_factory=list)


def _rule_matches(pattern: str, finding: Finding) -> bool:
    """A rule pattern may name the scanner rule id, the CVE, or the finding type.

    Glob rather than equality, so `CKV_AWS_*` and `gitleaks:*` both work — but
    a bare `*` is refused at parse time (see `parse`): "suppress everything" is
    a decision that belongs in a conversation, not in a YAML file.
    """
    return any(fnmatch.fnmatch(value, pattern)
               for value in (finding.rule_id, finding.finding_type,
                             f"{finding.scanner}:{finding.rule_id}"))


def parse(text: str) -> Config:
    """Parse `.gatehouse.yml`. Never raises — a broken file must not break scans."""
    config = Config()
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        config.problems.append(f"{CONFIG_NAME} is not valid YAML: {str(exc)[:160]}")
        return config
    if not isinstance(raw, dict):
        config.problems.append(f"{CONFIG_NAME} must be a mapping")
        return config

    scanners = raw.get("scanners")
    if isinstance(scanners, dict):
        config.disabled_scanners = [
            str(name) for name, on in scanners.items() if on is False]

    ai = raw.get("ai_review")
    if ai is not None:
        if not isinstance(ai, dict):
            config.problems.append("`ai_review` must be a mapping")
        else:
            for key in ai:
                if key not in ("enabled", "blocking"):
                    config.problems.append(f"`ai_review.{key}` is not a known key")
            if "enabled" in ai:
                if isinstance(ai["enabled"], bool):
                    config.ai_enabled = ai["enabled"]
                else:
                    config.problems.append("`ai_review.enabled` must be true or false")
            if "blocking" in ai:
                if isinstance(ai["blocking"], bool):
                    config.ai_blocking = ai["blocking"]
                else:
                    config.problems.append("`ai_review.blocking` must be true or false")

    suggest = raw.get("suggested_fixes")
    if suggest is not None:
        if not isinstance(suggest, dict):
            config.problems.append("`suggested_fixes` must be a mapping")
        else:
            for key in suggest:
                if key not in ("enabled",):
                    config.problems.append(f"`suggested_fixes.{key}` is not a known key")
            if "enabled" in suggest:
                if isinstance(suggest["enabled"], bool):
                    config.suggest_enabled = suggest["enabled"]
                else:
                    config.problems.append("`suggested_fixes.enabled` must be true or false")

    # AIM-298: per-repo blocking threshold. Service default remains
    # GATEHOUSE_FAIL_ON; this only overrides when the base-branch config says so.
    enforcement = raw.get("enforcement")
    if enforcement is not None:
        if not isinstance(enforcement, dict):
            config.problems.append("`enforcement` must be a mapping")
        else:
            for key in enforcement:
                if key not in ("block_on",):
                    config.problems.append(f"`enforcement.{key}` is not a known key")
            if "block_on" in enforcement:
                value = enforcement["block_on"]
                if isinstance(value, str) and value in _VALID_BLOCK_ON:
                    config.block_on = value
                else:
                    config.problems.append(
                        "`enforcement.block_on` must be one of "
                        + ", ".join(_VALID_BLOCK_ON)
                    )

    entries = raw.get("suppressions") or []
    if not isinstance(entries, list):
        config.problems.append("`suppressions` must be a list")
        entries = []
    if len(entries) > MAX_RULES:
        config.problems.append(
            f"{len(entries)} suppressions exceeds the {MAX_RULES} cap; extra entries ignored")
        entries = entries[:MAX_RULES]

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            config.problems.append(f"suppression #{index + 1} is not a mapping")
            continue
        rule = str(entry.get("rule") or "").strip()
        path = str(entry.get("path") or "**").strip()
        reason = str(entry.get("reason") or "").strip()
        if not rule:
            config.problems.append(f"suppression #{index + 1} has no `rule`")
            continue
        if rule == "*" or path.startswith("/") or ".." in path:
            config.problems.append(
                f"suppression #{index + 1} (`{rule}`) refused: a bare `*` rule or a path "
                "outside the repo is not allowed")
            continue
        if not reason:
            config.problems.append(
                f"suppression #{index + 1} (`{rule}`) refused: `reason` is required")
            continue
        config.suppressions.append(Suppression(
            rule=rule, path=path, reason=reason[:300],
            expires=str(entry.get("expires") or "").strip()))
    return config


def apply(findings: list[Finding], config: Config,
          today: datetime.date | None = None) -> tuple[list[Finding], list[tuple[Finding, str]]]:
    """Split findings into (blocking, suppressed-with-reason).

    Nothing is discarded. The second list is what makes a suppression visible
    on the check run and on the bus.
    """
    today = today or datetime.date.today()
    live = [s for s in config.suppressions if not s.expired(today)]
    for stale in (s for s in config.suppressions if s.expired(today)):
        config.problems.append(
            f"suppression `{stale.rule}` expired on {stale.expires} and no longer applies")

    blocking: list[Finding] = []
    suppressed: list[tuple[Finding, str]] = []
    for finding in findings:
        match = next((s for s in live if s.matches(finding)), None)
        if match:
            suppressed.append((finding, match.reason))
        else:
            blocking.append(finding)
    return blocking, suppressed

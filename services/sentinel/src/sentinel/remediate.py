"""Turn an incident into a remediation *proposal* a human can paste.

Precedence, and the reasoning behind it (D4: the agent never applies anything,
and every command it prints is a command a human will run with far more
privilege than this service has):

1. **The curated catalogue** (``catalogue/remediation.yml``). Reviewed, in git,
   diffable. This is the only source allowed to produce a command.
2. **The publisher's own ``remediation_hint``.** The pillar that raised the
   finding often knows the fix better than a generic catalogue does — Trivy
   knows the fixed version, gatehouse knows the rule. Rendered as prose, and
   labelled with its source.
3. **Nothing.** Rendered as an explicit "no vetted remediation for this finding
   type", with the finding type printed so an operator can add one.

The LLM is deliberately absent from this list. It writes the explanation and
the blast-radius assessment (``triage.py``); it does not write commands. A
hallucinated flag in a real ``aws`` invocation is not a quality problem, it is
an incident of its own — and the whole value of "copy-paste, human applies" is
that the human is reviewing something a human wrote.

The same precedence carries into the draft-PR path (AIM-185). An entry may
additionally carry a ``patch:`` block, which is a *reviewed transformation* —
"set this attribute to this literal on this kind of block" — that ``patch.py``
applies to the flagged file. The model may cause an entry to be selected and
its placeholders filled; it may not author a diff, and there is nowhere in the
code for it to try.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from .patch import PatchSpec

CATALOGUE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "catalogue", "remediation.yml")

# Newlines, tabs and other control characters in a publisher-supplied value.
# See `_placeholder_value` for why a newline in particular is the dangerous one.
_UNSAFE_VALUE = re.compile(r"[\x00-\x1f\x7f]")


class CatalogueUnavailable(Exception):
    """The catalogue file is missing or unparseable — pings would go out with
    no fix in them. Loud at startup rather than empty at 02:00."""


# autofix_mode values (AIM-330):
#   patch   — catalogue may open a draft PR carrying a reviewed diff
#   guided  — post rotate/purge guidance only; NEVER open a history-rewriting
#             or secret-stripping PR without explicit human approval
#   none    — no autofix path (same as absent)
AUTOFIX_PATCH = "patch"
AUTOFIX_GUIDED = "guided"


@dataclass(frozen=True)
class Proposal:
    source: str                 # catalogue | publisher_hint | none
    title: str
    explanation: str = ""
    cli: str = ""
    terraform: str = ""
    console: str = ""
    docs: str = ""
    caution: str = ""
    entry_id: str = ""
    # Present only when the entry carries a reviewed `patch:` block. `None` is
    # the common case and means "copy-paste only" — the draft-PR path renders
    # that as an explicit sentence rather than opening nothing quietly.
    patch: PatchSpec | None = None
    # AIM-330: how far autofix is allowed to go for this finding class.
    autofix_mode: str = AUTOFIX_PATCH

    @property
    def has_snippet(self) -> bool:
        return bool(self.cli or self.terraform)

    @property
    def allows_draft_pr(self) -> bool:
        """Secrets and other guided-only classes never get an autofix PR."""
        return self.autofix_mode != AUTOFIX_GUIDED and self.patch is not None


@dataclass
class Catalogue:
    entries: list[dict] = field(default_factory=list)
    _compiled: list[tuple[Any, dict[str, Any], dict]] = field(default_factory=list)

    @classmethod
    def load(cls, path: str = CATALOGUE_PATH) -> "Catalogue":
        import yaml
        try:
            with open(path) as fh:
                doc = yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError) as err:
            raise CatalogueUnavailable(f"remediation catalogue unreadable at {path}: {err}") from err
        entries = doc.get("entries") or []
        if not entries:
            raise CatalogueUnavailable(f"remediation catalogue at {path} has no entries")
        cat = cls(entries=entries)
        for entry in entries:
            entry_id = entry.get("id", "?")
            try:
                pattern = re.compile(f"^(?:{entry['finding_type']})$")
            except (KeyError, re.error) as err:
                raise CatalogueUnavailable(
                    f"catalogue entry {entry_id}: bad finding_type pattern: {err}") from err
            try:
                label_patterns = {
                    str(k): re.compile(f"^(?:{v})$")
                    for k, v in ((entry.get("when") or {}).get("labels") or {}).items()}
            except re.error as err:
                raise CatalogueUnavailable(
                    f"catalogue entry {entry_id}: bad when.labels pattern: {err}") from err
            if entry.get("patch"):
                # Parsed at load, not at first use: a malformed patch spec must
                # fail the build and the startup, not the one 02:00 page that
                # would have used it.
                try:
                    PatchSpec.parse(entry["patch"], entry_id=str(entry_id))
                except ValueError as err:
                    raise CatalogueUnavailable(str(err)) from err
            cat._compiled.append((pattern, label_patterns, entry))
        return cat

    def match(self, finding_type: str, labels: dict | None = None) -> dict | None:
        """First entry whose finding_type matches and whose `when.labels` all match.

        `labels` is publisher-controlled, so it can only *select* one reviewed
        entry over another — never introduce content. The damage a wrong
        selection could do is bounded again downstream: a patch names the block
        types it applies to, so an entry steered onto the wrong finding refuses
        rather than editing whatever is at the flagged line.
        """
        labels = labels or {}
        for pattern, label_patterns, entry in self._compiled:
            if not pattern.match(finding_type or ""):
                continue
            if all(match.match(str(labels.get(key, ""))) for key, match in label_patterns.items()):
                return entry
        return None


def _placeholder_value(raw: object, key: str) -> str:
    """One substituted value, made safe to splice into a reviewed template.

    The template is reviewed; the value is not. It comes from ``resource`` on a
    bus alert, and the contract constrains only its *length* — a newline in
    ``resource.display`` validates fine at both ends. That matters more here
    than anywhere else in the renderer, because these templates include the
    copy-paste ``cli`` block, and the ping tells a human to paste it into a
    terminal holding cloud admin credentials. A value carrying

        acme-logs\\naws iam create-access-key --user-name admin

    would turn a one-line remediation into two commands, the second of which
    the operator never read and no human ever wrote. That is the exact inverse
    of the rule this module is built on.

    So: newlines and control characters collapse to a space, and the result is
    length-capped. Deliberately *not* shell-quoted — quoting would imply this
    output is safe to execute unreviewed, and it never is. Neutralising the
    line break is what stops one command from silently becoming two; a human
    still reads the line before running it.
    """
    if raw is None or raw == "":
        return f"<unknown-{key}>"
    return _UNSAFE_VALUE.sub(" ", str(raw))[:200]


def _fill(template: str, alert: dict) -> str:
    """Substitute placeholders; an absent value renders visibly, not emptily."""
    resource = alert.get("resource") or {}
    values = {
        "resource_ref": resource.get("ref"),
        "resource_display": resource.get("display"),
        "region": resource.get("region"),
        "account_ref": resource.get("account_ref"),
        "provider": resource.get("provider"),
    }
    out = template
    for key, value in values.items():
        out = out.replace("{" + key + "}", _placeholder_value(value, key))
    return out


def _autofix_mode(entry: dict) -> str:
    """Normalise catalogue autofix_mode. Default is patch when a patch exists."""
    raw = str(entry.get("autofix_mode") or "").strip().lower()
    if raw in (AUTOFIX_GUIDED, AUTOFIX_PATCH, "none"):
        return raw
    if entry.get("patch"):
        return AUTOFIX_PATCH
    return "none"


def propose(alert: dict, catalogue: Catalogue) -> Proposal:
    entry = catalogue.match(alert.get("finding_type", ""), alert.get("labels") or {})
    if entry:
        mode = _autofix_mode(entry)
        # Guided-only entries must never carry a patch block into the opener —
        # even if a future catalogue author adds one by mistake.
        patch = None
        if mode != AUTOFIX_GUIDED and entry.get("patch"):
            patch = PatchSpec.parse(entry["patch"], entry_id=str(entry.get("id", "")))
        return Proposal(
            source="catalogue",
            entry_id=str(entry.get("id", "")),
            patch=patch,
            autofix_mode=mode,
            title=str(entry.get("title") or "Remediation"),
            explanation=_fill(str(entry.get("explanation") or ""), alert).strip(),
            cli=_fill(str(entry.get("cli") or ""), alert).strip(),
            terraform=_fill(str(entry.get("terraform") or ""), alert).strip(),
            console=_fill(str(entry.get("console") or ""), alert).strip(),
            docs=str(entry.get("docs") or ""),
            caution=_fill(str(entry.get("caution") or ""), alert).strip(),
        )
    hint = alert.get("remediation_hint")
    if hint:
        return Proposal(
            source="publisher_hint",
            title="Remediation suggested by the reporting pillar",
            explanation=str(hint).strip(),
            autofix_mode="none",
        )
    return Proposal(
        source="none",
        title="No vetted remediation for this finding type",
        explanation=(
            f"No catalogue entry matches `{alert.get('finding_type', '?')}` and the reporting "
            f"pillar sent no remediation_hint. Triage from the evidence link, then add an entry "
            f"to services/sentinel/src/sentinel/catalogue/remediation.yml so the next one carries "
            f"a fix."),
        autofix_mode="none",
    )

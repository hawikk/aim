"""Heuristics: does this signal look like an AI *coding* tool?

The fixed catalogue (`catalogue/ai-tools.json`) is the allow/deny knowledge
base. Auto-discovery raises ``unknown_ai_coding_tool`` only when a signal is
**not** in the catalogue (and not known-non-AI) *and* these heuristics fire.

Signals considered:
- OAuth app display names / client ids
- Proxy tool_raw / domain labels
- Process / binary basenames (endpoint process inventory)

Never blocks. Discovery only. Patterns are data-shaped so Security can tune
without rewriting the emission path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Strong single-token / phrase markers for AI coding surfaces. Matched as
# case-insensitive substrings against the normalized signal.
STRONG_NAME_MARKERS: tuple[str, ...] = (
    "copilot",
    "codeium",
    "codestral",
    "tabnine",
    "windsurf",
    "codewhisperer",
    "amazon q",
    "amazonq",
    "sourcegraph cody",
    "cody",
    "continue.dev",
    "continue ai",
    "supermaven",
    "augment code",
    "augmentcode",
    "kilo code",
    "kilocode",
    "kilo-code",
    "roo code",
    "roo-code",
    "claude code",
    "claudecode",
    "cursor",
    "aider",
    "cline",
    "devin",
    "replit agent",
    "gemini cli",
    "gemini code",
    "codex cli",
    "openai codex",
    "github copilot",
    "jetbrains ai",
    "grazie",
    "fauxpilot",
    "ghostwriter",
    "sweep ai",
    "mentat",
    "openhands",
    "opendevin",
    "swe-agent",
    "gpt engineer",
    "gpt-engineer",
    "smol developer",
    "cursor.sh",
)

# Domain / host labels that imply coding-agent SaaS (suffix-friendly).
STRONG_DOMAIN_MARKERS: tuple[str, ...] = (
    "codeium.com",
    "tabnine.com",
    "windsurf.com",
    "codeium.dev",
    "cursor.sh",
    "cursor.com",
    "aider.chat",
    "continue.dev",
    "supermaven.com",
    "augmentcode.com",
    "sourcegraph.com",
    "cody.dev",
    "replit.com",
    "jetbrains.ai",
    "grazie.ai",
    "sweep.dev",
    "mentat.ai",
    "openhands.dev",
)

# Process / binary basenames (no path). Exact or prefix match after normalize.
STRONG_BINARY_MARKERS: tuple[str, ...] = (
    "aider",
    "cline",
    "codeium",
    "cursor",
    "codex",
    "gemini",
    "claude",
    "kilocode",
    "kilo-code",
    "continue",
    "tabnine",
    "windsurf",
    "cody",
    "opencode",
    "openhands",
    "swe-agent",
    "gpt-engineer",
    "fauxpilot",
)

# Weak: need at least two independent weak hits (or one strong).
WEAK_CODING_MARKERS: tuple[str, ...] = (
    "code",
    "coding",
    "ide",
    "editor",
    "refactor",
    "autocomplete",
    "pair-program",
    "pair program",
)
WEAK_AI_MARKERS: tuple[str, ...] = (
    "ai",
    "llm",
    "gpt",
    "claude",
    "gemini",
    "assistant",
    "copilot",
    "agent",
)


@dataclass(frozen=True)
class HeuristicHit:
    matched: bool
    strength: str  # strong | weak | none
    patterns: tuple[str, ...]
    signal_kind: str  # name | domain | binary


def _norm(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def score_name(app_name: str) -> HeuristicHit:
    """Score an OAuth app display name / tool_raw label."""
    n = _norm(app_name)
    if not n:
        return HeuristicHit(False, "none", (), "name")
    hits: list[str] = []
    for m in STRONG_NAME_MARKERS:
        if m in n:
            hits.append(m)
    if hits:
        return HeuristicHit(True, "strong", tuple(sorted(set(hits))), "name")
    coding = [m for m in WEAK_CODING_MARKERS if m in n]
    ai = [m for m in WEAK_AI_MARKERS if m in n]
    if coding and ai:
        return HeuristicHit(
            True, "weak", tuple(sorted(set(coding + ai))), "name"
        )
    return HeuristicHit(False, "none", (), "name")


def score_domain(domain: str) -> HeuristicHit:
    """Score a domain / host label (proxy tool_raw often is a tool id, not FQDN)."""
    d = _norm(domain).lstrip(".")
    if not d:
        return HeuristicHit(False, "none", (), "domain")
    hits: list[str] = []
    for m in STRONG_DOMAIN_MARKERS:
        if d == m or d.endswith("." + m) or m in d:
            hits.append(m)
    if hits:
        return HeuristicHit(True, "strong", tuple(sorted(set(hits))), "domain")
    # Fall back to name scoring for tool_raw labels like "windsurf" / "codeium"
    name_hit = score_name(d)
    if name_hit.matched:
        return HeuristicHit(
            True, name_hit.strength, name_hit.patterns, "domain"
        )
    return HeuristicHit(False, "none", (), "domain")


def score_binary(process_name: str) -> HeuristicHit:
    """Score a process / binary basename (path stripped by caller)."""
    base = _norm(process_name)
    if not base:
        return HeuristicHit(False, "none", (), "binary")
    # strip common suffixes
    for suf in (".exe", ".bin", ".app", ".cmd", ".ps1"):
        if base.endswith(suf):
            base = base[: -len(suf)]
    hits: list[str] = []
    for m in STRONG_BINARY_MARKERS:
        if base == m or base.startswith(m + "-") or base.startswith(m + "_"):
            hits.append(m)
        elif m in base and len(m) >= 4:
            hits.append(m)
    if hits:
        return HeuristicHit(True, "strong", tuple(sorted(set(hits))), "binary")
    name_hit = score_name(base)
    if name_hit.matched:
        return HeuristicHit(
            True, name_hit.strength, name_hit.patterns, "binary"
        )
    return HeuristicHit(False, "none", (), "binary")


def looks_like_ai_coding_tool(
    *,
    name: str | None = None,
    domain: str | None = None,
    binary: str | None = None,
) -> HeuristicHit:
    """OR across signal kinds; prefer the strongest hit."""
    candidates = []
    if name:
        candidates.append(score_name(name))
    if domain:
        candidates.append(score_domain(domain))
    if binary:
        candidates.append(score_binary(binary))
    matched = [c for c in candidates if c.matched]
    if not matched:
        return HeuristicHit(False, "none", (), "name")
    strong = [c for c in matched if c.strength == "strong"]
    best = strong[0] if strong else matched[0]
    patterns = tuple(sorted({p for c in matched for p in c.patterns}))
    return HeuristicHit(True, best.strength, patterns, best.signal_kind)

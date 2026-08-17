"""OAuth scope classification: what can this app actually reach?

Classification is deliberately coarse — a security lead needs "does it read
our repos or our mail?", not a taxonomy. Matching is substring-based over the
scope URI so it works across IdPs (Google full URLs, Entra short names).
"""

from __future__ import annotations

# class -> (weight, substrings). Weight is the risk contribution when ANY
# granted scope falls in the class; the tool takes the max across classes.
SCOPE_CLASSES: dict[str, tuple[int, list[str]]] = {
    "mail": (40, ["mail.google.com", "gmail", "mail.read", "mail.readwrite"]),
    "files": (35, ["drive", "docs", "spreadsheets", "presentations", "files.read"]),
    "code": (35, ["repo", "github", "sourcecode", "code.read"]),
    "calendar": (15, ["calendar", "calendars.read"]),
    "contacts": (15, ["contacts", "people"]),
    "identity": (5, ["userinfo.profile", "userinfo.email", "openid", "profile", "email"]),
}
UNKNOWN_CLASS = "unclassified-scope"
UNKNOWN_WEIGHT = 10


def classify_scope(scope: str) -> str:
    s = (scope or "").lower()
    for cls, (_w, needles) in SCOPE_CLASSES.items():
        if any(n in s for n in needles):
            return cls
    return UNKNOWN_CLASS


def classify_scopes(scopes: list[str]) -> list[str]:
    """Ordered, deduped access classes for a set of scopes."""
    seen: dict[str, None] = {}
    for scope in scopes:
        seen.setdefault(classify_scope(scope))
    return list(seen)


def scope_breadth_weight(scope_classes: list[str]) -> int:
    """Max class weight — one broad scope dominates many narrow ones."""
    weights = {cls: w for cls, (w, _n) in SCOPE_CLASSES.items()}
    weights[UNKNOWN_CLASS] = UNKNOWN_WEIGHT
    return max((weights.get(c, UNKNOWN_WEIGHT) for c in scope_classes), default=0)

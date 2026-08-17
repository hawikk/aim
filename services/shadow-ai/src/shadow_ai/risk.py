"""Risk scoring: deterministic, explainable, no ML.

Every point is attributable to a named component so a security lead can see
WHY a tool scores what it does (AIM-300 acceptance criterion 2). Components:

- scope_breadth:    max weight across granted OAuth scope classes (does it
                    read our repos or our mail?). 0 for proxy-only tools.
- data_access:      what the tool inherently touches, from the catalogue
                    data_access_class.
- adoption:         distinct identities with an active grant. Proxy-only
                    tools are unattributed by contract -> fixed 10 with the
                    honesty note that spread is unknown.
- unsanctioned:     flat +25 when the tool is not on the approved list.
- uncatalogued:     flat +10 when we have no catalogue entry — we know the
                    least about these; they are the triage queue.

Bands: >=70 critical, >=45 high, >=25 medium, else low.
"""

from __future__ import annotations

from .scopes import scope_breadth_weight

DATA_ACCESS_WEIGHTS = {
    "communication-data": 30,
    "code-context": 25,
    "prompts-and-files": 20,
    "model-api": 10,
    "unknown": 10,
}

BANDS = [(70, "critical"), (45, "high"), (25, "medium"), (0, "low")]


def adoption_weight(identity_count: int | None) -> int:
    if identity_count is None:
        return 10  # unattributed (proxy-only): spread unknown, can't rule out
    if identity_count >= 50:
        return 25
    if identity_count >= 20:
        return 20
    if identity_count >= 5:
        return 15
    if identity_count >= 2:
        return 10
    return 5


def band_for(score: int) -> str:
    for threshold, band in BANDS:
        if score >= threshold:
            return band
    return "low"


def score_tool(
    *,
    scope_classes: list[str],
    data_access_class: str | None,
    identity_count: int | None,
    sanctioned: bool | None,
    catalogued: bool,
) -> dict:
    components: list[dict] = []

    breadth = scope_breadth_weight(scope_classes)
    components.append(
        {
            "name": "scope_breadth",
            "points": breadth,
            "detail": (
                f"broadest granted scope class reaches weight {breadth}"
                if scope_classes
                else "no OAuth grants observed (proxy-only signal)"
            ),
        }
    )

    dac = data_access_class or "unknown"
    dac_points = DATA_ACCESS_WEIGHTS.get(dac, DATA_ACCESS_WEIGHTS["unknown"])
    components.append(
        {"name": "data_access", "points": dac_points, "detail": f"data_access_class={dac}"}
    )

    adopt = adoption_weight(identity_count)
    components.append(
        {
            "name": "adoption",
            "points": adopt,
            "detail": (
                f"{identity_count} identities with active grants"
                if identity_count is not None
                else "unattributed source (proxy): adoption unknown"
            ),
        }
    )

    if sanctioned is False:
        components.append(
            {"name": "unsanctioned", "points": 25, "detail": "not on the approved tool list"}
        )
    if not catalogued:
        components.append(
            {
                "name": "uncatalogued",
                "points": 10,
                "detail": "no catalogue entry — needs security triage",
            }
        )

    score = min(100, sum(c["points"] for c in components))
    return {"score": score, "band": band_for(score), "components": components}

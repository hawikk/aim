"""xAI list-price cost estimates for Grok Build events (AIM-539).

Public short-context rates from docs.x.ai/developers/pricing. Used only for
``cost_estimate_usd`` — a list-price proxy, not subscription credits or
invoiced spend.

Cache-aware formula (matches xAI billing dimensions):

  cost = (uncached_input * pin + cached_input * pcache + output * pout) / 1e6

where ``uncached_input = max(prompt_tokens - cached_prompt_tokens, 0)``.

Schema v1 still stores full ``prompt_tokens`` in ``tokens_in`` (volume
dashboards); the billable split only affects the cost estimate field.
Long-context (≥200k) rates are ~2× and are not modeled — treat as error bar.
"""

from __future__ import annotations

from typing import Optional, Tuple

# model prefix → (input, cached_input, output) USD per 1M tokens. Longest match.
_PRICING: list[tuple[str, float, float, float]] = [
    ("grok-4.5", 2.0, 0.30, 6.0),
    ("grok-4.3", 1.25, 0.20, 2.5),
    ("grok-4.20", 1.25, 0.20, 2.5),
    ("grok-build-0.1", 1.0, 0.20, 2.0),
    ("grok-code-fast-1", 0.2, 0.05, 1.5),  # cache rate estimated
    ("grok-3", 3.0, 0.75, 15.0),  # cache rate estimated when not published
    ("grok", 2.0, 0.30, 6.0),  # fleet default → grok-4.5 band
]


def lookup_price(model: Optional[str]) -> Optional[Tuple[float, float, float]]:
    """Return ``(input, cached, output)`` USD/1M, or None if unknown."""
    if not model:
        return None
    name = model.strip().lower().split("/")[-1]
    best: Optional[Tuple[str, float, float, float]] = None
    for prefix, pin, pcache, pout in _PRICING:
        if name.startswith(prefix) or name == prefix:
            if best is None or len(prefix) > len(best[0]):
                best = (prefix, pin, pcache, pout)
    if best is None:
        return None
    return (best[1], best[2], best[3])


def estimate_cost(
    model: Optional[str],
    tokens_in: Optional[int],
    tokens_out: Optional[int],
    tokens_cached: Optional[int] = None,
) -> Optional[float]:
    """Estimate USD cost. None if model unknown or no token counts given.

    ``tokens_in`` is full prompt volume (including cache). ``tokens_cached``
    is the cache-hit subset when known; when omitted, all input is billed at
    the uncached input rate (overstates cost — prefer passing cache).
    """
    price = lookup_price(model)
    if price is None:
        return None
    if tokens_in is None and tokens_out is None:
        return None
    pin, pcache, pout = price
    tin = max(int(tokens_in or 0), 0)
    tout = max(int(tokens_out or 0), 0)
    cached = max(int(tokens_cached or 0), 0)
    if cached > tin:
        cached = tin
    uncached = tin - cached
    cost = (uncached * pin + cached * pcache + tout * pout) / 1_000_000.0
    return round(cost, 6)

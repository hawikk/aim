"""Best-effort per-model token pricing (USD per 1M tokens).

Used only to produce ``cost_usd_estimate`` -- a rough proxy for chargeback
and anomaly detection, not billing data. Unknown models yield ``None``.
Prices are public list rates as of 2026-08 and should be refreshed
periodically. Keep aligned with apps/api/src/pricing.js (AIM-539).
"""

from __future__ import annotations

from typing import List, Optional, Tuple

# (name prefix, input USD/1M, output USD/1M). Longest prefix wins.
# More-specific SKUs must appear before shorter parents (e.g. opus-4-8
# before opus-4) — the loop picks the longest matching prefix.
_PRICING: List[Tuple[str, float, float]] = [
    # Anthropic (docs.anthropic.com, 2026-08)
    ("claude-fable-5", 10.0, 50.0),
    ("claude-mythos-5", 10.0, 50.0),
    ("claude-opus-5", 5.0, 25.0),
    ("claude-opus-4-8", 5.0, 25.0),
    ("claude-opus-4-7", 5.0, 25.0),
    ("claude-opus-4-6", 5.0, 25.0),
    ("claude-opus-4-5", 5.0, 25.0),
    ("claude-opus-4-1", 15.0, 75.0),
    ("claude-opus-4", 15.0, 75.0),
    ("claude-sonnet-5", 2.0, 10.0),
    ("claude-sonnet-4-6", 3.0, 15.0),
    ("claude-sonnet-4-5", 3.0, 15.0),
    ("claude-sonnet-4", 3.0, 15.0),
    ("claude-haiku-4-5", 1.0, 5.0),
    ("claude-haiku-3-5", 0.80, 4.0),
    ("claude-3-7-sonnet", 3.0, 15.0),
    ("claude-3-5-sonnet", 3.0, 15.0),
    ("claude-3-5-haiku", 0.80, 4.0),
    ("claude-3-opus", 15.0, 75.0),
    ("claude-3-haiku", 0.25, 1.25),
    # OpenAI
    ("gpt-4o-mini", 0.15, 0.60),
    ("gpt-4o", 2.50, 10.0),
    ("gpt-4.1-mini", 0.40, 1.60),
    ("gpt-4.1", 2.0, 8.0),
    ("gpt-4-turbo", 10.0, 30.0),
    ("gpt-4", 30.0, 60.0),
    ("o4-mini", 1.10, 4.40),
    ("o3", 2.0, 8.0),
    ("o1", 15.0, 60.0),
    # Google Gemini
    ("gemini-3.1-pro", 2.0, 12.0),
    ("gemini-3-pro", 2.0, 12.0),
    ("gemini-3.6-flash", 1.5, 7.5),
    ("gemini-3.5-flash-lite", 0.30, 2.50),
    ("gemini-3.5-flash", 1.5, 9.0),
    ("gemini-3.1-flash-lite", 0.25, 1.5),
    ("gemini-3-flash", 0.50, 3.0),
    ("gemini-2.5-pro", 1.25, 10.0),
    ("gemini-2.5-flash-lite", 0.10, 0.40),
    ("gemini-2.5-flash", 0.30, 2.50),
    ("gemini-1.5-pro", 1.25, 5.0),
    ("gemini-1.5-flash", 0.075, 0.30),
    # xAI
    ("grok-4.5", 2.0, 6.0),
    ("grok-4.3", 1.25, 2.5),
    ("grok-4.20", 1.25, 2.5),
    ("grok-build-0.1", 1.0, 2.0),
    ("grok-3", 3.0, 15.0),
    ("grok-code-fast-1", 0.2, 1.5),
    # Moonshot / Kimi
    ("kimi-code/k3", 3.0, 15.0),
    ("kimi-k3", 3.0, 15.0),
    ("kimi-code/kimi-for-coding", 0.73, 3.5),
    ("kimi-for-coding", 0.73, 3.5),
    ("kimi-k2.7-code", 0.73, 3.5),
    ("kimi-k2.6", 0.59, 2.48),
    ("kimi-k2.5", 0.57, 2.85),
    ("kimi-k2-thinking", 0.6, 2.5),
    ("kimi-k2-0905", 0.6, 2.5),
    ("kimi-k2", 0.57, 2.3),
    ("moonshot-v1", 1.0, 3.0),
]


def lookup_price(model: Optional[str]) -> Optional[Tuple[float, float]]:
    """Return ``(input_usd_per_1m, output_usd_per_1m)`` for a model, or None."""
    if not model:
        return None
    name = model.strip().lower()
    base = name.split("/")[-1]
    best: Optional[Tuple[str, float, float]] = None
    for prefix, pin, pout in _PRICING:
        if (
            name == prefix
            or name.startswith(prefix + "-")
            or name.startswith(prefix + "/")
            or base == prefix
            or base.startswith(prefix + "-")
            or name.endswith("/" + prefix)
            or ("/" + prefix + "-") in name
        ):
            if best is None or len(prefix) > len(best[0]):
                best = (prefix, pin, pout)
    if best is None:
        return None
    return (best[1], best[2])


def estimate_cost(
    model: Optional[str], tokens_in: Optional[int], tokens_out: Optional[int]
) -> Optional[float]:
    """Estimate cost in USD. None if the model is unknown or no tokens given."""
    price = lookup_price(model)
    if price is None:
        return None
    if tokens_in is None and tokens_out is None:
        return None
    pin, pout = price
    cost = ((tokens_in or 0) / 1_000_000.0) * pin + (
        (tokens_out or 0) / 1_000_000.0
    ) * pout
    return round(cost, 6)

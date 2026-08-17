"""Where the bundle goes, and how much it costs.

Two implementations of one tiny protocol:

* `HttpProvider` — any OpenAI-compatible `POST {endpoint}/chat/completions`.
  stdlib `urllib` only, so the feature works against a self-hosted server
  (the default endpoint is a local Ollama) with no new dependency. The API key
  comes from `GATEHOUSE_AI_API_KEY`, is sent as a bearer token, and is never
  logged and never included in an error message — errors carry the exception
  *type*, not the request.
* `StubProvider` — a canned response supplied by the caller. This is what the
  eval harness and the unit tests run on: the golden response stands in for a
  live model, so CI exercises parsing, anchoring, dedupe and scoring without a
  network.

Configuration is environment, like the rest of gatehouse. When
`GATEHOUSE_AI_PROVIDER` is `off` (the default) or the http provider has no
model configured, `from_env()` returns None and the AI step is skipped
silently-clean — the scanners alone still produce a valid check.

Cost is measured, not guessed: providers return token usage, a static price
table (overridable per install via `GATEHOUSE_AI_PRICE_IN`/`_OUT`) turns it
into USD, and the numbers land in `ScanResult.ai_stats` and the eval report.
With the stub provider the token counts are estimates (bytes/4), which the
stats say so.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Protocol

from .. import telemetry
from . import prompt

DEFAULT_ENDPOINT = "http://127.0.0.1:11434/v1"
DEFAULT_SYSTEM = "openai"  # gen_ai.system — OpenAI-compatible chat/completions
TIMEOUT = 60  # seconds; a hung endpoint must not stall the 3-minute scan budget

# USD per 1M tokens (input, output). "default" applies to every model the env
# does not price explicitly; self-hosted models can set both to 0.
PRICE_USD_PER_1M = {"default": (5.0, 15.0)}


class ProviderError(RuntimeError):
    """The endpoint failed. A soft failure — the orchestrator degrades the
    check to neutral with this message on it, never red, never silent."""


class Provider(Protocol):
    name: str

    def review(self, bundle_text: str, *, model: str) -> tuple[str, dict]:
        """Return (raw response text, usage dict).

        Usage is {"tokens_in": int, "tokens_out": int, "estimated": bool}.
        """
        ...


class HttpProvider:
    name = "http"

    def __init__(self, endpoint: str, *, api_key: str = "", timeout: int = TIMEOUT,
                 system_prompt: str = prompt.SYSTEM_PROMPT,
                 gen_ai_system: str = DEFAULT_SYSTEM):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.system_prompt = system_prompt
        self.gen_ai_system = gen_ai_system or DEFAULT_SYSTEM

    def review(self, bundle_text: str, *, model: str) -> tuple[str, dict]:
        payload = {
            "model": model,
            "temperature": 0,  # a review should be boring; sampling adds no rigour
            # Ask the endpoint to constrain generation to a JSON object. This
            # is the OpenAI-compatible protocol doing what the prompt asks —
            # not output repair: review.py still rejects anything that is not
            # strict JSON. Without it, small instruct models wrap the answer in
            # ```json fences and every review soft-fails (live eval).
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": bundle_text},
            ],
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(
            f"{self.endpoint}/chat/completions",
            data=json.dumps(payload).encode(), headers=headers)
        # every live LLM call emits one GenAI span (never prompt text).
        with telemetry.llm_span(self.gen_ai_system, model) as span:
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    body = json.loads(response.read())
            except urllib.error.HTTPError as exc:
                # The status is useful; the body may echo the request, so it is
                # deliberately not included.
                raise ProviderError(f"endpoint returned HTTP {exc.code}") from exc
            except urllib.error.URLError as exc:
                # str(exc) embeds the full request URL — including any credentials
                # an operator put in the endpoint (https://user:pass@host/v1), and
                # this message lands on the PR check summary. Log the reason only.
                raise ProviderError(f"URLError: {exc.reason}") from exc
            except (OSError, json.JSONDecodeError) as exc:
                raise ProviderError(f"{type(exc).__name__}: {exc}") from exc
            try:
                content = body["choices"][0]["message"]["content"]
                usage = body.get("usage") or {}
                tokens_in = int(usage.get("prompt_tokens") or 0)
                tokens_out = int(usage.get("completion_tokens") or 0)
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise ProviderError(f"unexpected response shape: {type(exc).__name__}") from exc
            if tokens_in:
                span.set_attribute("gen_ai.usage.input_tokens", tokens_in)
            if tokens_out:
                span.set_attribute("gen_ai.usage.output_tokens", tokens_out)
            served = body.get("model")
            if isinstance(served, str) and served:
                span.set_attribute("gen_ai.response.model", served)
        return content, {"tokens_in": tokens_in, "tokens_out": tokens_out,
                         "estimated": False}


class StubProvider:
    """Returns the caller's canned response. Token counts are byte estimates,
    marked as such — the eval report is honest about which numbers are real."""

    name = "stub"

    def __init__(self, response_text: str):
        self.response_text = response_text

    def review(self, bundle_text: str, *, model: str) -> tuple[str, dict]:
        usage = {"tokens_in": len(bundle_text.encode()) // 4,
                 "tokens_out": len(self.response_text.encode()) // 4,
                 "estimated": True}
        return self.response_text, usage


def from_env(env: dict | None = None) -> Provider | None:
    """Build the configured provider, or None when the AI step is off.

    None is not an error: it means "scanners only", which is a valid check.
    """
    env = os.environ if env is None else env
    kind = (env.get("GATEHOUSE_AI_PROVIDER") or "off").strip().lower()
    if kind == "http":
        if not (env.get("GATEHOUSE_AI_MODEL") or "").strip():
            # An http provider without a model cannot make a well-formed
            # request; treat as unconfigured rather than failing every scan.
            return None
        # Production default stays TIMEOUT (60 s): a hung endpoint must not
        # stall the 3-minute PR scan budget. Eval (and operators who know the
        # endpoint is slow) raise it via GATEHOUSE_AI_TIMEOUT.
        timeout_raw = (env.get("GATEHOUSE_AI_TIMEOUT") or "").strip()
        timeout = int(timeout_raw) if timeout_raw else TIMEOUT
        return HttpProvider(
            env.get("GATEHOUSE_AI_ENDPOINT") or DEFAULT_ENDPOINT,
            api_key=env.get("GATEHOUSE_AI_API_KEY") or "",
            timeout=timeout,
            gen_ai_system=(env.get("GATEHOUSE_AI_SYSTEM") or DEFAULT_SYSTEM).strip()
            or DEFAULT_SYSTEM)
    if kind == "stub":
        return StubProvider(env.get("GATEHOUSE_AI_STUB_RESPONSE") or '{"findings": []}')
    return None


def settings(env: dict | None = None) -> dict:
    """The non-provider knobs of the AI step, read once per scan."""
    env = os.environ if env is None else env
    # GATEHOUSE_AI_GRAPH=0/false/off disables the slice entirely.
    graph_raw = (env.get("GATEHOUSE_AI_GRAPH") or "1").strip().lower()
    include_graph = graph_raw not in {"0", "false", "off", "no"}
    max_graph = env.get("GATEHOUSE_AI_MAX_GRAPH_BYTES")
    return {
        "model": (env.get("GATEHOUSE_AI_MODEL") or "").strip() or "stub",
        "max_bytes": int(env.get("GATEHOUSE_AI_MAX_BYTES") or 0) or None,
        "context_lines": int(env.get("GATEHOUSE_AI_CONTEXT_LINES") or 0) or None,
        "max_graph_bytes": int(max_graph) if max_graph not in (None, "") else None,
        "include_graph": include_graph,
        "price_in": float(env.get("GATEHOUSE_AI_PRICE_IN")
                          or PRICE_USD_PER_1M["default"][0]),
        "price_out": float(env.get("GATEHOUSE_AI_PRICE_OUT")
                           or PRICE_USD_PER_1M["default"][1]),
    }


def estimate_cost(tokens_in: int, tokens_out: int, *, price_in: float,
                  price_out: float) -> float:
    return round(tokens_in / 1_000_000 * price_in
                 + tokens_out / 1_000_000 * price_out, 6)

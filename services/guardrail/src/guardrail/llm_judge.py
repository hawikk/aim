"""LLM-as-judge call site for the guardrail engine (dogfood pilot).

The guardrail rules engine is deterministic (policy-as-code over event
metadata). The judge is the escalation path for *content-adjacent* questions a
regex can't answer — e.g. "does this flagged snippet look like a real secret
or a placeholder?" — sent to an OpenAI-compatible chat endpoint. This module
is the service's LLM call site, and it is instrumented with the GenAI
telemetry wrapper (telemetry.py): every call emits one llm.chat span with
provider/model/token usage/status — never the prompt or completion text.

Configuration:
  AIM_LLM_BASE_URL   OpenAI-compatible base, e.g. https://api.openai.com
                     ("/v1/chat/completions" is appended; a URL already ending
                     in /v1 is used as-is)
  AIM_LLM_API_KEY    bearer key for the provider (optional for local stubs)
  AIM_LLM_MODEL      model name (required to run)
  AIM_LLM_SYSTEM     gen_ai.system reported to telemetry (default: openai)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from . import telemetry

DEFAULT_SYSTEM = "openai"

JUDGE_SYSTEM_PROMPT = (
    "You are a security guardrail judge for an AI-usage monitoring platform. "
    "You are shown a short snippet flagged by a deterministic rule. Decide "
    "whether it is a true positive. Answer with JSON only: "
    '{"verdict": "flag"|"allow", "reason": "<one short sentence>"}.'
)


class LlmJudgeError(RuntimeError):
    """The provider call failed (transport, HTTP status, or malformed body)."""


class LlmJudge:
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        system: str = DEFAULT_SYSTEM,
        timeout: float = 30.0,
    ) -> None:
        base = base_url.rstrip("/")
        self._url = base if base.endswith("/v1/chat/completions") else base + "/v1/chat/completions"
        self._model = model
        self._api_key = api_key
        self._system = system
        self._timeout = timeout

    @classmethod
    def from_env(cls, env: dict | None = None) -> "LlmJudge":
        env = env if env is not None else os.environ
        base_url = env.get("AIM_LLM_BASE_URL")
        model = env.get("AIM_LLM_MODEL")
        if not base_url or not model:
            raise ValueError("AIM_LLM_BASE_URL and AIM_LLM_MODEL are required")
        return cls(
            base_url,
            model,
            api_key=env.get("AIM_LLM_API_KEY") or None,
            system=env.get("AIM_LLM_SYSTEM") or DEFAULT_SYSTEM,
        )

    def judge(self, snippet: str) -> dict:
        """Classify one flagged snippet. Returns {"verdict", "reason", "model"}.
        Raises LlmJudgeError on any provider failure (the span still records
        the error before the raise)."""
        payload = json.dumps({
            "model": self._model,
            "messages": [
                {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                {"role": "user", "content": snippet},
            ],
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        with telemetry.llm_span(self._system, self._model) as span:
            req = urllib.request.Request(self._url, data=payload, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                raise LlmJudgeError(f"LLM provider returned HTTP {exc.code}") from exc
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                raise LlmJudgeError(f"LLM provider call failed: {exc}") from exc

            usage = body.get("usage") or {}
            # Only allowlisted operational metadata goes on the span.
            if isinstance(usage.get("prompt_tokens"), int):
                span.set_attribute("gen_ai.usage.input_tokens", usage["prompt_tokens"])
            if isinstance(usage.get("completion_tokens"), int):
                span.set_attribute("gen_ai.usage.output_tokens", usage["completion_tokens"])
            served_model = body.get("model")
            if isinstance(served_model, str) and served_model:
                span.set_attribute("gen_ai.response.model", served_model)

            try:
                content = body["choices"][0]["message"]["content"]
                verdict = json.loads(content)
            except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
                raise LlmJudgeError("LLM provider returned a malformed completion") from exc
            return {
                "verdict": verdict.get("verdict"),
                "reason": verdict.get("reason"),
                "model": served_model or self._model,
            }

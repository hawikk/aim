"""LLM triage: what happened, how far it reaches, is it real.

Contract with the rest of the service: **this module never raises and never
blocks longer than the configured timeout.** It returns a ``Triage`` whose
``degraded`` field says what went wrong. Every caller renders a notification
either way — a triage failure downgrades the *quality* of a ping, never its
existence. That is the acceptance criterion ("an LLM outage degrades to raw
pass-through notification, never silence") and it is also the standing bar for
this stack: a finding that disappears without an error is the worst outcome
available.

What crosses the boundary (D5 boundary 3, and this list is the whole of it):
the projected alert's metadata — title, finding type, severity, resource
display name, account ref, region, evidence summary and labels. Not prompt
content (the AI-usage pillar never puts it on the bus), not secret values
(never stored unmasked anywhere in the stack), not plaintext identity
(``subject_ref`` is an HMAC pseudonym by contract, and is dropped here anyway
because a triage answer does not improve for knowing which pseudonym it was).
``_prompt_payload`` is the enforcement point, and it is an allowlist rather
than a denylist so a future contract field cannot silently start flowing to a
third-party endpoint.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Callable

from . import telemetry

MAX_SUMMARY_CHARS = 600
MAX_ALERTS_IN_PROMPT = 12

SYSTEM_PROMPT = """\
You are the triage half of a self-hosted security stack. You receive normalized
security alerts (metadata only — never prompt text, never secret values) and
you answer for an on-call engineer who has 30 seconds.

Reply with a single JSON object, no prose around it, with exactly these keys:
  "what_happened":  2-3 plain-English sentences. No jargon, no vendor rule ids.
                    Someone who does not know this tool must understand it.
  "blast_radius":   one sentence: who or what is exposed, and to whom.
  "is_real":        "likely_real" | "needs_verification" | "likely_noise"
  "confidence":     "high" | "medium" | "low"
  "why":            one sentence justifying is_real from the evidence given.

Rules:
- Judge only from the fields provided. Do not invent resource names, account
  numbers, CVEs or timelines that are not in the input.
- If the input is too thin to judge, say so in "why" and use
  "needs_verification" with "low" confidence. A hedge is more useful than a
  guess.
- Never output remediation commands. A reviewed catalogue supplies those.
"""


@dataclass(frozen=True)
class Triage:
    what_happened: str
    blast_radius: str
    is_real: str
    confidence: str
    why: str
    degraded: str = ""      # "" when the LLM answered; otherwise the reason
    model: str = ""
    latency_ms: int = 0

    def as_dict(self) -> dict:
        return asdict(self)


def _fallback(alert: dict, reason: str, incident_count: int = 1) -> Triage:
    """The pass-through triage: raw alert fields, phrased as plainly as code can.

    Deliberately not empty strings. A ping that says "triage unavailable" and
    nothing else teaches the reader to ignore the channel; this one still
    carries what the alert itself asserts, and is explicitly labelled as
    un-triaged so nobody mistakes a restatement for an assessment.
    """
    resource = alert.get("resource") or {}
    evidence = alert.get("evidence") or {}
    where = resource.get("display") or resource.get("ref") or "an unnamed resource"
    scope = ", ".join(x for x in (resource.get("provider"), resource.get("account_ref"),
                                  resource.get("region")) if x)
    more = f" and {incident_count - 1} more affected resource(s)" if incident_count > 1 else ""
    return Triage(
        what_happened=(f"{alert.get('title', 'A security finding was raised')} — reported by "
                       f"{(alert.get('producer') or {}).get('name', 'a pillar')} against {where}"
                       f"{more}. {evidence.get('summary', '')}").strip(),
        blast_radius=(f"Scope as reported: {scope}." if scope
                      else "Scope not reported by the source pillar."),
        is_real="needs_verification",
        confidence="low",
        why="Not assessed: automated triage was unavailable, so this is the raw alert.",
        degraded=reason,
    )


def _prompt_payload(alert: dict) -> dict:
    """Allowlist of fields that may leave the VM. See the module docstring."""
    resource = alert.get("resource") or {}
    evidence = alert.get("evidence") or {}
    return {
        "pillar": alert.get("pillar"),
        "finding_type": alert.get("finding_type"),
        "title": alert.get("title"),
        "severity": alert.get("severity"),
        "status": alert.get("status"),
        "first_seen_at": alert.get("first_seen_at"),
        "last_seen_at": alert.get("last_seen_at"),
        "observed_count": alert.get("observed_count"),
        "resource": {
            "kind": resource.get("kind"),
            "display": resource.get("display"),
            "provider": resource.get("provider"),
            "account_ref": resource.get("account_ref"),
            "region": resource.get("region"),
        },
        "evidence_summary": (evidence.get("summary") or "")[:MAX_SUMMARY_CHARS],
        "detail_count": evidence.get("detail_count"),
        "labels": alert.get("labels") or {},
    }


def build_prompt(alert: dict, siblings: list[dict] | None = None) -> str:
    payload = {"alert": _prompt_payload(alert)}
    siblings = [s for s in (siblings or []) if s.get("alert_id") != alert.get("alert_id")]
    if siblings:
        # The other resources in the same incident. Their presence is the
        # difference between "a bucket is public" and "a deploy made 40 buckets
        # public", and only the second one tells the on-call what to do.
        payload["also_in_this_incident"] = [
            {"title": s.get("title"),
             "resource": (s.get("resource") or {}).get("display"),
             "severity": s.get("severity")}
            for s in siblings[:MAX_ALERTS_IN_PROMPT]
        ]
        payload["incident_alert_count"] = len(siblings) + 1
    return json.dumps(payload, indent=2, sort_keys=True)


def _extract_json(text: str) -> dict | None:
    """Models fence JSON, prepend "Here is", or answer with a bare object."""
    text = (text or "").strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    candidate = fenced.group(1) if fenced else None
    if candidate is None:
        start, end = text.find("{"), text.rfind("}")
        candidate = text[start:end + 1] if start != -1 and end > start else None
    if candidate is None:
        return None
    try:
        parsed = json.loads(candidate)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


HttpPost = Callable[[str, dict, bytes, float], tuple[int, bytes]]


def _urllib_post(url: str, headers: dict, body: bytes, timeout: float) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


class Triager:
    """Calls the configured LLM. `post` is injectable; tests use it to prove
    the degrade paths, which are the ones that must never be broken."""

    def __init__(self, cfg, post: HttpPost | None = None):
        self.cfg = cfg
        self._post = post or _urllib_post

    def triage(self, alert: dict, siblings: list[dict] | None = None) -> Triage:
        llm = self.cfg.llm
        if not llm.enabled:
            return _fallback(alert, "llm_disabled", len(siblings or []) + 1)
        if not llm.endpoint:
            return _fallback(alert, "llm_not_configured", len(siblings or []) + 1)

        import time
        started = time.monotonic()
        system = (llm.flavor or "openai").strip().lower() or "openai"
        # instrument the live provider call only. Disabled/unconfigured
        # paths are explicit exceptions (no network call → no GenAI span).
        try:
            with telemetry.llm_span(system, llm.model) as span:
                try:
                    url, headers, body = self._request(build_prompt(alert, siblings))
                    status, raw = self._post(url, headers, body, llm.timeout_seconds)
                except (urllib.error.URLError, OSError, TimeoutError) as err:
                    # Span is marked error by llm_span; re-raise via fallback path.
                    raise _TriageTransportError(
                        f"llm_unreachable: {type(err).__name__}") from err
                except Exception as err:  # noqa: BLE001 — see below
                    # Broad on purpose. This module's contract is "never raises":
                    # a new exception type from an injected transport or a client
                    # library must degrade the ping, not kill the loop.
                    raise _TriageTransportError(
                        f"llm_error: {type(err).__name__}") from err

                latency_ms = int((time.monotonic() - started) * 1000)
                self._record_usage(span, raw)
                if status >= 300:
                    span.set_error()
                    return _fallback(alert, f"llm_http_{status}",
                                     len(siblings or []) + 1)
                text = self._extract_text(raw)
                parsed = _extract_json(text) if text else None
                if not parsed:
                    span.set_error()
                    return _fallback(alert, "llm_unparseable",
                                     len(siblings or []) + 1)

                required = ("what_happened", "blast_radius", "is_real",
                            "confidence", "why")
                if any(not str(parsed.get(k, "")).strip() for k in required):
                    span.set_error()
                    return _fallback(alert, "llm_incomplete",
                                     len(siblings or []) + 1)
                is_real = str(parsed["is_real"]).strip().lower()
                if is_real not in ("likely_real", "needs_verification", "likely_noise"):
                    # An out-of-vocabulary verdict is not trusted into a field the
                    # renderer uses to set tone — but the prose is still useful, so
                    # keep it and downgrade the verdict rather than dropping the answer.
                    is_real = "needs_verification"
                served = self._extract_model(raw)
                if served:
                    span.set_attribute("gen_ai.response.model", served)
                return Triage(
                    what_happened=str(parsed["what_happened"]).strip()[:1200],
                    blast_radius=str(parsed["blast_radius"]).strip()[:600],
                    is_real=is_real,
                    confidence=str(parsed["confidence"]).strip().lower()[:16],
                    why=str(parsed["why"]).strip()[:600],
                    model=llm.model,
                    latency_ms=latency_ms,
                )
        except _TriageTransportError as err:
            return _fallback(alert, str(err), len(siblings or []) + 1)

    def _request(self, user_content: str) -> tuple[str, dict, bytes]:
        llm = self.cfg.llm
        headers = {"content-type": "application/json"}
        if llm.flavor == "anthropic":
            headers["x-api-key"] = llm.api_key
            headers["anthropic-version"] = "2023-06-01"
            payload = {
                "model": llm.model,
                "max_tokens": llm.max_output_tokens,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_content}],
            }
        else:
            # OpenAI-compatible /chat/completions — what vLLM, Ollama, LiteLLM
            # and most self-hosted gateways speak, so "configurable endpoint"
            # means a URL change and not a code change.
            if llm.api_key:
                headers["authorization"] = f"Bearer {llm.api_key}"
            payload = {
                "model": llm.model,
                "max_tokens": llm.max_output_tokens,
                "temperature": 0,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
            }
        return llm.endpoint, headers, json.dumps(payload).encode()

    @staticmethod
    def _extract_text(raw: bytes) -> str:
        try:
            doc = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            return ""
        if not isinstance(doc, dict):
            return ""
        # Anthropic Messages
        content = doc.get("content")
        if isinstance(content, list):
            return "".join(part.get("text", "") for part in content
                           if isinstance(part, dict) and part.get("type") == "text")
        # OpenAI chat completions
        choices = doc.get("choices")
        if isinstance(choices, list) and choices:
            message = choices[0].get("message") if isinstance(choices[0], dict) else None
            if isinstance(message, dict):
                return str(message.get("content") or "")
        return ""

    @staticmethod
    def _extract_model(raw: bytes) -> str:
        try:
            doc = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            return ""
        if not isinstance(doc, dict):
            return ""
        model = doc.get("model")
        return model if isinstance(model, str) else ""

    @staticmethod
    def _record_usage(span, raw: bytes) -> None:
        """Attach allowlisted token counts when the provider reports them."""
        try:
            doc = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            return
        if not isinstance(doc, dict):
            return
        usage = doc.get("usage") or {}
        if not isinstance(usage, dict):
            return
        # OpenAI: prompt_tokens/completion_tokens; Anthropic: input_tokens/output_tokens
        tokens_in = usage.get("prompt_tokens", usage.get("input_tokens"))
        tokens_out = usage.get("completion_tokens", usage.get("output_tokens"))
        if isinstance(tokens_in, int) and tokens_in >= 0:
            span.set_attribute("gen_ai.usage.input_tokens", tokens_in)
        if isinstance(tokens_out, int) and tokens_out >= 0:
            span.set_attribute("gen_ai.usage.output_tokens", tokens_out)


class _TriageTransportError(Exception):
    """Internal: transport failure already recorded on the GenAI span."""


def pass_through(alert: dict, reason: str, incident_count: int = 1) -> Triage:
    """Public name for the degrade path, used by the runner when it decides on
    its own that triage must be skipped (e.g. a backlog it must drain fast)."""
    return _fallback(alert, reason, incident_count)

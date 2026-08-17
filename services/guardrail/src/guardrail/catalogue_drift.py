"""Provider / model catalogue drift alerts.

Complements new-sources (first-ever host×known-provider) with:

  * ``app-llm-new-provider`` — a *provider string* whose first-ever event falls
    inside the lookback window AND is **not** in the known provider catalogue
    (union of all ``endpoints.json`` rule providers). Signal: catalogue gap —
    OTel or a future collector emitted a provider we do not own yet.

  * ``app-llm-new-model`` — a *model id* whose first-ever event falls inside
    the lookback window AND does not match the list-price table
    (``apps/api/src/pricing.js`` ``PRICE_PER_MTOK`` keys, longest-prefix +
    boundary semantics matching platform ``resolvePrice``). Signal: cost view
    is falling back to DEFAULT; catalogue needs a pricing row.

Both are observe-only, metadata-only, edge-triggered on the first event id
(``UNIQUE (rule_id, event_id)``). Re-runs never re-page.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .engine import DECISION, FINDING_SCHEMA

NEW_PROVIDER_NS = uuid.UUID("a7380000-0000-4000-8000-000000000001")
NEW_MODEL_NS = uuid.UUID("a7380000-0000-4000-8000-000000000002")

RULE_NEW_PROVIDER = "app-llm-new-provider"
RULE_NEW_MODEL = "app-llm-new-model"
SEVERITY = "low"  # catalogue ops, not a security incident by itself

DEFAULT_LOOKBACK_HOURS = 48
MAX_FINDINGS_PER_RUN = 50

# Fallback when endpoints.json is not mounted into the guardrail image.
# Keep in sync with collectors/proxy/endpoints.json (all rule providers is the
# ideal set; this fallback is the provider-api App-LLM core + common tools).
FALLBACK_KNOWN_PROVIDERS: frozenset[str] = frozenset({
    "anthropic", "openai", "azure_openai", "aws_bedrock", "google",
    "mistral", "cohere", "groq", "xai", "openrouter", "moonshot",
    "together", "fireworks", "cursor", "github", "aws", "codeium",
    "tabnine", "sourcegraph", "deepseek", "huggingface", "other",
})

NEW_PROVIDERS_QUERY = """
SELECT provider, first_seen, first_event_id, event_count FROM (
  SELECT
    e.provider,
    MIN(e.ts) AS first_seen,
    (array_agg(e.event_id ORDER BY e.ts ASC, e.event_id ASC))[1] AS first_event_id,
    COUNT(*) AS event_count
  FROM events e
  WHERE e.provider IS NOT NULL AND btrim(e.provider) <> ''
  GROUP BY 1
) f
WHERE f.first_seen >= now() - (%s || ' hours')::interval
ORDER BY first_seen DESC
LIMIT %s
"""

NEW_MODELS_QUERY = """
SELECT model, provider, first_seen, first_event_id, event_count FROM (
  SELECT
    e.model,
    (array_agg(e.provider ORDER BY e.ts ASC, e.event_id ASC)
      FILTER (WHERE e.provider IS NOT NULL))[1] AS provider,
    MIN(e.ts) AS first_seen,
    (array_agg(e.event_id ORDER BY e.ts ASC, e.event_id ASC))[1] AS first_event_id,
    COUNT(*) AS event_count
  FROM events e
  WHERE e.model IS NOT NULL AND btrim(e.model) <> ''
  GROUP BY 1
) f
WHERE f.first_seen >= now() - (%s || ' hours')::interval
ORDER BY first_seen DESC
LIMIT %s
"""


@dataclass
class DriftRunSummary:
    new_providers_candidates: int = 0
    new_models_candidates: int = 0
    findings: int = 0
    findings_inserted: int = 0
    skipped_missing_table: bool = False
    lookback_hours: int = DEFAULT_LOOKBACK_HOURS
    known_providers: int = 0
    known_models: int = 0
    errors: list[str] = field(default_factory=list)


def lookback_hours_from_env(env: dict | None = None) -> int:
    env = env if env is not None else os.environ
    raw = env.get("APP_LLM_CATALOGUE_DRIFT_LOOKBACK_HOURS")
    if raw is None or str(raw).strip() == "":
        # Fall back to the new-source lookback so one knob covers both.
        raw = env.get("APP_LLM_NEW_SOURCE_LOOKBACK_HOURS")
    if raw is None or str(raw).strip() == "":
        return DEFAULT_LOOKBACK_HOURS
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"APP_LLM_CATALOGUE_DRIFT_LOOKBACK_HOURS must be a positive integer, got {raw!r}"
        ) from exc
    if value <= 0:
        raise ValueError(
            f"APP_LLM_CATALOGUE_DRIFT_LOOKBACK_HOURS must be > 0, got {value}"
        )
    return value


def _repo_root() -> Path:
    # services/guardrail/src/guardrail/thisfile.py → repo root is parents[4]
    return Path(__file__).resolve().parents[4]


def load_known_providers(endpoints_path: Path | None = None) -> frozenset[str]:
    """All provider strings from endpoints.json rules (not just provider-api)."""
    path = endpoints_path or (
        _repo_root() / "collectors" / "proxy" / "endpoints.json"
    )
    try:
        import json

        data = json.loads(path.read_text(encoding="utf-8"))
        out: set[str] = set()
        for rule in data.get("rules") or []:
            p = rule.get("provider")
            if isinstance(p, str) and p.strip():
                out.add(p.strip())
        if out:
            return frozenset(out)
    except Exception:  # noqa: BLE001 — image may not ship endpoints.json
        pass
    return FALLBACK_KNOWN_PROVIDERS


def load_known_model_keys(pricing_js: Path | None = None) -> tuple[str, ...]:
    """PRICE_PER_MTOK keys from apps/api/src/pricing.js, longest first."""
    path = pricing_js or (_repo_root() / "apps" / "api" / "src" / "pricing.js")
    try:
        src = path.read_text(encoding="utf-8")
    except OSError:
        return ()
    m = re.search(r"export const PRICE_PER_MTOK = \{(?P<body>[\s\S]*?)\n\};?", src)
    if not m:
        m = re.search(r"PRICE_PER_MTOK = \{(?P<body>[\s\S]*?)\n\}", src)
    if not m:
        return ()
    keys = re.findall(r"['\"]([^'\"]+)['\"]\s*:", m.group("body"))
    # longest first for prefix matching
    return tuple(sorted(set(keys), key=lambda k: (-len(k), k)))


def model_is_catalogued(model: str, keys: Iterable[str]) -> bool:
    """Mirror apps/api resolvePrice longest-prefix + boundary semantics."""
    if not model:
        return False
    m = model.strip().lower()
    for key in keys:
        k = key.lower()
        if m == k:
            return True
        if m.startswith(k + "-") or m.startswith(k + "/"):
            return True
        if "/" not in k:
            # vendor-path forms: provider/key or provider/key-date
            if m.endswith("/" + k) or f"/{k}-" in m or f"/{k}/" in m:
                return True
    return False


def _iso(ts: datetime | str) -> str:
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(ts)


def _build_provider_finding(
    *,
    provider: str,
    first_seen: datetime | str,
    first_event_id: str | None,
    event_count: int,
    policy_hash: str,
    ruleset_version: int | str,
    now: datetime,
) -> dict:
    first_seen_iso = _iso(first_seen)
    if first_event_id:
        event_id = str(first_event_id)
    else:
        event_id = str(
            uuid.uuid5(NEW_PROVIDER_NS, f"{provider}:{first_seen_iso}")
        )
    return {
        "schema": FINDING_SCHEMA,
        "finding_id": str(uuid.uuid4()),
        "rule_id": RULE_NEW_PROVIDER,
        "ruleset_version": ruleset_version,
        "policy_hash": policy_hash,
        "severity": SEVERITY,
        "title": f"New uncatalogued provider: {provider}",
        "decision": DECISION,
        "ts": first_seen_iso if first_seen_iso.endswith("Z") else now.isoformat(),
        "subject": {"user_ref": None, "host_ref": None},
        "evidence": {
            "event_ids": [event_id],
            "detail": {
                "signal": "app_llm_new_provider",
                "provider": provider,
                "first_seen": first_seen_iso,
                "event_count": int(event_count),
            },
            "group_by": {"provider": provider},
            "matched": [{
                "detector": "app-llm:catalogue-drift:provider",
                "category": "policy",
                "severity": SEVERITY,
            }],
            "context": {
                "provider": provider,
                "source": "app_llm_catalogue_drift_evaluator",
            },
        },
    }


def _build_model_finding(
    *,
    model: str,
    provider: str | None,
    first_seen: datetime | str,
    first_event_id: str | None,
    event_count: int,
    policy_hash: str,
    ruleset_version: int | str,
    now: datetime,
) -> dict:
    first_seen_iso = _iso(first_seen)
    if first_event_id:
        event_id = str(first_event_id)
    else:
        event_id = str(uuid.uuid5(NEW_MODEL_NS, f"{model}:{first_seen_iso}"))
    model_short = model if len(model) <= 48 else model[:45] + "…"
    return {
        "schema": FINDING_SCHEMA,
        "finding_id": str(uuid.uuid4()),
        "rule_id": RULE_NEW_MODEL,
        "ruleset_version": ruleset_version,
        "policy_hash": policy_hash,
        "severity": SEVERITY,
        "title": f"New uncatalogued model: {model_short}",
        "decision": DECISION,
        "ts": first_seen_iso if first_seen_iso.endswith("Z") else now.isoformat(),
        "subject": {"user_ref": None, "host_ref": None},
        "evidence": {
            "event_ids": [event_id],
            "detail": {
                "signal": "app_llm_new_model",
                "model": model,
                "provider": provider,
                "first_seen": first_seen_iso,
                "event_count": int(event_count),
            },
            "group_by": {"model": model},
            "matched": [{
                "detector": "app-llm:catalogue-drift:model",
                "category": "policy",
                "severity": SEVERITY,
            }],
            "context": {
                "model": model,
                "provider": provider,
                "source": "app_llm_catalogue_drift_evaluator",
            },
        },
    }


def _fetch(conn: Any, query: str, params: tuple) -> list[tuple] | None:
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return list(cur.fetchall())
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).lower()
        if "events" in msg and (
            "does not exist" in msg
            or "undefinedtable" in msg
            or "undefined column" in msg
        ):
            try:
                conn.rollback()
            except Exception:  # noqa: BLE001
                pass
            return None
        raise


def evaluate_catalogue_drift(
    conn: Any,
    *,
    policy_hash: str = "catalogue-drift-evaluator",
    ruleset_version: int | str = 1,
    now: datetime | None = None,
    lookback_hours: int | None = None,
    known_providers: frozenset[str] | None = None,
    known_model_keys: tuple[str, ...] | None = None,
    env: dict | None = None,
) -> tuple[list[dict], DriftRunSummary]:
    """Return findings for uncatalogued new providers and models."""
    summary = DriftRunSummary()
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    try:
        lookback = (
            lookback_hours
            if lookback_hours is not None
            else lookback_hours_from_env(env)
        )
    except ValueError as exc:
        summary.errors.append(str(exc))
        return [], summary
    summary.lookback_hours = lookback

    providers = known_providers if known_providers is not None else load_known_providers()
    model_keys = (
        known_model_keys if known_model_keys is not None else load_known_model_keys()
    )
    summary.known_providers = len(providers)
    summary.known_models = len(model_keys)

    findings: list[dict] = []

    try:
        prov_rows = _fetch(
            conn, NEW_PROVIDERS_QUERY, (str(lookback), MAX_FINDINGS_PER_RUN)
        )
    except Exception as exc:  # noqa: BLE001
        summary.errors.append(f"fetch new providers failed: {exc}")
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        return [], summary

    if prov_rows is None:
        summary.skipped_missing_table = True
        return [], summary

    for row in prov_rows:
        provider, first_seen, first_event_id, event_count = row
        provider = (provider or "").strip()
        if not provider or provider in providers:
            continue
        summary.new_providers_candidates += 1
        findings.append(
            _build_provider_finding(
                provider=provider,
                first_seen=first_seen,
                first_event_id=str(first_event_id) if first_event_id else None,
                event_count=int(event_count or 0),
                policy_hash=policy_hash,
                ruleset_version=ruleset_version,
                now=now,
            )
        )

    try:
        model_rows = _fetch(
            conn, NEW_MODELS_QUERY, (str(lookback), MAX_FINDINGS_PER_RUN * 2)
        )
    except Exception as exc:  # noqa: BLE001
        summary.errors.append(f"fetch new models failed: {exc}")
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        # still return provider findings collected so far
        summary.findings = len(findings)
        return findings, summary

    if model_rows is None:
        summary.skipped_missing_table = True
        summary.findings = len(findings)
        return findings, summary

    for row in model_rows:
        model, provider, first_seen, first_event_id, event_count = row
        model = (model or "").strip()
        if not model:
            continue
        if model_keys and model_is_catalogued(model, model_keys):
            continue
        if not model_keys:
            # No price table available in this install — skip model alerts rather
            # than page on every model.
            continue
        summary.new_models_candidates += 1
        if summary.new_models_candidates > MAX_FINDINGS_PER_RUN:
            break
        findings.append(
            _build_model_finding(
                model=model,
                provider=(provider or None),
                first_seen=first_seen,
                first_event_id=str(first_event_id) if first_event_id else None,
                event_count=int(event_count or 0),
                policy_hash=policy_hash,
                ruleset_version=ruleset_version,
                now=now,
            )
        )

    summary.findings = len(findings)
    return findings, summary


def apply_drift_findings(
    conn: Any,
    findings: list[dict],
    insert_finding_fn,
) -> list[dict]:
    inserted: list[dict] = []
    for finding in findings:
        if insert_finding_fn(conn, finding):
            inserted.append(finding)
    return inserted

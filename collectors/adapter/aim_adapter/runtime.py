"""Orchestrate discover → extract → emit for all registered manifests."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from . import alert_map, emit
from .identity import IdentityContext, Pseudonymizer, default_identity
from .registry import load_all_manifests
from .surfaces import get_driver


@dataclass
class Failure:
    tool_id: str
    surface: str
    code: str
    message: str


@dataclass
class RunResult:
    discoveries: list[Any] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    dropped: int = 0
    failures: list[Failure] = field(default_factory=list)
    alert_stubs: list[dict[str, Any]] = field(default_factory=list)

    def fleet_counts(self) -> dict[str, int]:
        """Unified-stack style counts: COALESCE(tool_raw, tool)."""
        c: Counter[str] = Counter()
        for e in self.events:
            name = e.get("tool_raw") or e.get("tool") or "unknown"
            c[str(name)] += 1
        return dict(sorted(c.items()))


def _surface_source(surface: dict[str, Any], default: str = "endpoint") -> str:
    extraction = surface.get("extraction") or {}
    return extraction.get("source") or default


def run_manifest(
    manifest: dict[str, Any],
    *,
    identity: IdentityContext | None = None,
    pseudo: Pseudonymizer | None = None,
    root: str | None = None,
    injected: dict[str, list[dict[str, Any]]] | None = None,
    host_hits: list[str] | None = None,
) -> RunResult:
    """Run all surfaces for one tool manifest.

    ``injected`` maps surface type → list of raw records (for tests / offline).
    """
    identity = identity or default_identity()
    pseudo = pseudo or Pseudonymizer()
    injected = injected or {}
    result = RunResult()

    for surface in manifest.get("surfaces") or []:
        stype = surface["type"]
        try:
            driver = get_driver(stype)
        except KeyError as e:
            result.failures.append(
                Failure(manifest["id"], stype, "unknown_surface", str(e))
            )
            continue

        # Discovery
        try:
            if stype == "proxy_domain":
                disc = driver.discover(
                    manifest, surface, root=root, host_hits=host_hits
                )
            else:
                disc = driver.discover(manifest, surface, root=root)
            result.discoveries.append(disc)
        except Exception as e:  # fail-soft
            result.failures.append(
                Failure(manifest["id"], stype, "discover_error", type(e).__name__)
            )
            continue

        # Extraction
        try:
            kwargs: dict[str, Any] = {"root": root}
            if stype in injected:
                kwargs["records"] = injected[stype]
            rows, dropped, fails = driver.extract_rows(manifest, surface, **kwargs)
            result.dropped += dropped
            for f in fails:
                result.failures.append(
                    Failure(manifest["id"], stype, "extract", f)
                )
        except Exception as e:
            result.failures.append(
                Failure(manifest["id"], stype, "extract_error", type(e).__name__)
            )
            continue

        source = _surface_source(
            surface,
            default="proxy" if stype == "proxy_domain" else "endpoint",
        )
        for row in rows:
            try:
                event = emit.to_event(
                    manifest=manifest,
                    row=row,
                    identity=identity,
                    pseudo=pseudo,
                    source=source,
                )
            except Exception as e:
                result.failures.append(
                    Failure(manifest["id"], stype, "emit_error", type(e).__name__)
                )
                continue
            if event is None:
                result.dropped += 1
                continue
            # Privacy: model null for pure presence surfaces is fine
            if source == "endpoint" and event.get("model") is None:
                # inventory / presence rows without model — still valid if
                # we don't claim token volume; schema allows null model on
                # non-endpoint... endpoint prefers model. Use proxy for
                # presence-only extension inventory to avoid schema fights.
                if stype == "editor_extension_hooks":
                    event["source"] = "endpoint"
                    # skip model-less inventory in fleet proof; still count discovery
                    result.dropped += 1
                    continue
            result.events.append(event)
            if event.get("match_flags"):
                result.alert_stubs.extend(alert_map.flags_to_alert_stubs(event))

    return result


def run_all(
    *,
    manifest_dir: str | None = None,
    tool_ids: list[str] | None = None,
    identity: IdentityContext | None = None,
    pseudo: Pseudonymizer | None = None,
    root: str | None = None,
    injected_by_tool: dict[str, dict[str, list[dict[str, Any]]]] | None = None,
    host_hits: list[str] | None = None,
) -> RunResult:
    """Run every manifest (or a filtered set) and merge results."""
    identity = identity or default_identity()
    pseudo = pseudo or Pseudonymizer()
    injected_by_tool = injected_by_tool or {}
    merged = RunResult()
    for manifest in load_all_manifests(manifest_dir):
        if tool_ids is not None and manifest["id"] not in tool_ids:
            continue
        partial = run_manifest(
            manifest,
            identity=identity,
            pseudo=pseudo,
            root=root,
            injected=injected_by_tool.get(manifest["id"]),
            host_hits=host_hits,
        )
        merged.discoveries.extend(partial.discoveries)
        merged.events.extend(partial.events)
        merged.dropped += partial.dropped
        merged.failures.extend(partial.failures)
        merged.alert_stubs.extend(partial.alert_stubs)
    return merged

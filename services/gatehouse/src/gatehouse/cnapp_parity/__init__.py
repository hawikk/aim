"""IaC ↔ CNAPP posture rule parity.

Gatehouse already runs Checkov on PR diffs. This module makes those findings
tell the *code-to-cloud* story pre-merge:

* every mapped IaC rule names the CNAPP posture rule it prevents
* PR comments surface the would-be cloud finding (severity + rule)
* drift between the mapping and the posture catalog fails CI

The CNAPP catalog is vendored from Cloud Sentry (littlewiz `backend/rules/`)
so a PR scan does not need a live CNAPP API call. Live asset correlation is out of scope here; this module is the rule-semantics half.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from functools import lru_cache
from pathlib import Path
from typing import Iterable

import yaml

from ..models import Finding

_DATA_DIR = Path(__file__).resolve().parent
_DEFAULT_MAPPING = _DATA_DIR / "mapping.yml"
_DEFAULT_CATALOG = _DATA_DIR / "posture_catalog.yml"

# Labels written onto Finding.labels (short keys — bus cap is 10 labels total).
LABEL_CNAPP_RULE = "cnapp_rule"
LABEL_CNAPP_SEV = "cnapp_sev"
LABEL_WOULD_BE = "would_be_cloud"

_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}


@dataclass(frozen=True)
class PostureRule:
    slug: str
    severity: str
    title: str
    iac_required: bool = True
    frameworks: tuple[str, ...] = ()


@dataclass(frozen=True)
class MappingEntry:
    iac_rule: str
    cnapp_rule: str
    scanner: str = "checkov"
    note: str = ""


@dataclass
class DriftReport:
    """Parity drift between the mapping file and the CNAPP catalog."""

    unknown_cnapp_targets: list[str] = field(default_factory=list)
    unmapped_required_cnapp: list[str] = field(default_factory=list)
    unmapped_watchlist: list[str] = field(default_factory=list)
    duplicate_mappings: list[str] = field(default_factory=list)
    catalog_size: int = 0
    mapping_size: int = 0

    @property
    def ok(self) -> bool:
        return not (
            self.unknown_cnapp_targets
            or self.unmapped_required_cnapp
            or self.unmapped_watchlist
            or self.duplicate_mappings
        )

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "catalog_size": self.catalog_size,
            "mapping_size": self.mapping_size,
            "unknown_cnapp_targets": list(self.unknown_cnapp_targets),
            "unmapped_required_cnapp": list(self.unmapped_required_cnapp),
            "unmapped_watchlist": list(self.unmapped_watchlist),
            "duplicate_mappings": list(self.duplicate_mappings),
        }

    def summary_md(self) -> str:
        if self.ok:
            return (
                f"IaC↔CNAPP parity OK — {self.mapping_size} mapping(s) cover "
                f"{self.catalog_size} posture rule(s)."
            )
        lines = ["**IaC↔CNAPP parity drift detected**"]
        if self.unknown_cnapp_targets:
            lines.append(
                "- Mapping targets unknown CNAPP rules: "
                + ", ".join(f"`{s}`" for s in self.unknown_cnapp_targets)
            )
        if self.unmapped_required_cnapp:
            lines.append(
                "- CNAPP rules with `iac_required` but no IaC mapping: "
                + ", ".join(f"`{s}`" for s in self.unmapped_required_cnapp)
            )
        if self.unmapped_watchlist:
            lines.append(
                "- High-value Checkov ids on the watchlist with no mapping: "
                + ", ".join(f"`{s}`" for s in self.unmapped_watchlist)
            )
        if self.duplicate_mappings:
            lines.append(
                "- Duplicate IaC rule keys: "
                + ", ".join(f"`{s}`" for s in self.duplicate_mappings)
            )
        return "\n".join(lines)


@dataclass(frozen=True)
class WouldBeCloudFinding:
    """What the same misconfiguration becomes as a CNAPP cloud finding."""

    iac_rule: str
    iac_severity: str
    cnapp_rule: str
    cnapp_severity: str
    cnapp_title: str
    path: str
    line: int
    resource_hint: str = ""
    note: str = ""


def _load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: root must be a mapping")
    return doc


@lru_cache(maxsize=4)
def load_catalog(path: str | None = None) -> dict[str, PostureRule]:
    p = Path(path) if path else _DEFAULT_CATALOG
    doc = _load_yaml(p)
    out: dict[str, PostureRule] = {}
    for item in doc.get("rules") or []:
        if not isinstance(item, dict) or not item.get("slug"):
            continue
        sev = str(item.get("severity") or "medium").lower()
        if sev not in _SEVERITY_RANK:
            sev = "medium"
        frameworks = tuple(str(x) for x in (item.get("frameworks") or []))
        out[str(item["slug"])] = PostureRule(
            slug=str(item["slug"]),
            severity=sev,
            title=str(item.get("title") or item["slug"]),
            iac_required=bool(item.get("iac_required", True)),
            frameworks=frameworks,
        )
    return out


@lru_cache(maxsize=4)
def load_mapping(path: str | None = None) -> tuple[tuple[MappingEntry, ...], tuple[str, ...]]:
    p = Path(path) if path else _DEFAULT_MAPPING
    doc = _load_yaml(p)
    entries: list[MappingEntry] = []
    for item in doc.get("mappings") or []:
        if not isinstance(item, dict):
            continue
        iac = str(item.get("iac_rule") or "").strip()
        cnapp = str(item.get("cnapp_rule") or "").strip()
        if not iac or not cnapp:
            continue
        entries.append(MappingEntry(
            iac_rule=iac,
            cnapp_rule=cnapp,
            scanner=str(item.get("scanner") or "checkov"),
            note=str(item.get("note") or ""),
        ))
    watch = tuple(str(x) for x in (doc.get("watchlist") or []) if x)
    return tuple(entries), watch


def mapping_index(
    path: str | None = None,
) -> dict[str, MappingEntry]:
    """iac_rule → MappingEntry (last wins if duplicates; drift reports them)."""
    entries, _ = load_mapping(path)
    return {e.iac_rule: e for e in entries}


def check_drift(
    *,
    mapping_path: str | None = None,
    catalog_path: str | None = None,
) -> DriftReport:
    entries, watch = load_mapping(mapping_path)
    catalog = load_catalog(catalog_path)
    report = DriftReport(catalog_size=len(catalog), mapping_size=len(entries))

    seen: dict[str, int] = {}
    covered: set[str] = set()
    for entry in entries:
        seen[entry.iac_rule] = seen.get(entry.iac_rule, 0) + 1
        covered.add(entry.cnapp_rule)
        if entry.cnapp_rule not in catalog:
            report.unknown_cnapp_targets.append(
                f"{entry.iac_rule}→{entry.cnapp_rule}"
            )

    report.duplicate_mappings = sorted(k for k, n in seen.items() if n > 1)
    report.unmapped_required_cnapp = sorted(
        slug for slug, rule in catalog.items()
        if rule.iac_required and slug not in covered
    )
    mapped_iac = set(seen)
    report.unmapped_watchlist = sorted(w for w in watch if w not in mapped_iac)
    # de-dupe unknown targets while preserving order
    report.unknown_cnapp_targets = list(dict.fromkeys(report.unknown_cnapp_targets))
    return report


def _resource_hint(finding: Finding) -> str:
    msg = finding.message or ""
    # checkov adapter: "`resource` (framework)."
    if "`" in msg:
        parts = msg.split("`")
        if len(parts) >= 2:
            return parts[1][:120]
    return ""


def enrich_findings(
    findings: Iterable[Finding],
    *,
    mapping_path: str | None = None,
    catalog_path: str | None = None,
    align_severity: bool = False,
) -> list[Finding]:
    """Attach CNAPP posture labels to mapped IaC findings.

    Returns a new list (Finding is frozen). Unmapped findings pass through.
    When ``align_severity`` is true, severity is raised to the CNAPP catalog
    severity if the catalog is *more* severe than the Checkov table — never
    lowered (fail-closed for the would-be cloud finding story).
    """
    index = mapping_index(mapping_path)
    catalog = load_catalog(catalog_path)
    out: list[Finding] = []
    for finding in findings:
        entry = index.get(finding.rule_id)
        if entry is None or finding.scanner not in ("checkov", entry.scanner):
            out.append(finding)
            continue
        posture = catalog.get(entry.cnapp_rule)
        labels = dict(finding.labels or {})
        labels[LABEL_CNAPP_RULE] = entry.cnapp_rule[:64]
        labels[LABEL_WOULD_BE] = "true"
        severity = finding.severity
        if posture is not None:
            labels[LABEL_CNAPP_SEV] = posture.severity[:16]
            if align_severity:
                if _SEVERITY_RANK.get(posture.severity, 99) < _SEVERITY_RANK.get(
                    finding.severity, 99
                ):
                    severity = posture.severity
        # message carries the code-to-cloud sentence reviewers read first
        title = posture.title if posture else entry.cnapp_rule
        cnapp_sev = posture.severity if posture else finding.severity
        cloud_line = (
            f"Would-be cloud finding: [{cnapp_sev}] {entry.cnapp_rule} — {title}."
        )
        message = finding.message or ""
        if "Would-be cloud finding:" not in message:
            message = f"{message} {cloud_line}".strip() if message else cloud_line
        out.append(replace(
            finding,
            severity=severity,
            message=message[:600],
            labels=labels,
            remediation=finding.remediation or (
                f"Fix the IaC so CNAPP rule `{entry.cnapp_rule}` will not fire "
                f"post-deploy. {entry.note}".strip()
            )[:500],
        ))
    return out


def would_be_cloud_findings(
    findings: Iterable[Finding],
    *,
    mapping_path: str | None = None,
    catalog_path: str | None = None,
) -> list[WouldBeCloudFinding]:
    """Project IaC findings into the would-be CNAPP cloud findings list."""
    index = mapping_index(mapping_path)
    catalog = load_catalog(catalog_path)
    rows: list[WouldBeCloudFinding] = []
    for finding in findings:
        # Prefer labels if already enriched; else look up mapping.
        cnapp_rule = (finding.labels or {}).get(LABEL_CNAPP_RULE) or ""
        entry = index.get(finding.rule_id)
        if not cnapp_rule and entry is not None:
            cnapp_rule = entry.cnapp_rule
        if not cnapp_rule:
            continue
        posture = catalog.get(cnapp_rule)
        rows.append(WouldBeCloudFinding(
            iac_rule=finding.rule_id,
            iac_severity=finding.severity,
            cnapp_rule=cnapp_rule,
            cnapp_severity=(
                (finding.labels or {}).get(LABEL_CNAPP_SEV)
                or (posture.severity if posture else finding.severity)
            ),
            cnapp_title=posture.title if posture else cnapp_rule,
            path=finding.path,
            line=finding.line,
            resource_hint=_resource_hint(finding),
            note=entry.note if entry else "",
        ))
    # Most severe CNAPP severity first
    rows.sort(key=lambda r: (_SEVERITY_RANK.get(r.cnapp_severity, 99), r.path, r.line))
    return rows


def render_would_be_section(
    findings: Iterable[Finding],
    *,
    mapping_path: str | None = None,
    catalog_path: str | None = None,
    max_rows: int = 20,
) -> str:
    """Markdown block for the PR comment / check-run summary (AC#3)."""
    rows = would_be_cloud_findings(
        findings, mapping_path=mapping_path, catalog_path=catalog_path)
    if not rows:
        return ""
    lines = [
        "",
        "### Would-be cloud findings (code → cloud)",
        "",
        "These IaC misconfigurations map to the **same CNAPP posture rules** "
        "Cloud Sentry enforces post-deploy. Fixing them here prevents the "
        "cloud finding from ever opening.",
        "",
        "| Cloud severity | CNAPP rule | IaC rule | Location |",
        "|---|---|---|---|",
    ]
    for row in rows[:max_rows]:
        loc = f"{_md(row.path)}:{row.line}" if row.line else _md(row.path)
        lines.append(
            f"| **{row.cnapp_severity}** | `{_md(row.cnapp_rule, 48)}` "
            f"({_md(row.cnapp_title, 60)}) | `{_md(row.iac_rule, 32)}` | {loc} |"
        )
    if len(rows) > max_rows:
        lines.append(f"\n…and {len(rows) - max_rows} more would-be cloud finding(s).")
    lines.append(
        "\n<sub>Rule parity map: gatehouse `cnapp_parity`. "
        "Asset-level code-to-cloud linking is.</sub>"
    )
    return "\n".join(lines)


def _md(text: str, limit: int = 120) -> str:
    cleaned = (text or "").replace("`", "'").replace("|", "/").replace("<", "&lt;")
    cleaned = cleaned.replace(">", "&gt;").replace("\r", " ").replace("\n", " ")
    return " ".join(cleaned.split())[:limit]


# --- CLI / CI helpers -------------------------------------------------------

DEFAULT_IAC_GLOBS = (
    "infra/**/*.tf",
    "infra/**/*.tfvars",
    "deploy/helm/**/*.yaml",
    "deploy/helm/**/*.yml",
    "deploy/**/Chart.yaml",
    "**/k8s/**/*.yaml",
    "**/k8s/**/*.yml",
    "**/kubernetes/**/*.yaml",
    "**/manifests/**/*.yaml",
)


def discover_iac_paths(repo_dir: str, globs: Iterable[str] | None = None) -> list[str]:
    """Repo-relative IaC paths for a full-tree CI scan (not diff-scoped)."""
    root = Path(repo_dir)
    patterns = list(globs) if globs is not None else list(DEFAULT_IAC_GLOBS)
    found: set[str] = set()
    for pattern in patterns:
        for match in root.glob(pattern):
            if not match.is_file():
                continue
            # Skip values files that are pure config without workload pods? No —
            # checkov still wants values for helm; include everything yaml under helm.
            rel = match.relative_to(root).as_posix()
            if any(part.startswith(".") for part in match.parts):
                continue
            if "node_modules" in match.parts or ".terraform" in match.parts:
                continue
            found.add(rel)
    return sorted(found)


def clear_caches() -> None:
    """Test helper — reload mapping/catalog after writing temp files."""
    load_catalog.cache_clear()
    load_mapping.cache_clear()


def env_align_severity() -> bool:
    return os.environ.get("GATEHOUSE_CNAPP_ALIGN_SEVERITY", "0") not in (
        "0", "false", "False", ""
    )

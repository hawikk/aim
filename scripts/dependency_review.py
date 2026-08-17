#!/usr/bin/env python3
"""PR-time dependency review + lockfile tamper gate.

Diffs every tracked npm lockfile against a base ref and enforces two rules:

1. **Lockfile tamper (hard fail).** Same package name+version with a changed
   ``integrity`` hash or ``resolved``/``tarball`` URL. There is no legitimate
   package-manager reason for that edit — regenerate the lockfile.

2. **Dependency review (hard fail = flagged for human).** Added or
   version-changed packages are scored against npm registry metadata:
   install scripts, release age, package age, publisher change. Unreachable
   registry metadata is fail-closed (an unassessed dep is a review item).

Stdlib only so the supply-chain CI job can run this without a pip install.
Rules are proven alive by ``--self-test`` (offline fixtures + mock registry).

Usage:
    python3 scripts/dependency_review.py --base origin/main
    python3 scripts/dependency_review.py --self-test
    python3 scripts/dependency_review.py --base-lock a.yaml --head-lock b.yaml
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parent.parent

# Lockfiles we know how to parse. Yarn classic is out of scope for v1.
LOCKFILE_NAMES = (
    "pnpm-lock.yaml",
    "package-lock.json",
    "npm-shrinkwrap.json",
)

INSTALL_SCRIPT_KEYS = frozenset(
    {"preinstall", "install", "postinstall"}
)

# Thresholds match docs/adr-supply-chain-slsa.md Decision 1.
VERSION_AGE_DAYS = 7
PACKAGE_AGE_DAYS = 30

# Registry base. Override via env in air-gapped tests only.
DEFAULT_REGISTRY = "https://registry.npmjs.org"

# Resolution field keys we treat as integrity identity of a pinned artifact.
INTEGRITY_FIELDS = ("integrity", "resolved", "tarball")


@dataclass(frozen=True)
class PinnedPkg:
    name: str
    version: str
    integrity: str = ""
    resolved: str = ""
    source_lock: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return (self.name, self.version)

    def artifact_id(self) -> tuple[str, str]:
        """Identity of the bytes we would install (hash + URL)."""
        return (self.integrity or "", self.resolved or "")


@dataclass
class Finding:
    severity: str  # "tamper" | "review"
    package: str
    version: str
    message: str
    lockfile: str = ""

    def format(self) -> str:
        loc = f" ({self.lockfile})" if self.lockfile else ""
        return f"[{self.severity}] {self.package}@{self.version}{loc}: {self.message}"


@dataclass
class ReviewReport:
    findings: list[Finding] = field(default_factory=list)
    reviewed: list[str] = field(default_factory=list)
    lockfiles: list[str] = field(default_factory=list)

    @property
    def tampers(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "tamper"]

    @property
    def reviews(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "review"]

    def ok(self) -> bool:
        return not self.findings


# ── lockfile parsers ─────────────────────────────────────────────────────────


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1]
    return s


def split_name_version(key: str) -> tuple[str, str] | None:
    """Parse a pnpm packages-key like ``@scope/name@1.2.3`` or ``name@1.2.3``.

    Peer-dep suffix ``(peer@x)`` is stripped; the resolution still pins one
    artifact per name@version.
    """
    key = key.strip()
    if "(" in key:
        key = key.split("(", 1)[0]
    if not key or key == ".":
        return None
    # Scoped: @scope/name@version  — version is after the *last* @ that is
    # not the leading scope marker.
    if key.startswith("@"):
        # @scope/name@1.2.3
        m = re.match(r"^(@[^@/]+/[^@]+)@(.+)$", key)
        if not m:
            return None
        return m.group(1), m.group(2)
    if "@" not in key:
        return None
    name, ver = key.rsplit("@", 1)
    if not name or not ver:
        return None
    return name, ver


_RESOLUTION_RE = re.compile(
    r"resolution:\s*\{([^}]*)\}"
)
_FIELD_RE = re.compile(r"(integrity|tarball|resolved):\s*([^,}\s]+)")


def parse_pnpm_lock(text: str, source: str = "pnpm-lock.yaml") -> dict[tuple[str, str], PinnedPkg]:
    """Extract name@version → PinnedPkg from a pnpm lockfile v6/v9 ``packages:`` map.

    Intentionally line-oriented (no PyYAML) so the supply-chain job stays
    stdlib-only on the self-hosted runner.
    """
    out: dict[tuple[str, str], PinnedPkg] = {}
    in_packages = False
    current_key: str | None = None
    current_fields: dict[str, str] = {}

    def flush() -> None:
        nonlocal current_key, current_fields
        if current_key is None:
            return
        nv = split_name_version(current_key)
        if nv is None:
            current_key = None
            current_fields = {}
            return
        name, ver = nv
        integrity = current_fields.get("integrity", "").strip()
        resolved = (
            current_fields.get("tarball")
            or current_fields.get("resolved")
            or ""
        ).strip()
        # Prefer first-seen identity; peer-dep variants share name@version and
        # must not differ in integrity (if they do, last write still detects
        # via compare against base).
        pkg = PinnedPkg(
            name=name,
            version=ver,
            integrity=integrity,
            resolved=resolved,
            source_lock=source,
        )
        prev = out.get(pkg.key)
        if prev is not None and prev.artifact_id() != pkg.artifact_id():
            # Same name@version, different artifact inside one lockfile — treat
            # as the later entry; tamper vs base still covers the real case.
            pass
        out[pkg.key] = pkg
        current_key = None
        current_fields = {}

    for raw in text.splitlines():
        line = raw.rstrip()
        if not in_packages:
            if line == "packages:" or line.startswith("packages:"):
                in_packages = True
            continue
        # Next top-level section ends packages.
        if line and not line.startswith(" ") and not line.startswith("\t") and line.endswith(":"):
            if line != "packages:":
                flush()
                break
        # Package key at 2-space indent: `  'foo@1.0.0':` or `  foo@1.0.0:`
        m = re.match(r"^  (\S.*):\s*$", line)
        if m and not line.startswith("    "):
            flush()
            current_key = _strip_quotes(m.group(1))
            current_fields = {}
            continue
        if current_key is None:
            continue
        # resolution: {integrity: …, tarball: …}
        rm = _RESOLUTION_RE.search(line)
        if rm:
            for fm in _FIELD_RE.finditer(rm.group(1)):
                current_fields[fm.group(1)] = fm.group(2).rstrip(",")
            continue
        # Multi-line form (rare in v9, defensive):
        for field in ("integrity", "tarball", "resolved"):
            m2 = re.match(rf"^\s+{field}:\s+(\S+)\s*$", line)
            if m2:
                current_fields[field] = m2.group(1)
    flush()
    return out


def parse_npm_lock(text: str, source: str = "package-lock.json") -> dict[tuple[str, str], PinnedPkg]:
    """Parse npm lockfile v2/v3 ``packages`` map (and v1 ``dependencies`` tree)."""
    data = json.loads(text)
    out: dict[tuple[str, str], PinnedPkg] = {}

    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            if path in ("", "."):
                continue  # root project
            name = meta.get("name")
            if not name:
                # node_modules/@scope/pkg or node_modules/pkg
                cleaned = path
                if cleaned.startswith("node_modules/"):
                    cleaned = cleaned[len("node_modules/") :]
                # nested: node_modules/a/node_modules/b → b
                if "/node_modules/" in cleaned:
                    cleaned = cleaned.rsplit("/node_modules/", 1)[-1]
                name = cleaned
            version = meta.get("version")
            if not name or not version:
                continue
            if meta.get("link") is True:
                continue
            pkg = PinnedPkg(
                name=name,
                version=str(version),
                integrity=str(meta.get("integrity") or ""),
                resolved=str(meta.get("resolved") or ""),
                source_lock=source,
            )
            out[pkg.key] = pkg
        return out

    # lockfileVersion 1
    def walk(deps: dict, prefix: str = "") -> None:
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            ver = meta.get("version")
            if ver:
                pkg = PinnedPkg(
                    name=name,
                    version=str(ver),
                    integrity=str(meta.get("integrity") or ""),
                    resolved=str(meta.get("resolved") or ""),
                    source_lock=source,
                )
                out[pkg.key] = pkg
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                walk(nested, name)

    root_deps = data.get("dependencies")
    if isinstance(root_deps, dict):
        walk(root_deps)
    return out


def parse_lockfile(path: str, text: str) -> dict[tuple[str, str], PinnedPkg]:
    name = Path(path).name
    if name == "pnpm-lock.yaml":
        return parse_pnpm_lock(text, source=path)
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        return parse_npm_lock(text, source=path)
    raise ValueError(f"unsupported lockfile: {path}")


# ── git + discovery ──────────────────────────────────────────────────────────


def discover_lockfiles(root: Path) -> list[str]:
    found: list[str] = []
    for dirpath, dirnames, filenames in root.walk() if hasattr(root, "walk") else _os_walk(root):
        # Skip heavy/irrelevant trees.
        base = Path(dirpath)
        parts = set(base.relative_to(root).parts) if base != root else set()
        skip = {
            "node_modules",
            ".git",
            "dist",
            "build",
            ".venv",
            "venv",
            "__pycache__",
            ".wt",
            "wt-aim292",
            "wt-aim297",
            "wt-aim321",
            "wt-aim327",
            "wt-aim328",
            "wt-aim332",
            "wt-aim334",
            "wt-aim381-siem",
            "wt-aim382",
            "cnapp-198",
            "cnapp-237",
            "ai-monitoring",
        }
        dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith("wt-")]
        for fn in filenames:
            if fn in LOCKFILE_NAMES:
                rel = str((base / fn).relative_to(root))
                found.append(rel)
    return sorted(found)


def _os_walk(root: Path):
    import os

    for dirpath, dirnames, filenames in os.walk(root):
        yield dirpath, dirnames, filenames


def git_show(ref: str, path: str, repo: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            cwd=repo,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ── registry metadata ────────────────────────────────────────────────────────


PackumentFetcher = Callable[[str], dict | None]


def default_fetch_packument(name: str, registry: str = DEFAULT_REGISTRY) -> dict | None:
    # Scoped packages need percent-encoding of the slash.
    url = f"{registry.rstrip('/')}/{quote(name, safe='@')}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "aim-dependency-review/1.0",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, ValueError):
        return None


def _parse_npm_time(value: str) -> datetime | None:
    if not value:
        return None
    # npm uses ISO-8601 with Z.
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except ValueError:
        return None


def assess_package(
    name: str,
    version: str,
    *,
    previous_version: str | None,
    packument: dict | None,
    now: datetime | None = None,
) -> list[str]:
    """Return human-readable flag reasons (empty = clean)."""
    reasons: list[str] = []
    if packument is None:
        reasons.append(
            "registry metadata unreachable (fail-closed — unassessed dependency)"
        )
        return reasons

    now = now or datetime.now(timezone.utc)
    times = packument.get("time") or {}
    ver_time = _parse_npm_time(str(times.get(version) or ""))
    created = _parse_npm_time(str(times.get("created") or ""))

    if ver_time is not None:
        age_days = (now - ver_time).total_seconds() / 86400.0
        if age_days < VERSION_AGE_DAYS:
            reasons.append(
                f"version published {age_days:.1f}d ago "
                f"(< {VERSION_AGE_DAYS}d threshold)"
            )
    else:
        reasons.append("version publish timestamp missing from packument")

    if created is not None:
        pkg_age = (now - created).total_seconds() / 86400.0
        if pkg_age < PACKAGE_AGE_DAYS:
            reasons.append(
                f"package first published {pkg_age:.1f}d ago "
                f"(< {PACKAGE_AGE_DAYS}d threshold)"
            )

    versions = packument.get("versions") or {}
    ver_meta = versions.get(version) if isinstance(versions, dict) else None
    if isinstance(ver_meta, dict):
        scripts = ver_meta.get("scripts") or {}
        if isinstance(scripts, dict):
            present = sorted(k for k in scripts if k in INSTALL_SCRIPT_KEYS)
            if present:
                reasons.append(
                    "install lifecycle scripts present: " + ", ".join(present)
                )
        if previous_version and previous_version in versions:
            old_meta = versions.get(previous_version) or {}
            old_user = _publisher(old_meta if isinstance(old_meta, dict) else {})
            new_user = _publisher(ver_meta)
            if old_user and new_user and old_user != new_user:
                reasons.append(
                    f"publisher changed {old_user!r} → {new_user!r} "
                    f"(between {previous_version} and {version})"
                )
    else:
        reasons.append(f"version {version} not present in packument versions map")

    return reasons


def _publisher(meta: dict) -> str:
    user = meta.get("_npmUser")
    if isinstance(user, dict):
        return str(user.get("name") or user.get("email") or "")
    if isinstance(user, str):
        return user
    maintainers = meta.get("maintainers")
    if isinstance(maintainers, list) and maintainers:
        m0 = maintainers[0]
        if isinstance(m0, dict):
            return str(m0.get("name") or m0.get("email") or "")
        if isinstance(m0, str):
            return m0
    return ""


# ── core compare ─────────────────────────────────────────────────────────────


def compare_pins(
    base: dict[tuple[str, str], PinnedPkg],
    head: dict[tuple[str, str], PinnedPkg],
    *,
    lockfile: str,
    fetch: PackumentFetcher,
    now: datetime | None = None,
    skip_registry: bool = False,
) -> ReviewReport:
    report = ReviewReport(lockfiles=[lockfile])

    # Index base by name → set of versions (for previous_version lookup).
    base_by_name: dict[str, set[str]] = {}
    for (name, ver) in base:
        base_by_name.setdefault(name, set()).add(ver)

    # Tamper: same name+version, different artifact identity.
    for key, head_pkg in head.items():
        base_pkg = base.get(key)
        if base_pkg is None:
            continue
        if base_pkg.artifact_id() != head_pkg.artifact_id():
            parts = []
            if base_pkg.integrity != head_pkg.integrity:
                parts.append(
                    f"integrity {base_pkg.integrity[:24] or '(empty)'}… → "
                    f"{head_pkg.integrity[:24] or '(empty)'}…"
                )
            if base_pkg.resolved != head_pkg.resolved:
                parts.append(
                    f"resolved/tarball URL changed "
                    f"({base_pkg.resolved or '(empty)'} → {head_pkg.resolved or '(empty)'})"
                )
            report.findings.append(
                Finding(
                    severity="tamper",
                    package=head_pkg.name,
                    version=head_pkg.version,
                    message=(
                        "lockfile tamper: same name@version but "
                        + "; ".join(parts)
                        + ". Regenerate the lockfile with the package manager; "
                        "do not hand-edit integrity/resolved fields."
                    ),
                    lockfile=lockfile,
                )
            )

    # Added or version-changed packages (present in head, not in base).
    for key, head_pkg in sorted(head.items()):
        if key in base:
            continue
        name, ver = key
        prev_versions = base_by_name.get(name, set())
        previous = sorted(prev_versions)[-1] if prev_versions else None
        kind = "version-changed" if previous else "added"
        label = f"{name}@{ver} ({kind}" + (f" from {previous}" if previous else "") + ")"
        report.reviewed.append(label)

        if skip_registry:
            continue

        packument = fetch(name)
        reasons = assess_package(
            name,
            ver,
            previous_version=previous,
            packument=packument,
            now=now,
        )
        for reason in reasons:
            report.findings.append(
                Finding(
                    severity="review",
                    package=name,
                    version=ver,
                    message=reason,
                    lockfile=lockfile,
                )
            )

    return report


def review_repo(
    root: Path,
    *,
    base_ref: str | None,
    fetch: PackumentFetcher | None = None,
    now: datetime | None = None,
    skip_registry: bool = False,
    lockfile_paths: Iterable[str] | None = None,
) -> ReviewReport:
    fetch = fetch or default_fetch_packument
    paths = list(lockfile_paths) if lockfile_paths is not None else discover_lockfiles(root)
    combined = ReviewReport()

    if not paths:
        return combined

    for rel in paths:
        head_path = root / rel
        if not head_path.is_file():
            continue
        head_text = read_text(head_path)
        try:
            head_pins = parse_lockfile(rel, head_text)
        except (ValueError, json.JSONDecodeError) as exc:
            combined.findings.append(
                Finding(
                    severity="review",
                    package="(lockfile)",
                    version="-",
                    message=f"failed to parse head lockfile: {exc}",
                    lockfile=rel,
                )
            )
            combined.lockfiles.append(rel)
            continue

        base_pins: dict[tuple[str, str], PinnedPkg] = {}
        if base_ref:
            base_text = git_show(base_ref, rel, root)
            if base_text is not None:
                try:
                    base_pins = parse_lockfile(rel, base_text)
                except (ValueError, json.JSONDecodeError) as exc:
                    combined.findings.append(
                        Finding(
                            severity="review",
                            package="(lockfile)",
                            version="-",
                            message=f"failed to parse base lockfile at {base_ref}: {exc}",
                            lockfile=rel,
                        )
                    )
            # If the file is new on this branch, base_pins stays empty → all added.

        part = compare_pins(
            base_pins,
            head_pins,
            lockfile=rel,
            fetch=fetch,
            now=now,
            skip_registry=skip_registry,
        )
        combined.findings.extend(part.findings)
        combined.reviewed.extend(part.reviewed)
        combined.lockfiles.append(rel)

    return combined


ALLOWLIST_PATH = REPO_ROOT / "docs" / "security" / "dependency-review-allowlist.json"


def load_review_allowlist(
    path: Path = ALLOWLIST_PATH,
    *,
    now: datetime | None = None,
) -> dict[tuple[str, str], dict]:
    """Load human-reviewed name@version exceptions for age/publisher flags.

    Lockfile-tamper findings are never filtered by this list. Entries with an
    ``expires`` date (YYYY-MM-DD, UTC) in the past are ignored so the next PR
    re-evaluates the package.
    """
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    entries = data.get("entries") or []
    if not isinstance(entries, list):
        return {}
    now = now or datetime.now(timezone.utc)
    out: dict[tuple[str, str], dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        version = str(entry.get("version") or "").strip()
        if not name or not version:
            continue
        expires = str(entry.get("expires") or "").strip()
        if expires:
            try:
                exp_dt = datetime.strptime(expires, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if now >= exp_dt:
                continue
        out[(name, version)] = entry
    return out


def apply_review_allowlist(
    report: ReviewReport,
    allowlist: dict[tuple[str, str], dict],
) -> list[str]:
    """Drop severity=review findings covered by the allowlist; return notes.

    Tamper findings are never dropped.
    """
    if not allowlist:
        return []
    kept: list[Finding] = []
    notes: list[str] = []
    for f in report.findings:
        if f.severity == "review" and (f.package, f.version) in allowlist:
            entry = allowlist[(f.package, f.version)]
            reason = entry.get("reason") or entry.get("advisory") or "allowlisted"
            notes.append(
                f"{f.package}@{f.version}: allowlisted ({reason})"
            )
            continue
        kept.append(f)
    report.findings = kept
    return notes


def write_step_summary(
    report: ReviewReport,
    stream,
    *,
    allowlist_notes: list[str] | None = None,
) -> None:
    stream.write("## Dependency review\n\n")
    stream.write(f"Lockfiles scanned: {', '.join(report.lockfiles) or '(none)'}\n\n")
    if report.tampers:
        stream.write("### Lockfile tamper (block)\n\n")
        for f in report.tampers:
            stream.write(f"- {f.format()}\n")
        stream.write("\n")
    if report.reviews:
        stream.write("### Flagged for human review\n\n")
        for f in report.reviews:
            stream.write(f"- {f.format()}\n")
        stream.write("\n")
    if allowlist_notes:
        stream.write("### Allowlisted (human-reviewed security pins)\n\n")
        for note in allowlist_notes:
            stream.write(f"- {note}\n")
        stream.write("\n")
    if report.reviewed:
        stream.write("### Packages reviewed\n\n")
        for item in report.reviewed:
            stream.write(f"- `{item}`\n")
        stream.write("\n")
    if report.ok():
        stream.write("No tamper and no review flags.\n")


# ── self-test ────────────────────────────────────────────────────────────────


def _fixture_pnpm(packages: dict[str, dict[str, str]]) -> str:
    lines = ["lockfileVersion: '9.0'", "", "packages:", ""]
    for key, fields in packages.items():
        lines.append(f"  '{key}':")
        body = ", ".join(f"{k}: {v}" for k, v in fields.items())
        lines.append(f"    resolution: {{{body}}}")
        lines.append("")
    return "\n".join(lines) + "\n"


def _fixture_npm(packages: dict[str, dict]) -> str:
    return json.dumps({"lockfileVersion": 3, "packages": packages}, indent=2)


def self_test() -> int:
    failures: list[str] = []
    fixed_now = datetime(2026, 7, 29, tzinfo=timezone.utc)

    def expect(rule: str, cond: bool, detail: str = "") -> None:
        if not cond:
            failures.append(f"{rule}: {detail or 'condition false'}")

    # ── parsers ──────────────────────────────────────────────────────────
    pnpm = _fixture_pnpm(
        {
            "left-pad@1.3.0": {
                "integrity": "sha512-AAA",
                "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            },
            "@scope/pkg@2.0.0": {"integrity": "sha512-BBB"},
        }
    )
    pins = parse_pnpm_lock(pnpm)
    expect("pnpm parse count", len(pins) == 2, f"got {len(pins)}")
    expect(
        "pnpm scoped name",
        ("@scope/pkg", "2.0.0") in pins,
        str(list(pins)),
    )
    expect(
        "pnpm integrity",
        pins[("left-pad", "1.3.0")].integrity == "sha512-AAA",
    )

    npm = _fixture_npm(
        {
            "": {"name": "root", "version": "0.0.1"},
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-AAA",
            },
            "node_modules/@scope/pkg": {
                "version": "2.0.0",
                "integrity": "sha512-BBB",
            },
        }
    )
    npins = parse_npm_lock(npm)
    expect("npm parse count", len(npins) == 2, f"got {list(npins)}")
    expect("npm scoped", ("@scope/pkg", "2.0.0") in npins)

    # ── tamper detection ─────────────────────────────────────────────────
    base = parse_pnpm_lock(
        _fixture_pnpm({"left-pad@1.3.0": {"integrity": "sha512-AAA"}})
    )
    head_tamper = parse_pnpm_lock(
        _fixture_pnpm({"left-pad@1.3.0": {"integrity": "sha512-EVIL"}})
    )

    def no_fetch(_name: str) -> dict | None:
        failures.append("registry fetch should not run for pure-tamper compare")
        return None

    r = compare_pins(
        base, head_tamper, lockfile="pnpm-lock.yaml", fetch=no_fetch, skip_registry=True
    )
    expect("tamper fires", len(r.tampers) == 1, f"got {r.findings}")
    expect("tamper mentions integrity", "integrity" in r.tampers[0].message.lower())

    head_url = parse_pnpm_lock(
        _fixture_pnpm(
            {
                "left-pad@1.3.0": {
                    "integrity": "sha512-AAA",
                    "tarball": "https://evil.example/left-pad.tgz",
                }
            }
        )
    )
    base_url = parse_pnpm_lock(
        _fixture_pnpm(
            {
                "left-pad@1.3.0": {
                    "integrity": "sha512-AAA",
                    "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                }
            }
        )
    )
    r2 = compare_pins(
        base_url, head_url, lockfile="pnpm-lock.yaml", fetch=no_fetch, skip_registry=True
    )
    expect("url tamper fires", len(r2.tampers) == 1, f"got {r2.findings}")

    # Clean identical → no findings
    r_clean = compare_pins(
        base, base, lockfile="pnpm-lock.yaml", fetch=no_fetch, skip_registry=True
    )
    expect("identical clean", r_clean.ok())

    # ── install scripts flag ─────────────────────────────────────────────
    def packument_with_scripts(name: str) -> dict | None:
        if name != "evil-pkg":
            return None
        return {
            "time": {
                "created": "2020-01-01T00:00:00.000Z",
                "1.0.0": "2024-01-01T00:00:00.000Z",
            },
            "versions": {
                "1.0.0": {
                    "scripts": {"postinstall": "node malware.js", "test": "echo ok"},
                    "_npmUser": {"name": "alice"},
                }
            },
        }

    base_empty: dict[tuple[str, str], PinnedPkg] = {}
    head_new = parse_pnpm_lock(
        _fixture_pnpm({"evil-pkg@1.0.0": {"integrity": "sha512-XXX"}})
    )
    r3 = compare_pins(
        base_empty,
        head_new,
        lockfile="pnpm-lock.yaml",
        fetch=packument_with_scripts,
        now=fixed_now,
    )
    expect(
        "install scripts flag",
        any("install lifecycle scripts" in f.message for f in r3.reviews),
        f"got {[f.message for f in r3.reviews]}",
    )

    # ── release age flag ─────────────────────────────────────────────────
    def packument_fresh(name: str) -> dict | None:
        return {
            "time": {
                "created": "2020-01-01T00:00:00.000Z",
                "9.9.9": "2026-07-28T00:00:00.000Z",  # 1 day before fixed_now
            },
            "versions": {"9.9.9": {"_npmUser": {"name": "bob"}}},
        }

    head_fresh = parse_pnpm_lock(
        _fixture_pnpm({"fresh-pkg@9.9.9": {"integrity": "sha512-YYY"}})
    )
    r4 = compare_pins(
        base_empty,
        head_fresh,
        lockfile="pnpm-lock.yaml",
        fetch=packument_fresh,
        now=fixed_now,
    )
    expect(
        "version age flag",
        any("published" in f.message and "threshold" in f.message for f in r4.reviews),
        f"got {[f.message for f in r4.reviews]}",
    )

    # ── package age flag ─────────────────────────────────────────────────
    def packument_brand_new(name: str) -> dict | None:
        return {
            "time": {
                "created": "2026-07-20T00:00:00.000Z",  # 9 days old
                "0.0.1": "2026-07-20T00:00:00.000Z",
            },
            "versions": {"0.0.1": {"_npmUser": {"name": "carol"}}},
        }

    head_newpkg = parse_pnpm_lock(
        _fixture_pnpm({"brand-new@0.0.1": {"integrity": "sha512-ZZZ"}})
    )
    r5 = compare_pins(
        base_empty,
        head_newpkg,
        lockfile="pnpm-lock.yaml",
        fetch=packument_brand_new,
        now=fixed_now,
    )
    expect(
        "package age flag",
        any("first published" in f.message for f in r5.reviews),
        f"got {[f.message for f in r5.reviews]}",
    )

    # ── publisher change ─────────────────────────────────────────────────
    def packument_handoff(name: str) -> dict | None:
        return {
            "time": {
                "created": "2020-01-01T00:00:00.000Z",
                "1.0.0": "2024-01-01T00:00:00.000Z",
                "2.0.0": "2025-06-01T00:00:00.000Z",
            },
            "versions": {
                "1.0.0": {"_npmUser": {"name": "original-owner"}},
                "2.0.0": {"_npmUser": {"name": "new-owner"}},
            },
        }

    base_v1 = parse_pnpm_lock(
        _fixture_pnpm({"handoff@1.0.0": {"integrity": "sha512-OLD"}})
    )
    head_v2 = parse_pnpm_lock(
        _fixture_pnpm({"handoff@2.0.0": {"integrity": "sha512-NEW"}})
    )
    r6 = compare_pins(
        base_v1,
        head_v2,
        lockfile="pnpm-lock.yaml",
        fetch=packument_handoff,
        now=fixed_now,
    )
    expect(
        "publisher change flag",
        any("publisher changed" in f.message for f in r6.reviews),
        f"got {[f.message for f in r6.reviews]}",
    )
    expect("version change not tamper", len(r6.tampers) == 0, f"got {r6.tampers}")

    # ── fail-closed registry ─────────────────────────────────────────────
    def packument_down(_name: str) -> dict | None:
        return None

    head_any = parse_pnpm_lock(
        _fixture_pnpm({"mystery@1.0.0": {"integrity": "sha512-???"}})
    )
    r7 = compare_pins(
        base_empty,
        head_any,
        lockfile="pnpm-lock.yaml",
        fetch=packument_down,
        now=fixed_now,
    )
    expect(
        "fail-closed registry",
        any("fail-closed" in f.message for f in r7.reviews),
        f"got {[f.message for f in r7.reviews]}",
    )

    # ── assess_package unit: clean old package ───────────────────────────
    clean_reasons = assess_package(
        "left-pad",
        "1.3.0",
        previous_version=None,
        packument={
            "time": {
                "created": "2015-01-01T00:00:00.000Z",
                "1.3.0": "2018-01-01T00:00:00.000Z",
            },
            "versions": {"1.3.0": {"_npmUser": {"name": "old"}, "scripts": {"test": "true"}}},
        },
        now=fixed_now,
    )
    expect("clean package no flags", clean_reasons == [], f"got {clean_reasons}")

    # ── name/version split edge cases ────────────────────────────────────
    expect("split plain", split_name_version("foo@1.0.0") == ("foo", "1.0.0"))
    expect(
        "split scoped",
        split_name_version("@scope/foo@1.0.0") == ("@scope/foo", "1.0.0"),
    )
    expect(
        "split peer suffix",
        split_name_version("foo@1.0.0(bar@2.0.0)") == ("foo", "1.0.0"),
    )

    if failures:
        print("self-test FAILED:\n")
        for line in failures:
            print(f"  - {line}")
        return 1
    print(
        "self-test OK — tamper, install scripts, release age, package age, "
        "publisher change, and fail-closed registry rules all fire."
    )
    return 0


# ── CLI ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base",
        help="git ref to diff lockfiles against (e.g. origin/main)",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="repo root (default: parent of scripts/)",
    )
    parser.add_argument(
        "--skip-registry",
        action="store_true",
        help="only run tamper checks (no registry metadata fetch)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove each rule fires on offline fixtures",
    )
    parser.add_argument(
        "--base-lock",
        type=Path,
        help="direct path to base lockfile (pair with --head-lock; skips git)",
    )
    parser.add_argument(
        "--head-lock",
        type=Path,
        help="direct path to head lockfile",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.base_lock or args.head_lock:
        if not (args.base_lock and args.head_lock):
            print("error: --base-lock and --head-lock must be used together", file=sys.stderr)
            return 2
        base_pins = parse_lockfile(str(args.base_lock), args.base_lock.read_text())
        head_pins = parse_lockfile(str(args.head_lock), args.head_lock.read_text())
        report = compare_pins(
            base_pins,
            head_pins,
            lockfile=str(args.head_lock),
            fetch=default_fetch_packument,
            skip_registry=args.skip_registry,
        )
    else:
        if not args.base and not args.skip_registry:
            # Without a base we can only review the whole lockfile as "added",
            # which is noisy. Require --base for PR mode.
            print(
                "error: --base is required (PR base ref). "
                "Use --skip-registry with --base for tamper-only.",
                file=sys.stderr,
            )
            return 2
        report = review_repo(
            args.root.resolve(),
            base_ref=args.base,
            skip_registry=args.skip_registry,
        )

    allowlist = load_review_allowlist()
    allowlist_notes = apply_review_allowlist(report, allowlist)

    write_step_summary(report, sys.stdout, allowlist_notes=allowlist_notes)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as fh:
            write_step_summary(report, fh, allowlist_notes=allowlist_notes)

    if report.tampers:
        print(
            f"\nBLOCKED: {len(report.tampers)} lockfile tamper finding(s).",
            file=sys.stderr,
        )
        return 1
    if report.reviews:
        print(
            f"\nBLOCKED: {len(report.reviews)} package(s) flagged for human review.",
            file=sys.stderr,
        )
        return 1
    if allowlist_notes:
        print(
            f"\nOK: no lockfile tamper; {len(allowlist_notes)} review flag(s) "
            "covered by docs/security/dependency-review-allowlist.json."
        )
    else:
        print("\nOK: no lockfile tamper, no review flags.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

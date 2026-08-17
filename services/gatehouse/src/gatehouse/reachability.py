"""Import-level reachability for SCA findings (AIM-327).

Trivy (and every other lockfile scanner) reports *present* vulnerabilities.
Most of those packages are never imported by first-party code, so treating
every lockfile CVE as a merge blocker floods the queue with noise and trains
engineers to ignore the gate.

This module answers a narrower question: **does first-party source import the
vulnerable package?** That is import-level reachability — not call-graph
taint, not "does the vulnerable function execute". It is the precision bar
the scorecard asks for: unreachable findings stay visible and land on the
bus, but they never fail the check.

Ecosystems covered first (charter): npm (package-lock / yarn / pnpm) and pip
(requirements / poetry / Pipfile). Everything else returns `unknown` with an
explicit reason rather than a silent "reachable" default — fail-open on the
block decision only when we *know* the import is unused; uncertainty still
may block at the severity threshold.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

# Verdicts written onto finding.labels["reachability"] and the bus.
REACHABLE = "reachable"
UNREACHABLE = "unreachable"
UNKNOWN = "unknown"

# First-party source we walk. Manifests and generated trees are excluded so a
# package name appearing only inside package-lock.json never counts as an import.
_SOURCE_EXTS = {
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
    ".py", ".pyi",
}
_SKIP_DIR_NAMES = {
    ".git", ".hg", ".svn",
    "node_modules", "bower_components",
    ".venv", "venv", "env", ".tox", ".mypy_cache", ".pytest_cache",
    "__pycache__", ".eggs", "dist", "build", "coverage",
    "vendor", "third_party", "third-party",
    ".gatehouse-cache",
}

# npm: require("x"), import … from "x", import("x"), export … from "x"
# Captures bare and scoped names; subpath imports (`lodash/get`) still match
# the package name via the prefix check in `_js_imported`.
_JS_IMPORT_RE = re.compile(
    r"""(?:import|export)(?:\s+[^'"\n]*?\s+from\s+|\s*\(\s*)['"]([^'"]+)['"]"""
    r"""|require\s*\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""|from\s+['"]([^'"]+)['"]""",
    re.MULTILINE,
)

# pip: `import foo`, `from foo import …`, `from foo.bar import …`
_PY_IMPORT_RE = re.compile(
    r"""^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*))""",
    re.MULTILINE,
)

# Common PyPI distribution name → import root mismatches. Extend as we hit them;
# unknown names fall back to dash→underscore.
_PY_IMPORT_ALIASES: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "python-dateutil": ("dateutil",),
    "pillow": ("PIL",),
    "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",),
    "beautifulsoup4": ("bs4",),
    "scikit-learn": ("sklearn",),
    "msgpack-python": ("msgpack",),
    "protobuf": ("google.protobuf", "google"),
    "attrs": ("attr", "attrs"),
    "typing-extensions": ("typing_extensions",),
}

_NPM_MANIFESTS = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "package.json",
}
_PIP_MANIFESTS = {
    "requirements.txt", "poetry.lock", "pipfile.lock", "pipfile",
    "pyproject.toml",
}


@dataclass(frozen=True)
class Reachability:
    """Import-level verdict for one vulnerable package in one checkout."""

    verdict: str  # reachable | unreachable | unknown
    evidence: str  # short, human + machine readable; no source content
    dep_path: str  # e.g. "package.json → express → lodash"


def ecosystem_for(manifest_path: str) -> str:
    """`npm`, `pip`, or `other` based on the lockfile/manifest basename."""
    name = os.path.basename(manifest_path).lower()
    if name in _NPM_MANIFESTS:
        return "npm"
    if name in _PIP_MANIFESTS or name.startswith("requirements"):
        return "pip"
    return "other"


def analyze(repo_dir: str, package: str, manifest_path: str,
            *, installed_version: str = "") -> Reachability:
    """Decide import-level reachability for `package` under `repo_dir`.

    `manifest_path` is the trivy target (lockfile) the CVE was found in — it
    selects the ecosystem and seeds the dependency-path string. Missing or
    empty package names are `unknown`, never `unreachable`: we refuse to
    green-light a finding we could not even name.
    """
    package = (package or "").strip()
    if not package:
        return Reachability(UNKNOWN, "package name missing from scanner output",
                            dep_path=_dep_path(manifest_path, "?", installed_version))

    eco = ecosystem_for(manifest_path)
    dep_path = dependency_path(repo_dir, package, manifest_path, installed_version)

    if eco == "other":
        return Reachability(
            UNKNOWN,
            f"import-level reachability not implemented for this ecosystem "
            f"({os.path.basename(manifest_path) or 'unknown manifest'}); "
            f"npm + pip first (AIM-327)",
            dep_path=dep_path,
        )

    if eco == "npm":
        hit = _find_js_import(repo_dir, package)
        if hit is not None:
            path, line, form = hit
            return Reachability(
                REACHABLE,
                f"first-party import of {package!r} at {path}:{line} ({form})",
                dep_path=dep_path,
            )
        return Reachability(
            UNREACHABLE,
            f"no first-party JS/TS import of {package!r}; "
            f"present only via {os.path.basename(manifest_path) or 'lockfile'}",
            dep_path=dep_path,
        )

    # pip
    roots = _python_import_roots(package)
    hit = _find_py_import(repo_dir, roots)
    if hit is not None:
        path, line, form = hit
        return Reachability(
            REACHABLE,
            f"first-party import of {package!r} (as {form}) at {path}:{line}",
            dep_path=dep_path,
        )
    return Reachability(
        UNREACHABLE,
        f"no first-party Python import of {package!r} "
        f"(tried: {', '.join(roots)}); "
        f"present only via {os.path.basename(manifest_path) or 'lockfile'}",
        dep_path=dep_path,
    )


def dependency_path(repo_dir: str, package: str, manifest_path: str,
                    installed_version: str = "") -> str:
    """Best-effort chain from the project root to the vulnerable package.

    Prefer a real reverse edge from the lockfile when one is cheap to read;
    otherwise report honesty (`direct` vs `transitive`) rather than invent a
    multi-hop path we did not compute.
    """
    base = _dep_path(manifest_path, package, installed_version)
    if not repo_dir or not package:
        return base

    eco = ecosystem_for(manifest_path)
    abs_manifest = os.path.join(repo_dir, manifest_path) if not os.path.isabs(manifest_path) else manifest_path
    # Prefer walking the concrete lockfile trivy named; fall back to common roots.
    candidates = [abs_manifest]
    if eco == "npm":
        candidates.extend(
            os.path.join(repo_dir, p)
            for p in ("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock")
        )
    elif eco == "pip":
        candidates.extend(
            os.path.join(repo_dir, p)
            for p in ("requirements.txt", "requirements-dev.txt", "poetry.lock",
                      "Pipfile.lock", "pyproject.toml")
        )

    seen: set[str] = set()
    for path in candidates:
        if not path or path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        rel = os.path.relpath(path, repo_dir).replace("\\", "/")
        if eco == "npm":
            chain = _npm_chain(path, package)
            if chain:
                return " → ".join([rel, *chain])
        elif eco == "pip":
            chain = _pip_chain(path, package)
            if chain:
                return " → ".join([rel, *chain])
    return base


def _dep_path(manifest_path: str, package: str, installed_version: str) -> str:
    leaf = package if not installed_version else f"{package}@{installed_version}"
    manifest = os.path.basename(manifest_path) or "lockfile"
    return f"{manifest} → {leaf}"


# ---------------------------------------------------------------------------
# Source walk + import matchers
# ---------------------------------------------------------------------------


def _iter_source_files(repo_dir: str):
    """Yield repo-relative POSIX paths of first-party source files."""
    repo_dir = os.path.abspath(repo_dir)
    for root, dirnames, filenames in os.walk(repo_dir):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIR_NAMES and not d.startswith(".")]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in _SOURCE_EXTS:
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, repo_dir).replace("\\", "/")
            yield rel, full


def _find_js_import(repo_dir: str, package: str) -> tuple[str, int, str] | None:
    for rel, full in _iter_source_files(repo_dir):
        if not rel.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")):
            continue
        try:
            text = open(full, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for match in _JS_IMPORT_RE.finditer(text):
            spec = next(g for g in match.groups() if g)
            if _js_spec_matches(spec, package):
                line = text.count("\n", 0, match.start()) + 1
                return rel, line, f"import/require {spec!r}"
    return None


def _js_spec_matches(spec: str, package: str) -> bool:
    """True when an import specifier refers to `package` (incl. subpaths)."""
    if not spec or spec.startswith(".") or spec.startswith("/"):
        return False  # relative / absolute — not a dependency name
    if package.startswith("@"):
        # scoped: @scope/name or @scope/name/sub
        return spec == package or spec.startswith(package + "/")
    # unscoped: exact, subpath, or (rarely) the package as a path segment only at start
    return spec == package or spec.startswith(package + "/")


def _python_import_roots(package: str) -> tuple[str, ...]:
    norm = package.lower().replace("_", "-")
    if norm in _PY_IMPORT_ALIASES:
        return _PY_IMPORT_ALIASES[norm]
    # PEP 503 normalized name → typical import: dashes become underscores.
    root = package.replace("-", "_")
    # Also try the raw name when it already looks like an identifier.
    if root != package:
        return (root, package.replace("-", ""))
    return (root,)


def _find_py_import(repo_dir: str, roots: tuple[str, ...]) -> tuple[str, int, str] | None:
    root_set = {r.split(".", 1)[0] for r in roots}
    for rel, full in _iter_source_files(repo_dir):
        if not rel.endswith((".py", ".pyi")):
            continue
        try:
            text = open(full, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for match in _PY_IMPORT_RE.finditer(text):
            if match.group(1):
                top = match.group(1).split(".", 1)[0]
                if top in root_set:
                    line = text.count("\n", 0, match.start()) + 1
                    return rel, line, match.group(1)
            if match.group(2):
                for part in match.group(2).split(","):
                    name = part.strip().split(" as ", 1)[0].strip()
                    top = name.split(".", 1)[0]
                    if top in root_set:
                        line = text.count("\n", 0, match.start()) + 1
                        return rel, line, name
    return None


# ---------------------------------------------------------------------------
# Dependency-path helpers (lockfile reverse edges, best-effort)
# ---------------------------------------------------------------------------


def _npm_chain(path: str, package: str) -> list[str] | None:
    """Return a short chain ending at `package`, or None if not found."""
    base = os.path.basename(path).lower()
    try:
        if base == "package.json":
            data = json.loads(open(path, encoding="utf-8").read())
            for section in ("dependencies", "devDependencies", "optionalDependencies",
                            "peerDependencies"):
                deps = data.get(section) or {}
                if package in deps:
                    return [package]
            return None
        if base == "package-lock.json":
            data = json.loads(open(path, encoding="utf-8").read())
            packages = data.get("packages") or {}
            # Direct dependency on the root package entry.
            root_deps = (packages.get("") or {}).get("dependencies") or {}
            root_deps = {**root_deps, **((packages.get("") or {}).get("devDependencies") or {})}
            if package in root_deps:
                return [package]
            # One reverse hop: who lists this package as a dependency?
            needle = f"node_modules/{package}"
            if package.startswith("@"):
                needle = f"node_modules/{package}"
            if needle not in packages and f"node_modules/{package}" not in packages:
                # Still report transitive if the package entry exists under any key.
                present = any(
                    k == f"node_modules/{package}" or k.endswith(f"/node_modules/{package}")
                    for k in packages
                )
                if not present and package not in (data.get("dependencies") or {}):
                    return None
            for key, meta in packages.items():
                if not key or not isinstance(meta, dict):
                    continue
                deps = meta.get("dependencies") or {}
                if package in deps:
                    parent = key.removeprefix("node_modules/").split("/node_modules/")[-1]
                    if parent and parent != package:
                        return [parent, package]
            return [f"(transitive) {package}"]
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return None


def _pip_chain(path: str, package: str) -> list[str] | None:
    base = os.path.basename(path).lower()
    norm = _pep503(package)
    try:
        if base.startswith("requirements") and base.endswith(".txt"):
            text = open(path, encoding="utf-8", errors="replace").read()
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # requirement line: name[extras]operator version
                name = re.split(r"[<>=!~;\s\[]", line, maxsplit=1)[0].strip()
                if _pep503(name) == norm:
                    return [package]
            return None
        if base == "poetry.lock":
            # Minimal TOML scrape — avoid a tomllib dependency on partial files.
            text = open(path, encoding="utf-8", errors="replace").read()
            # [[package]] / name = "foo"
            names = re.findall(r'(?m)^name\s*=\s*"([^"]+)"', text)
            if any(_pep503(n) == norm for n in names):
                # poetry.lock has no cheap reverse edge without full parse; mark present.
                return [f"(lockfile) {package}"]
            return None
        if base == "pipfile.lock":
            data = json.loads(open(path, encoding="utf-8").read())
            for section in ("default", "develop"):
                block = data.get(section) or {}
                for name in block:
                    if _pep503(name) == norm:
                        return [package]
            return None
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return None


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").lower())

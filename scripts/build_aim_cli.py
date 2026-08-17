#!/usr/bin/env python3
"""Build the packaged `aim` CLI — wheel + sdist, stdlib only.

One command produces both artifacts::

    python3 scripts/build_aim_cli.py

Output lands in ``packaging/aim-cli/dist/`` (names follow the PEP 621 project
name in ``packaging/aim-cli/pyproject.toml``, currently
``aimonitoring-security`` → normalized wheel
``aimonitoring_security-<version>-py3-none-any.whl``)::

    aimonitoring_security-<version>-py3-none-any.whl
    aimonitoring_security-<version>.tar.gz

Why a hand-rolled builder instead of `python -m build`:

  * Security bar: versioned, auditable artifacts, no `curl | sh`,
    stdlib-only runtime. This script depends on nothing outside the standard
    library, so an IT admin can build the mirror artifact on an air-gapped box
    with a bare Python — no pip, no setuptools, no network.
  * A wheel is just a zip with a defined layout and an sdist just a tar.gz;
    both are ~150 lines of readable stdlib here, fully auditable.
  * The build is deterministic (sorted entries, fixed mtime), so the same
    source yields a byte-identical artifact — reproducible by construction.

The package version and name are read from packaging/aim-cli/pyproject.toml,
the single source of truth. Collector source is vendored verbatim (no
binaries) into src/aim/_vendor/ preserving the monorepo-relative layout the
collectors walk up to discover.

The *distribution* name may be ``aimonitoring-security`` (public PyPI)
while the import package and console script remain ``aim``.
"""

import base64
import hashlib
import io
import os
import re
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - older interpreters
    tomllib = None

REPO = Path(__file__).resolve().parents[1]
PKG_ROOT = REPO / "packaging" / "aim-cli"
SRC = PKG_ROOT / "src"
VENDOR = SRC / "aim" / "_vendor"
DIST = PKG_ROOT / "dist"

# Deterministic timestamp for every archive member (reproducible builds).
# Honors SOURCE_DATE_EPOCH when set, else a fixed epoch.
_EPOCH = int(os.environ.get("SOURCE_DATE_EPOCH", "1700000000"))
_ZIP_DATE = (2023, 11, 14, 0, 0, 0)  # matches _EPOCH, in UTC, for zip members

# What to vendor: (source dir in repo, destination under _vendor). Only the
# collector *packages* and the dashboard static root are copied — no tests,
# no __pycache__, no build cruft. The relative shape under _vendor mirrors the
# monorepo so the collectors' own walk-up discovery runs unchanged.
VENDOR_MAP = [
    ("collectors/claude-code/aim_collector", "collectors/claude-code/aim_collector"),
    ("collectors/cursor/cursor_collector", "collectors/cursor/cursor_collector"),
    ("collectors/kilo-code/kilo_collector", "collectors/kilo-code/kilo_collector"),
    ("collectors/kimi-code/kimi_collector", "collectors/kimi-code/kimi_collector"),
    ("collectors/grok-build/grok_collector", "collectors/grok-build/grok_collector"),
    ("collectors/github-copilot/copilot_collector", "collectors/github-copilot/copilot_collector"),
    ("apps/web/public", "apps/web/public"),
]

# Extensions to skip when copying collector python packages.
_SKIP_DIRS = {"__pycache__", "tests", ".pytest_cache"}
_SKIP_SUFFIXES = {".pyc", ".pyo"}


def _read_project() -> dict:
    text = (PKG_ROOT / "pyproject.toml").read_text()
    if tomllib is not None:
        return tomllib.loads(text)["project"]
    # Minimal fallback: pull name/version by line scan (build hosts are 3.11+).
    proj = {}
    for line in text.splitlines():
        for key in ("name", "version", "description", "requires-python"):
            token = key.replace("requires-python", "requires-python")
            if line.strip().startswith(f"{token} ="):
                proj[key] = line.split("=", 1)[1].strip().strip('"')
    return proj


def _normalize_dist_name(name: str) -> str:
    """PEP 427 / packaging: non-alphanumeric runs → single underscore, lower."""
    return re.sub(r"[-_.]+", "_", name).lower()


def _clean_vendor() -> None:
    if VENDOR.exists():
        shutil.rmtree(VENDOR)
    VENDOR.mkdir(parents=True)


def _copy_tree(src: Path, dst: Path) -> int:
    """Copy src → dst, skipping caches/tests/compiled files. Returns file count."""
    count = 0
    for root, dirs, files in os.walk(src):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        rel = Path(root).relative_to(src)
        for name in sorted(files):
            if Path(name).suffix in _SKIP_SUFFIXES:
                continue
            out = dst / rel / name
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(Path(root) / name, out)
            count += 1
    return count


def vendor_collectors() -> int:
    _clean_vendor()
    total = 0
    for src_rel, dst_rel in VENDOR_MAP:
        src = REPO / src_rel
        if not src.is_dir():
            sys.exit(f"build: expected source dir missing: {src_rel}")
        n = _copy_tree(src, VENDOR / dst_rel)
        print(f"  vendored {n:>4} files  {src_rel} -> _vendor/{dst_rel}")
        total += n
    # Marker so provenance is obvious inside an installed artifact.
    (VENDOR / "VENDORED.txt").write_text(
        "Collector source vendored verbatim from the ai-monitoring monorepo "
        "by scripts/build_aim_cli.py.\nStdlib-only; no binaries.\n")
    return total


def _iter_files(root: Path):
    for p in sorted(root.rglob("*")):
        if p.is_file():
            yield p


def _record_line(arcname: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"{arcname},sha256={digest.decode()},{len(data)}"


# packaging floor. Keep in lockstep with
# packaging/aim-cli/pyproject.toml `requires-python` and aim.MIN_PYTHON.
REQUIRED_PYTHON = ">=3.11"


def _assert_python_floor(proj: dict) -> None:
    """Fail the build if requires-python drifts below the product floor.

    CI's aim-package job runs this builder on Python 3.11; pinning the
    declared floor here means a silent reversion to ``>=3.8`` cannot ship
    without breaking the wheel build (and unit tests cover the same string).
    Kept outside ``.github/`` so auto-merge is not refused for refuse_paths.
    """
    req = (proj.get("requires-python") or "").strip()
    if req != REQUIRED_PYTHON:
        raise SystemExit(
            f"packaging/aim-cli requires-python must be "
            f"{REQUIRED_PYTHON!r} (got {req!r}). Hard-require 3.11+ so "
            f"pip install refuses on 3.9/3.10 instead of mid-join TypeError."
        )


def _assert_version_sync(proj: dict) -> None:
    """Fail the build if ``aim.__version__`` disagrees with pyproject.

    The builder reads the version from pyproject but copies ``__init__.py``
    verbatim, so a bump in one place and not the other ships a wheel whose
    dist-info and ``aim --version`` disagree. 0.1.2 was built that way before
    this check existed.
    """
    declared = (proj.get("version") or "").strip()
    init = SRC / "aim" / "__init__.py"
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', init.read_text(), re.M)
    if match is None:
        raise SystemExit(f"no __version__ found in {init}")
    if match.group(1) != declared:
        raise SystemExit(
            f"version drift: pyproject says {declared!r} but "
            f"{init.relative_to(REPO)} says {match.group(1)!r}. Bump both — "
            f"dist-info and `aim --version` must agree."
        )


def _metadata(proj: dict) -> str:
    """PEP 566 metadata. Long description is the packaging README."""
    readme = (PKG_ROOT / "README.md").read_text()
    fields = [
        "Metadata-Version: 2.1",
        f"Name: {proj['name']}",
        f"Version: {proj['version']}",
        f"Summary: {proj.get('description', '')}",
        f"Requires-Python: {proj.get('requires-python', REQUIRED_PYTHON)}",
        "License: Apache-2.0",
        "Home-page: https://github.com/hawikk/aim",
        "Project-URL: GitHub Releases, https://github.com/hawikk/aim/releases",
        "Project-URL: Repository, https://github.com/hawikk/aim",
        "Classifier: License :: OSI Approved :: Apache Software License",
        "Classifier: Programming Language :: Python :: 3",
        "Classifier: Intended Audience :: Developers",
        "Classifier: Topic :: Security",
        "Description-Content-Type: text/markdown",
        "",
        readme,
    ]
    return "\n".join(fields)



def build_wheel(proj: dict) -> Path:
    name, version = proj["name"], proj["version"]
    nname = _normalize_dist_name(name)
    distinfo = f"{nname}-{version}.dist-info"
    wheel_name = f"{nname}-{version}-py3-none-any.whl"
    DIST.mkdir(parents=True, exist_ok=True)
    out = DIST / wheel_name

    members: list[tuple[str, bytes]] = []
    # 1. package payload: everything under src/aim/
    pkg_src = SRC / "aim"
    for f in _iter_files(pkg_src):
        arc = f"aim/{f.relative_to(pkg_src).as_posix()}"
        members.append((arc, f.read_bytes()))
    # 2. dist-info metadata
    members.append((f"{distinfo}/METADATA", _metadata(proj).encode()))
    members.append((f"{distinfo}/WHEEL",
                    ("Wheel-Version: 1.0\n"
                     "Generator: aim-build (stdlib)\n"
                     "Root-Is-Purelib: true\n"
                     "Tag: py3-none-any\n").encode()))
    members.append((f"{distinfo}/entry_points.txt",
                    "[console_scripts]\naim = aim.cli:main\n".encode()))

    # 3. RECORD (references every member; its own hash/size are blank)
    record = [_record_line(arc, data) for arc, data in members]
    record.append(f"{distinfo}/RECORD,,")
    members.append((f"{distinfo}/RECORD", ("\n".join(record) + "\n").encode()))

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, data in members:
            info = zipfile.ZipInfo(arc, date_time=_ZIP_DATE)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    return out


def build_sdist(proj: dict) -> Path:
    name, version = proj["name"], proj["version"]
    nname = _normalize_dist_name(name)
    base = f"{nname}-{version}"
    out = DIST / f"{base}.tar.gz"
    DIST.mkdir(parents=True, exist_ok=True)

    # Files that make the sdist buildable/auditable: project config, readme,
    # the full src tree (including vendored collectors), and PKG-INFO.
    include_roots = [PKG_ROOT / "pyproject.toml", PKG_ROOT / "README.md", SRC]
    entries: list[tuple[str, bytes]] = []
    for root in include_roots:
        if root.is_file():
            entries.append((f"{base}/{root.relative_to(PKG_ROOT).as_posix()}",
                            root.read_bytes()))
        else:
            for f in _iter_files(root):
                entries.append((f"{base}/{f.relative_to(PKG_ROOT).as_posix()}",
                                f.read_bytes()))
    entries.append((f"{base}/PKG-INFO", _metadata(proj).encode()))
    entries.sort(key=lambda e: e[0])

    with tarfile.open(out, "w:gz", format=tarfile.PAX_FORMAT) as tf:
        for arc, data in entries:
            ti = tarfile.TarInfo(arc)
            ti.size = len(data)
            ti.mtime = _EPOCH
            ti.mode = 0o644
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            tf.addfile(ti, io.BytesIO(data))
    return out


def main() -> int:
    proj = _read_project()
    _assert_python_floor(proj)
    _assert_version_sync(proj)
    nname = _normalize_dist_name(proj["name"])
    print(f"building {proj['name']} {proj['version']} "
          f"(console script: aim; stdlib builder)")
    total = vendor_collectors()
    print(f"  vendored {total} collector files total")
    # Fresh dist/ so stale aim-*.whl from prior names cannot leak into CI.
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)
    wheel = build_wheel(proj)
    sdist = build_sdist(proj)
    print(f"\nwrote {wheel.relative_to(REPO)}  ({wheel.stat().st_size} bytes)")
    print(f"wrote {sdist.relative_to(REPO)}  ({sdist.stat().st_size} bytes)")
    print(f"\nversion: {proj['version']}  (embedded; `aim version` will report it)")
    print(f"dist name: {proj['name']}  (normalized: {nname})")
    print("install offline:  pipx install " + str(wheel.relative_to(REPO)))
    print("install public:   pipx install aimonitoring-security")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

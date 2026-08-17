#!/usr/bin/env python3
"""Build AIM-510 PyPI stub(s) and verify the security acceptance gates.

Gates (must all pass before upload):
1. Package builds to sdist + wheel at version 0.0.1.
2. No console-script entry points named `aim` (or any entry points at all).
3. No product source trees (collectors, services, apps, aim CLI modules).
4. Wheel METADATA / README text points at GitHub Releases.
5. Clean venv install succeeds and puts no `aim` on PATH.

Stdlib-only where possible; uses `python -m build` if available, else
setuptools' own build backend via pip wheel.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]  # repo root
STUBS = ROOT / "packaging" / "pypi-stubs"
# Board-configured name after PyPI similarity block on aimonitoring/aim-monitoring.
PACKAGES = ("aimonitoring-security",)
# Import / distribution names used in the clean-install gate.
PRIMARY_DIST = "aimonitoring-security"
PRIMARY_IMPORT = "aimonitoring_security"
VERSION = "0.0.1"
RELEASE_URL_NEEDLE = "github.com/hawikk/aim/releases"

# Paths that must NEVER appear inside a stub artifact.
PRODUCT_PATH_MARKERS = (
    "collectors/",
    "services/",
    "apps/",
    "aim/cli",
    "aim/_vendor",
    "aim_collector",
    "cursor_collector",
    "kilo_collector",
    "kimi_collector",
)


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, text=True, **kwargs)


def ensure_build_python(work: Path) -> str:
    """Return a python that has the `build` package (PEP 668-safe via venv)."""
    # Fast path: host already has it (CI after `pip install build`).
    probe = subprocess.run(
        [sys.executable, "-c", "import build"],
        capture_output=True,
        text=True,
    )
    if probe.returncode == 0:
        return sys.executable
    venv = work / "build-tools"
    if not (venv / "bin" / "python").exists():
        run([sys.executable, "-m", "venv", str(venv)])
        run([str(venv / "bin" / "pip"), "install", "--quiet", "--upgrade", "pip", "build"])
    return str(venv / "bin" / "python")


def build_one(pkg: str, out_dir: Path, build_python: str) -> list[Path]:
    src = STUBS / pkg
    if not (src / "pyproject.toml").is_file():
        raise SystemExit(f"missing pyproject for {pkg}")
    dist = out_dir / pkg
    dist.mkdir(parents=True, exist_ok=True)
    run(
        [build_python, "-m", "build", "--outdir", str(dist), str(src)],
        cwd=str(ROOT),
    )
    artifacts = sorted(p for p in dist.iterdir() if p.is_file())
    if not artifacts:
        raise SystemExit(f"no artifacts produced for {pkg}")
    return artifacts


def inspect_wheel(wheel: Path) -> None:
    print(f"inspect {wheel.name}", flush=True)
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
        for marker in PRODUCT_PATH_MARKERS:
            hits = [n for n in names if marker in n]
            if hits:
                raise SystemExit(f"product path marker {marker!r} in {wheel.name}: {hits[:5]}")
        # Entry points: reject any console_scripts, especially `aim`.
        ep_files = [n for n in names if n.endswith("entry_points.txt")]
        for ep in ep_files:
            text = zf.read(ep).decode("utf-8", errors="replace")
            if text.strip():
                raise SystemExit(f"non-empty entry_points in {wheel.name}:\n{text}")
        # METADATA must mention the GitHub Releases trust anchor.
        meta_files = [n for n in names if n.endswith("METADATA")]
        if not meta_files:
            raise SystemExit(f"no METADATA in {wheel.name}")
        meta = zf.read(meta_files[0]).decode("utf-8", errors="replace")
        if RELEASE_URL_NEEDLE not in meta:
            raise SystemExit(
                f"{wheel.name} METADATA missing trust-anchor URL "
                f"({RELEASE_URL_NEEDLE})"
            )
        # Must not depend on the real `aim` package (AimStack).
        if re.search(r"(?im)^Requires-Dist:\s*aim\b", meta):
            raise SystemExit(f"{wheel.name} must not depend on the real aim package")
        if "aim = " in meta or "console_scripts" in meta.lower():
            raise SystemExit(f"{wheel.name} appears to declare console scripts")
        # Only the stub package modules + dist-info.
        py_files = [n for n in names if n.endswith(".py")]
        for py in py_files:
            base = Path(py).name
            if base not in ("__init__.py",):
                raise SystemExit(f"unexpected python module in stub wheel: {py}")


def clean_install_check(wheel: Path, work: Path) -> None:
    """Install primary stub wheel into a throwaway venv; assert no `aim` binary."""
    venv = work / "venv"
    run([sys.executable, "-m", "venv", str(venv)])
    pip = venv / "bin" / "pip"
    python = venv / "bin" / "python"
    run([str(pip), "install", "--quiet", str(wheel)])
    # pip show must mention GitHub Releases (Home-page and/or Project-URL).
    show = run([str(pip), "show", PRIMARY_DIST], capture_output=True)
    combined = (show.stdout or "") + (show.stderr or "")
    print(combined)
    if RELEASE_URL_NEEDLE not in combined:
        meta = run(
            [
                str(python),
                "-c",
                "import importlib.metadata as m; "
                f"print(m.metadata({PRIMARY_DIST!r}).get('Home-page','')); "
                f"print(m.metadata({PRIMARY_DIST!r}).get_all('Project-URL') or '')",
            ],
            capture_output=True,
        )
        meta_out = (meta.stdout or "") + (meta.stderr or "")
        print(meta_out)
        if RELEASE_URL_NEEDLE not in meta_out:
            raise SystemExit("installed package metadata missing GitHub Releases URL")
    # No aim executable on the venv PATH.
    aim_bin = venv / "bin" / "aim"
    if aim_bin.exists():
        raise SystemExit(f"stub install put `aim` on PATH: {aim_bin}")
    # Import works; version matches.
    run(
        [
            str(python),
            "-c",
            f"import {PRIMARY_IMPORT} as m; assert m.__version__ == {VERSION!r}",
        ]
    )
    # Ensure no console script entry points registered for this dist.
    eps = run(
        [
            str(python),
            "-c",
            "import importlib.metadata as m; "
            f"eps=list(m.distribution({PRIMARY_DIST!r}).entry_points); "
            "print(eps); assert eps == [], eps",
        ],
        capture_output=True,
    )
    print(eps.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--outdir",
        type=Path,
        default=STUBS / "dist",
        help="directory that receives built artifacts (default: packaging/pypi-stubs/dist)",
    )
    parser.add_argument(
        "--skip-install",
        action="store_true",
        help="skip the clean-venv install check (CI build-only steps)",
    )
    args = parser.parse_args()

    if args.outdir.exists():
        shutil.rmtree(args.outdir)
    args.outdir.mkdir(parents=True)

    expected = len(PACKAGES)
    with tempfile.TemporaryDirectory(prefix="aim-510-build-") as tools_td:
        build_python = ensure_build_python(Path(tools_td))
        all_artifacts: list[Path] = []
        for pkg in PACKAGES:
            arts = build_one(pkg, args.outdir, build_python)
            all_artifacts.extend(arts)

    wheels = [p for p in all_artifacts if p.suffix == ".whl"]
    sdists = [p for p in all_artifacts if p.name.endswith(".tar.gz")]
    if len(wheels) != expected or len(sdists) != expected:
        raise SystemExit(
            f"expected {expected} wheels + {expected} sdists, "
            f"got wheels={wheels} sdists={sdists}"
        )

    for w in wheels:
        if VERSION not in w.name:
            raise SystemExit(f"wheel version not {VERSION}: {w.name}")
        inspect_wheel(w)

    if not args.skip_install:
        # Wheel filenames normalize hyphens to underscores.
        primary_wheel = next(
            w
            for w in wheels
            if w.name.startswith(PRIMARY_DIST.replace("-", "_") + "-")
            or w.name.startswith(PRIMARY_DIST + "-")
        )
        with tempfile.TemporaryDirectory(prefix="aim-510-stub-") as td:
            clean_install_check(primary_wheel, Path(td))

    print("OK: stub build + security gates passed")
    for a in sorted(all_artifacts):
        print(" ", a.relative_to(ROOT) if a.is_relative_to(ROOT) else a)
    return 0


if __name__ == "__main__":
    # Path.is_relative_to is stdlib on the project floor (Python 3.11+).
    raise SystemExit(main())

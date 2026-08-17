"""Make `python -m pytest packaging/aim-cli/tests` work from the repo root:
put the package src dir on sys.path so `import aim` resolves against the
in-tree source (not an installed wheel), matching how the collector suites
run their own package from cwd."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

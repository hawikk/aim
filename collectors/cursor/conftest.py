"""Make `python -m pytest collectors/cursor/tests` work from the repo root:
put the collector package dir on sys.path so `import cursor_collector`
(and `from test_hook import ...` between test modules) resolves."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

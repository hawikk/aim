"""State directory: spool, checkpoint, config. Shares ~/.aim-collector."""

import json
import os
import uuid
from pathlib import Path

DEFAULT_DIR = "~/.aim-collector"


def state_dir() -> Path:
    p = Path(os.environ.get("AIM_STATE_DIR", DEFAULT_DIR)).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    return p


def host_id() -> str:
    """Stable per-machine id, generated once. Random UUID, not a hardware
    fingerprint."""
    f = state_dir() / "host_id"
    if f.exists():
        return f.read_text().strip()
    hid = str(uuid.uuid4())
    f.write_text(hid)
    return hid


def spool_path() -> Path:
    return state_dir() / "spool-copilot.jsonl"


def checkpoint_path() -> Path:
    return state_dir() / "checkpoint-copilot.json"


def load_checkpoint() -> dict:
    f = checkpoint_path()
    if f.exists():
        try:
            data = json.loads(f.read_text())
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    return {}


def save_checkpoint(cp: dict) -> None:
    tmp = checkpoint_path().with_suffix(".tmp")
    tmp.write_text(json.dumps(cp))
    os.replace(tmp, checkpoint_path())

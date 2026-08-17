"""Configuration. YAML on disk, environment for anything secret.

The one rule: a credential is never read from the config file. Tokens come from
the environment, so that the file describing our secret hygiene is not itself a
committed file full of secrets.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_STATE_DIR = os.environ.get("HYGIENE_STATE_DIR", "/var/lib/hygiene")

# The documented minimum for this stack's own GitHub token. gatehouse needs to
# read PR contents and write check runs; nothing in the stack needs to write
# repository contents, administer the org, or edit workflows. Anything beyond
# this list is what check 3 reports.
DEFAULT_MIN_SCOPES = ["repo:status", "read:org"]


@dataclass
class Config:
    repos: list[str] = field(default_factory=list)
    state_dir: str = DEFAULT_STATE_DIR
    retention_days: int = 30
    minimum_scopes: list[str] = field(default_factory=lambda: list(DEFAULT_MIN_SCOPES))
    ciem_base_url: str = ""
    gitleaks_config: str = ""
    liveness_enabled: bool = True
    report_dir: str = ""
    stream_key: str = ""

    @property
    def key_path(self) -> str:
        """The HMAC key, beside the state DB but in its own file — see
        models.load_or_create_key for why they are not in the same place."""
        return os.path.join(self.state_dir, "fingerprint.key")

    @property
    def db_path(self) -> str:
        return os.path.join(self.state_dir, "findings.db")

    @property
    def github_token(self) -> str:
        """Read-only by policy (D4). Never from the YAML file."""
        return os.environ.get("HYGIENE_GITHUB_TOKEN", "") or os.environ.get("GITHUB_TOKEN", "")


def load(path: str = "") -> Config:
    """Load config from YAML, letting the environment override.

    A missing file is fine — the defaults plus environment are a working
    configuration, which is what makes `hygiene scan ./repo` work with no setup.
    """
    data: dict = {}
    if path and os.path.exists(path):
        import yaml
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}

    scan = data.get("scan") or {}
    liveness = data.get("liveness") or {}
    integrations = data.get("integrations") or {}
    storage = data.get("storage") or {}

    config = Config(
        repos=list(scan.get("repos") or []),
        state_dir=str(storage.get("state_dir") or DEFAULT_STATE_DIR),
        retention_days=int(storage.get("retention_days") or 30),
        minimum_scopes=list(scan.get("minimum_scopes") or DEFAULT_MIN_SCOPES),
        ciem_base_url=str(integrations.get("ciem_base_url") or ""),
        gitleaks_config=str(scan.get("gitleaks_config") or ""),
        liveness_enabled=bool(liveness.get("enabled", True)),
        report_dir=str(storage.get("report_dir") or ""),
        stream_key=str((data.get("bus") or {}).get("stream_key") or ""),
    )
    if os.environ.get("HYGIENE_STATE_DIR"):
        config.state_dir = os.environ["HYGIENE_STATE_DIR"]
    if os.environ.get("CIEM_BASE_URL"):
        config.ciem_base_url = os.environ["CIEM_BASE_URL"]
    # The env kill switch can only ever turn liveness OFF, never on. A file
    # that says `enabled: false` is a decision someone made deliberately, and
    # an environment variable should not be able to quietly reverse it.
    if str(os.environ.get("HYGIENE_LIVENESS", "on")).lower() in ("off", "0", "false", "no"):
        config.liveness_enabled = False
    return config

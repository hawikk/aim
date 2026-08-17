"""The finding shape for pillar 4, and the two functions that decide what a
secret is allowed to turn into.

Everything this service produces passes through `Finding`. The rule that makes
that worth enforcing in one place: **a secret value never becomes a field.**
The scanner sees the credential because it must; `Finding` carries only

* `masked` — a human-recognizable stub, built by `mask()`, and
* `fingerprint` — a keyed one-way digest, built by `fingerprint()`.

Both are derived at the construction site and the raw value is dropped there.
`Finding` has no field a raw secret fits in, so "we accidentally logged it" is
a type error rather than an incident.

Why the fingerprint is *keyed* rather than a plain sha256: a large share of
real leaked credentials are low-entropy (`postgres://user:password@…`,
`admin123`, a 6-digit PIN). A plain sha256 of those is reversible by anyone
holding the database in about a second, which would make our "we only store a
hash" claim false in exactly the cases where it matters most. The HMAC key is
generated once per install, lives beside the state DB, and never leaves the
box — so a stolen findings table is not a secret-recovery oracle.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import stat
from dataclasses import dataclass, field

# Same scale as guardrail/bus.py and gatehouse/models.py, so all four pillars
# rank identically in one inbox (D3.1 §3.2).
SEVERITY_ID = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

# Prefixes that identify a credential's *issuer* without identifying the
# credential. Showing these is the whole point of masking: "rotate the thing
# behind AKIA…" is actionable, and the prefix is a public constant, not
# secret material. Ordered longest-first so `github_pat_` wins over `ghp_`.
_PUBLIC_PREFIXES = (
    "github_pat_", "sk_live_", "sk_test_", "xoxb-", "xoxp-", "xapp-",
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-",
    "AKIA", "ASIA", "ABIA", "ACCA", "A3T",
    "AIza", "ya29.", "eyJ", "-----BEGIN",
)

# Below this length, a first-4/last-4 mask leaks most of the value, so we show
# nothing but the length. 20 is deliberately conservative: an 16-char mask of a
# 20-char secret discloses 40% of it.
_MIN_LEN_FOR_TAIL = 20


def mask(value: str) -> str:
    """Render a secret as something recognizable but not usable.

    Two jobs, in priority order: (1) never disclose enough to authenticate,
    (2) tell the engineer *which system to go rotate*. The issuer prefix does
    job 2 and costs nothing, because `AKIA` is the same four characters in
    every AWS key on earth.

    The last four characters are shown only for values long enough that four
    characters are a negligible fraction — they exist so an engineer holding
    three AWS keys in a vault can tell which one this is.

        >>> mask("AKIA" + "2E0A8F3B244C9986")
        'AKIA…[12 more]…9986'
        >>> mask("hunter2")
        '…[7 chars redacted]…'

    The example key is split after its prefix so this docstring does not itself
    trip a secret scanner — gitleaks-action@v2's ruleset matches
    `AKIA[A-Z0-9]{16}`, and a docstring in the masking module is a silly place
    to fail the build.
    """
    text = (value or "").strip()
    if not text:
        return "…[empty]…"
    prefix = next((p for p in _PUBLIC_PREFIXES if text.startswith(p)), "")
    if len(text) < _MIN_LEN_FOR_TAIL:
        # Short or unrecognized: length only. A short secret cannot afford a
        # tail, and the length alone is not a credential.
        return f"{prefix}…[{len(text)} chars redacted]…" if prefix \
            else f"…[{len(text)} chars redacted]…"
    body = text[len(prefix):]
    return f"{prefix}…[{len(body) - 4} more]…{text[-4:]}"


def fingerprint(value: str, key: bytes) -> str:
    """Keyed, one-way, install-scoped identity for a secret value.

    Used to answer "is this the same credential we saw last week, and is it the
    same one that is in three other repos?" without keeping the credential.
    Truncated to 32 hex (128 bits) — collision-free at any scale this product
    will see, and short enough to read in a report.
    """
    return hmac.new(key, (value or "").strip().encode("utf-8", "replace"),
                    hashlib.sha256).hexdigest()[:32]


def load_or_create_key(path: str) -> bytes:
    """The per-install HMAC key. Created 0600 on first use, never rotated
    automatically (rotating it would orphan every existing fingerprint).

    Kept out of the state DB on purpose: a database file gets copied to a
    laptop for debugging far more often than a key file does, and separating
    them is what makes "a stolen findings table reveals nothing" true.
    """
    if os.path.exists(path):
        with open(path, "rb") as fh:
            key = fh.read().strip()
        if len(key) >= 32:
            return key
        raise ValueError(f"{path}: fingerprint key is too short ({len(key)} bytes); "
                         "refusing to fingerprint with a weak key")
    key = secrets.token_hex(32).encode("ascii")
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    # Create with the restrictive mode atomically rather than chmod-ing after:
    # between open() and chmod() the key is world-readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


@dataclass(frozen=True)
class Finding:
    """One hygiene finding. Three checks converge here before anything renders.

    There is no `secret`, `match`, `line_text` or `snippet` field, and that is
    the design: the report renderer, the bus publisher and the SQLite store all
    read `Finding` and cannot reach a raw value even by mistake.
    """

    check: str            # "history" | "worktree" | "tokens"
    rule_id: str          # gitleaks rule, or our own rule name
    finding_type: str     # secrets_hygiene.<something>
    title: str
    severity: str
    repo: str             # "hawikk/aim" or a local path label
    path: str = ""        # repo-relative POSIX path, when the finding has one
    line: int = 0
    commit: str = ""      # short sha for history findings
    author_date: str = "" # when the leak entered history — drives "how long exposed"
    masked: str = ""      # mask(secret); never the value
    fingerprint: str = "" # fingerprint(secret, key); never reversible off-box
    message: str = ""
    remediation: str = "" # copy-paste steps (D4: never executed by us)
    liveness: str = "unknown"   # "live" | "dead" | "unknown" | "not_checked"
    liveness_detail: str = ""   # e.g. the ARN STS returned — an identity, not a credential
    # Why we could not determine liveness, in prose. Its own field rather than
    # a label because labels are scrubbed for the bus (`safe_label` strips
    # spaces), and "could not verify (no read-only identity probe exists for
    # 'slack')" is the sentence an operator has to read in the report.
    liveness_reason: str = ""
    labels: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ID:
            raise ValueError(f"{self.check}: severity not normalized: {self.severity!r}")
        if self.liveness not in ("live", "dead", "unknown", "not_checked"):
            raise ValueError(f"{self.check}: bad liveness state: {self.liveness!r}")
        # A defense-in-depth check on the invariant this module exists to keep.
        # `masked` is the one field built from secret material; if a caller
        # hands it a raw value it will not contain the redaction marker.
        if self.masked and "…[" not in self.masked:
            raise ValueError(
                f"{self.check}/{self.rule_id}: `masked` was not produced by mask() — "
                "refusing to construct a Finding that may carry a raw secret")

    @property
    def severity_id(self) -> int:
        return SEVERITY_ID[self.severity]

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self.severity)

    @property
    def location(self) -> str:
        where = self.path or self.repo
        if self.line:
            where = f"{where}:{self.line}"
        if self.commit:
            where = f"{where}@{self.commit[:8]}"
        return where


def dedupe_key(finding: Finding) -> str:
    """Stable identity across runs, so a nightly scan does not re-open the same
    finding every night.

    Keyed on *what the problem is*, not on when we looked: repo, check, rule,
    path and the secret's fingerprint. Deliberately excludes the commit sha —
    the same leaked key reachable from two commits is one credential to rotate,
    not two — and excludes liveness, which is allowed to change from `unknown`
    to `live` without becoming a different finding.
    """
    material = "|".join((finding.repo, finding.check, finding.rule_id,
                         finding.path, finding.fingerprint))
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:32]


_SAFE_LABEL = re.compile(r"[^A-Za-z0-9._/-]")


def safe_label(text: str, limit: int = 128) -> str:
    """Scrub a value destined for a label or a report cell. Labels are rendered
    into Slack and into a check-run summary; a path is attacker-controlled
    (anyone who can open a PR picks the filename)."""
    return _SAFE_LABEL.sub("_", (text or ""))[:limit]

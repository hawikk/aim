"""Check 2 — the hygiene problems that are not "a secret matched a regex".

gitleaks answers "does a high-entropy credential appear here". Three real and
common failures slip straight past that question, and each one is in this
module because the seeded fixture proved gitleaks misses it:

* **A committed `.env`.** Every value in it is a credential by convention. Some
  match a rule; `DB_PASSWORD=hunter2` matches nothing, because it has no
  entropy and no issuer prefix. The *file being tracked at all* is the finding.
* **Inline credentials in config.** `postgres://acme_app:<pw>@db/acme` in a
  `database.yml` is a live database password. Verified against the fixture:
  gitleaks reports nothing for that line. A password with no format is
  invisible to a format scanner, which is why this check keys on *structure*
  (a userinfo field in a URL, a `password:` assignment) rather than on entropy.
* **A `.gitignore` that does not protect the obvious.** This is the only
  preventive finding the pillar produces — it is how the *next* leak does not
  happen, and it is worth more than any individual rotation.

Everything here works from `git ls-files`, not from a directory walk. That
distinction is the check: a `.env` sitting in a working directory is correct and
normal, and flagging it would train people to ignore us. A `.env` that git is
*tracking* is the incident. Only the second is reported.
"""

from __future__ import annotations

import os
import re
import subprocess

from .. import remediation
from ..models import Finding, fingerprint, mask, safe_label

ENV_FILE = "secrets_hygiene.committed_env_file"
INLINE = "secrets_hygiene.inline_credential"
GITIGNORE_GAP = "secrets_hygiene.gitignore_gap"

# Tracked files whose entire purpose is to hold secrets.
_ENV_NAMES = re.compile(
    r"(^|/)\.env(\.[A-Za-z0-9_-]+)?$|(^|/)\.envrc$|(^|/)secrets?\.(ya?ml|json|toml)$")
# …except the ones that exist to be committed. `.env.example` is good practice,
# not a finding; treating it as one is how a scanner loses its audience.
_ENV_TEMPLATE = re.compile(
    r"\.(example|sample|template|dist|defaults?)$|(^|/)\.env\.(example|sample|template|dist)$",
    re.IGNORECASE)

_CONFIG_SUFFIX = (".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
                  ".properties", ".xml", ".tf", ".tfvars", ".env", ".sh", ".py",
                  ".js", ".ts", ".rb", ".php", ".java", ".go")

# A credential in a connection string: `scheme://user:secret@host`. The
# userinfo password field is unambiguous — there is no benign reason for a
# non-placeholder value to sit there.
_URL_CRED = re.compile(
    r"\b(?P<scheme>[a-z][a-z0-9+.-]{1,15})://(?P<user>[^\s:/@]{1,64}):(?P<secret>[^\s/@]{3,256})@")

# `password: value`, `api_key = "value"`, `secret_key: value` and friends.
# Anchored on the *key name*, so a value with no format is still caught.
_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<key>[A-Za-z0-9_.-]*
        (?:pass(?:wd|word)?|secret|api[_-]?key|access[_-]?key|auth[_-]?token
           |client[_-]?secret|private[_-]?key|credential)
     [A-Za-z0-9_.-]*)
    \s*[:=]\s*
    (?P<quote>["']?)(?P<secret>[^\s"',;}\)]{6,256})(?P=quote)
    """)

# Values that are placeholders, not credentials. Missing any of these produces
# a report full of `password: <YOUR_PASSWORD>`, which is how a check gets
# switched off. Kept deliberately broad — a false negative here is one line in
# one config file; a false positive here costs us the whole check's credibility.
_PLACEHOLDER = re.compile(
    r"""(?ix) ^(
        [<{\[$].* | .*[}>\]]$ | \*+ | x{3,} | \.{3,} | -+ | _+
      | (change[_-]?me|changeit|your[_-].*|my[_-]?secret|placeholder|redacted|dummy
         |example|sample|test|testing|fake|none|null|nil|todo|tbd|unset|empty
         |password|passwd|secret|hunter2|foobar?|abc123|s3cret)
      | (true|false|yes|no|on|off|enabled|disabled)
      | \d{1,4}
      | env\..* | process\.env.* | os\.environ.* | vault:.* | secretref:.*
      | \$\{.*\}? | %\(.*\)s | \{\{.*\}?\}?
    )$""")

# Paths a .gitignore ought to protect, and why. Ordered by how badly it hurts.
_WANTED_IGNORES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("env-files", (".env", "*.env"), "environment files holding runtime credentials"),
    ("private-keys", ("*.pem", "*.key", "id_rsa", "*.p12", "*.pfx"),
     "private keys and PKCS#12 bundles"),
    ("cloud-creds", (".aws/", "credentials.json", "*-service-account*.json", "gha-creds-*.json"),
     "cloud provider credential files"),
    ("terraform", ("*.tfvars", "*.tfstate", "*.tfstate.*"),
     "terraform variable and state files, which contain resolved secrets"),
)


class ScanError(RuntimeError):
    """The check could not run. Raised rather than returning zero findings."""


def _tracked_files(repo_dir: str) -> list[str]:
    """What git is actually tracking. `-z` because filenames may contain
    newlines, and a naive split would silently truncate the file list — a
    scanner that quietly stops looking is the failure mode we care most about."""
    try:
        proc = subprocess.run(["git", "ls-files", "-z"], cwd=repo_dir, check=True,
                              capture_output=True, text=True, timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        raise ScanError(f"git ls-files failed in {repo_dir}: {exc}") from exc
    return [p for p in proc.stdout.split("\0") if p]


def is_env_file(path: str) -> bool:
    return bool(_ENV_NAMES.search(path)) and not _ENV_TEMPLATE.search(path)


def is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.match((value or "").strip()))


def scan(repo_dir: str, *, repo: str, key: bytes, max_bytes: int = 2_000_000) -> list[Finding]:
    """Run all three worktree rules. Raises `ScanError` if the tree cannot be
    enumerated; an unreadable individual file is skipped, not fatal."""
    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        raise ScanError(f"{repo_dir} is not a git repository")
    tracked = _tracked_files(repo_dir)
    findings: list[Finding] = []

    for path in tracked:
        if is_env_file(path):
            findings.append(_env_finding(repo_dir, path, repo=repo, key=key))
        if path.endswith(_CONFIG_SUFFIX):
            findings.extend(_inline_findings(repo_dir, path, repo=repo, key=key,
                                             max_bytes=max_bytes))
    findings.extend(_gitignore_findings(repo_dir, repo=repo, tracked=set(tracked)))
    return findings


def _read(repo_dir: str, path: str, max_bytes: int) -> str | None:
    full = os.path.join(repo_dir, path)
    try:
        if os.path.getsize(full) > max_bytes:
            return None
        with open(full, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _env_finding(repo_dir: str, path: str, *, repo: str, key: bytes) -> Finding:
    """A tracked env file. The finding is the *tracking*; we count the keys it
    holds to size the blast radius but never read a value into the finding."""
    text = _read(repo_dir, path, 1_000_000) or ""
    names = [ln.split("=", 1)[0].strip() for ln in text.splitlines()
             if "=" in ln and not ln.lstrip().startswith("#")]
    populated = [ln.split("=", 1)[0].strip() for ln in text.splitlines()
                 if "=" in ln and not ln.lstrip().startswith("#")
                 and ln.split("=", 1)[1].strip()]
    return Finding(
        check="worktree",
        rule_id="committed-env-file",
        finding_type=ENV_FILE,
        severity="high",
        title=f"`{path}` is tracked by git in {repo}",
        repo=repo,
        path=path,
        # The *names* of the variables are structure, not secret material, and
        # they are what tells an engineer which systems to rotate. The values
        # are never read into the finding.
        message=(f"{path} is committed to the repository and defines "
                 f"{len(populated)} populated of {len(names)} variables. Every value in a "
                 "tracked env file must be treated as disclosed to everyone who can "
                 "clone the repo, including values no secret scanner matches "
                 "(a plain database password has no format to detect)."),
        remediation=(
            f"1. ROTATE every populated value in {path}. Assume all of them are known.\n"
            f"2. STOP TRACKING it, keeping your local copy:\n"
            f"     git rm --cached {path}\n"
            f"     echo '{os.path.basename(path)}' >> .gitignore\n"
            f"     git commit -m 'stop tracking {path}'\n"
            f"3. COMMIT a `{os.path.basename(path)}.example` with the keys and empty values,\n"
            f"   so the next engineer does not recreate this file from scratch.\n"
            f"4. PURGE it from history — it stays recoverable until you do:\n"
            f"{remediation.purge_history(path, repo_hint=repo)}"),
        labels={"path": safe_label(path, 64), "variables": str(len(names)),
                "populated": str(len(populated))},
    )


def _inline_findings(repo_dir: str, path: str, *, repo: str, key: bytes,
                     max_bytes: int) -> list[Finding]:
    text = _read(repo_dir, path, max_bytes)
    if text is None:
        return []
    out: list[Finding] = []
    seen: set[str] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000 or line.lstrip().startswith(("#", "//", ";", "*")):
            continue
        for rule, value, detail in _matches(line):
            if is_placeholder(value):
                continue
            print_ = fingerprint(value, key)
            # One finding per distinct value per file: the same password
            # repeated on six lines is one credential to rotate.
            if print_ in seen:
                continue
            seen.add(print_)
            out.append(Finding(
                check="worktree",
                rule_id=rule,
                finding_type=INLINE,
                severity="high",
                title=f"Inline credential in `{path}` ({detail})",
                repo=repo,
                path=path,
                line=number,
                masked=mask(value),
                fingerprint=print_,
                message=(f"{detail} at {path}:{number}, value {mask(value)}. This is a "
                         "committed credential that carries no detectable format, so a "
                         "format-based secret scanner does not report it."),
                remediation=(
                    f"1. ROTATE the credential at its owner — see the connection target in "
                    f"{path}:{number}.\n"
                    f"2. REPLACE the literal with a reference the runtime resolves "
                    f"(`${{DATABASE_URL}}` from the secret store), not with a second literal.\n"
                    f"3. PURGE the value from history:\n"
                    f"{remediation.purge_history(path, repo_hint=repo)}"),
                labels={"path": safe_label(path, 64), "kind": safe_label(rule, 40)},
            ))
    return out


def _matches(line: str):
    """Yield (rule_id, secret, human description) for one line."""
    for match in _URL_CRED.finditer(line):
        yield ("inline-url-password", match.group("secret"),
               f"password in a {match.group('scheme')}:// connection string")
    for match in _ASSIGNMENT.finditer(line):
        # A URL password already reported above would otherwise be reported
        # again by the assignment rule when written as `url: postgres://…`.
        if "://" in match.group("secret"):
            continue
        yield ("inline-assignment", match.group("secret"),
               f"`{safe_label(match.group('key'), 40)}` assigned a literal value")


def _gitignore_findings(repo_dir: str, *, repo: str, tracked: set[str]) -> list[Finding]:
    """The preventive check. Severity depends on whether the gap is theoretical
    or already being exercised."""
    path = os.path.join(repo_dir, ".gitignore")
    try:
        with open(path, "r", errors="replace") as fh:
            patterns = {ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")}
        exists = True
    except OSError:
        patterns, exists = set(), False

    missing = [(name, wanted, why) for name, wanted, why in _WANTED_IGNORES
               if not any(p in patterns for p in wanted)]
    if not missing:
        return []

    # A gap that is already tracking a matching file is not hypothetical. That
    # case is reported by the other two rules as `high`; this finding stays the
    # preventive one, but says so rather than pretending the risk is abstract.
    exercised = any(is_env_file(p) for p in tracked)
    lines = "\n".join(f"  {' '.join(w)}   # {why}" for _, w, why in missing)
    return [Finding(
        check="worktree",
        rule_id="gitignore-gap",
        finding_type=GITIGNORE_GAP,
        severity="medium" if exercised else "low",
        title=(f"`.gitignore` does not protect {len(missing)} credential file "
               f"{'class' if len(missing) == 1 else 'classes'} in {repo}"),
        repo=repo,
        path=".gitignore",
        message=(
            f"{'.gitignore is missing entirely' if not exists else '.gitignore exists'} and does "
            f"not cover: {', '.join(name for name, _, _ in missing)}. "
            + ("A credential file is already tracked in this repo, so this gap is being "
               "exercised today, not hypothetically."
               if exercised else
               "No matching file is tracked today; this is the control that keeps it that way.")),
        remediation=(
            "Append to .gitignore — this is the cheapest control in the whole pillar:\n\n"
            f"cat >> .gitignore <<'EOF'\n{lines}\nEOF\n\n"
            "Then confirm nothing is already tracked despite the new rules "
            "(.gitignore does not untrack files):\n"
            "  git ls-files -i -c --exclude-standard\n"
            "Anything listed needs `git rm --cached <path>` and rotation."),
        labels={"missing": safe_label(",".join(n for n, _, _ in missing), 100),
                "exercised": "true" if exercised else "false"},
    )]

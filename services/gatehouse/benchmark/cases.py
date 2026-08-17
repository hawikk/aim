"""Versioned precision corpus for gatehouse scanners (AIM-334).

Each case is a small synthetic tree plus labeled expected findings (or a clean
control with zero expected). The harness materializes cases into temp repos
and runs the real scanners against them.

Corpus design notes
-------------------
* Secrets are format-valid and cryptographically dead — never live credentials.
  gitleaks' own allowlist for AWS's documented EXAMPLE keys means we must use
  random AKIA… values (see tests/fixtures/vulnerable_pr.py).
* SAST cases target the *vendored* semgrep ruleset only (rules/semgrep/).
* IaC cases seed the high-signal checkov checks we lift in severity.py.
* SCA cases pin long-lived vulnerable package versions; matching is by
  package name (any HIGH/CRITICAL CVE) because CVE ids rotate with the DB.
* Clean controls are the precision surface: a finding on a clean case is a
  false positive. Unexpected findings on positive cases are reported as
  diagnostics but do not count against the FP budget (incomplete multi-label
  labels on checkov would otherwise tank precision unfairly).

``CORPUS_VERSION`` is bumped when cases are added/removed/relabeled. CI fails
if the committed version and the runtime version disagree with the generator
count checks.
"""

from __future__ import annotations

import json
import secrets
import string
from dataclasses import dataclass, field
from typing import Iterable

from . import CORPUS_VERSION

_ALNUM = string.ascii_letters + string.digits


def _rand(n: int, alphabet: str = _ALNUM) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


# Structurally valid, unbound. Same values as tests/fixtures/vulnerable_pr.py —
# gitleaks allowlists AWS's documented AKIAIOSFODNN7EXAMPLE, and random AKIAs
# fail its shape check, so this known-good synthetic value is load-bearing.
_AWS_KEY_ID = "AKIA" + "3PXQ7VZK2WNMTB4C"
_AWS_SECRET = "kR8vN2pQ7xL4mT6wY9zB3cF5hJ1n" + "D0sG8aE4uI2o"


def _aws_key() -> str:
    return _AWS_KEY_ID


def _aws_secret() -> str:
    return _AWS_SECRET


def _ghp() -> str:
    return "ghp_" + _rand(36)


def _github_fg() -> str:
    return "github_pat_" + _rand(22) + "_" + _rand(59)


def _glpat() -> str:
    return "glpat-" + _rand(20)


def _stripe() -> str:
    return "sk_live_" + _rand(24)


def _slack_bot() -> str:
    return f"xoxb-{_rand(12, string.digits)}-{_rand(13, string.digits)}-{_rand(24)}"


def _slack_hook() -> str:
    return (
        "https://hooks.slack.com/services/"
        f"T{_rand(8)}/B{_rand(8)}/{_rand(24)}"
    )


def _npm() -> str:
    return "npm_" + _rand(36)


def _sendgrid() -> str:
    return f"SG.{_rand(22)}.{_rand(43)}"


def _twilio() -> str:
    return "SK" + _rand(32, "abcdef0123456789")


@dataclass(frozen=True)
class ExpectedFinding:
    """One seeded true positive the gate must catch."""

    path: str
    rule_id: str
    gate: str  # scanner name
    line_min: int = 1
    line_max: int = 10_000
    # For SCA: match any finding whose labels.pkg equals package (rule_id ignored).
    package: str | None = None

    def matches(self, finding) -> bool:
        if finding.scanner != self.gate:
            return False
        if finding.path.replace("\\", "/") != self.path.replace("\\", "/"):
            return False
        line = int(finding.line or 0)
        # File-level findings (trivy line=0) always pass the line window.
        if line and not (self.line_min <= line <= self.line_max):
            return False
        if self.package is not None:
            pkg = (finding.labels or {}).get("pkg") or ""
            return pkg == self.package or self.package in (finding.title or "")
        # Rule id: exact or suffix match (semgrep namespaces with path prefixes).
        rid = finding.rule_id or ""
        return rid == self.rule_id or rid.endswith(self.rule_id) or rid.endswith(
            "." + self.rule_id)


@dataclass
class Case:
    id: str
    gate_class: str  # secret | sast | iac | sca | clean
    gate: str  # primary scanner under test (or "any" for clean multi-gate)
    files: dict[str, str]
    expected: list[ExpectedFinding] = field(default_factory=list)
    clean: bool = False
    note: str = ""

    @property
    def seeded_count(self) -> int:
        return len(self.expected)


def _secret_cases() -> list[Case]:
    """≥15 seeded secret findings across common credential classes."""
    cases: list[Case] = []

    # Multi-finding: AWS key id (+ optional secret-shaped value).
    # Only seed aws-access-token — the secret line may or may not fire as
    # generic-api-key depending on entropy heuristics; that is diagnostic only.
    aws_id, aws_sec = _aws_key(), _aws_secret()
    cases.append(Case(
        id="secret-aws-credentials",
        gate_class="secret", gate="gitleaks",
        files={"app/settings.py": (
            '"""Deployment settings."""\n\n'
            f'AWS_ACCESS_KEY_ID = "{aws_id}"\n'
            f'AWS_SECRET_ACCESS_KEY = "{aws_sec}"\n'
            'AWS_REGION = "eu-central-1"\n'
        )},
        expected=[
            ExpectedFinding("app/settings.py", "aws-access-token", "gitleaks", 3, 3),
        ],
        note="Hardcoded AWS credentials (structurally valid, unbound).",
    ))

    for i, (name, value, rule) in enumerate([
        ("github-pat", _ghp(), "github-pat"),
        ("github-fine-grained", _github_fg(), "github-fine-grained-pat"),
        ("gitlab-pat", _glpat(), "gitlab-pat"),
        ("stripe-live", _stripe(), "stripe-access-token"),
        ("slack-bot", _slack_bot(), "slack-bot-token"),
        ("slack-webhook", _slack_hook(), "slack-webhook-url"),
        ("npm-token", _npm(), "npm-access-token"),
        ("sendgrid", _sendgrid(), "sendgrid-api-token"),
        ("twilio", _twilio(), "twilio-api-key"),
    ], start=1):
        path = f"config/secrets_{name}.env"
        cases.append(Case(
            id=f"secret-{name}",
            gate_class="secret", gate="gitleaks",
            files={path: f"TOKEN={value}\n"},
            expected=[ExpectedFinding(path, rule, "gitleaks", 1, 1)],
        ))

    # Private key
    cases.append(Case(
        id="secret-rsa-private-key",
        gate_class="secret", gate="gitleaks",
        files={"deploy/id_rsa": (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PZGFw4qQIDAQAB\n"
            "-----END RSA PRIVATE KEY-----\n"
        )},
        expected=[ExpectedFinding("deploy/id_rsa", "private-key", "gitleaks", 1, 3)],
    ))

    # JWT (common gitleaks rule)
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    cases.append(Case(
        id="secret-jwt",
        gate_class="secret", gate="gitleaks",
        files={"app/session.py": f'SESSION_TOKEN = "{jwt}"\n'},
        expected=[ExpectedFinding("app/session.py", "jwt", "gitleaks", 1, 1)],
    ))

    # Same known-good AWS key in a different path (path-scoping exercise).
    cases.append(Case(
        id="secret-aws-key-only",
        gate_class="secret", gate="gitleaks",
        files={"infra/ci.env": f"AWS_ACCESS_KEY_ID={_aws_key()}\n"},
        expected=[ExpectedFinding("infra/ci.env", "aws-access-token", "gitleaks", 1, 1)],
    ))

    # Multi-secret dump
    dump = "\n".join([
        f"GHP={_ghp()}",
        f"GL={_glpat()}",
        f"STRIPE={_stripe()}",
        f"NPM={_npm()}",
        f"SG={_sendgrid()}",
    ]) + "\n"
    cases.append(Case(
        id="secret-multi-dump",
        gate_class="secret", gate="gitleaks",
        files={"tmp/leaked.env": dump},
        expected=[
            ExpectedFinding("tmp/leaked.env", "github-pat", "gitleaks", 1, 1),
            ExpectedFinding("tmp/leaked.env", "gitlab-pat", "gitleaks", 2, 2),
            ExpectedFinding("tmp/leaked.env", "stripe-access-token", "gitleaks", 3, 3),
            ExpectedFinding("tmp/leaked.env", "npm-access-token", "gitleaks", 4, 4),
            ExpectedFinding("tmp/leaked.env", "sendgrid-api-token", "gitleaks", 5, 5),
        ],
    ))
    return cases


def _sast_cases() -> list[Case]:
    """SAST cases against the vendored injection.yaml ruleset."""
    cases: list[Case] = []

    # SQL injection variants (Python)
    for i, body in enumerate([
        'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)\n',
        'cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n',
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n',
        'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))\n',
        (
            'query = "SELECT * FROM t WHERE id = %s" % user_id\n'
            "cursor.execute(query)\n"
        ),
    ], start=1):
        path = f"app/sqli_{i}.py"
        cases.append(Case(
            id=f"sast-python-sqli-{i}",
            gate_class="sast", gate="semgrep",
            files={path: "import psycopg\n\n\ndef find(conn, user_id):\n    cursor = conn.cursor()\n    "
                         + body + "    return cursor.fetchone()\n"},
            expected=[ExpectedFinding(
                path, "python-sql-injection-format", "semgrep", 1, 20)],
        ))

    # JS SQL injection
    cases.append(Case(
        id="sast-js-sqli-template",
        gate_class="sast", gate="semgrep",
        files={"app/query.js": (
            "function findUser(db, id) {\n"
            "  return db.query(`SELECT * FROM users WHERE id = ${id}`);\n"
            "}\n"
        )},
        expected=[ExpectedFinding(
            "app/query.js", "js-sql-injection-template", "semgrep", 1, 5)],
    ))
    cases.append(Case(
        id="sast-js-sqli-concat",
        gate_class="sast", gate="semgrep",
        files={"app/query2.js": (
            "function findUser(db, id) {\n"
            '  return db.query("SELECT * FROM users WHERE id = " + id);\n'
            "}\n"
        )},
        expected=[ExpectedFinding(
            "app/query2.js", "js-sql-injection-template", "semgrep", 1, 5)],
    ))

    # Command injection
    for i, body in enumerate([
        'subprocess.run(f"git clone {url}", shell=True)\n',
        'subprocess.call("git clone " + url, shell=True)\n',
        'os.system(f"echo {msg}")\n',
    ], start=1):
        path = f"app/shell_{i}.py"
        cases.append(Case(
            id=f"sast-python-shell-{i}",
            gate_class="sast", gate="semgrep",
            files={path: "import os, subprocess\n\n\ndef run(url, msg='x'):\n    " + body},
            expected=[ExpectedFinding(
                path, "python-shell-command-injection", "semgrep", 1, 10)],
        ))

    # Unsafe deserialization
    cases.append(Case(
        id="sast-python-pickle",
        gate_class="sast", gate="semgrep",
        files={"app/load.py": (
            "import pickle\n\n\ndef load(blob):\n    return pickle.loads(blob)\n"
        )},
        expected=[ExpectedFinding(
            "app/load.py", "python-unsafe-deserialization", "semgrep", 1, 6)],
    ))
    cases.append(Case(
        id="sast-python-yaml-load",
        gate_class="sast", gate="semgrep",
        files={"app/cfg.py": (
            "import yaml\n\n\ndef load(path):\n"
            "    with open(path) as fh:\n"
            "        return yaml.load(fh)\n"
        )},
        expected=[ExpectedFinding(
            "app/cfg.py", "python-unsafe-deserialization", "semgrep", 1, 8)],
    ))

    # Weak hash
    cases.append(Case(
        id="sast-weak-md5",
        gate_class="sast", gate="semgrep",
        files={"app/auth.py": (
            "import hashlib\n\n\ndef hash_pw(pw):\n"
            "    return hashlib.md5(pw.encode()).hexdigest()\n"
        )},
        expected=[ExpectedFinding(
            "app/auth.py", "weak-hash-for-credentials", "semgrep", 1, 6)],
    ))
    cases.append(Case(
        id="sast-weak-sha1",
        gate_class="sast", gate="semgrep",
        files={"app/token.py": (
            "import hashlib\n\n\ndef token(v):\n"
            "    return hashlib.sha1(v.encode()).hexdigest()\n"
        )},
        expected=[ExpectedFinding(
            "app/token.py", "weak-hash-for-credentials", "semgrep", 1, 6)],
    ))

    # TLS verification disabled
    cases.append(Case(
        id="sast-tls-verify-false",
        gate_class="sast", gate="semgrep",
        files={"app/client.py": (
            "import requests\n\n\ndef get(url):\n"
            "    return requests.get(url, verify=False)\n"
        )},
        expected=[ExpectedFinding(
            "app/client.py", "tls-verification-disabled", "semgrep", 1, 6)],
    ))
    cases.append(Case(
        id="sast-tls-unverified-context",
        gate_class="sast", gate="semgrep",
        files={"app/ssl_client.py": (
            "import ssl, urllib.request\n\n\ndef open_url(url):\n"
            "    ctx = ssl._create_unverified_context()\n"
            "    return urllib.request.urlopen(url, context=ctx)\n"
        )},
        expected=[ExpectedFinding(
            "app/ssl_client.py", "tls-verification-disabled", "semgrep", 1, 8)],
    ))
    return cases


def _iac_cases() -> list[Case]:
    """IaC cases — public exposure and open security groups."""
    cases: list[Case] = []

    # Public S3 — checkov fires a cluster of checks; seed the high-signal ones.
    for i in range(1, 4):
        path = f"infra/public_bucket_{i}.tf"
        cases.append(Case(
            id=f"iac-public-s3-{i}",
            gate_class="iac", gate="checkov",
            files={path: (
                f'resource "aws_s3_bucket" "exports_{i}" {{\n'
                f'  bucket = "demo-exports-{i}"\n'
                "}\n\n"
                f'resource "aws_s3_bucket_acl" "exports_{i}" {{\n'
                f"  bucket = aws_s3_bucket.exports_{i}.id\n"
                '  acl    = "public-read"\n'
                "}\n"
            )},
            expected=[
                ExpectedFinding(path, "CKV_AWS_20", "checkov"),
            ],
            note="Public-read S3 bucket (CKV_AWS_20 is the blocking check).",
        ))

    # Open SSH
    for i in range(1, 4):
        path = f"infra/open_ssh_{i}.tf"
        cases.append(Case(
            id=f"iac-open-ssh-{i}",
            gate_class="iac", gate="checkov",
            files={path: (
                f'resource "aws_security_group" "bad_{i}" {{\n'
                f'  name = "bad-ssh-{i}"\n'
                "  ingress {\n"
                "    from_port   = 22\n"
                "    to_port     = 22\n"
                '    protocol    = "tcp"\n'
                '    cidr_blocks = ["0.0.0.0/0"]\n'
                "  }\n"
                "}\n"
            )},
            expected=[
                ExpectedFinding(path, "CKV_AWS_24", "checkov"),
            ],
        ))

    # Open RDP
    for i in range(1, 3):
        path = f"infra/open_rdp_{i}.tf"
        cases.append(Case(
            id=f"iac-open-rdp-{i}",
            gate_class="iac", gate="checkov",
            files={path: (
                f'resource "aws_security_group" "rdp_{i}" {{\n'
                f'  name = "bad-rdp-{i}"\n'
                "  ingress {\n"
                "    from_port   = 3389\n"
                "    to_port     = 3389\n"
                '    protocol    = "tcp"\n'
                '    cidr_blocks = ["0.0.0.0/0"]\n'
                "  }\n"
                "}\n"
            )},
            expected=[ExpectedFinding(path, "CKV_AWS_25", "checkov")],
        ))

    # Combined public bucket + open SG (multiple seeded findings)
    cases.append(Case(
        id="iac-combo-public-and-ssh",
        gate_class="iac", gate="checkov",
        files={
            "infra/combo.tf": (
                'resource "aws_s3_bucket" "combo" {\n'
                '  bucket = "combo-public"\n'
                "}\n"
                'resource "aws_s3_bucket_acl" "combo" {\n'
                "  bucket = aws_s3_bucket.combo.id\n"
                '  acl    = "public-read"\n'
                "}\n"
                'resource "aws_security_group" "combo_ssh" {\n'
                '  name = "combo-ssh"\n'
                "  ingress {\n"
                "    from_port   = 22\n"
                "    to_port     = 22\n"
                '    protocol    = "tcp"\n'
                '    cidr_blocks = ["0.0.0.0/0"]\n'
                "  }\n"
                "}\n"
            ),
        },
        expected=[
            ExpectedFinding("infra/combo.tf", "CKV_AWS_20", "checkov"),
            ExpectedFinding("infra/combo.tf", "CKV_AWS_24", "checkov"),
        ],
    ))

    # More public-read variants
    for i in range(4, 7):
        path = f"infra/exports_{i}.tf"
        cases.append(Case(
            id=f"iac-public-s3-extra-{i}",
            gate_class="iac", gate="checkov",
            files={path: (
                f'resource "aws_s3_bucket" "x{i}" {{ bucket = "x{i}" }}\n'
                f'resource "aws_s3_bucket_acl" "x{i}" {{\n'
                f"  bucket = aws_s3_bucket.x{i}.id\n"
                '  acl = "public-read"\n'
                "}\n"
            )},
            expected=[ExpectedFinding(path, "CKV_AWS_20", "checkov")],
        ))
    return cases


def _sca_cases() -> list[Case]:
    """SCA cases — long-lived vulnerable package pins.

    Matching is by package name (any HIGH/CRITICAL finding), not a specific
    CVE id, because the offline trivy DB pins CVE ids to the image build date.
    """
    cases: list[Case] = []

    # Python: pin ancient django / pyyaml / requests that stay in the DB.
    for i, (pkg, ver) in enumerate([
        ("django", "1.11.29"),
        ("pyyaml", "5.1"),
        ("requests", "2.19.0"),
        ("urllib3", "1.24.1"),
        ("jinja2", "2.10"),
    ], start=1):
        path = f"services/svc{i}/requirements.txt"
        cases.append(Case(
            id=f"sca-python-{pkg}",
            gate_class="sca", gate="trivy",
            files={path: f"{pkg}=={ver}\n"},
            expected=[ExpectedFinding(
                path, rule_id="*", gate="trivy", package=pkg)],
        ))

    # Node: lodash / minimist / serialize-javascript
    for i, (pkg, ver) in enumerate([
        ("lodash", "4.17.15"),
        ("minimist", "0.2.1"),
        ("serialize-javascript", "2.1.1"),
        ("node-fetch", "2.6.0"),
        ("axios", "0.18.0"),
    ], start=1):
        # Minimal package-lock that trivy can parse as npm.
        lock = {
            "name": f"demo-{i}",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "requires": True,
            "packages": {
                "": {"name": f"demo-{i}", "version": "1.0.0",
                     "dependencies": {pkg: ver}},
                f"node_modules/{pkg}": {
                    "version": ver,
                    "resolved": f"https://registry.npmjs.org/{pkg}/-/{pkg}-{ver}.tgz",
                    "integrity": "sha512-" + "0" * 64,
                },
            },
            "dependencies": {
                pkg: {
                    "version": ver,
                    "resolved": f"https://registry.npmjs.org/{pkg}/-/{pkg}-{ver}.tgz",
                    "integrity": "sha512-" + "0" * 64,
                },
            },
        }
        path = f"web/app{i}/package-lock.json"
        cases.append(Case(
            id=f"sca-npm-{pkg}",
            gate_class="sca", gate="trivy",
            files={
                f"web/app{i}/package.json": json.dumps({
                    "name": f"demo-{i}", "version": "1.0.0",
                    "dependencies": {pkg: ver},
                }, indent=2) + "\n",
                path: json.dumps(lock, indent=2) + "\n",
            },
            expected=[ExpectedFinding(
                path, rule_id="*", gate="trivy", package=pkg)],
        ))
    return cases


def _clean_cases() -> list[Case]:
    """Known-clean controls — any finding is a false positive."""
    return [
        Case(
            id="clean-parameterized-sql",
            gate_class="clean", gate="semgrep", clean=True,
            files={"app/users.py": (
                "import psycopg\n\n\n"
                "def find_user(conn, user_id):\n"
                "    cursor = conn.cursor()\n"
                '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
                "    return cursor.fetchone()\n"
            )},
            note="Parameterized query — must not fire python-sql-injection-format.",
        ),
        Case(
            id="clean-subprocess-list",
            gate_class="clean", gate="semgrep", clean=True,
            files={"app/clone.py": (
                "import subprocess\n\n\n"
                "def clone(url):\n"
                '    subprocess.run(["git", "clone", url], check=True)\n'
            )},
        ),
        Case(
            id="clean-yaml-safe-load",
            gate_class="clean", gate="semgrep", clean=True,
            files={"app/cfg.py": (
                "import yaml\n\n\n"
                "def load(path):\n"
                "    with open(path) as fh:\n"
                "        return yaml.safe_load(fh)\n"
            )},
        ),
        Case(
            id="clean-sha256",
            gate_class="clean", gate="semgrep", clean=True,
            files={"app/hash.py": (
                "import hashlib\n\n\n"
                "def digest(v):\n"
                "    return hashlib.sha256(v.encode()).hexdigest()\n"
            )},
        ),
        Case(
            id="clean-tls-verify-true",
            gate_class="clean", gate="semgrep", clean=True,
            # Fixed host only — a caller-supplied `url` param matches
            # python-ssrf-requests-user-url and would falsely score as an FP
            # against this TLS-verify control (AIM-445 SSRF pack).
            files={"app/client.py": (
                "import requests\n\n\n"
                "def get():\n"
                '    return requests.get("https://example.com/health", verify=True)\n'
            )},
        ),
        Case(
            id="clean-private-s3",
            gate_class="clean", gate="checkov", clean=True,
            # Fully hardened, not merely private: checkov runs the whole
            # terraform framework against this file, and a bare bucket trips
            # six hardening checks (versioning, logging, KMS, lifecycle,
            # replication, notifications) that are not the defect under test.
            # A "clean" control has to be clean against the gate as deployed —
            # verified: `checkov --framework terraform -f` reports 0 failures.
            files={"infra/logs.tf": (
                'resource "aws_kms_key" "logs" {\n'
                '  description             = "KMS key for demo-logs-private"\n'
                "  deletion_window_in_days = 30\n"
                "  enable_key_rotation     = true\n"
                "  policy = jsonencode({\n"
                '    Version = "2012-10-17"\n'
                "    Statement = [{\n"
                '      Sid       = "Enable IAM User Permissions"\n'
                '      Effect    = "Allow"\n'
                '      Principal = { AWS = "arn:aws:iam::123456789012:root" }\n'
                '      Action    = "kms:*"\n'
                '      Resource  = "*"\n'
                "    }]\n"
                "  })\n"
                "}\n\n"
                'resource "aws_s3_bucket" "logs" {\n'
                '  bucket = "demo-logs-private"\n'
                "}\n\n"
                'resource "aws_s3_bucket_public_access_block" "logs" {\n'
                "  bucket                  = aws_s3_bucket.logs.id\n"
                "  block_public_acls       = true\n"
                "  block_public_policy     = true\n"
                "  ignore_public_acls      = true\n"
                "  restrict_public_buckets = true\n"
                "}\n\n"
                'resource "aws_s3_bucket_versioning" "logs" {\n'
                "  bucket = aws_s3_bucket.logs.id\n"
                "  versioning_configuration {\n"
                '    status = "Enabled"\n'
                "  }\n"
                "}\n\n"
                'resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {\n'
                "  bucket = aws_s3_bucket.logs.id\n"
                "  rule {\n"
                "    apply_server_side_encryption_by_default {\n"
                '      sse_algorithm     = "aws:kms"\n'
                "      kms_master_key_id = aws_kms_key.logs.arn\n"
                "    }\n"
                "  }\n"
                "}\n\n"
                'resource "aws_s3_bucket_logging" "logs" {\n'
                "  bucket        = aws_s3_bucket.logs.id\n"
                "  target_bucket = aws_s3_bucket.logs.id\n"
                '  target_prefix = "self-access-logs/"\n'
                "}\n\n"
                'resource "aws_s3_bucket_lifecycle_configuration" "logs" {\n'
                "  bucket = aws_s3_bucket.logs.id\n"
                "  rule {\n"
                '    id     = "expire-old-logs"\n'
                '    status = "Enabled"\n'
                "    expiration {\n"
                "      days = 365\n"
                "    }\n"
                "    abort_incomplete_multipart_upload {\n"
                "      days_after_initiation = 7\n"
                "    }\n"
                "  }\n"
                "}\n\n"
                'resource "aws_s3_bucket_replication_configuration" "logs" {\n'
                "  bucket = aws_s3_bucket.logs.id\n"
                '  role   = "arn:aws:iam::123456789012:role/demo-logs-replication"\n'
                "  rule {\n"
                '    id     = "replicate-logs"\n'
                '    status = "Enabled"\n'
                "    destination {\n"
                '      bucket        = "arn:aws:s3:::demo-logs-private-replica"\n'
                '      storage_class = "STANDARD"\n'
                "    }\n"
                "  }\n"
                "}\n\n"
                'resource "aws_sns_topic" "logs_events" {\n'
                '  name              = "demo-logs-events"\n'
                "  kms_master_key_id = aws_kms_key.logs.arn\n"
                "}\n\n"
                'resource "aws_s3_bucket_notification" "logs" {\n'
                "  bucket = aws_s3_bucket.logs.id\n"
                "  topic {\n"
                "    topic_arn = aws_sns_topic.logs_events.arn\n"
                '    events    = ["s3:ObjectCreated:*"]\n'
                "  }\n"
                "}\n"
            )},
            note="Private bucket with public-access block — CKV_AWS_20 must not fire.",
        ),
        Case(
            id="clean-sg-restricted",
            gate_class="clean", gate="checkov", clean=True,
            # The SG is described and attached (CKV2_AWS_5 is a graph check:
            # an unattached SG is itself a finding). The vpc_endpoint is the
            # lightest attachment target that does not pull in a second
            # resource family's hardening checks — verified clean against
            # `checkov --framework terraform -f`.
            files={"infra/sg.tf": (
                'resource "aws_security_group" "app" {\n'
                '  name        = "app-internal"\n'
                '  description = "Internal app traffic on 443 from the corporate network"\n'
                "\n"
                "  ingress {\n"
                '    description = "HTTPS from the corporate network"\n'
                "    from_port   = 443\n"
                "    to_port     = 443\n"
                '    protocol    = "tcp"\n'
                '    cidr_blocks = ["10.0.0.0/8"]\n'
                "  }\n"
                "}\n\n"
                'resource "aws_vpc_endpoint" "app" {\n'
                '  vpc_id             = "vpc-0123456789abcdef0"\n'
                '  service_name       = "com.amazonaws.us-east-1.secretsmanager"\n'
                '  vpc_endpoint_type  = "Interface"\n'
                '  subnet_ids         = ["subnet-0123456789abcdef0"]\n'
                "  security_group_ids = [aws_security_group.app.id]\n"
                "\n"
                "  policy = jsonencode({\n"
                '    Version = "2012-10-17"\n'
                "    Statement = [{\n"
                '      Effect    = "Allow"\n'
                '      Principal = "*"\n'
                '      Action    = "secretsmanager:GetSecretValue"\n'
                '      Resource  = "arn:aws:secretsmanager:us-east-1:123456789012:secret:demo-*"\n'
                "    }]\n"
                "  })\n"
                "}\n"
            )},
        ),
        Case(
            id="clean-no-secrets-config",
            gate_class="clean", gate="gitleaks", clean=True,
            files={"config/app.env": (
                "APP_ENV=production\n"
                "LOG_LEVEL=info\n"
                "AWS_REGION=eu-central-1\n"
                "# Use the IAM role on the instance; no static keys here.\n"
            )},
        ),
        Case(
            id="clean-aws-example-key-doc",
            gate_class="clean", gate="gitleaks", clean=True,
            files={"docs/aws-example.md": (
                "AWS documents the example key `AKIAIOSFODNN7EXAMPLE`.\n"
                "It is allowlisted by gitleaks' default ruleset.\n"
            )},
            note="Documented EXAMPLE key must not flag (gitleaks allowlist).",
        ),
        Case(
            id="clean-fresh-npm-lock",
            gate_class="clean", gate="trivy", clean=True,
            files={
                "web/clean/package.json": json.dumps({
                    "name": "clean-app", "version": "1.0.0",
                    "dependencies": {},
                }, indent=2) + "\n",
                "web/clean/package-lock.json": json.dumps({
                    "name": "clean-app", "version": "1.0.0",
                    "lockfileVersion": 2, "requires": True,
                    "packages": {"": {"name": "clean-app", "version": "1.0.0"}},
                    "dependencies": {},
                }, indent=2) + "\n",
            },
            note="Empty lockfile — no vulnerable deps.",
        ),
        Case(
            id="clean-empty-requirements",
            gate_class="clean", gate="trivy", clean=True,
            files={"services/clean/requirements.txt": "# no deps\n"},
        ),
        Case(
            id="clean-readme-only",
            gate_class="clean", gate="any", clean=True,
            files={"README.md": "# demo\n\nA clean control with no code.\n"},
        ),
    ]


def all_cases() -> list[Case]:
    """Full versioned corpus. Deterministic structure; secret values are random
    per process so live-looking credentials never land in git."""
    return (
        _secret_cases()
        + _sast_cases()
        + _iac_cases()
        + _sca_cases()
        + _clean_cases()
    )


def corpus_stats(cases: Iterable[Case] | None = None) -> dict:
    cases = list(cases if cases is not None else all_cases())
    seeded = sum(c.seeded_count for c in cases)
    by_class: dict[str, int] = {}
    by_gate: dict[str, int] = {}
    clean = 0
    for c in cases:
        if c.clean:
            clean += 1
            continue
        by_class[c.gate_class] = by_class.get(c.gate_class, 0) + c.seeded_count
        for exp in c.expected:
            by_gate[exp.gate] = by_gate.get(exp.gate, 0) + 1
    return {
        "corpus_version": CORPUS_VERSION,
        "cases": len(cases),
        "seeded_findings": seeded,
        "clean_controls": clean,
        "seeded_by_class": by_class,
        "seeded_by_gate": by_gate,
    }


def assert_corpus_meets_charter(cases: list[Case] | None = None) -> dict:
    """Charter: ≥50 seeded findings across secret/SAST/IaC/SCA + clean controls."""
    stats = corpus_stats(cases)
    missing = []
    if stats["seeded_findings"] < 50:
        missing.append(f"seeded_findings={stats['seeded_findings']} < 50")
    for cls in ("secret", "sast", "iac", "sca"):
        if stats["seeded_by_class"].get(cls, 0) < 1:
            missing.append(f"class {cls} has no seeded findings")
    if stats["clean_controls"] < 1:
        missing.append("no clean controls")
    if missing:
        raise AssertionError("corpus charter violated: " + "; ".join(missing))
    return stats

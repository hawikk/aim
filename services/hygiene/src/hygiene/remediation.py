"""What to actually do about it — per issuer, copy-pasteable, never executed.

D4 is absolute: this service holds read-only credentials and never remediates.
So the product *is* the instructions, and vague instructions are the same as no
finding. "Rotate your AWS key" is vague. "Open this console URL, click Create
access key, then run this CLI line" is a fix.

Two rules encoded here, both learned the hard way in incident reviews:

1. **Rotate before you purge.** Rewriting history first tells the attacker
   you noticed, does not revoke anything, and burns the window in which you
   could have rotated quietly. Every step list starts with rotation.
2. **Deleting the line is not the fix.** A secret that reached a remote branch
   is in every fork, every CI cache and every clone. The purge steps are for
   hygiene; the rotation is the security control.

The gitleaks rule id is the join key. Unknown rules fall back to a generic
entry rather than producing an empty remediation — a finding with no next step
is a finding people scroll past.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Issuer:
    """Where a credential class comes from and how to revoke it there."""

    name: str
    console_url: str
    rotate_cli: str
    # Whether we can safely prove the credential is still live without using
    # its write scope. See liveness.py — this flag is what stops us from
    # inventing a "probe" that is really an unauthorized API call.
    liveness_probe: str = ""


ISSUERS: dict[str, Issuer] = {
    "aws": Issuer(
        name="AWS IAM",
        console_url="https://console.aws.amazon.com/iam/home#/security_credentials",
        rotate_cli=(
            "# 1. create the replacement first, so nothing breaks mid-rotation\n"
            "aws iam create-access-key --user-name <USER>\n"
            "# 2. deploy the new key, verify, then disable (not delete) the old one\n"
            "aws iam update-access-key --access-key-id <LEAKED_KEY_ID> --status Inactive --user-name <USER>\n"
            "# 3. after a cooling-off period with no AccessDenied in CloudTrail:\n"
            "aws iam delete-access-key --access-key-id <LEAKED_KEY_ID> --user-name <USER>"),
        liveness_probe="sts:GetCallerIdentity",
    ),
    "github": Issuer(
        name="GitHub",
        console_url="https://github.com/settings/tokens",
        rotate_cli=(
            "# classic PAT: revoke from the UI above (there is no REST delete for your own PAT).\n"
            "# fine-grained PAT: https://github.com/settings/personal-access-tokens\n"
            "# organization-owned tokens and App installations:\n"
            "gh api -X DELETE /applications/<CLIENT_ID>/token  # revokes an OAuth token\n"
            "# then re-issue with the minimum scopes only (see the scope audit finding)"),
        liveness_probe="GET /user",
    ),
    "gcp": Issuer(
        name="Google Cloud IAM",
        console_url="https://console.cloud.google.com/iam-admin/serviceaccounts",
        rotate_cli=(
            "gcloud iam service-accounts keys create new-key.json --iam-account=<SA_EMAIL>\n"
            "gcloud iam service-accounts keys delete <LEAKED_KEY_ID> --iam-account=<SA_EMAIL>"),
    ),
    "azure": Issuer(
        name="Microsoft Entra ID",
        console_url="https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps",
        rotate_cli="az ad app credential reset --id <APP_ID> --append",
    ),
    "slack": Issuer(
        name="Slack",
        console_url="https://api.slack.com/apps",
        rotate_cli="# Rotate from the app's OAuth & Permissions page; then re-install the app.",
    ),
    "stripe": Issuer(
        name="Stripe",
        console_url="https://dashboard.stripe.com/apikeys",
        rotate_cli="# Roll the key from the dashboard. A live key in git is a payments incident:\n"
                   "# notify whoever owns fraud/finance the same hour, not in a weekly report.",
    ),
    "openai": Issuer(
        name="OpenAI",
        console_url="https://platform.openai.com/api-keys",
        rotate_cli="# Revoke from the dashboard, then re-issue scoped to one project.",
    ),
    "anthropic": Issuer(
        name="Anthropic",
        console_url="https://console.anthropic.com/settings/keys",
        rotate_cli="# Revoke from the console, then re-issue scoped to one workspace.",
    ),
    "database": Issuer(
        name="the database owner",
        console_url="",
        rotate_cli="ALTER USER <user> WITH PASSWORD '<new>';  -- then update the secret store",
    ),
    "private-key": Issuer(
        name="whatever trusts this key",
        console_url="",
        rotate_cli="ssh-keygen -t ed25519 -f ./new-key   # then replace the public half everywhere\n"
                   "# For a TLS key: re-issue the certificate AND revoke the old one (CRL/OCSP).",
    ),
    "generic": Issuer(
        name="the credential's issuer",
        console_url="",
        rotate_cli="# Rotate at the issuer, then update the value in the secret store.",
    ),
}

# gitleaks rule id → issuer. Matched by prefix, so `aws-access-token` and
# `aws-secret-key` both resolve without listing every rule the upstream
# ruleset has ever shipped.
_RULE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("aws-", "aws"),
    ("github-", "github"),
    ("gitlab-", "github"),
    ("gcp-", "gcp"),
    ("google-", "gcp"),
    ("azure-", "azure"),
    ("slack-", "slack"),
    ("stripe-", "stripe"),
    ("openai-", "openai"),
    ("anthropic-", "anthropic"),
    ("private-key", "private-key"),
    ("rsa-", "private-key"),
    ("ssh-", "private-key"),
    ("postgres", "database"),
    ("mysql", "database"),
    ("mongodb", "database"),
    ("jdbc", "database"),
)


def issuer_for(rule_id: str) -> tuple[str, Issuer]:
    """Resolve a gitleaks rule id to (key, Issuer). Never returns None."""
    rule = (rule_id or "").lower()
    for prefix, key in _RULE_PREFIXES:
        if rule.startswith(prefix) or prefix in rule:
            return key, ISSUERS[key]
    return "generic", ISSUERS["generic"]


def purge_history(path: str, *, repo_hint: str = "<repo>") -> str:
    """The exact commands to remove a path from every commit, with the caveats
    that make the difference between a purge and a false sense of one."""
    safe = path or "<path>"
    return (
        f"# Purge `{safe}` from every commit. Do this AFTER rotating — a rewrite\n"
        f"# revokes nothing, and forks/CI caches keep the old objects regardless.\n"
        f"pip install git-filter-repo\n"
        f"git clone --mirror https://github.com/{repo_hint}.git {repo_hint.split('/')[-1]}.git\n"
        f"cd {repo_hint.split('/')[-1]}.git\n"
        f"git filter-repo --invert-paths --path '{safe}' --force\n"
        f"git push --force --all && git push --force --tags\n"
        f"#\n"
        f"# Then, and this is the part teams skip:\n"
        f"#  - ask GitHub Support to garbage-collect the old objects; until they do,\n"
        f"#    the blob is still fetchable by SHA at /{repo_hint}/commit/<sha>\n"
        f"#  - every collaborator must re-clone. A `git pull` on an old clone\n"
        f"#    reintroduces the purged objects on their next push.\n"
        f"#  - delete and re-create any fork, and purge CI caches/artifacts.")


def steps_for_leak(rule_id: str, path: str, *, repo_hint: str = "<repo>",
                   live: bool = False) -> str:
    """The full remediation block for a leaked-credential finding."""
    _, issuer = issuer_for(rule_id)
    urgency = ("This credential was VERIFIED LIVE against its issuer minutes ago. "
               "Rotate now — not at the next sprint boundary.\n\n") if live else ""
    console = f"   Console: {issuer.console_url}\n" if issuer.console_url else ""
    return (
        f"{urgency}"
        f"1. ROTATE at {issuer.name} — this is the fix.\n"
        f"{console}"
        f"   CLI:\n{_indent(issuer.rotate_cli)}\n\n"
        f"2. CHECK FOR ABUSE before assuming no harm: pull the issuer's audit log for\n"
        f"   this credential (AWS: CloudTrail by accessKeyId; GitHub: the org audit\n"
        f"   log by token id) covering first-commit-date → now.\n\n"
        f"3. PURGE the value from history:\n{_indent(purge_history(path, repo_hint=repo_hint))}\n\n"
        f"4. PREVENT the recurrence: move the value into the secret store and add a\n"
        f"   pre-commit gitleaks hook, so the next one never reaches a remote.")


def _indent(text: str, pad: str = "     ") -> str:
    return "\n".join(pad + line for line in text.splitlines())

"""Per-scanner severity normalization onto the alert contract's five levels.

Every scanner ships its own scale, and two of them ship no usable scale at all:

* **gitleaks** has no severity field. A committed credential is critical by
  policy, not by scanner opinion.
* **checkov** community edition emits `severity: null` — severities are a paid
  Bridgecrew feature. Taking that at face value would render every IaC finding
  as "unknown", so gatehouse owns the table below. It is small on purpose:
  only checks whose *failure mode* is public exposure or credential leakage
  are lifted above the medium default, and each entry says why.

The tables are data, not code, so Security can review the mapping without
reading Python — and so `docs/gatehouse-severity-mapping.md` can be generated
from them rather than drifting from them.
"""

from __future__ import annotations

# semgrep: ERROR/WARNING/INFO is a *confidence-weighted* scale, not an impact
# scale. ERROR means "this rule is confident", which for the security rulesets
# we run means a real exploitable pattern -> high. Nothing maps to critical:
# critical is reserved for live credential exposure, where the blast radius is
# immediate and does not depend on reachability.
SEMGREP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

# trivy speaks the same words we do, so this is a case fold plus UNKNOWN.
TRIVY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "informational",
}

# checkov: gatehouse-owned. Default is medium (see CHECKOV_DEFAULT); these are
# the checks where a misconfiguration is reachable from the public internet or
# leaks credentials, which is a different class of problem from "no tags".
CHECKOV_HIGH = {
    "CKV_AWS_20": "S3 bucket readable by any AWS principal or anonymous user",
    "CKV_AWS_57": "S3 bucket writable by any AWS principal or anonymous user",
    "CKV_AWS_53": "S3 account/bucket public-access block disabled (BlockPublicAcls)",
    "CKV_AWS_54": "S3 account/bucket public-access block disabled (BlockPublicPolicy)",
    "CKV_AWS_55": "S3 account/bucket public-access block disabled (IgnorePublicAcls)",
    "CKV_AWS_56": "S3 account/bucket public-access block disabled (RestrictPublicBuckets)",
    "CKV_AWS_23": "Security group rule opens a port to 0.0.0.0/0 without description",
    # CKV_AWS_24 / CKV_AWS_25 live in CHECKOV_CRITICAL (CNAPP aws_sg_wide_open).
    "CKV_AWS_260": "Security group allows ingress from 0.0.0.0/0 to port 80",
    "CKV_AWS_46": "Hardcoded credentials in an EC2 instance definition",
    "CKV_AWS_41": "Hardcoded AWS credentials in the provider block",
    "CKV_GCP_11": "GCP SQL instance exposed to the public internet",
    "CKV_GCP_28": "GCS bucket publicly accessible",
    "CKV_GCP_15": "BigQuery dataset publicly accessible",
    "CKV_AZURE_1": "Azure storage account allows blob public access",
    "CKV_AZURE_10": "Storage account allows public blob access",
    "CKV_AWS_16": "RDS instance storage not encrypted",
    "CKV_K8S_17": "Pod shares host PID namespace",
    "CKV_K8S_18": "Pod shares host IPC namespace",
    "CKV_K8S_19": "Pod shares host network namespace",
    "CKV_K8S_21": "Pod mounts a hostPath volume",
    "CKV_K8S_22": "Container may run as root (runAsNonRoot not set)",
    "CKV_K8S_23": "Container runAsUser is 0 / root",
    "CKV_K8S_25": "allowPrivilegeEscalation not disabled",
    "CKV_K8S_28": "Container adds NET_RAW capability",
    "CKV_K8S_37": "Container adds dangerous Linux capabilities",
    "CKV_K8S_45": "RBAC can read secrets",
    "CKV_K8S_46": "RBAC can create pods/exec",
}
CHECKOV_CRITICAL = {
    # Secret material in IaC is the same class as a secret in code: rotate now.
    "CKV_SECRET_6": "Base64 high-entropy string committed in infrastructure code",
    # AIM-329: CNAPP-critical posture prevented by these Checkov rules.
    "CKV_AWS_24": "Security group allows SSH from 0.0.0.0/0",
    "CKV_AWS_25": "Security group allows RDP from 0.0.0.0/0",
    "CKV_AWS_1": "IAM policy uses Action * and Resource *",
    "CKV_AWS_40": "IAM policy grants full administrative privileges",
    "CKV_K8S_16": "Container runs privileged",
    "CKV_K8S_42": "ClusterRoleBinding to cluster-admin",
    "CKV_K8S_49": "RBAC Role/ClusterRole uses wildcards",
}
CHECKOV_DEFAULT = "medium"


def from_semgrep(raw: str | None) -> str:
    return SEMGREP.get((raw or "").upper(), "medium")


def from_trivy(raw: str | None) -> str:
    return TRIVY.get((raw or "").upper(), "medium")


def from_checkov(check_id: str, raw: str | None = None) -> str:
    """Vendor severity when present (paid tiers set it), else our own table.

    Preferring the vendor value when it exists means a customer running a
    licensed checkov gets their tuned severities rather than ours, and the
    table degrades to a fallback instead of an override.
    """
    if raw:
        vendor = str(raw).upper()
        if vendor in TRIVY:  # same five words
            return TRIVY[vendor]
    if check_id in CHECKOV_CRITICAL:
        return "critical"
    if check_id in CHECKOV_HIGH:
        return "high"
    return CHECKOV_DEFAULT

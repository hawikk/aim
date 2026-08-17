"""gatehouse — PR-time security scanning (pillar 3 of the Unified Security Stack).

A GitHub App that runs Semgrep, Gitleaks, Checkov and Trivy against the lines a
pull request changed, merges the results into one check run and one comment,
and publishes each finding to the cross-pillar alert bus as `security.alert/v1`.

Entry points: `gatehouse.cli` (local scans, CI) and `gatehouse.server` (webhook).
"""

__version__ = "0.1.0"

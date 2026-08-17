"""Gate precision benchmark (AIM-334).

Measured FP/FN rates on a versioned corpus, per gate (gitleaks / semgrep /
checkov / trivy). Results feed the scorecard and drive auto-observe when a
gate exceeds its published FP budget.
"""

CORPUS_VERSION = "1.0.0"
GATES = ("gitleaks", "semgrep", "checkov", "trivy")

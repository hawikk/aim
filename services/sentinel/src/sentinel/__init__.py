"""Sentinel agent — the stack's triage and notification service (AIM-165).

Reads the unified alert bus (D3.1 / AIM-158), collapses bursts into incidents,
asks an LLM what happened and whether it is real, and pings a human with a
copy-paste remediation. It never applies a fix and holds no write credentials
anywhere (D4): every output of this service is text a human chooses to run.
"""

__version__ = "0.1.0"

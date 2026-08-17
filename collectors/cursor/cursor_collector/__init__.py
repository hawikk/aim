"""Cursor telemetry endpoint collector (metadata-only).

Collects AI-usage telemetry from Cursor's local surfaces (hooks, local
SQLite state) for a corporate AI-usage security monitoring platform.
Prompt/response text is matched locally for risk flags and is never
stored or transmitted.
"""

__version__ = "0.1.0"

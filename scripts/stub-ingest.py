#!/usr/bin/env python3
"""Minimal stub ingest endpoint for exercising `aim join`.

Stdlib-only. Speaks just enough of the enroll/heartbeat protocol
(docs/deployment/enrollment-and-heartbeat.md) to drive an end-to-end
`aim join` / `aim status` without the real ingest service:

  POST /v1/enroll     issues a fixed device token (or 401 for a bad token)
  POST /v1/heartbeat  accepts the device token (200)

It is a TEST/DEMO fixture, not a product surface — no persistence, no auth
beyond a single revoked-token check used to prove the fail-fast path.

Usage:
    python3 scripts/stub-ingest.py [PORT] [--revoked TOKEN]
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEVICE_TOKEN = "dev-tok-stub"
DEVICE_ID = "dev-stub-1"
_revoked = "revoked"


class _Handler(BaseHTTPRequestHandler):
    def _token(self) -> str:
        return (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()

    def do_POST(self):  # noqa: N802 (http.server API)
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == "/v1/enroll":
            if self._token() == _revoked or not self._token():
                return self._send(401, {"error": "enroll token revoked"})
            return self._send(201, {
                "device_token": DEVICE_TOKEN, "device_id": DEVICE_ID,
                "already_enrolled": False, "heartbeat_interval_sec": 300})
        if self.path == "/v1/heartbeat":
            if self._token() == DEVICE_TOKEN:
                return self._send(200, {"heartbeat_interval_sec": 300})
            return self._send(401, {"error": "unknown device token"})
        self._send(404, {"error": "not found"})

    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # keep the test output clean
        pass


def main(argv) -> int:
    port = 8799
    global _revoked
    rest = list(argv)
    if rest and rest[0].isdigit():
        port = int(rest.pop(0))
    if "--revoked" in rest:
        _revoked = rest[rest.index("--revoked") + 1]
    ThreadingHTTPServer(("127.0.0.1", port), _Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

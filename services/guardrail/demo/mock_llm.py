"""Local OpenAI-compatible chat stub for the sandbox pilot.

The sandbox has no external LLM provider key, so the dogfood pilot points the
guardrail LLM-judge at this stub instead. It implements just
POST /v1/chat/completions with deterministic token usage and a small latency,
so the real instrumentation path (client -> span -> OTLP receiver -> Apps
view) is exercised end-to-end without an external dependency. A snippet
containing TRIGGER_ERROR gets an HTTP 500 so the error/latency signals in the
Apps view are exercised too.

Run:  python services/guardrail/demo/mock_llm.py --port 9100
"""

from __future__ import annotations

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ERROR_TRIGGER = "TRIGGER_ERROR"


class MockLlmHandler(BaseHTTPRequestHandler):
    server_version = "aim-mock-llm/0.1"

    def do_POST(self) -> None:  # noqa: N802 (http.server naming)
        if self.path != "/v1/chat/completions":
            self._send(404, {"error": "unknown path"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._send(400, {"error": "bad request"})
            return

        model = body.get("model") or "mock-llm"
        messages = body.get("messages") or []
        prompt_text = " ".join(str(m.get("content", "")) for m in messages)
        # Rough-but-deterministic token accounting, like a real usage object.
        prompt_tokens = max(1, len(prompt_text.split()))
        if ERROR_TRIGGER in prompt_text:
            time.sleep(0.05)
            self._send(500, {"error": "simulated provider failure"})
            return

        verdict = "flag" if "AKIA" in prompt_text or "secret" in prompt_text.lower() else "allow"
        reason = "looks like a real credential" if verdict == "flag" else "placeholder or benign content"
        completion = json.dumps({"verdict": verdict, "reason": reason})
        time.sleep(0.05 + (len(prompt_text) % 5) * 0.02)  # 50-130ms fake latency
        self._send(200, {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": completion},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": len(completion.split()),
                "total_tokens": prompt_tokens + len(completion.split()),
            },
        })

    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: object) -> None:
        pass  # keep pilot output clean


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=9100)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), MockLlmHandler)
    print(f"mock LLM listening on http://{args.host}:{args.port}/v1/chat/completions")
    server.serve_forever()


if __name__ == "__main__":
    main()

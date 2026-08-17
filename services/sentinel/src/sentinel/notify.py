"""Delivery to humans: Slack, generic webhook, email.

Two properties this module exists to guarantee:

* **Fan-out, not fail-over.** Every enabled channel is attempted for every
  notification. A Slack outage must not swallow the email copy, and the result
  of each attempt is recorded separately in the outbox.
* **A failed delivery is a visible fact.** Retries are bounded (3, exponential
  backoff, on 429/5xx and network errors — the same policy as the guardrail
  notifier so operators only learn one). What is *not* bounded is the record:
  a delivery that never succeeded stays in the outbox with its error, is
  counted in ``/healthz``, and is retried by the next loop pass. Nothing here
  is allowed to end with a swallowed exception and a return.

Signature scheme for generic webhooks is deliberately the one already shipped
by AIM's guardrail notifier — ``X-AIM-Signature: sha256=<hex>`` over the exact
body bytes — so a receiver that already verifies AIM alerts needs no second
code path for sentinel ones.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

MAX_RETRIES = 3
BACKOFF_BASE_SECONDS = 0.5
DEFAULT_TIMEOUT_SECONDS = 10.0

# (url, headers, body) -> status code. Raises on network failure. Injectable.
Transport = Callable[[str, dict, bytes], int]


class DeliveryError(Exception):
    pass


@dataclass(frozen=True)
class DeliveryResult:
    channel: str
    delivered: bool
    attempts: int
    error: str = ""


def http_transport(url: str, headers: dict, body: bytes) -> int:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_SECONDS) as resp:
            return resp.status
    except urllib.error.HTTPError as err:
        return err.code
    except urllib.error.URLError as err:
        raise DeliveryError(f"network: {err.reason}") from err
    except OSError as err:
        raise DeliveryError(f"network: {err}") from err


def smtp_send(channel, subject: str, body: str) -> int:
    import smtplib
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"] = channel.smtp_from
    msg["To"] = channel.target
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(channel.smtp_host, channel.smtp_port, timeout=DEFAULT_TIMEOUT_SECONDS) as srv:
        srv.send_message(msg)
    return 200


def _retryable(status: int) -> bool:
    return status == 429 or 500 <= status < 600


class Notifier:
    """Sends one rendered notification to every enabled channel."""

    def __init__(self, cfg, *, transport: Transport | None = None,
                 mailer: Callable[[object, str, str], int] | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.cfg = cfg
        self._transport = transport or http_transport
        self._mailer = mailer or smtp_send
        self._sleep = sleep

    @property
    def enabled_channels(self) -> list:
        return [c for c in self.cfg.channels if c.enabled and c.target]

    def send(self, *, slack_payload: dict, text: str, subject: str) -> list[DeliveryResult]:
        results = []
        for channel in self.enabled_channels:
            results.append(self._send_one(channel, slack_payload, text, subject))
        if not results:
            # No channel configured at all is a deployment state, not an error
            # to swallow: the caller records it in the outbox as undelivered so
            # `/healthz` and the decision log show that the ping had nowhere to
            # go. Silence with no trace is the failure mode; silence with a
            # counter is a misconfiguration someone can see.
            results.append(DeliveryResult(channel="(none)", delivered=False, attempts=0,
                                          error="no notification channel configured"))
        return results

    def _send_one(self, channel, slack_payload: dict, text: str,
                  subject: str) -> DeliveryResult:
        last_error = ""
        attempt = 0
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                if channel.kind == "slack":
                    body = json.dumps(slack_payload).encode()
                    status = self._transport(channel.target, {"content-type": "application/json"},
                                             body)
                elif channel.kind == "webhook":
                    body = json.dumps({"kind": "sentinel.notification", "text": text,
                                       "slack": slack_payload}).encode()
                    headers = {"content-type": "application/json"}
                    if channel.secret:
                        digest = hmac.new(channel.secret.encode(), body, hashlib.sha256).hexdigest()
                        headers["X-AIM-Signature"] = f"sha256={digest}"
                    status = self._transport(channel.target, headers, body)
                elif channel.kind == "email":
                    status = self._mailer(channel, subject, text)
                else:
                    return DeliveryResult(channel=channel.name, delivered=False, attempts=attempt,
                                          error=f"unknown channel kind {channel.kind!r}")
            except DeliveryError as err:
                last_error = str(err)
            except Exception as err:  # noqa: BLE001
                # smtplib and injected transports raise their own families. The
                # loop that called us is the only path between a critical
                # finding and a human; it does not get to die here.
                last_error = f"{type(err).__name__}: {err}"
            else:
                if 200 <= status < 300:
                    return DeliveryResult(channel=channel.name, delivered=True, attempts=attempt)
                last_error = f"http {status}"
                if not _retryable(status):
                    break
            if attempt < MAX_RETRIES:
                self._sleep(BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))
        return DeliveryResult(channel=channel.name, delivered=False, attempts=attempt,
                              error=last_error or "unknown")

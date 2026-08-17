#!/usr/bin/env python3
"""Seed the ST8 scenario — a publicly readable S3 bucket — onto the alert bus.

    python services/sentinel/demo/seed_st8.py --url redis://localhost:6379/0
    python services/sentinel/demo/seed_st8.py --burst 12      # storm test
    python services/sentinel/demo/seed_st8.py --print-only    # no bus needed

Deliberately NOT part of the ``sentinel`` package. The service is read-only on
the bus by design — no XADD, no XDEL, no XTRIM anywhere in ``src/sentinel`` —
and shipping a publisher inside it would put an XADD one import away from the
consumer, where the next person to need one would find it. This file is a demo
harness that stands in for a CNAPP publisher; it lives beside the
service, not in it.

The alert it emits is shaped exactly like the CNAPP's real output
(``backend/alert_bus/mapping.py``): ``cloud_posture.prowler_s3_bucket_public_access``,
``critical``, an ARN resource ref, a ``cnapp:/…`` evidence ref. It is validated
against the publisher schema here before it is written, for the same reason the
real publishers do it — an invalid alert must fail at the publisher, loudly,
not become a consumer's mystery.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

PILLAR = "cloud_posture"
FINDING_TYPE = "cloud_posture.prowler_s3_bucket_public_access"
STREAM_KEY = os.environ.get("ALERT_BUS_STREAM", "secstack:alerts:v1")
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "..", "..", "packages", "schema", "schema", "v1",
                           "security-alert.schema.json")


def _dedupe_key(finding_type: str, resource_ref: str) -> str:
    return hashlib.sha256(f"{PILLAR}|{finding_type}|{resource_ref}".encode()).hexdigest()


def _alert_id(dedupe: str) -> str:
    """uuid4-shaped but derived — same trick as the real publishers, so a
    replay of the same finding carries the same id and the consumer's
    idempotency gate does its job."""
    hexed = dedupe[:32]
    return (f"{hexed[0:8]}-{hexed[8:12]}-4{hexed[13:16]}-"
            f"{'89ab'[int(hexed[16], 16) % 4]}{hexed[17:20]}-{hexed[20:32]}")


def build_alert(bucket: str, *, account: str = "123456789012", region: str = "eu-west-1",
                severity: str = "critical") -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ref = f"arn:aws:s3:::{bucket}"
    dedupe = _dedupe_key(FINDING_TYPE, ref)
    severity_id = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}[severity]
    return {
        "schema_version": "1.1",
        "alert_id": _alert_id(dedupe),
        "dedupe_key": dedupe,
        "pillar": PILLAR,
        "producer": {"name": "cnapp-scanner", "version": "0.1.0"},
        "finding_type": FINDING_TYPE,
        "title": f"S3 bucket {bucket} is publicly readable",
        "severity": severity,
        "severity_id": severity_id,
        "status": "new",
        "observed_at": now,
        "first_seen_at": now,
        "last_seen_at": now,
        "resource": {
            "kind": "cloud_resource",
            "ref": ref,
            "display": bucket,
            "provider": "aws",
            "account_ref": account,
            "region": region,
        },
        "subject_ref": None,
        "evidence": {
            "source_uri": f"cnapp:/issues/{dedupe[:16]}",
            "detail_count": 1,
            "summary": ("prowler/s3_bucket_public_access: bucket policy grants "
                        "s3:GetObject to Principal '*'."),
        },
        "labels": {"check": "s3_bucket_public_access", "scanner": "prowler",
                   "compliance": "cis-1.5"},
    }


def validate(alert: dict) -> list[str]:
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        print("seed: jsonschema not installed; publishing unvalidated is not supported",
              file=sys.stderr)
        raise SystemExit(2)
    with open(SCHEMA_PATH) as fh:
        validator = Draft202012Validator(json.load(fh))
    return [f"{'.'.join(str(p) for p in e.path) or '(root)'}: {e.message}"
            for e in validator.iter_errors(alert)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("ALERT_BUS_URL",
                                                        "redis://localhost:6379/0"))
    parser.add_argument("--stream", default=STREAM_KEY)
    parser.add_argument("--bucket", default="acme-customer-exports")
    parser.add_argument("--account", default="123456789012")
    parser.add_argument("--severity", default="critical")
    parser.add_argument("--burst", type=int, default=1,
                        help="publish N distinct buckets in the same account — the "
                             "storm case the sentinel must collapse into one incident")
    parser.add_argument("--print-only", action="store_true")
    args = parser.parse_args(argv)

    alerts = [build_alert(args.bucket if args.burst == 1 else f"{args.bucket}-{i:02d}",
                          account=args.account, severity=args.severity)
              for i in range(args.burst)]
    for alert in alerts:
        errors = validate(alert)
        if errors:
            print(f"seed: REFUSING to publish an invalid alert: {errors}", file=sys.stderr)
            return 1

    if args.print_only:
        print(json.dumps(alerts, indent=2))
        return 0

    import redis
    client = redis.Redis.from_url(args.url, decode_responses=True)
    for alert in alerts:
        entry_id = client.xadd(args.stream, {"alert": json.dumps(alert)})
        print(f"published {alert['alert_id']} ({alert['resource']['display']}) as {entry_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

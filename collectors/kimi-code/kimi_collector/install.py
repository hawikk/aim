"""One-line install UX (AIM-80).

Kimi Code has no hook API, so there is nothing to register — install
writes the managed config, enrolls the device with the ingestion service,
and verifies connectivity end-to-end. Collection then runs via
``watch``/``scan-once`` (scheduled task, cron, or systemd user timer).
"""

import sys

from . import enroll


def main(args: list) -> int:
    opts = enroll.parse_install_args(args)
    if opts is None:
        sys.stderr.write("usage: python -m kimi_collector "
                         + enroll.INSTALL_USAGE + "\n")
        return 2
    return enroll.setup(opts)


def uninstall() -> None:
    enroll.clear_device_token()

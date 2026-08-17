"""One-line install UX (AIM-80).

GitHub Copilot has no hook API we can register. Install writes managed
config, enrolls the device, and verifies connectivity. Collection runs
via ``watch`` / ``scan-once``.
"""

import sys

from . import enroll


def main(args: list) -> int:
    opts = enroll.parse_install_args(args)
    if opts is None:
        sys.stderr.write("usage: python -m copilot_collector "
                         + enroll.INSTALL_USAGE + "\n")
        return 2
    return enroll.setup(opts)


def uninstall() -> None:
    enroll.clear_device_token()

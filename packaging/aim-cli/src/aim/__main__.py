"""`python -m aim <command>` — same dispatch as the `aim` console script.

The auto-start service (AIM-139) launches the watcher as
``<interpreter> -m aim watch`` rather than by console-script name: the module
form resolves against the exact interpreter that installed the service, so it
keeps working even if the `aim` shim isn't on the service's PATH (a real gap
under systemd/launchd, whose environments are minimal by design).
"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())

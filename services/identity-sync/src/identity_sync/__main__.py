"""CLI entry point.

  identity-sync sync   # one-shot directory sync (called by the scheduler)
  identity-sync serve  # run the HTTP API
"""

from __future__ import annotations

import argparse

import uvicorn

from .config import get_settings
from .db import SessionLocal, init_db
from .directory_source import build_source
from .sync import sync_directory


def main() -> None:
    parser = argparse.ArgumentParser(prog="identity-sync")
    parser.add_argument("command", choices=["sync", "serve"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    settings = get_settings()
    init_db()

    if args.command == "sync":
        with SessionLocal() as session:
            result = sync_directory(session, build_source(settings))
        print(result)
    else:
        uvicorn.run("identity_sync.api:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()

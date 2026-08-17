"""CLI: shadow-ai sync | inventory | serve"""

from __future__ import annotations

import argparse
import json
import sys

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from .api import _row_to_dict, create_app
from .catalogue import Catalogue
from .coding_discovery import (
    build_coding_discoveries,
    persist_coding_discoveries,
    upsert_platform_coding_findings,
)
from .config import Settings
from .db import Base, ToolInventoryRow
from .discovery import discovery_lag_metrics, upsert_discovery_queue
from .findings import (
    build_grant_findings,
    persist_grant_findings,
    upsert_platform_findings,
)
from .grant_source import build_source
from .inventory import build_inventory, persist_inventory
from .process_source import build_process_source
from .proxy_source import build_proxy_source
from .sync import purge_expired_revokes, sync_grants


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shadow-ai")
    parser.add_argument("command", choices=["sync", "inventory", "serve"])
    args = parser.parse_args(argv)

    settings = Settings()
    engine = create_engine(settings.database_url)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)

    if args.command == "sync":
        with sessions() as session:
            catalogue = Catalogue.load(settings.catalogue_path)
            stats = sync_grants(session, build_source(settings), settings.pseudonym_secret)
            purged = purge_expired_revokes(session, settings.revoked_retention_days)
            rows = build_inventory(session, catalogue, build_proxy_source(settings))
            persist_inventory(session, rows)
            findings = build_grant_findings(session, catalogue)
            n_findings = persist_grant_findings(session, findings)
            coding = build_coding_discoveries(
                session,
                catalogue,
                build_proxy_source(settings),
                build_process_source(settings),
            )
            n_coding = persist_coding_discoveries(session, coding)
            n_platform = 0
            n_platform_coding = 0
            if settings.emit_platform_findings:
                n_platform = upsert_platform_findings(session, findings)
                n_platform_coding = upsert_platform_coding_findings(session, coding)
            discovery_stats = upsert_discovery_queue(session, catalogue)
            lag = discovery_lag_metrics(session)
            print(
                json.dumps(
                    {
                        **stats,
                        "revoked_grants_purged": purged,
                        "inventory_tools": len(rows),
                        "unapproved_ai_saas_grant_findings": n_findings,
                        "unknown_ai_coding_tool_findings": n_coding,
                        "platform_findings_upserted": n_platform,
                        "platform_coding_findings_upserted": n_platform_coding,
                        **discovery_stats,
                        **lag,
                    },
                    indent=2,
                )
            )
        return 0

    if args.command == "inventory":
        with sessions() as session:
            rows = session.execute(
                select(ToolInventoryRow).order_by(ToolInventoryRow.risk_score.desc())
            ).scalars().all()
            print(json.dumps({"tools": [_row_to_dict(r) for r in rows]}, indent=2, default=str))
        return 0

    if args.command == "serve":
        import uvicorn

        uvicorn.run(create_app(settings), host=settings.host, port=settings.port)
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())

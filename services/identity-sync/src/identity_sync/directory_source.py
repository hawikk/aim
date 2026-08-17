"""Directory sources: where user/org-unit reference data comes from.

- FixtureDirectorySource: dev/test source reading JSON files (mirrors the Admin SDK shape).
- GoogleDirectorySource: real Google Admin SDK Directory API, paged users.list + orgUnits.list.

Both return the same dataclasses so sync.py doesn't care which one is wired in.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .config import Settings


@dataclass
class DirectoryUser:
    id: str
    primary_email: str
    full_name: str
    org_unit_path: str
    suspended: bool = False


@dataclass
class DirectoryOrgUnit:
    org_unit_path: str
    name: str
    parent_path: str | None = None


@dataclass
class DirectorySnapshot:
    users: list[DirectoryUser] = field(default_factory=list)
    org_units: list[DirectoryOrgUnit] = field(default_factory=list)


class DirectorySource(Protocol):
    def fetch(self) -> DirectorySnapshot: ...


class FixtureDirectorySource:
    """Reads fixtures/directory_users.json and fixtures/org_units.json (Admin SDK field shapes)."""

    def __init__(self, fixture_dir: str):
        self.fixture_dir = Path(fixture_dir)

    def fetch(self) -> DirectorySnapshot:
        users_raw = json.loads((self.fixture_dir / "directory_users.json").read_text())
        ous_raw = json.loads((self.fixture_dir / "org_units.json").read_text())
        users = [
            DirectoryUser(
                id=u["id"],
                primary_email=u["primaryEmail"].lower(),
                full_name=u.get("name", {}).get("fullName", ""),
                org_unit_path=u.get("orgUnitPath", "/"),
                suspended=bool(u.get("suspended", False)),
            )
            for u in users_raw
        ]
        ous = [
            DirectoryOrgUnit(
                org_unit_path=o["orgUnitPath"],
                name=o.get("name", o["orgUnitPath"].rsplit("/", 1)[-1]),
                parent_path=o.get("parentOrgUnitPath"),
            )
            for o in ous_raw
        ]
        return DirectorySnapshot(users=users, org_units=ous)


class GoogleDirectorySource:
    """Google Admin SDK Directory API via a service account with domain-wide delegation.

    Required SA scopes:
      - https://www.googleapis.com/auth/admin.directory.user.readonly
      - https://www.googleapis.com/auth/admin.directory.orgunit.readonly
    """

    def __init__(self, settings: Settings):
        from google.oauth2 import service_account  # noqa: PLC0415 - optional dependency
        from googleapiclient.discovery import build  # noqa: PLC0415

        creds = service_account.Credentials.from_service_account_file(
            settings.google_service_account_file,
            scopes=[
                "https://www.googleapis.com/auth/admin.directory.user.readonly",
                "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
            ],
        ).with_subject(settings.google_admin_subject)
        self._service = build("admin", "directory_v1", credentials=creds, cache_discovery=False)
        self._customer_id = settings.google_customer_id

    def fetch(self) -> DirectorySnapshot:
        snapshot = DirectorySnapshot()

        ous_resp = self._service.orgunits().list(customerId=self._customer_id, type="all").execute()
        for o in ous_resp.get("organizationUnits", []):
            snapshot.org_units.append(
                DirectoryOrgUnit(
                    org_unit_path=o["orgUnitPath"],
                    name=o.get("name", o["orgUnitPath"].rsplit("/", 1)[-1]),
                    parent_path=o.get("parentOrgUnitPath"),
                )
            )

        page_token = None
        while True:
            resp = (
                self._service.users()
                .list(
                    customer=self._customer_id,
                    maxResults=500,
                    orderBy="email",
                    pageToken=page_token,
                    projection="basic",
                    showDeleted="false",
                )
                .execute()
            )
            for u in resp.get("users", []):
                snapshot.users.append(
                    DirectoryUser(
                        id=u["id"],
                        primary_email=u["primaryEmail"].lower(),
                        full_name=u.get("name", {}).get("fullName", ""),
                        org_unit_path=u.get("orgUnitPath", "/"),
                        suspended=bool(u.get("suspended", False)),
                    )
                )
            page_token = resp.get("nextPageToken")
            if not page_token:
                break
        return snapshot


def build_source(settings: Settings) -> DirectorySource:
    if settings.directory_source == "google":
        return GoogleDirectorySource(settings)
    return FixtureDirectorySource(settings.fixture_dir)

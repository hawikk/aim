"""OAuth grant sources: where IdP grant inventory comes from (Track 2).

Preferred build path — read-only grant inventory from corporate IdP:

- FixtureGrantSource: dev/dogfood fixture (Google Reports activity shape or
  normalized inventory shape).
- GoogleReportsGrantSource: Google Workspace Admin SDK Reports API `token`.
- EntraGrantSource: Microsoft Graph oauth2PermissionGrants + servicePrincipals
  + users (admin-consent and user grants).
- OktaGrantSource: Okta Apps API + user app assignments / grants.

All yield the same OAuthGrantEvent dataclass so sync.py does not care which
source is wired. Privacy: the email exists only inside this process long
enough to be pseudonymized; it is never stored or logged.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Protocol


@dataclass
class OAuthGrantEvent:
    user_email: str  # cleartext, pseudonymized at sync time, never stored
    app_name: str
    client_id: str | None
    scopes: list[str] = field(default_factory=list)
    ts: str = ""  # RFC 3339
    action: str = "authorize"  # authorize | revoke
    idp_source: str = "google_workspace"
    publisher: str | None = None


class GrantSource(Protocol):
    def fetch(self) -> Iterable[OAuthGrantEvent]: ...


def _parse_reports_activity(raw: dict, idp_source: str = "google_workspace") -> OAuthGrantEvent | None:
    """Normalize one Admin SDK Reports `token` activity into a grant event."""
    events = raw.get("events") or []
    if not events:
        return None
    ev = events[0]
    action = ev.get("name", "authorize")
    if action not in ("authorize", "revoke"):
        return None
    params: dict[str, object] = {}
    for p in ev.get("parameters", []):
        if "multiValue" in p:
            params[p["name"]] = list(p["multiValue"])
        else:
            params[p["name"]] = p.get("value", "")
    scope_param = params.get("scope", [])
    if isinstance(scope_param, str):
        scopes = scope_param.split()
    else:
        scopes = list(scope_param)
    email = (raw.get("actor") or {}).get("email", "")
    app_name = str(params.get("app_name", "")).strip()
    if not email or not app_name:
        return None
    return OAuthGrantEvent(
        user_email=email,
        app_name=app_name,
        client_id=str(params.get("client_id") or "") or None,
        scopes=scopes,
        ts=(raw.get("id") or {}).get("time", ""),
        action=action,
        idp_source=idp_source,
        publisher=str(params.get("publisher") or "") or None,
    )


def _parse_normalized_grant(raw: dict) -> OAuthGrantEvent | None:
    """Normalized inventory shape used by Entra/Okta fixtures and live adapters.

    {
      "user_email": "a@corp.example",
      "app_name": "ChatGPT",
      "client_id": "...",
      "scopes": ["openid", "..."],
      "ts": "2026-07-20T14:03:11Z",
      "action": "authorize",
      "idp_source": "entra",
      "publisher": "OpenAI"
    }
    """
    email = str(raw.get("user_email") or raw.get("email") or "").strip()
    app_name = str(raw.get("app_name") or raw.get("appName") or "").strip()
    if not email or not app_name:
        return None
    scopes = raw.get("scopes") or []
    if isinstance(scopes, str):
        scopes = scopes.split()
    return OAuthGrantEvent(
        user_email=email,
        app_name=app_name,
        client_id=str(raw.get("client_id") or raw.get("clientId") or "") or None,
        scopes=list(scopes),
        ts=str(raw.get("ts") or raw.get("timestamp") or ""),
        action=str(raw.get("action") or "authorize"),
        idp_source=str(raw.get("idp_source") or raw.get("idpSource") or "fixture"),
        publisher=str(raw.get("publisher") or "") or None,
    )


class FixtureGrantSource:
    """Reads a fixture file supporting both shapes:

    - Google Reports: {"items": [<admin#reports#activity>, ...]}
    - Normalized inventory: {"grants": [{user_email, app_name, ...}, ...]}
    """

    def __init__(self, fixture_path: str):
        self.fixture_path = Path(fixture_path)

    def fetch(self) -> Iterable[OAuthGrantEvent]:
        raw = json.loads(self.fixture_path.read_text())
        for item in raw.get("items", []):
            grant = _parse_reports_activity(item)
            if grant is not None:
                yield grant
        for item in raw.get("grants", []):
            grant = _parse_normalized_grant(item)
            if grant is not None:
                yield grant


class GoogleReportsGrantSource:
    """Google Workspace Admin SDK Reports API (reports_v1) token activities.

    Requires a service account with domain-wide delegation, scope
    https://www.googleapis.com/auth/admin.reports.audit.readonly, and an
    admin user to impersonate. Install the `google` extra for the client libs.
    """

    def __init__(self, credentials_file: str, delegated_admin: str, start_time: str | None = None):
        self.credentials_file = credentials_file
        self.delegated_admin = delegated_admin
        self.start_time = start_time

    def fetch(self) -> Iterable[OAuthGrantEvent]:
        from google.oauth2 import service_account  # noqa: PLC0415
        from googleapiclient.discovery import build  # noqa: PLC0415

        creds = service_account.Credentials.from_service_account_file(
            self.credentials_file,
            scopes=["https://www.googleapis.com/auth/admin.reports.audit.readonly"],
        ).with_subject(self.delegated_admin)
        service = build("admin", "reports_v1", credentials=creds, cache_discovery=False)
        request = service.activities().list(
            userKey="all",
            applicationName="token",
            **({"startTime": self.start_time} if self.start_time else {}),
        )
        while request is not None:
            resp = request.execute()
            for item in resp.get("items", []):
                grant = _parse_reports_activity(item, idp_source="google_workspace")
                if grant is not None:
                    yield grant
            request = service.activities().list_next(request, resp)


def _http_json(url: str, headers: dict[str, str], method: str = "GET", body: bytes | None = None) -> dict:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"HTTP {exc.code} from {url}: {detail}") from exc


class EntraGrantSource:
    """Microsoft Entra ID (Azure AD) OAuth2 permission grants via MS Graph.

    Read-only application permissions required on the app registration:
      - DelegatedPermissionGrant.Read.All  (or Directory.Read.All)
      - Application.Read.All
      - User.Read.All

    Auth: client-credentials (tenant_id + client_id + client_secret).
    Maps principalId → user UPN/mail and clientId (service principal object id)
    → app displayName + appId for catalogue matching.
    """

    TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    GRAPH = "https://graph.microsoft.com/v1.0"

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        if not tenant_id or not client_id or not client_secret:
            raise ValueError("EntraGrantSource requires tenant_id, client_id, client_secret")
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

    def _token(self) -> str:
        body = urllib.parse.urlencode(
            {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            }
        ).encode()
        data = _http_json(
            self.TOKEN_URL.format(tenant=self.tenant_id),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
            body=body,
        )
        return str(data["access_token"])

    def _paged(self, url: str, headers: dict[str, str]) -> Iterable[dict]:
        while url:
            data = _http_json(url, headers=headers)
            yield from data.get("value", [])
            url = data.get("@odata.nextLink") or ""

    def fetch(self) -> Iterable[OAuthGrantEvent]:
        token = self._token()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        # servicePrincipal object id → (displayName, appId, publisher)
        sp_by_id: dict[str, tuple[str, str | None, str | None]] = {}
        for sp in self._paged(
            f"{self.GRAPH}/servicePrincipals?$select=id,appId,displayName,publisherName&$top=999",
            headers,
        ):
            sp_by_id[str(sp["id"])] = (
                str(sp.get("displayName") or sp.get("appId") or "unknown"),
                str(sp.get("appId") or "") or None,
                str(sp.get("publisherName") or "") or None,
            )

        # user object id → mail/UPN
        user_by_id: dict[str, str] = {}
        for u in self._paged(
            f"{self.GRAPH}/users?$select=id,mail,userPrincipalName&$top=999",
            headers,
        ):
            email = str(u.get("mail") or u.get("userPrincipalName") or "").strip()
            if email:
                user_by_id[str(u["id"])] = email

        for g in self._paged(
            f"{self.GRAPH}/oauth2PermissionGrants?$top=999",
            headers,
        ):
            # consentType AllPrincipals = admin consent for all users — still a
            # grant of the AI SaaS against corporate identity; surface once as
            # a synthetic principal so inventory is not empty of admin-consent apps.
            principal_id = g.get("principalId")
            client_sp = str(g.get("clientId") or "")
            app_name, app_id, publisher = sp_by_id.get(client_sp, (client_sp or "unknown", None, None))
            scopes = str(g.get("scope") or "").split()
            ts = str(g.get("startTime") or g.get("expiryTime") or "")

            if principal_id and principal_id in user_by_id:
                yield OAuthGrantEvent(
                    user_email=user_by_id[str(principal_id)],
                    app_name=app_name,
                    client_id=app_id or client_sp,
                    scopes=scopes,
                    ts=ts,
                    action="authorize",
                    idp_source="entra",
                    publisher=publisher,
                )
            elif str(g.get("consentType") or "") == "AllPrincipals":
                # Admin-consent-only: no per-user principal. Attribute to a
                # stable synthetic mailbox so inventory + findings still fire;
                # analysts see idp_source=entra + app, not a real person.
                yield OAuthGrantEvent(
                    user_email="admin-consent@entra.local",
                    app_name=app_name,
                    client_id=app_id or client_sp,
                    scopes=scopes,
                    ts=ts,
                    action="authorize",
                    idp_source="entra",
                    publisher=publisher,
                )


class OktaGrantSource:
    """Okta application assignments / OAuth grants (read-only).

    Token needs:
      - okta.apps.read
      - okta.users.read

    Walks /api/v1/apps and for each OIDC/OAuth app lists assigned users with
    scopes where available. app.label becomes app_name; client_id from
    credentials.oauthClient.client_id.
    """

    def __init__(self, org_url: str, api_token: str):
        if not org_url or not api_token:
            raise ValueError("OktaGrantSource requires org_url and api_token")
        self.org_url = org_url.rstrip("/")
        self.api_token = api_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"SSWS {self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _paged(self, url: str) -> Iterable[dict]:
        while url:
            req = urllib.request.Request(url, headers=self._headers(), method="GET")
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                link = resp.headers.get("Link") or resp.headers.get("link") or ""
            if isinstance(body, list):
                yield from body
            else:
                yield from body.get("items", body.get("value", []))
            url = ""
            # Parse RFC 5988 Link: <url>; rel="next"
            for part in link.split(","):
                if 'rel="next"' in part or "rel=next" in part:
                    url = part.split(";")[0].strip().strip("<>")
                    break

    def fetch(self) -> Iterable[OAuthGrantEvent]:
        for app in self._paged(f"{self.org_url}/api/v1/apps?limit=200"):
            status = str(app.get("status") or "").upper()
            if status and status not in ("ACTIVE", "INACTIVE"):
                continue
            label = str(app.get("label") or app.get("name") or "").strip()
            if not label:
                continue
            creds = (app.get("credentials") or {}).get("oauthClient") or {}
            client_id = str(creds.get("client_id") or app.get("id") or "") or None
            app_id = str(app.get("id") or "")
            sign_on = str(app.get("signOnMode") or "")
            # Prefer OIDC/OAuth apps; still include SAML/SWA AI SaaS signups
            # because the security question is "who signed up", not only OAuth.
            if sign_on and "OPENID" not in sign_on.upper() and "OAUTH" not in sign_on.upper():
                # keep SAML/bookmark apps — ChatGPT SSO is often SAML
                pass

            for assignment in self._paged(f"{self.org_url}/api/v1/apps/{app_id}/users?limit=200"):
                profile = assignment.get("profile") or {}
                # Prefer nested user credentials if expanded; otherwise fetch email
                email = str(
                    assignment.get("credentials", {}).get("userName")
                    or profile.get("email")
                    or assignment.get("id")
                    or ""
                ).strip()
                # assignment.id is user id — resolve via /users when needed
                if email and "@" not in email:
                    try:
                        u = _http_json(
                            f"{self.org_url}/api/v1/users/{email}",
                            headers=self._headers(),
                        )
                        email = str(
                            (u.get("profile") or {}).get("email")
                            or (u.get("profile") or {}).get("login")
                            or ""
                        ).strip()
                    except Exception:
                        continue
                if not email or "@" not in email:
                    continue
                scopes: list[str] = []
                scope_raw = profile.get("scopes") or assignment.get("scope")
                if isinstance(scope_raw, str):
                    scopes = scope_raw.split()
                elif isinstance(scope_raw, list):
                    scopes = [str(s) for s in scope_raw]
                yield OAuthGrantEvent(
                    user_email=email,
                    app_name=label,
                    client_id=client_id,
                    scopes=scopes,
                    ts=str(assignment.get("lastUpdated") or assignment.get("created") or ""),
                    action="authorize" if status != "INACTIVE" else "revoke",
                    idp_source="okta",
                    publisher=str(app.get("name") or "") or None,
                )


class MultiGrantSource:
    """Concatenate multiple GrantSources (e.g. fixture + entra during cutover)."""

    def __init__(self, sources: list[GrantSource]):
        self.sources = sources

    def fetch(self) -> Iterable[OAuthGrantEvent]:
        for src in self.sources:
            yield from src.fetch()


def build_source(settings) -> GrantSource:
    kind = (settings.grant_source or "fixture").lower().strip()
    if kind == "fixture":
        return FixtureGrantSource(settings.grant_fixture_path)
    if kind == "google":
        return GoogleReportsGrantSource(
            settings.google_credentials_file,
            settings.google_delegated_admin,
        )
    if kind == "entra":
        return EntraGrantSource(
            settings.entra_tenant_id,
            settings.entra_client_id,
            settings.entra_client_secret,
        )
    if kind == "okta":
        return OktaGrantSource(settings.okta_org_url, settings.okta_api_token)
    if kind == "multi":
        # Comma-separated SHADOW_AI_GRANT_SOURCES e.g. "fixture,entra"
        parts = [p.strip() for p in (settings.grant_sources or "").split(",") if p.strip()]
        if not parts:
            raise ValueError("SHADOW_AI_GRANT_SOURCE=multi requires SHADOW_AI_GRANT_SOURCES")
        # Temporarily build each child by mutating a shallow copy of settings kind
        children: list[GrantSource] = []
        for p in parts:
            children.append(build_source(_ChildSettings(settings, p)))
        return MultiGrantSource(children)
    raise ValueError(f"unknown SHADOW_AI_GRANT_SOURCE: {settings.grant_source}")


class _ChildSettings:
    """Proxy that overrides grant_source for multi-source composition."""

    def __init__(self, base, grant_source: str):
        self._base = base
        self.grant_source = grant_source

    def __getattr__(self, name: str):
        return getattr(self._base, name)

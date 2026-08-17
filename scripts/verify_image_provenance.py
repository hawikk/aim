#!/usr/bin/env python3
"""Verify GHCR image digests carry SLSA build provenance.

After ``release-images.yml`` pushes an image with buildx ``provenance: mode=max``,
this script reads the digest back through the OCI Referrers API and fails if no
``https://slsa.dev/provenance/*`` in-toto attestation is attached.

Dogfood: we generate provenance in the same workflow; this is the check that
the control actually landed. A green build with no provenance is exactly the
drift this product exists to catch.

Auth note: GHCR rejects raw GitHub PATs / ``GITHUB_TOKEN`` values
when sent as ``Authorization: Bearer <token>`` on the registry v2 API — the
response is ``HTTP 403 DENIED: invalid token``. The Docker registry token
exchange is required: Basic-auth the GitHub credential against
``https://ghcr.io/token?service=ghcr.io&scope=repository:<owner>/<image>:pull``,
then use the returned short-lived token as Bearer. Cosign / docker login do
this exchange internally; this script must too.

Stdlib only. ``--self-test`` proves the parser offline against fixture
referrers responses (no registry needed).

Usage:
    python3 scripts/verify_image_provenance.py \\
        --registry ghcr.io --owner hawikk --image aim-api \\
        --digest sha256:abc… --token-env GHCR_TOKEN --username-env GHCR_USERNAME

    python3 scripts/verify_image_provenance.py --self-test
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

# Predicate types accepted as "build provenance is present".
# buildx mode=max historically emitted v0.2; newer buildkit may emit v1.
SLSA_PREDICATE_PREFIXES = (
    "https://slsa.dev/provenance/",
    "https://slsa.dev/provenance",
)

WWW_AUTH_BEARER_RE = re.compile(
    r'Bearer\s+((?:[^=,\s]+="[^"]*"|[^=,\s]+=[^,\s]+)(?:,\s*(?:[^=,\s]+="[^"]*"|[^=,\s]+=[^,\s]+))*)',
    re.IGNORECASE,
)
WWW_AUTH_PARAM_RE = re.compile(r'([^=,\s]+)="([^"]*)"')


@dataclass(frozen=True)
class ProvenanceHit:
    predicate_type: str
    media_type: str
    digest: str
    artifact_type: str = ""


@dataclass(frozen=True)
class AuthChallenge:
    realm: str
    service: str
    scope: str


def is_slsa_predicate(value: str) -> bool:
    if not value:
        return False
    return any(value == p or value.startswith(p) for p in SLSA_PREDICATE_PREFIXES)


def extract_predicate_types(descriptor: dict[str, Any]) -> list[str]:
    """Pull predicate-type candidates out of an OCI referrer descriptor."""
    found: list[str] = []
    artifact_type = str(descriptor.get("artifactType") or "")
    if artifact_type:
        found.append(artifact_type)

    annotations = descriptor.get("annotations") or {}
    if isinstance(annotations, dict):
        for key in (
            "in-toto.io/predicate-type",
            "org.opencontainers.image.predicate-type",
            "predicate-type",
        ):
            val = annotations.get(key)
            if val:
                found.append(str(val))

    # Some referrers put the predicate type only in subject-adjacent mediaType.
    media = str(descriptor.get("mediaType") or "")
    if "slsa.dev/provenance" in media:
        found.append(media)

    return found


def find_provenance(referrers_doc: dict[str, Any]) -> list[ProvenanceHit]:
    """Return SLSA provenance hits from an OCI index / referrers list response."""
    manifests = referrers_doc.get("manifests") or []
    hits: list[ProvenanceHit] = []
    if not isinstance(manifests, list):
        return hits

    for desc in manifests:
        if not isinstance(desc, dict):
            continue
        media = str(desc.get("mediaType") or "")
        artifact_type = str(desc.get("artifactType") or "")
        digest = str(desc.get("digest") or "")
        predicates = extract_predicate_types(desc)

        # buildx attaches provenance as an in-toto statement whose
        # artifactType (or annotation) is the SLSA predicate URI.
        slsa_preds = [p for p in predicates if is_slsa_predicate(p)]
        if not slsa_preds:
            # Fallback: artifactType itself may be the full predicate URI.
            if is_slsa_predicate(artifact_type):
                slsa_preds = [artifact_type]
            else:
                continue

        # Prefer known attestation media types, but do not hard-require them —
        # registries occasionally rewrite media types; the predicate type is
        # the load-bearing signal.
        for pred in slsa_preds:
            hits.append(
                ProvenanceHit(
                    predicate_type=pred,
                    media_type=media,
                    digest=digest,
                    artifact_type=artifact_type,
                )
            )
    return hits


def is_attestation_descriptor(desc: dict[str, Any]) -> bool:
    """True if an index entry looks like a buildx/docker attestation manifest."""
    annotations = desc.get("annotations") or {}
    if isinstance(annotations, dict):
        ref_type = str(annotations.get("vnd.docker.reference.type") or "")
        if ref_type == "attestation-manifest":
            return True
    artifact_type = str(desc.get("artifactType") or "")
    if "in-toto" in artifact_type or is_slsa_predicate(artifact_type):
        return True
    media = str(desc.get("mediaType") or "")
    return "in-toto" in media


def attestation_candidate_digests(index_doc: dict[str, Any]) -> list[str]:
    """Digests of index siblings that may carry in-toto provenance layers."""
    out: list[str] = []
    for desc in index_doc.get("manifests") or []:
        if not isinstance(desc, dict):
            continue
        digest = str(desc.get("digest") or "")
        if digest.startswith("sha256:") and is_attestation_descriptor(desc):
            out.append(digest)
    return out


def find_provenance_in_attestation_manifest(manifest: dict[str, Any]) -> list[ProvenanceHit]:
    """Scan an attestation image-manifest for SLSA predicate annotations on layers."""
    hits: list[ProvenanceHit] = []
    # Layers carry the in-toto statement; config is usually empty JSON.
    for layer in manifest.get("layers") or []:
        if not isinstance(layer, dict):
            continue
        media = str(layer.get("mediaType") or "")
        digest = str(layer.get("digest") or "")
        predicates = extract_predicate_types(layer)
        # Also treat in-toto layer media as a weak signal; require SLSA predicate.
        slsa_preds = [p for p in predicates if is_slsa_predicate(p)]
        if not slsa_preds and "slsa.dev/provenance" in media:
            slsa_preds = [media]
        for pred in slsa_preds:
            hits.append(
                ProvenanceHit(
                    predicate_type=pred,
                    media_type=media,
                    digest=digest,
                    artifact_type=str(layer.get("artifactType") or ""),
                )
            )
    # Some layouts put the predicate on the manifest itself.
    hits.extend(find_provenance({"manifests": [manifest]}))
    return hits


def _registry_host(registry: str) -> str:
    return registry.removeprefix("https://").removeprefix("http://").rstrip("/")


def _repo_path(owner: str, image: str) -> str:
    return f"{owner.lower()}/{image.lower()}"


def build_referrers_url(registry: str, owner: str, image: str, digest: str) -> str:
    if not digest.startswith("sha256:"):
        raise ValueError(f"digest must be sha256:…, got {digest!r}")
    # GHCR repository path is owner/image (lowercase).
    return f"https://{_registry_host(registry)}/v2/{_repo_path(owner, image)}/referrers/{digest}"


def build_manifest_url(registry: str, owner: str, image: str, digest: str) -> str:
    if not digest.startswith("sha256:"):
        raise ValueError(f"digest must be sha256:…, got {digest!r}")
    return f"https://{_registry_host(registry)}/v2/{_repo_path(owner, image)}/manifests/{digest}"


# Accept both OCI index and image manifests. buildx with provenance+sbom
# pushes an image *index* whose sibling manifests carry the attestations.
MANIFEST_ACCEPT = (
    "application/vnd.oci.image.index.v1+json,"
    "application/vnd.docker.distribution.manifest.list.v2+json,"
    "application/vnd.oci.image.manifest.v1+json,"
    "application/vnd.docker.distribution.manifest.v2+json,"
    "application/vnd.oci.image.index.v1+json"
)


def parse_www_authenticate(header: str) -> AuthChallenge | None:
    """Parse a Docker-style ``WWW-Authenticate: Bearer realm=…,service=…,scope=…`` header."""
    if not header:
        return None
    match = WWW_AUTH_BEARER_RE.search(header)
    if not match:
        return None
    params = dict(WWW_AUTH_PARAM_RE.findall(match.group(1)))
    realm = params.get("realm")
    if not realm:
        return None
    return AuthChallenge(
        realm=realm,
        service=params.get("service", ""),
        scope=params.get("scope", ""),
    )


def default_token_url(registry: str, owner: str, image: str) -> str:
    """Build the well-known GHCR token exchange URL for a pull scope."""
    registry = registry.removeprefix("https://").removeprefix("http://").rstrip("/")
    repo = f"{owner.lower()}/{image.lower()}"
    query = urllib.parse.urlencode(
        {
            "service": registry,
            "scope": f"repository:{repo}:pull",
        }
    )
    return f"https://{registry}/token?{query}"


def exchange_registry_token(
    *,
    token_url: str,
    github_token: str,
    username: str | None,
) -> str:
    """Exchange a GitHub credential for a short-lived OCI registry bearer token.

    GHCR expects Basic auth of ``username:github_token`` against the token
    realm. For Actions, username is ``github.actor``; for classic PATs any
    non-empty username works, but the actor is preferred for auditability.
    """
    user = (username or "x-access-token").strip() or "x-access-token"
    basic = base64.b64encode(f"{user}:{github_token}".encode("utf-8")).decode("ascii")
    req = urllib.request.Request(
        token_url,
        headers={
            "Authorization": f"Basic {basic}",
            "Accept": "application/json",
            "User-Agent": "aim-verify-image-provenance/1.1",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise urllib.error.HTTPError(
            exc.url,
            exc.code,
            f"registry token exchange failed: {exc.reason}; body={detail!r}",
            exc.headers,
            None,
        ) from None

    try:
        payload = json.loads(body) if body.strip() else {}
    except json.JSONDecodeError as exc:
        raise ValueError(f"registry token response is not JSON: {body[:200]!r}") from exc

    registry_token = payload.get("token") or payload.get("access_token")
    if not registry_token:
        raise ValueError(
            f"registry token response missing token/access_token: keys={list(payload.keys())}"
        )
    return str(registry_token)


def _http_get_json(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def fetch_registry_json(
    url: str,
    *,
    token: str | None,
    username: str | None = None,
    registry: str = "ghcr.io",
    owner: str = "",
    image: str = "",
    accept: str = "application/vnd.oci.image.index.v1+json",
    empty_on_404: bool = True,
) -> dict[str, Any]:
    """GET a registry JSON document with Docker token exchange for GHCR.

    Order of attempts:
    1. Unauthenticated (public packages).
    2. Registry token obtained via Docker auth exchange from the GitHub token.
    """
    base_headers = {
        "Accept": accept,
        "User-Agent": "aim-verify-image-provenance/1.2",
    }

    # 1) Public packages need no auth.
    status, headers, body = _http_get_json(url, base_headers)
    if status == 200:
        return _decode_json_body(body)
    if status == 404 and empty_on_404:
        return {"manifests": []}

    # 2) Authenticated path. Never send a raw GitHub token as Bearer — GHCR
    # returns 403 DENIED/invalid token for ghs_/gho_ values.
    if not token:
        raise urllib.error.HTTPError(
            url, status, f"HTTP Error {status}: authentication required and no token provided",
            None, None,
        )

    token_url: str | None = None
    challenge = parse_www_authenticate(headers.get("www-authenticate", ""))
    if challenge and challenge.realm:
        q = {}
        if challenge.service:
            q["service"] = challenge.service
        if challenge.scope:
            q["scope"] = challenge.scope
        token_url = challenge.realm
        if q:
            token_url = f"{challenge.realm}?{urllib.parse.urlencode(q)}"
    elif owner and image:
        token_url = default_token_url(registry, owner, image)

    if not token_url:
        raise urllib.error.HTTPError(
            url,
            status,
            (
                f"HTTP Error {status}: cannot derive registry token URL "
                f"(www-authenticate={headers.get('www-authenticate')!r})"
            ),
            None,
            None,
        )

    registry_token = exchange_registry_token(
        token_url=token_url,
        github_token=token,
        username=username,
    )
    auth_headers = {**base_headers, "Authorization": f"Bearer {registry_token}"}
    status2, _headers2, body2 = _http_get_json(url, auth_headers)
    if status2 == 200:
        return _decode_json_body(body2)
    if status2 == 404 and empty_on_404:
        return {"manifests": []}

    detail = body2.decode("utf-8", errors="replace")[:300]
    return _raise_http(url, status2, detail)


def fetch_referrers(
    url: str,
    *,
    token: str | None,
    username: str | None = None,
    registry: str = "ghcr.io",
    owner: str = "",
    image: str = "",
    accept: str = "application/vnd.oci.image.index.v1+json",
) -> dict[str, Any]:
    """Fetch OCI referrers (legacy entry point; wraps fetch_registry_json)."""
    return fetch_registry_json(
        url,
        token=token,
        username=username,
        registry=registry,
        owner=owner,
        image=image,
        accept=accept,
        empty_on_404=True,
    )


def _raise_http(url: str, status: int, detail: str) -> dict[str, Any]:
    # Preserve the historical error shape that release-images logs show, while
    # adding the response body so the next 403 is debuggable in one glance.
    msg = f"HTTP Error {status}: Forbidden" if status == 403 else f"HTTP Error {status}"
    if detail:
        msg = f"{msg}; body={detail!r}"
    raise urllib.error.HTTPError(url, status, msg, None, None)


def _decode_json_body(body: bytes) -> dict[str, Any]:
    text = body.decode("utf-8")
    if not text.strip():
        return {"manifests": []}
    return json.loads(text)


def _dedupe_hits(hits: list[ProvenanceHit]) -> list[ProvenanceHit]:
    seen: set[tuple[str, str, str]] = set()
    out: list[ProvenanceHit] = []
    for h in hits:
        key = (h.predicate_type, h.digest, h.media_type)
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out


def verify(
    *,
    registry: str,
    owner: str,
    image: str,
    digest: str,
    token: str | None,
    username: str | None = None,
) -> list[ProvenanceHit]:
    """Locate SLSA provenance for a pushed image digest.

    buildx ``provenance: mode=max`` + ``sbom: true`` pushes an OCI *image
    index* whose sibling manifests carry the in-toto attestations (mediaType
    ``application/vnd.oci.image.index.v1+json``). Those are **inside** the
    index, not referrers of it. We therefore:

    1. Fetch the manifest at ``digest`` and, when it is an index, scan its
       ``manifests[]`` for SLSA predicate types.
    2. Also query the OCI Referrers API (attestation-as-referrer layout used
       by some registries / older attach modes).
    """
    common = dict(
        token=token,
        username=username,
        registry=registry,
        owner=owner,
        image=image,
    )
    hits: list[ProvenanceHit] = []

    # 1) Index / manifest body.
    manifest_url = build_manifest_url(registry, owner, image, digest)
    try:
        manifest = fetch_registry_json(
            manifest_url,
            accept=MANIFEST_ACCEPT,
            empty_on_404=False,
            **common,
        )
    except urllib.error.HTTPError as exc:
        # 404 here means the subject digest is missing — still try referrers
        # for clearer combined failure messaging below.
        if exc.code != 404:
            raise
        manifest = {}

    media = str(manifest.get("mediaType") or "")
    if "index" in media or "manifest.list" in media or "manifests" in manifest:
        hits.extend(find_provenance(manifest))
        # buildx often only marks siblings as attestation-manifest; the SLSA
        # predicate-type lives on the attestation's layer annotations.
        for att_digest in attestation_candidate_digests(manifest):
            att_url = build_manifest_url(registry, owner, image, att_digest)
            try:
                att_manifest = fetch_registry_json(
                    att_url,
                    accept=MANIFEST_ACCEPT,
                    empty_on_404=False,
                    **common,
                )
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    continue
                raise
            hits.extend(find_provenance_in_attestation_manifest(att_manifest))

    # 2) Referrers of the subject (or of the index).
    referrers_url = build_referrers_url(registry, owner, image, digest)
    referrers = fetch_referrers(referrers_url, **common)
    hits.extend(find_provenance(referrers))

    return _dedupe_hits(hits)


# ── self-test ────────────────────────────────────────────────────────────────


FIXTURE_WITH_PROVENANCE = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "manifests": [
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:deadbeef",
            "size": 1234,
            "artifactType": "application/vnd.in-toto+json",
            "annotations": {
                "in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2",
            },
        },
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:sbom",
            "size": 99,
            "artifactType": "application/vnd.cyclonedx+json",
        },
    ],
}

FIXTURE_PROVENANCE_V1_ARTIFACT_TYPE = {
    "manifests": [
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:abc",
            "artifactType": "https://slsa.dev/provenance/v1",
        }
    ]
}

FIXTURE_NO_PROVENANCE = {
    "manifests": [
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:sbom",
            "artifactType": "application/vnd.cyclonedx+json",
        }
    ]
}

FIXTURE_EMPTY = {"manifests": []}


def self_test() -> int:
    failures: list[str] = []

    def expect(rule: str, cond: bool, detail: str = "") -> None:
        if not cond:
            failures.append(f"{rule}: {detail or 'condition false'}")

    hits = find_provenance(FIXTURE_WITH_PROVENANCE)
    expect("finds v0.2 provenance", len(hits) == 1, f"got {hits}")
    expect(
        "predicate type preserved",
        hits[0].predicate_type == "https://slsa.dev/provenance/v0.2",
    )
    expect("ignores SBOM sibling", hits[0].digest == "sha256:deadbeef")

    hits_v1 = find_provenance(FIXTURE_PROVENANCE_V1_ARTIFACT_TYPE)
    expect("finds v1 via artifactType", len(hits_v1) == 1, f"got {hits_v1}")
    expect("v1 predicate", is_slsa_predicate(hits_v1[0].predicate_type))

    expect("empty is no provenance", find_provenance(FIXTURE_EMPTY) == [])
    expect("sbom-only is no provenance", find_provenance(FIXTURE_NO_PROVENANCE) == [])

    # buildx attestation-manifest sibling (predicate only on nested layers)
    att_index = {
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:platform",
                "platform": {"architecture": "amd64", "os": "linux"},
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:attestation",
                "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
            },
        ],
    }
    expect(
        "attestation candidates from index",
        attestation_candidate_digests(att_index) == ["sha256:attestation"],
    )
    att_manifest = {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [
            {
                "mediaType": "application/vnd.in-toto+json",
                "digest": "sha256:statement",
                "annotations": {
                    "in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2",
                },
            }
        ],
    }
    att_hits = find_provenance_in_attestation_manifest(att_manifest)
    expect("nested attestation layer provenance", len(att_hits) == 1, f"got {att_hits}")
    expect(
        "nested predicate type",
        att_hits[0].predicate_type == "https://slsa.dev/provenance/v0.2",
    )

    # URL builder
    url = build_referrers_url(
        "ghcr.io", "Hawikk", "Aim-API", "sha256:" + "a" * 64
    )
    expect(
        "url lowercases owner/image",
        url
        == f"https://ghcr.io/v2/hawikk/aim-api/referrers/sha256:{'a' * 64}",
        url,
    )
    murl = build_manifest_url("ghcr.io", "Hawikk", "Aim-API", "sha256:" + "b" * 64)
    expect(
        "manifest url lowercases owner/image",
        murl
        == f"https://ghcr.io/v2/hawikk/aim-api/manifests/sha256:{'b' * 64}",
        murl,
    )
    try:
        build_referrers_url("ghcr.io", "o", "i", "not-a-digest")
        expect("rejects bad digest", False, "no ValueError")
    except ValueError:
        expect("rejects bad digest", True)

    expect("predicate prefix match", is_slsa_predicate("https://slsa.dev/provenance/v0.2"))
    expect("predicate reject random", not is_slsa_predicate("application/vnd.cyclonedx+json"))
    expect("predicate reject empty", not is_slsa_predicate(""))

    # auth challenge parser + default token URL (no network).
    challenge = parse_www_authenticate(
        'Bearer realm="https://ghcr.io/token",service="ghcr.io",'
        'scope="repository:hawikk/aim-api:pull"'
    )
    expect("parses www-authenticate realm", challenge is not None and challenge.realm == "https://ghcr.io/token")
    expect(
        "parses www-authenticate service",
        challenge is not None and challenge.service == "ghcr.io",
    )
    expect(
        "parses www-authenticate scope",
        challenge is not None and challenge.scope == "repository:hawikk/aim-api:pull",
    )
    expect("empty www-authenticate is None", parse_www_authenticate("") is None)
    expect(
        "non-bearer www-authenticate is None",
        parse_www_authenticate('Basic realm="x"') is None,
    )

    tok_url = default_token_url("ghcr.io", "Hawikk", "Aim-API")
    expect(
        "default token url lowercases repo",
        tok_url
        == "https://ghcr.io/token?service=ghcr.io&scope=repository%3Ahawikk%2Faim-api%3Apull",
        tok_url,
    )

    if failures:
        print("self-test FAILED:\n")
        for line in failures:
            print(f"  - {line}")
        return 1
    print(
        "self-test OK — referrers parser finds SLSA v0.2/v1 provenance, "
        "rejects SBOM-only and empty indexes, URL builder normalizes names, "
        "WWW-Authenticate/token-exchange helpers parse GHCR challenges "
        "(raw GITHUB_TOKEN as Bearer is never used)."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default="ghcr.io")
    parser.add_argument("--owner", help="GHCR owner (e.g. hawikk)")
    parser.add_argument("--image", help="image name (e.g. aim-api)")
    parser.add_argument("--digest", help="image digest sha256:…")
    parser.add_argument(
        "--token-env",
        default="GHCR_TOKEN",
        help="env var holding a GitHub credential (default: GHCR_TOKEN); "
        "exchanged for a GHCR registry token before the referrers call",
    )
    parser.add_argument(
        "--token",
        help="GitHub credential (prefer --token-env so secrets stay out of argv)",
    )
    parser.add_argument(
        "--username-env",
        default="GHCR_USERNAME",
        help="env var holding the GitHub username / actor for token exchange "
        "(default: GHCR_USERNAME; falls back to x-access-token)",
    )
    parser.add_argument(
        "--username",
        help="GitHub username / actor for registry token exchange",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    missing = [n for n in ("owner", "image", "digest") if not getattr(args, n)]
    if missing:
        print(f"error: missing required args: {', '.join(missing)}", file=sys.stderr)
        return 2

    token = args.token or os.environ.get(args.token_env)
    if not token:
        print(
            f"error: no token (set --token or env {args.token_env})",
            file=sys.stderr,
        )
        return 2

    username = args.username or os.environ.get(args.username_env) or None

    try:
        hits = verify(
            registry=args.registry,
            owner=args.owner,
            image=args.image,
            digest=args.digest,
            token=token,
            username=username,
        )
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: provenance verify failed: {exc}", file=sys.stderr)
        return 1

    if not hits:
        print(
            f"BLOCKED: no SLSA provenance attestation attached to "
            f"{args.owner}/{args.image}@{args.digest}",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {len(hits)} SLSA provenance attestation(s) on "
        f"{args.owner}/{args.image}@{args.digest}"
    )
    for h in hits:
        print(f"  - {h.predicate_type}  media={h.media_type}  referrer={h.digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

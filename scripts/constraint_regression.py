#!/usr/bin/env python3
"""Constraint regression suite for locked product constraints (AIM-760).

CI fails when a change would land that breaks locked works-council / privacy /
identity / deploy-mode constraints. The suite is intentionally *static* —
it inspects schema, auth source, and deploy manifests in the repo so a PR
that re-opens a content field, trusts a client identity header, or ships
``AIM_AUTH_DEV=1`` in a production helm values file is blocked before merge.

Dimensions covered (parent epic AIM-641 "Fit to locked constraints"):

  privacy      — metadata-only event schema (no content fields); closed
                 objects; invalid content examples still reject; no-semantic-
                 content-classifier ADR present.
  identity     — pseudonym fields retained; client-supplied identity headers
                 never trusted; reveal is a separate grant; spoof tests live.
  deploy_modes — production helm shapes never enable authDev / open personal
                 mode by default; no oauth2-proxy / AUTH_MODE revival;
                 personal-mode warning stays in helm NOTES.

Usage:
    python3 scripts/constraint_regression.py            # print report
    python3 scripts/constraint_regression.py --check    # CI gate (exit 1 on fail)
    python3 scripts/constraint_regression.py --self-test  # prove rules fire
    python3 scripts/constraint_regression.py --json-report out.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:  # pragma: no cover — CI always has PyYAML via requirements-dev
    yaml = None  # type: ignore

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None  # type: ignore

REPO_ROOT = Path(__file__).resolve().parent.parent

SCHEMA_PATH = (
    REPO_ROOT / "packages" / "schema" / "schema" / "v1" / "ai-usage-event.schema.json"
)
EXAMPLES_DIR = REPO_ROOT / "packages" / "schema" / "examples"
AUTH_JS = REPO_ROOT / "apps" / "api" / "src" / "auth.js"
IDENTITY_AUTH = (
    REPO_ROOT / "services" / "identity-sync" / "src" / "identity_sync" / "auth.py"
)
IDENTITY_API = (
    REPO_ROOT / "services" / "identity-sync" / "src" / "identity_sync" / "api.py"
)
IDENTITY_REVEAL_TEST = (
    REPO_ROOT / "services" / "identity-sync" / "tests" / "test_api.py"
)
HELM_VALUES = REPO_ROOT / "deploy" / "helm" / "aim" / "values.yaml"
HELM_STANDARD = REPO_ROOT / "deploy" / "helm" / "aim" / "values-standard.yaml"
HELM_AIRGAPPED = REPO_ROOT / "deploy" / "helm" / "aim" / "values-airgapped.yaml"
HELM_DEV = REPO_ROOT / "deploy" / "helm" / "aim" / "values-dev.yaml"
HELM_API_TMPL = REPO_ROOT / "deploy" / "helm" / "aim" / "templates" / "api.yaml"
HELM_NOTES = REPO_ROOT / "deploy" / "helm" / "aim" / "templates" / "NOTES.txt"
COMPOSE = REPO_ROOT / "docker-compose.yml"
DATA_MINIMIZATION = REPO_ROOT / "docs" / "security" / "data-minimization.md"
NO_SEMANTIC_ADR = (
    REPO_ROOT / "docs" / "security" / "adr-no-semantic-content-classifiers.md"
)
FIELDS_MD = REPO_ROOT / "packages" / "schema" / "FIELDS.md"

# Field names that would re-introduce content collection. Presence of any of
# these as a declared property (at any closed object in the event schema)
# fails the privacy gate. Match is exact (case-sensitive, schema style).
FORBIDDEN_CONTENT_PROPERTIES: frozenset[str] = frozenset(
    {
        "prompt",
        "prompt_text",
        "prompts",
        "response",
        "response_text",
        "responses",
        "completion",
        "completions",
        "content",
        "body",
        "message",
        "messages",
        "arguments",
        "args",
        "input",
        "inputs",
        "output",
        "outputs",
        "code",
        "code_snippet",
        "code_snippets",
        "file_content",
        "file_contents",
        "diff",
        "diffs",
        "text",
        "raw_prompt",
        "raw_response",
        "raw_text",
        "snippet",
        "snippets",
        "keystroke",
        "keystrokes",
        "screenshot",
        "screenshots",
        "screen_content",
    }
)

# Nested object paths that must remain closed (additionalProperties: false).
# Paths use dotted form from the schema root; `[]` means array items.
CLOSED_OBJECT_PATHS: tuple[str, ...] = (
    "$",
    "$.tool_calls[]",
    "$.configured_mcp_servers[]",
    "$.match_flags[]",
    "$.enforcement",
    "$.enforcement_posture",
)

# Pseudonym / identity fields the event store is allowed to carry.
REQUIRED_PSEUDONYM_FIELDS: frozenset[str] = frozenset(
    {"host_ref", "user_ref", "repo_ref"}
)

# Invalid examples that pin the content-rejection contract. CI must keep them.
REQUIRED_INVALID_EXAMPLES: tuple[str, ...] = (
    "invalid-contains-prompt-text.json",
    "invalid-tool-call-arguments.json",
)

# Substrings that must never reappear as live deploy config.
FORBIDDEN_DEPLOY_SNIPPETS: tuple[tuple[str, str], ...] = (
    ("AUTH_MODE", "legacy AUTH_MODE env (purged; in-app OIDC only)"),
    ("oauth2-proxy", "oauth2-proxy sidecar (purged; in-app OIDC only)"),
)

# Files scanned for forbidden deploy snippets (active config only).
DEPLOY_SCAN_PATHS: tuple[Path, ...] = (
    COMPOSE,
    HELM_VALUES,
    HELM_STANDARD,
    HELM_AIRGAPPED,
    HELM_DEV,
    HELM_API_TMPL,
    REPO_ROOT / "deploy" / "helm" / "aim" / "templates",
)


@dataclass
class Check:
    id: str
    dimension: str  # privacy | identity | deploy_modes
    ok: bool
    detail: str


@dataclass
class Report:
    schema: str = "aim.constraint.regression/v1"
    ok: bool = False
    checks: list[Check] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "ok": self.ok,
            "passed": sum(1 for c in self.checks if c.ok),
            "failed": sum(1 for c in self.checks if not c.ok),
            "checks": [asdict(c) for c in self.checks],
        }


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_yaml(path: Path) -> Any:
    if yaml is None:
        raise RuntimeError("PyYAML is required (pip install -r requirements-dev.txt)")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _schema_node_at(schema: dict[str, Any], path: str) -> dict[str, Any] | None:
    """Resolve a CLOSED_OBJECT_PATHS-style path into a schema node."""
    if path == "$":
        return schema
    assert path.startswith("$.")
    parts = path[2:].split(".")
    node: Any = schema
    for part in parts:
        is_items = part.endswith("[]")
        key = part[:-2] if is_items else part
        if not isinstance(node, dict):
            return None
        props = node.get("properties") or {}
        if key not in props:
            return None
        node = props[key]
        if is_items:
            if not isinstance(node, dict) or "items" not in node:
                return None
            node = node["items"]
    return node if isinstance(node, dict) else None


def _iter_property_names(schema: dict[str, Any]) -> Iterable[tuple[str, str]]:
    """Yield (path, property_name) for every properties map in the schema."""

    def walk(node: Any, path: str) -> Iterable[tuple[str, str]]:
        if not isinstance(node, dict):
            return
        props = node.get("properties")
        if isinstance(props, dict):
            for name, child in props.items():
                yield path, name
                yield from walk(child, f"{path}.{name}" if path != "$" else f"$.{name}")
        items = node.get("items")
        if isinstance(items, dict):
            yield from walk(items, f"{path}[]")
        for combinator in ("oneOf", "anyOf", "allOf"):
            alts = node.get(combinator)
            if isinstance(alts, list):
                for i, alt in enumerate(alts):
                    yield from walk(alt, f"{path}/{combinator}[{i}]")

    yield from walk(schema, "$")


def check_privacy(root: Path = REPO_ROOT) -> list[Check]:
    checks: list[Check] = []
    schema_path = root / SCHEMA_PATH.relative_to(REPO_ROOT)
    examples_dir = root / EXAMPLES_DIR.relative_to(REPO_ROOT)
    fields_md = root / FIELDS_MD.relative_to(REPO_ROOT)
    data_min = root / DATA_MINIMIZATION.relative_to(REPO_ROOT)
    adr = root / NO_SEMANTIC_ADR.relative_to(REPO_ROOT)

    if not schema_path.is_file():
        checks.append(
            Check(
                "privacy.schema_present",
                "privacy",
                False,
                f"missing event schema at {schema_path.relative_to(root)}",
            )
        )
        return checks

    schema = _load_json(schema_path)
    checks.append(
        Check(
            "privacy.schema_present",
            "privacy",
            True,
            f"schema present ({schema_path.relative_to(root)})",
        )
    )

    # Root + nested closed objects.
    for path in CLOSED_OBJECT_PATHS:
        node = _schema_node_at(schema, path)
        if node is None:
            checks.append(
                Check(
                    f"privacy.closed:{path}",
                    "privacy",
                    False,
                    f"expected closed object at {path} is missing from schema",
                )
            )
            continue
        ap = node.get("additionalProperties")
        ok = ap is False
        checks.append(
            Check(
                f"privacy.closed:{path}",
                "privacy",
                ok,
                (
                    f"{path} has additionalProperties: false"
                    if ok
                    else f"{path} additionalProperties={ap!r} (must be false)"
                ),
            )
        )

    # No forbidden content field names as declared properties.
    offenders = [
        (path, name)
        for path, name in _iter_property_names(schema)
        if name in FORBIDDEN_CONTENT_PROPERTIES
    ]
    if offenders:
        detail = "; ".join(f"{p}.{n}" if p != "$" else n for p, n in offenders[:12])
        checks.append(
            Check(
                "privacy.no_content_properties",
                "privacy",
                False,
                f"forbidden content properties declared: {detail}",
            )
        )
    else:
        checks.append(
            Check(
                "privacy.no_content_properties",
                "privacy",
                True,
                f"no forbidden content properties among {len(FORBIDDEN_CONTENT_PROPERTIES)} banned names",
            )
        )

    # Pin the rejection contract with required invalid examples.
    missing_examples = [
        name for name in REQUIRED_INVALID_EXAMPLES if not (examples_dir / name).is_file()
    ]
    if missing_examples:
        checks.append(
            Check(
                "privacy.invalid_examples_present",
                "privacy",
                False,
                f"missing invalid examples: {', '.join(missing_examples)}",
            )
        )
    else:
        checks.append(
            Check(
                "privacy.invalid_examples_present",
                "privacy",
                True,
                f"required invalid examples present: {', '.join(REQUIRED_INVALID_EXAMPLES)}",
            )
        )

    # Live-validate that those examples actually fail schema validation.
    if Draft202012Validator is None:
        checks.append(
            Check(
                "privacy.invalid_examples_reject",
                "privacy",
                False,
                "jsonschema not installed; cannot prove content rejection",
            )
        )
    elif not missing_examples:
        validator = Draft202012Validator(schema)
        still_valid: list[str] = []
        for name in REQUIRED_INVALID_EXAMPLES:
            doc = _load_json(examples_dir / name)
            if validator.is_valid(doc):
                still_valid.append(name)
        ok = not still_valid
        checks.append(
            Check(
                "privacy.invalid_examples_reject",
                "privacy",
                ok,
                (
                    "content-bearing invalid examples are rejected by schema"
                    if ok
                    else f"examples unexpectedly valid (content accepted): {', '.join(still_valid)}"
                ),
            )
        )

    # Docs that lock the privacy bar stay in-tree.
    for cid, path, needle in (
        (
            "privacy.doc_data_minimization",
            data_min,
            "prompt or response text",
        ),
        (
            "privacy.doc_no_semantic_adr",
            adr,
            "semantic",
        ),
        (
            "privacy.doc_fields_metadata_only",
            fields_md,
            "additionalProperties",
        ),
    ):
        if not path.is_file():
            checks.append(
                Check(cid, "privacy", False, f"missing policy doc {path.relative_to(root)}")
            )
            continue
        text = path.read_text(encoding="utf-8")
        ok = needle.lower() in text.lower()
        checks.append(
            Check(
                cid,
                "privacy",
                ok,
                (
                    f"{path.relative_to(root)} present and references {needle!r}"
                    if ok
                    else f"{path.relative_to(root)} missing expected language {needle!r}"
                ),
            )
        )

    return checks


def check_identity(root: Path = REPO_ROOT) -> list[Check]:
    checks: list[Check] = []
    schema_path = root / SCHEMA_PATH.relative_to(REPO_ROOT)
    auth_js = root / AUTH_JS.relative_to(REPO_ROOT)
    id_auth = root / IDENTITY_AUTH.relative_to(REPO_ROOT)
    id_api = root / IDENTITY_API.relative_to(REPO_ROOT)
    id_test = root / IDENTITY_REVEAL_TEST.relative_to(REPO_ROOT)

    if schema_path.is_file():
        schema = _load_json(schema_path)
        props = set((schema.get("properties") or {}).keys())
        missing = sorted(REQUIRED_PSEUDONYM_FIELDS - props)
        ok = not missing
        checks.append(
            Check(
                "identity.pseudonym_fields",
                "identity",
                ok,
                (
                    f"schema retains pseudonym fields {sorted(REQUIRED_PSEUDONYM_FIELDS)}"
                    if ok
                    else f"schema missing pseudonym fields: {missing}"
                ),
            )
        )
    else:
        checks.append(
            Check(
                "identity.pseudonym_fields",
                "identity",
                False,
                "schema missing; cannot verify pseudonym fields",
            )
        )

    if not auth_js.is_file():
        checks.append(
            Check("identity.auth_never_trust_headers", "identity", False, "auth.js missing")
        )
        return checks

    auth_src = auth_js.read_text(encoding="utf-8")

    # Explicit contract comment + no code path that treats x-forwarded-user
    # (or oauth2-proxy style headers) as identity.
    never_trusted = re.search(
        r"client-supplied identity headers.*NEVER trusted",
        auth_src,
        re.IGNORECASE | re.DOTALL,
    ) or ("NEVER trusted" in auth_src and "x-forwarded" in auth_src.lower())
    checks.append(
        Check(
            "identity.auth_never_trust_comment",
            "identity",
            bool(never_trusted),
            (
                "auth.js documents client-supplied identity headers as NEVER trusted"
                if never_trusted
                else "auth.js lost the 'NEVER trusted' client-header contract"
            ),
        )
    )

    # Dangerous header reads that would re-introduce proxy-auth identity.
    dangerous = []
    for needle in (
        "x-forwarded-user",
        "x-forwarded-email",
        "x-auth-request-user",
        "x-auth-request-email",
        "remote-user",
        "x-aim-role",
        "x-aim-actor",
    ):
        if needle in auth_src.lower():
            dangerous.append(needle)
    checks.append(
        Check(
            "identity.auth_no_proxy_identity_headers",
            "identity",
            not dangerous,
            (
                "auth.js does not read proxy/client identity headers"
                if not dangerous
                else f"auth.js references proxy identity headers: {', '.join(dangerous)}"
            ),
        )
    )

    # Session cookie is the SSO identity source (or personal mode identity).
    has_session = "aim_session" in auth_src or "SESSION_COOKIE" in auth_src
    checks.append(
        Check(
            "identity.session_cookie_source",
            "identity",
            has_session,
            (
                "auth.js uses a session cookie as the identity source"
                if has_session
                else "auth.js has no session-cookie identity source"
            ),
        )
    )

    # Reveal is a separate grant, not bundled into admin.
    reveal_sep = (
        "revealGroups" in auth_src
        or "AIM_REVEAL_GROUPS" in auth_src
        or "hasRevealGrant" in auth_src
    )
    checks.append(
        Check(
            "identity.reveal_separate_grant",
            "identity",
            reveal_sep,
            (
                "reveal is a separate capability (AIM_REVEAL_GROUPS / hasRevealGrant)"
                if reveal_sep
                else "reveal grant wiring missing from auth.js"
            ),
        )
    )

    # identity-sync: no client-supplied header trust.
    for cid, path, needle in (
        (
            "identity.sync_auth_no_client_headers",
            id_auth,
            "client-supplied",
        ),
        (
            "identity.sync_api_gate_before_body",
            id_api,
            "client-supplied",
        ),
    ):
        if not path.is_file():
            checks.append(
                Check(cid, "identity", False, f"missing {path.relative_to(root)}")
            )
            continue
        text = path.read_text(encoding="utf-8")
        ok = needle.lower() in text.lower()
        checks.append(
            Check(
                cid,
                "identity",
                ok,
                (
                    f"{path.relative_to(root)} refuses client-supplied identity headers"
                    if ok
                    else f"{path.relative_to(root)} lost client-header refusal language"
                ),
            )
        )

    if id_test.is_file():
        test_src = id_test.read_text(encoding="utf-8")
        spoof_ok = (
            "test_reveal_spoofed_role_header_is_rejected" in test_src
            or "spoofed" in test_src.lower()
        )
        checks.append(
            Check(
                "identity.reveal_spoof_test",
                "identity",
                spoof_ok,
                (
                    "identity-sync keeps a spoofed-header reveal rejection test"
                    if spoof_ok
                    else "identity-sync reveal spoof test missing"
                ),
            )
        )
    else:
        checks.append(
            Check(
                "identity.reveal_spoof_test",
                "identity",
                False,
                f"missing {id_test.relative_to(root)}",
            )
        )

    return checks


def _helm_auth_dev(values: dict[str, Any] | None) -> Any:
    if not isinstance(values, dict):
        return None
    api = values.get("api") or {}
    if not isinstance(api, dict):
        return None
    return api.get("authDev")


def check_deploy_modes(root: Path = REPO_ROOT) -> list[Check]:
    checks: list[Check] = []

    values_path = root / HELM_VALUES.relative_to(REPO_ROOT)
    standard_path = root / HELM_STANDARD.relative_to(REPO_ROOT)
    airgapped_path = root / HELM_AIRGAPPED.relative_to(REPO_ROOT)
    api_tmpl = root / HELM_API_TMPL.relative_to(REPO_ROOT)
    notes = root / HELM_NOTES.relative_to(REPO_ROOT)
    compose = root / COMPOSE.relative_to(REPO_ROOT)

    # Default chart values: authDev must be false.
    if values_path.is_file():
        values = _load_yaml(values_path)
        auth_dev = _helm_auth_dev(values)
        ok = auth_dev is False
        checks.append(
            Check(
                "deploy.default_auth_dev_false",
                "deploy_modes",
                ok,
                (
                    "values.yaml sets api.authDev: false"
                    if ok
                    else f"values.yaml api.authDev={auth_dev!r} (must be false)"
                ),
            )
        )
    else:
        checks.append(
            Check(
                "deploy.default_auth_dev_false",
                "deploy_modes",
                False,
                "values.yaml missing",
            )
        )

    # Production overlays must never enable authDev.
    for cid, path in (
        ("deploy.standard_no_auth_dev", standard_path),
        ("deploy.airgapped_no_auth_dev", airgapped_path),
    ):
        if not path.is_file():
            checks.append(
                Check(cid, "deploy_modes", False, f"missing {path.relative_to(root)}")
            )
            continue
        raw = path.read_text(encoding="utf-8")
        parsed = _load_yaml(path) or {}
        auth_dev = _helm_auth_dev(parsed)
        # Absent is fine (inherits false). Explicit true is the failure.
        enabled = auth_dev is True or bool(
            re.search(r"(?m)^\s*authDev\s*:\s*true\s*$", raw)
        )
        checks.append(
            Check(
                cid,
                "deploy_modes",
                not enabled,
                (
                    f"{path.name} does not enable api.authDev"
                    if not enabled
                    else f"{path.name} enables api.authDev — open auth in a production shape"
                ),
            )
        )
        # Production shapes must still document in-app OIDC / no proxy-auth.
        text_l = raw.lower()
        oidc_ok = "oidc" in text_l or "sso" in text_l
        no_proxy = "proxy-auth" in text_l or "no proxy" in text_l or "never trusted" in text_l
        checks.append(
            Check(
                f"{cid}.oidc_posture",
                "deploy_modes",
                oidc_ok,
                (
                    f"{path.name} documents OIDC/SSO production posture"
                    if oidc_ok
                    else f"{path.name} lost OIDC/SSO production posture language"
                ),
            )
        )
        checks.append(
            Check(
                f"{cid}.no_proxy_auth",
                "deploy_modes",
                no_proxy or oidc_ok,
                (
                    f"{path.name} retains no-proxy-auth / OIDC production language"
                    if (no_proxy or oidc_ok)
                    else f"{path.name} has neither no-proxy-auth nor OIDC language"
                ),
            )
        )

    # Helm template only injects AIM_AUTH_DEV behind `if .Values.api.authDev`.
    if api_tmpl.is_file():
        tmpl = api_tmpl.read_text(encoding="utf-8")
        conditional = bool(
            re.search(
                r"\{\{-?\s*if\s+\.Values\.api\.authDev\s*-?\}\}.*?AIM_AUTH_DEV",
                tmpl,
                re.DOTALL,
            )
        )
        # Must not unconditionally set AIM_AUTH_DEV: "1".
        unconditional = bool(
            re.search(
                r"name:\s*AIM_AUTH_DEV\s*\n\s*value:\s*\"1\"",
                tmpl,
            )
        ) and not conditional
        ok = conditional and not unconditional
        checks.append(
            Check(
                "deploy.helm_auth_dev_gated",
                "deploy_modes",
                ok,
                (
                    "api.yaml only sets AIM_AUTH_DEV when api.authDev is true"
                    if ok
                    else "api.yaml AIM_AUTH_DEV injection is not gated on api.authDev"
                ),
            )
        )
    else:
        checks.append(
            Check(
                "deploy.helm_auth_dev_gated",
                "deploy_modes",
                False,
                "helm api.yaml template missing",
            )
        )

    # NOTES.txt must warn when OIDC is absent (personal mode).
    if notes.is_file():
        notes_txt = notes.read_text(encoding="utf-8")
        warn_ok = (
            "personal/standalone" in notes_txt.lower()
            or "no oidc is configured" in notes_txt.lower()
        ) and "values-standard" in notes_txt
        checks.append(
            Check(
                "deploy.notes_personal_mode_warning",
                "deploy_modes",
                warn_ok,
                (
                    "NOTES.txt warns that personal mode is not for shared environments"
                    if warn_ok
                    else "NOTES.txt lost personal-mode / values-standard warning"
                ),
            )
        )
    else:
        checks.append(
            Check(
                "deploy.notes_personal_mode_warning",
                "deploy_modes",
                False,
                "NOTES.txt missing",
            )
        )

    # docker-compose must not hardcode AIM_AUTH_DEV=1 (env passthrough only).
    if compose.is_file():
        compose_txt = compose.read_text(encoding="utf-8")
        hardcoded = bool(
            re.search(r"AIM_AUTH_DEV\s*:\s*[\"']?1[\"']?\s*$", compose_txt, re.M)
        ) or bool(re.search(r"AIM_AUTH_DEV\s*=\s*1\b", compose_txt))
        # Accept ${AIM_AUTH_DEV:-} or similar passthrough.
        passthrough = "AIM_AUTH_DEV" not in compose_txt or bool(
            re.search(r"AIM_AUTH_DEV\s*:\s*\$\{AIM_AUTH_DEV", compose_txt)
        )
        ok = (not hardcoded) and passthrough
        checks.append(
            Check(
                "deploy.compose_no_hardcoded_auth_dev",
                "deploy_modes",
                ok,
                (
                    "docker-compose does not hardcode AIM_AUTH_DEV=1"
                    if ok
                    else "docker-compose hardcodes AIM_AUTH_DEV=1 (open auth by default)"
                ),
            )
        )
    else:
        checks.append(
            Check(
                "deploy.compose_no_hardcoded_auth_dev",
                "deploy_modes",
                False,
                "docker-compose.yml missing",
            )
        )

    # Forbidden legacy auth modes in active deploy config.
    for snippet, reason in FORBIDDEN_DEPLOY_SNIPPETS:
        hits: list[str] = []
        for base in DEPLOY_SCAN_PATHS:
            rel = base.relative_to(REPO_ROOT) if base.is_absolute() else Path(base)
            path = root / rel
            if path.is_dir():
                files = sorted(path.rglob("*"))
            elif path.is_file():
                files = [path]
            else:
                continue
            for f in files:
                if not f.is_file():
                    continue
                if f.suffix in {".png", ".jpg", ".gz", ".tgz", ".zip"}:
                    continue
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if snippet in text:
                    rel_s = f.relative_to(root).as_posix()
                    if rel_s.startswith("docs/"):
                        continue
                    hits.append(rel_s)
        ok = not hits
        checks.append(
            Check(
                f"deploy.forbidden:{snippet}",
                "deploy_modes",
                ok,
                (
                    f"no {snippet!r} in active deploy config ({reason})"
                    if ok
                    else f"{snippet!r} found in: {', '.join(hits[:8])} ({reason})"
                ),
            )
        )

    return checks


def run_suite(root: Path | None = None) -> Report:
    root = Path(root) if root is not None else REPO_ROOT
    checks: list[Check] = []
    checks.extend(check_privacy(root))
    checks.extend(check_identity(root))
    checks.extend(check_deploy_modes(root))
    return Report(ok=all(c.ok for c in checks), checks=checks)


# ---------------------------------------------------------------------------
# Self-test: each rule category must fire on a synthetic breakage.
# ---------------------------------------------------------------------------


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _copy_tree(src: Path, dst: Path, rels: Iterable[str]) -> None:
    for rel in rels:
        s = src / rel
        d = dst / rel
        if s.is_file():
            _write(d, s.read_text(encoding="utf-8"))
        elif s.is_dir():
            for f in s.rglob("*"):
                if f.is_file():
                    _write(
                        d / f.relative_to(s),
                        f.read_text(encoding="utf-8", errors="replace"),
                    )


def _baseline_tree(tmp: Path) -> None:
    """Seed a temp tree with the real constraint-bearing files."""
    rels = [
        "packages/schema/schema/v1/ai-usage-event.schema.json",
        "packages/schema/examples",
        "packages/schema/FIELDS.md",
        "docs/security/data-minimization.md",
        "docs/security/adr-no-semantic-content-classifiers.md",
        "apps/api/src/auth.js",
        "services/identity-sync/src/identity_sync/auth.py",
        "services/identity-sync/src/identity_sync/api.py",
        "services/identity-sync/tests/test_api.py",
        "deploy/helm/aim/values.yaml",
        "deploy/helm/aim/values-standard.yaml",
        "deploy/helm/aim/values-airgapped.yaml",
        "deploy/helm/aim/values-dev.yaml",
        "deploy/helm/aim/templates/api.yaml",
        "deploy/helm/aim/templates/NOTES.txt",
        "docker-compose.yml",
    ]
    _copy_tree(REPO_ROOT, tmp, rels)


def _assert_fails(root: Path, check_id_prefix: str, label: str) -> None:
    report = run_suite(root)
    failed_ids = [c.id for c in report.checks if not c.ok]
    if not any(i == check_id_prefix or i.startswith(check_id_prefix) for i in failed_ids):
        raise AssertionError(
            f"self-test {label!r}: expected a failure for {check_id_prefix!r}, "
            f"got failures={failed_ids}"
        )


def self_test() -> None:
    # Healthy tree must pass.
    with tempfile.TemporaryDirectory(prefix="aim760-ok-") as td:
        root = Path(td)
        _baseline_tree(root)
        report = run_suite(root)
        if not report.ok:
            failed = [c for c in report.checks if not c.ok]
            raise AssertionError(
                "self-test baseline should pass; failed:\n"
                + "\n".join(f"  - {c.id}: {c.detail}" for c in failed)
            )

    # privacy: open additionalProperties at root.
    with tempfile.TemporaryDirectory(prefix="aim760-ap-") as td:
        root = Path(td)
        _baseline_tree(root)
        schema = _load_json(root / SCHEMA_PATH.relative_to(REPO_ROOT))
        schema["additionalProperties"] = True
        _write(
            root / SCHEMA_PATH.relative_to(REPO_ROOT),
            json.dumps(schema, indent=2) + "\n",
        )
        _assert_fails(root, "privacy.closed:$", "open additionalProperties")

    # privacy: declare a content field.
    with tempfile.TemporaryDirectory(prefix="aim760-cf-") as td:
        root = Path(td)
        _baseline_tree(root)
        schema = _load_json(root / SCHEMA_PATH.relative_to(REPO_ROOT))
        schema.setdefault("properties", {})["prompt_text"] = {"type": "string"}
        _write(
            root / SCHEMA_PATH.relative_to(REPO_ROOT),
            json.dumps(schema, indent=2) + "\n",
        )
        _assert_fails(root, "privacy.no_content_properties", "content field prompt_text")

    # privacy: drop invalid content example so rejection is unpinned.
    with tempfile.TemporaryDirectory(prefix="aim760-ex-") as td:
        root = Path(td)
        _baseline_tree(root)
        (
            root
            / EXAMPLES_DIR.relative_to(REPO_ROOT)
            / "invalid-contains-prompt-text.json"
        ).unlink()
        _assert_fails(root, "privacy.invalid_examples_present", "drop content invalid example")

    # identity: strip NEVER trusted contract.
    with tempfile.TemporaryDirectory(prefix="aim760-id-") as td:
        root = Path(td)
        _baseline_tree(root)
        auth = (root / AUTH_JS.relative_to(REPO_ROOT)).read_text(encoding="utf-8")
        auth = auth.replace("NEVER trusted", "sometimes trusted")
        auth = auth.replace("x-forwarded-*", "x-forwarded-kept")
        _write(root / AUTH_JS.relative_to(REPO_ROOT), auth)
        _assert_fails(root, "identity.auth_never_trust_comment", "strip NEVER trusted")

    # identity: reintroduce proxy identity header usage.
    with tempfile.TemporaryDirectory(prefix="aim760-hdr-") as td:
        root = Path(td)
        _baseline_tree(root)
        auth_path = root / AUTH_JS.relative_to(REPO_ROOT)
        auth = auth_path.read_text(encoding="utf-8")
        auth += "\nconst spoof = req.headers['x-forwarded-user'];\n"
        _write(auth_path, auth)
        _assert_fails(
            root,
            "identity.auth_no_proxy_identity_headers",
            "x-forwarded-user identity",
        )

    # deploy: enable authDev in production standard values.
    with tempfile.TemporaryDirectory(prefix="aim760-dev-") as td:
        root = Path(td)
        _baseline_tree(root)
        p = root / HELM_STANDARD.relative_to(REPO_ROOT)
        text = p.read_text(encoding="utf-8")
        text += "\napi:\n  authDev: true\n"
        _write(p, text)
        _assert_fails(root, "deploy.standard_no_auth_dev", "authDev true in standard")

    # deploy: hardcode AIM_AUTH_DEV=1 in compose.
    with tempfile.TemporaryDirectory(prefix="aim760-compose-") as td:
        root = Path(td)
        _baseline_tree(root)
        p = root / COMPOSE.relative_to(REPO_ROOT)
        text = p.read_text(encoding="utf-8")
        text = text.replace(
            "AIM_AUTH_DEV: ${AIM_AUTH_DEV:-}",
            'AIM_AUTH_DEV: "1"',
        )
        _write(p, text)
        _assert_fails(
            root,
            "deploy.compose_no_hardcoded_auth_dev",
            "compose AIM_AUTH_DEV=1",
        )

    # deploy: revive AUTH_MODE in helm values.
    with tempfile.TemporaryDirectory(prefix="aim760-authmode-") as td:
        root = Path(td)
        _baseline_tree(root)
        p = root / HELM_VALUES.relative_to(REPO_ROOT)
        text = p.read_text(encoding="utf-8") + "\n# AUTH_MODE: open\n"
        _write(p, text)
        _assert_fails(root, "deploy.forbidden:AUTH_MODE", "AUTH_MODE revival")

    print(
        "CONSTRAINT_REGRESSION_SELF_TEST_OK "
        "baseline + privacy + identity + deploy_modes mutations fire"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if any constraint check fails (CI gate)",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="prove each rule fires on synthetic breakage",
    )
    ap.add_argument(
        "--json-report",
        type=Path,
        help="write machine-readable report JSON",
    )
    ap.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="override repo root (tests)",
    )
    args = ap.parse_args(argv)

    if args.self_test:
        try:
            self_test()
        except AssertionError as e:
            print(f"CONSTRAINT_REGRESSION_SELF_TEST_FAILED: {e}", file=sys.stderr)
            return 1
        return 0

    report = run_suite(args.repo_root)

    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(
            json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
        print(f"wrote {args.json_report}")

    # Human summary grouped by dimension.
    by_dim: dict[str, list[Check]] = {}
    for c in report.checks:
        by_dim.setdefault(c.dimension, []).append(c)

    for dim, items in by_dim.items():
        passed = sum(1 for c in items if c.ok)
        print(f"\n== {dim} ({passed}/{len(items)} passed)")
        for c in items:
            mark = "OK  " if c.ok else "FAIL"
            print(f"  {mark} {c.id}: {c.detail}")

    print()
    if report.ok:
        print(
            f"CONSTRAINT_REGRESSION_OK passed={sum(1 for c in report.checks if c.ok)}"
        )
        return 0

    failed = [c for c in report.checks if not c.ok]
    print("CONSTRAINT_REGRESSION_FAILED:", file=sys.stderr)
    for c in failed:
        print(f"  - [{c.dimension}] {c.id}: {c.detail}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

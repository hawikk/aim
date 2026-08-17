"""Condition tree evaluation for guardrail rules.

A condition tree is `{all: [...]}`, `{any: [...]}`, or a single leaf condition.

Field leaves (``field:`` + one op):
  eq, neq, in, not_in, contains, contains_detector, gt, gte, lt, lte,
  plus settings-aware ops: not_in_approved_providers_for,
  not_in_approved_models_for, model_provider_not_permitted_for_scope,
  in_off_hours, in_restricted_repos, mcp_call_to_unapproved_server,
  tool_call_action_class_in, tool_call_name_matches,
  configured_mcp_server_unapproved, mcp_call_to_unapproved_tool.

Attribute leaves (``attr:`` + one of eq/neq/in/not_in) — ABAC-style
dimensions:
  user, group, repo_class, tool

Evaluation returns (matched: bool, detail: dict) — detail records WHY it
matched so findings carry auditable evidence without storing event content.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from datetime import datetime, timezone
from typing import Any

# Salt env var shared with the collectors (they HMAC repo_ref host-side).
REPO_REF_SALT_ENV = "AIM_HASH_SALT"
_CACHE_KEY = "_restricted_repo_refs_cache"
_REPO_CLASS_CACHE_KEY = "_repo_class_index_cache"
_USER_LIST_CACHE_KEY = "_user_list_cache"

# ABAC attribute dimensions. Validated at ruleset load time.
KNOWN_ATTRS = frozenset({"user", "group", "repo_class", "tool"})
ATTR_OPS = frozenset({"eq", "neq", "in", "not_in"})

# token-needle FP suppressions for tool_call_name_matches.
# Usage/pagination/tokenizer segments make bare "token" a false positive for
# credential-shaped intent; credential co-segments re-enable the match.
_TOKEN_BENIGN_SEGS = frozenset({
    "count", "counts", "usage", "budget", "limit", "remaining", "max", "min",
    "page", "pages", "pagination", "cursor", "offset", "next", "prev",
    "previous", "encoding", "encode", "decode",
})
_TOKEN_CRED_SEGS = frozenset({
    "access", "auth", "api", "bearer", "refresh", "id", "secret", "password",
    "credential", "credentials", "session", "oauth", "pat", "private",
    "service", "key", "passwd", "login", "identity", "saml", "oidc", "jwt",
})
_TOKEN_SUPPRESS_SEGS = frozenset({
    "tokenizer", "tiktoken", "tokenize", "tokenless", "untokenize", "untoken",
})

# Every leaf op eval_leaf implements. rules.py validates condition trees
# against this at ruleset load time — an unknown op must fail fast at deploy,
# not silently kill the rule per-event at runtime (adversarial finding).
KNOWN_OPS = frozenset({
    "eq", "neq", "in", "not_in", "contains", "contains_detector",
    "gt", "gte", "lt", "lte",
    "not_in_approved_providers_for", "not_in_approved_models_for",
    "model_provider_not_permitted_for_scope",
    "in_off_hours", "in_restricted_repos",
    "mcp_call_to_unapproved_server", "tool_call_action_class_in",
    "tool_call_name_matches",
    "configured_mcp_server_unapproved",
    "mcp_call_to_unapproved_tool",
})


class ConditionError(ValueError):
    pass


def tool_name_segments(name: str) -> list[str]:
    """Split a tool_name into lowercase alphanumeric segments (snake + camel).

    Collectors store MCP tools as the bare tool part after ``mcp__server__``
    split (e.g. ``GetSecretValue``), so camelCase segmentation is required for
    needles like ``secret`` / ``token`` to land on word boundaries.
    """
    if not name:
        return []
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    return [p for p in re.split(r"[^A-Za-z0-9]+", s.lower()) if p]


def _token_needle_matches(segs: list[str]) -> bool:
    """Match bare ``token``/``tokens`` with usage/pagination FP suppression."""
    tokenish: list[str] = []
    for s in segs:
        if s in ("token", "tokens"):
            tokenish.append(s)
        elif s in _TOKEN_SUPPRESS_SEGS or s.startswith("untoken") or "tokenless" in s:
            continue
        elif "token" in s and (s.endswith("token") or s.endswith("tokens") or s.startswith("token")):
            tokenish.append(s)
    if not tokenish:
        return False
    has_benign = any(s in _TOKEN_BENIGN_SEGS for s in segs)
    has_cred = any(s in _TOKEN_CRED_SEGS for s in segs)
    if has_benign and not has_cred:
        return False
    return True


def tool_name_matches_needle(name: str, needle: str) -> bool:
    """Return True if ``name`` matches a credential-shaped needle.

    Matching is segment-aware (camelCase + snake_case) so short needles like
    ``vault`` do not fire on ``envault_backup``, while ``GetAccessToken`` still
    matches ``token``. Bare ``token`` suppresses usage/pagination/tokenizer
    names unless a credential co-segment is present.
    """
    n = (needle or "").lower()
    if not n or not name:
        return False
    raw = name.lower()
    segs = tool_name_segments(name)

    # Literal ".env" must stay a raw substring — segment split drops the dot.
    if n == ".env":
        return ".env" in raw

    if n in ("token", "tokens"):
        return _token_needle_matches(segs)

    nsegs = [p for p in re.split(r"[^a-z0-9]+", n) if p]
    if not nsegs:
        return n in raw

    # Multi-part needle (api_key, private_key, service_account, aws_access).
    if len(nsegs) > 1:
        L = len(nsegs)
        if any(segs[i:i + L] == nsegs for i in range(len(segs) - L + 1)):
            return True
        compact = "".join(nsegs)
        return compact in segs or compact in raw

    n0 = nsegs[0]
    if n0 in segs:
        return True
    # Long needles may appear inside a single camel/snake segment
    # (getsecretvalue, serviceaccount). Short ones require exact segments
    # to avoid envault/SecretSanta residual-only behavior where possible.
    if len(n0) >= 6:
        return any(n0 in s for s in segs) or n0 in raw
    return False


def normalize_repo_id(value: str) -> str:
    """Normalize a repo identifier exactly like the collectors do before
    HMAC-ing (collectors/*/events.py: normpath, lowercase, backslash->slash),
    so a policy-configured repo path lands on the same repo_ref pseudonym."""
    return os.path.normpath(value).lower().replace("\\", "/")


def repo_ref_for(value: str, salt: str | bytes) -> str:
    """The HMAC-SHA256 repo_ref a collector would emit for `value`. Used for
    restricted-repo matching and by the `repo-ref` CLI helper (ops/seeding)."""
    key = salt.encode() if isinstance(salt, str) else salt
    return hmac.new(key, normalize_repo_id(value).encode(), hashlib.sha256).hexdigest()


def _restricted_repo_refs(settings: dict) -> frozenset | None:
    """HMAC set of settings['restricted_repos'], cached on the settings dict.
    Returns None when matching is disabled (AIM_HASH_SALT not configured) —
    the engine cannot re-derive pseudonyms without the company salt."""
    repos = tuple(settings.get("restricted_repos") or ())
    salt = os.environ.get(REPO_REF_SALT_ENV) or ""
    cache_key = (salt, repos)
    cached = settings.get(_CACHE_KEY)
    if cached is not None and cached[0] == cache_key:
        return cached[1]
    refs = frozenset(repo_ref_for(r, salt) for r in repos) if salt else None
    settings[_CACHE_KEY] = (cache_key, refs)
    return refs



def _looks_like_hex_ref(value: str) -> bool:
    """64-hex collector HMAC (user_ref / repo_ref / host_ref)."""
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower())


def _looks_like_pseudonym(value: str) -> bool:
    """identity-sync style ``u_`` + 32 hex (see services/identity-sync/pseudonym.py)."""
    if not value.startswith("u_") or len(value) != 34:
        return False
    return all(c in "0123456789abcdef" for c in value[2:].lower())


def user_ref_for(value: str, salt: str | bytes) -> str:
    """HMAC-SHA256 identity the same way collectors would for a cleartext
    principal (email / id). Used so policy-as-code user lists can name people
    without committing their live user_ref digests."""
    key = salt.encode() if isinstance(salt, str) else salt
    return hmac.new(key, value.strip().lower().encode(), hashlib.sha256).hexdigest()


def _resolve_user_idents(entries: list, settings: dict) -> frozenset[str]:
    """Expand a user allow/deny list to the set of identity tokens that may
    appear on an event (raw user_ref, user_pseudonym, or HMAC of cleartext).

    Cleartext entries (emails) are HMAC'd with AIM_HASH_SALT so the policy
    file stays reviewable while matching stays pseudonymized. Without the
    salt, cleartext entries are dropped (fail-closed); raw refs still match.
    """
    salt = os.environ.get(REPO_REF_SALT_ENV) or ""
    raw_key = tuple(str(e) for e in entries if e is not None and str(e))
    cache = settings.get(_USER_LIST_CACHE_KEY)
    if cache is not None and cache[0] == (salt, raw_key):
        return cache[1]
    out: set[str] = set()
    for entry in raw_key:
        if _looks_like_hex_ref(entry) or _looks_like_pseudonym(entry):
            out.add(entry)
        elif salt:
            out.add(user_ref_for(entry, salt))
        # else: cleartext with no salt → omit (cannot re-derive)
    frozen = frozenset(out)
    settings[_USER_LIST_CACHE_KEY] = ((salt, raw_key), frozen)
    return frozen


def _event_user_idents(event: dict) -> set[str]:
    """Identity tokens present on the event for ABAC user matching.

    Prefer both collector ``user_ref`` (when set) and the identity-sync
    ``user_pseudonym`` column reattached by the DB runner.
    """
    idents: set[str] = set()
    for key in ("user_ref", "user_pseudonym"):
        val = event.get(key)
        if isinstance(val, str) and val:
            idents.add(val)
    return idents


def _event_groups(event: dict, settings: dict) -> set[str]:
    """Group membership for ABAC group matching.

    Sources (union):
      1. event.groups — optional list of IdP/group names on the evaluation
         event (when identity enrichment attaches them).
      2. event.team — identity-enrichment team (org-unit rollup) is treated
         as a group name for policy purposes.
      3. settings.group_members — policy-as-code map of group → [users].
         A group matches when the event's user identity is in that list
         (same expansion as attr:user). Enables group conditions without
         requiring groups on every event row.
    """
    groups: set[str] = set()
    raw = event.get("groups")
    if isinstance(raw, list):
        groups.update(str(g) for g in raw if g)
    team = event.get("team")
    if isinstance(team, str) and team:
        groups.add(team)

    members_map = settings.get("group_members") or {}
    if isinstance(members_map, dict) and members_map:
        user_idents = _event_user_idents(event)
        if user_idents:
            for gname, members in members_map.items():
                if not isinstance(members, list):
                    continue
                allowed = _resolve_user_idents(members, settings)
                if user_idents & allowed:
                    groups.add(str(gname))
    return groups


def _repo_class_index(settings: dict) -> dict[str, frozenset[str]] | None:
    """repo_ref → frozenset of class names.

    settings.repo_classes maps class name → list of cleartext repo paths
    (HMAC'd like restricted_repos). settings.restricted_repos entries are
    unioned into class ``restricted``.
    """
    classes = settings.get("repo_classes") or {}
    restricted = tuple(settings.get("restricted_repos") or ())
    if not isinstance(classes, dict):
        classes = {}
    salt = os.environ.get(REPO_REF_SALT_ENV) or ""
    class_items = tuple(
        (str(name), tuple(str(p) for p in (paths or ()) if p))
        for name, paths in sorted(classes.items())
        if isinstance(paths, (list, tuple))
    )
    cache_key = (salt, class_items, restricted)
    cached = settings.get(_REPO_CLASS_CACHE_KEY)
    if cached is not None and cached[0] == cache_key:
        return cached[1]

    if not class_items and not restricted:
        settings[_REPO_CLASS_CACHE_KEY] = (cache_key, {})
        return {}

    if not salt:
        # Cannot HMAC cleartext paths without the company salt — fail closed.
        settings[_REPO_CLASS_CACHE_KEY] = (cache_key, {})
        return {}

    index: dict[str, set[str]] = {}
    for name, paths in class_items:
        for path in paths:
            ref = repo_ref_for(path, salt)
            index.setdefault(ref, set()).add(name)
    for path in restricted:
        ref = repo_ref_for(path, salt)
        index.setdefault(ref, set()).add("restricted")
    frozen = {ref: frozenset(names) for ref, names in index.items()}
    settings[_REPO_CLASS_CACHE_KEY] = (cache_key, frozen)
    return frozen


def _event_repo_classes(event: dict, settings: dict) -> set[str]:
    """Classes of event.repo_ref per settings.repo_classes (+ restricted_repos)."""
    ref = event.get("repo_ref")
    if not isinstance(ref, str) or not ref:
        return set()
    index = _repo_class_index(settings)
    if not index:
        return set()
    return set(index.get(ref) or ())


def _match_set_attr(op: str, actual: set[str], expected: Any) -> bool:
    """ABAC set-valued attribute match (group, repo_class, multi-ident user)."""
    if op == "eq":
        return str(expected) in actual
    if op == "neq":
        return str(expected) not in actual
    if op in ("in", "not_in"):
        if not isinstance(expected, list):
            raise ConditionError(f"{op} operand must be a list or settings list name")
        want = {str(x) for x in expected if x is not None and str(x)}
        hit = bool(actual & want)
        return hit if op == "in" else not hit
    raise ConditionError(f"attr op {op!r} not supported")


def eval_attr(cond: dict, event: dict, settings: dict) -> tuple[bool, dict]:
    """Evaluate an ABAC attribute leaf (``attr:`` + one of eq/neq/in/not_in).

    Dimensions:
      user       — event.user_ref / user_pseudonym vs policy list (HMAC cleartext)
      group      — event.team ∪ event.groups ∪ settings.group_members
      repo_class — settings.repo_classes (+ restricted_repos → 'restricted')
      tool       — event.tool (scalar; same ops as field:tool)
    """
    attr = cond.get("attr")
    if attr not in KNOWN_ATTRS:
        raise ConditionError(f"unknown attr {attr!r} (known: {sorted(KNOWN_ATTRS)})")
    ops = [k for k in cond if k != "attr"]
    if len(ops) != 1:
        raise ConditionError(f"attr condition needs exactly one op: {cond}")
    op = ops[0]
    if op not in ATTR_OPS:
        raise ConditionError(f"attr op {op!r} not allowed (allowed: {sorted(ATTR_OPS)})")
    expected = cond[op]

    if attr == "user":
        actual_set = _event_user_idents(event)
        if op in ("in", "not_in"):
            expected = _resolve_reference(expected, settings)
            if not isinstance(expected, list):
                raise ConditionError(
                    f"{op} operand must be a list or settings list name: {cond}"
                )
            want = _resolve_user_idents(expected, settings)
            hit = bool(actual_set & want)
            ok = hit if op == "in" else not hit
            # Unattributed: do not match positive or negative membership.
            if not actual_set:
                ok = False
            detail_actual: Any = sorted(actual_set) if actual_set else None
        else:  # eq / neq
            want = _resolve_user_idents([expected], settings)
            hit = bool(actual_set & want)
            ok = hit if op == "eq" else (bool(actual_set) and not hit)
            detail_actual = sorted(actual_set) if actual_set else None
        return ok, {
            "attr": attr, "op": op, "expected": expected,
            "actual": detail_actual,
        }

    if attr == "group":
        actual_set = _event_groups(event, settings)
        expected = _resolve_reference(expected, settings) if op in ("in", "not_in") else expected
        if op in ("in", "not_in") and not isinstance(expected, list):
            raise ConditionError(
                f"{op} operand must be a list or settings list name: {cond}"
            )
        ok = _match_set_attr(op, actual_set, expected)
        if not actual_set:
            ok = False
        return ok, {
            "attr": attr, "op": op, "expected": expected,
            "actual": sorted(actual_set) if actual_set else None,
        }

    if attr == "repo_class":
        actual_set = _event_repo_classes(event, settings)
        expected = _resolve_reference(expected, settings) if op in ("in", "not_in") else expected
        if op in ("in", "not_in") and not isinstance(expected, list):
            raise ConditionError(
                f"{op} operand must be a list or settings list name: {cond}"
            )
        ok = _match_set_attr(op, actual_set, expected)
        if not actual_set:
            ok = False
        return ok, {
            "attr": attr, "op": op, "expected": expected,
            "actual": sorted(actual_set) if actual_set else None,
        }

    # tool — scalar event.tool
    actual = event.get("tool")
    if op == "eq":
        ok = actual == expected
    elif op == "neq":
        ok = actual is not None and actual != expected
    elif op in ("in", "not_in"):
        expected = _resolve_reference(expected, settings)
        if not isinstance(expected, list):
            raise ConditionError(
                f"{op} operand must be a list or settings list name: {cond}"
            )
        if actual is None:
            ok = False
        else:
            ok = (actual in expected) if op == "in" else (actual not in expected)
    else:
        raise ConditionError(f"attr op {op!r} not supported for tool")
    return ok, {"attr": attr, "op": op, "expected": expected, "actual": actual}


def _resolve_reference(value: Any, settings: dict) -> Any:
    """A bare string operand names a list in ruleset settings (e.g. approved_tools)."""
    if isinstance(value, str) and value in settings and isinstance(settings[value], list):
        return settings[value]
    return value


def _event_local_hour(event: dict, ts_value: Any) -> int | None:
    """Endpoint-local hour if the event carries it (proposed additive field),
    else UTC hour parsed from the ts value."""
    local_hour = event.get("local_hour")
    if local_hour is not None:
        try:
            return int(local_hour)
        except (TypeError, ValueError):
            return None
    if not isinstance(ts_value, str):
        return None
    try:
        dt = datetime.fromisoformat(ts_value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.hour


def _in_off_hours(hour: int | None, settings: dict) -> bool:
    if hour is None:
        return False
    start = int(settings.get("off_hours_start", 20))
    end = int(settings.get("off_hours_end", 7))
    if start <= end:  # same-day window (not our config, but handle it)
        return start <= hour < end
    return hour >= start or hour < end


def eval_leaf(cond: dict, event: dict, settings: dict) -> tuple[bool, dict]:
    # ABAC attribute leaves use ``attr:`` instead of ``field:``.
    if "attr" in cond:
        return eval_attr(cond, event, settings)
    field = cond.get("field")
    if not field:
        raise ConditionError(f"leaf condition missing 'field' or 'attr': {cond}")
    actual = event.get(field)
    ops = [k for k in cond if k not in ("field",)]
    if len(ops) != 1:
        raise ConditionError(f"leaf condition needs exactly one op: {cond}")
    op = ops[0]
    expected = cond[op]

    if op == "eq":
        ok = actual == expected
    elif op == "neq":
        ok = actual != expected
    elif op in ("in", "not_in"):
        expected = _resolve_reference(expected, settings)
        if not isinstance(expected, list):
            raise ConditionError(f"{op} operand must be a list or settings list name: {cond}")
        ok = (actual in expected) if op == "in" else (actual not in expected)
    elif op == "contains":
        ok = isinstance(actual, list) and expected in actual
    elif op == "contains_detector":
        # match_flags entries are {detector, category, severity?} objects.
        # "prefix:*" matches by detector-name prefix; anything else is exact.
        if not isinstance(actual, list):
            ok = False
        else:
            names = [f.get("detector", "") for f in actual if isinstance(f, dict)]
            if str(expected).endswith("*"):
                prefix = str(expected)[:-1]
                ok = any(n.startswith(prefix) for n in names)
            else:
                ok = expected in names
    elif op in ("gt", "gte", "lt", "lte"):
        if actual is None:
            ok = False
        else:
            ok = {"gt": actual > expected, "gte": actual >= expected,
                  "lt": actual < expected, "lte": actual <= expected}[op]
    elif op == "not_in_approved_providers_for":
        # Settings-driven: field (e.g. provider) must be in the approved list for
        # the tool named by event[expected]. No list configured = any provider OK.
        # Null provider (unobservable, e.g. proxy source) does not fire.
        tool = event.get(expected)
        approved = (settings.get("approved_providers") or {}).get(tool)
        ok = actual is not None and bool(approved) and actual not in approved
    elif op == "not_in_approved_models_for":
        # model must be in approved_models[tool]. Empty/missing = OK.
        tool = event.get(expected)
        approved = (settings.get("approved_models") or {}).get(tool)
        ok = actual is not None and bool(approved) and actual not in approved
    elif op == "model_provider_not_permitted_for_scope":
        # model/provider not permitted for the event's scope.
        # Team allowlist (settings.team_approved_models[team][tool]) wins over
        # global approved_models[tool]; else fall back to approved_providers.
        # Empty configuration = degrade open (does not fire).
        tool = event.get("tool")
        team = event.get("team")
        provider = event.get("provider")
        model = event.get("model")
        if model is None and provider is None:
            ok = False
            actual = {"reason": "unobservable"}
        else:
            team_map = (settings.get("team_approved_models") or {}).get(team) if team else None
            team_models = (team_map or {}).get(tool) if isinstance(team_map, dict) else None
            global_models = (settings.get("approved_models") or {}).get(tool)
            approved_models = team_models if team_models else global_models
            approved_providers = (settings.get("approved_providers") or {}).get(tool)
            if approved_models:
                if model is None:
                    ok = False
                    reason = "model_unobservable_under_model_allowlist"
                elif model not in approved_models:
                    ok = True
                    reason = "model_not_on_allowlist"
                else:
                    ok = False
                    reason = "model_permitted"
                scope = "team" if team_models else "global"
            elif approved_providers:
                if provider is None:
                    ok = False
                    reason = "provider_unobservable"
                elif provider not in approved_providers:
                    ok = True
                    reason = "provider_not_on_allowlist"
                else:
                    ok = False
                    reason = "provider_permitted"
                scope = "provider_matrix"
            else:
                ok = False
                reason = "no_allowlist_configured"
                scope = None
            actual = {
                "team": team, "tool": tool, "provider": provider,
                "model": model, "scope": scope, "reason": reason,
            }
        if not expected:
            ok = False
    elif op == "in_off_hours":
        hour = _event_local_hour(event, actual)
        ok = _in_off_hours(hour, settings) if expected else not _in_off_hours(hour, settings)
    elif op == "in_restricted_repos":
        # Settings-driven: settings['restricted_repos'] lists cleartext repo
        # identifiers (policy-as-code, PR-reviewed); the engine HMACs them
        # with the same AIM_HASH_SALT the collectors use and matches the
        # pseudonymized event.repo_ref directly — no collection-point
        # classifier involved. Never matches without the salt or with an
        # empty list (fail-closed, but loud in the audit detail).
        refs = _restricted_repo_refs(settings)
        ok = bool(expected) and refs is not None and actual in refs
        if refs is None:
            expected = f"{expected} (disabled: {REPO_REF_SALT_ENV} not set)"
    elif op == "mcp_call_to_unapproved_server":
        # Settings-driven: fires when any tool_calls[]
        # entry is an MCP call (action_class == "mcp_call") to a server
        # outside settings['approved_mcp_servers']. A null/missing
        # mcp_server counts as unapproved (unknown server). An EMPTY
        # approved list fires on every MCP call — formal deny-unlisted
        # allowlist inventory (mcp_allowlist_mode:
        # deny_unlisted), not open-ended discovery. See core.yaml.
        # The recorded `actual` is metadata-only: the offending
        # {tool_name, mcp_server} pairs, never counts/durations/args.
        approved = settings.get("approved_mcp_servers") or []
        calls = actual if isinstance(actual, list) else []
        actual = [
            {"tool_name": c.get("tool_name"), "mcp_server": c.get("mcp_server")}
            for c in calls
            if isinstance(c, dict)
            and c.get("action_class") == "mcp_call"
            and c.get("mcp_server") not in approved
        ]
        ok = bool(expected) and bool(actual)
    elif op == "tool_call_action_class_in":
        # Tool_calls-aware: fires when any tool_calls[] entry on a
        # tool_use event has an action_class in the operand list (e.g.
        # ["shell"], ["network"]). Missing/null tool_calls never matches.
        # The recorded `actual` is metadata-only: the matching
        # {tool_name, action_class} pairs, never counts/durations/args.
        classes = expected if isinstance(expected, list) else []
        calls = actual if isinstance(actual, list) else []
        actual = [
            {"tool_name": c.get("tool_name"), "action_class": c.get("action_class")}
            for c in calls
            if isinstance(c, dict) and c.get("action_class") in classes
        ]
        ok = bool(classes) and bool(actual)
    elif op == "tool_call_name_matches":
        # credential-shaped / sensitive tool names on
        # tool_calls[]. Operand is a list of case-insensitive needles, or a
        # settings list name (e.g. credential_tool_name_substrings).
        # Matching is segment-aware (camel + snake) with token FP suppression
        # — see tool_name_matches_needle. Metadata only: {tool_name,
        # action_class}, never arguments/results.
        expected = _resolve_reference(expected, settings)
        needles = [
            str(n).lower()
            for n in (expected if isinstance(expected, list) else [])
            if n
        ]
        calls = actual if isinstance(actual, list) else []
        actual = []
        for c in calls:
            if not isinstance(c, dict):
                continue
            name = str(c.get("tool_name") or "")
            if any(tool_name_matches_needle(name, n) for n in needles):
                actual.append({
                    "tool_name": name,
                    "action_class": c.get("action_class"),
                })
        ok = bool(needles) and bool(actual)

    elif op == "mcp_call_to_unapproved_tool":
        # per-(server, tool) allowlist on top of server allowlist.
        # settings.approved_mcp_tools is a list of "server/tool_name" strings
        # (exact match, case-sensitive). EMPTY list = no tool-level restriction
        # (server allowlist alone still applies via mcp_call_to_unapproved_server).
        # Fires only for action_class=mcp_call when the list is non-empty and
        # the pair is absent. Null mcp_server always unapproved at tool level.
        # Metadata only: {tool_name, mcp_server}, never args/results.
        approved_tools = settings.get("approved_mcp_tools") or []
        if not approved_tools:
            actual = []
            ok = False
        else:
            allowed = set()
            for entry in approved_tools:
                if isinstance(entry, str) and "/" in entry:
                    allowed.add(entry)
                elif isinstance(entry, dict):
                    s, tn = entry.get("server"), entry.get("tool_name")
                    if isinstance(s, str) and isinstance(tn, str):
                        allowed.add(f"{s}/{tn}")
            calls = actual if isinstance(actual, list) else []
            actual = []
            for c in calls:
                if not isinstance(c, dict) or c.get("action_class") != "mcp_call":
                    continue
                server = c.get("mcp_server")
                tname = c.get("tool_name")
                key = f"{server}/{tname}" if server and tname else None
                if key is None or key not in allowed:
                    actual.append({
                        "tool_name": tname,
                        "mcp_server": server,
                    })
            ok = bool(expected) and bool(actual)

    elif op == "configured_mcp_server_unapproved":
        # Settings-driven: fires when any
        # configured_mcp_servers[] entry on an inventory event names a
        # server outside settings['approved_mcp_servers']. An EMPTY
        # approved list fires on every configured server — formal
        # deny-unlisted allowlist (discovery mode closed after
        # inventory; see core.yaml mcp_allowlist_mode).
        # The recorded `actual` is metadata-only: the offending
        # {name, scope} pairs, nothing else from the inventory entry.
        approved = settings.get("approved_mcp_servers") or []
        servers = actual if isinstance(actual, list) else []
        actual = [
            {"name": s.get("name"), "scope": s.get("scope")}
            for s in servers
            if isinstance(s, dict) and s.get("name") not in approved
        ]
        ok = bool(expected) and bool(actual)
    else:
        raise ConditionError(f"unknown op {op!r} in {cond}")

    return ok, {"field": field, "op": op, "expected": expected, "actual": actual}


def eval_tree(tree: dict, event: dict, settings: dict) -> tuple[bool, list[dict]]:
    """Returns (matched, details). For `any`, details cover the matching branches;
    for `all`, details cover every leaf."""
    if "all" in tree:
        matched_all = True
        details = []
        for sub in tree["all"]:
            ok, d = eval_tree(sub, event, settings) if ("all" in sub or "any" in sub) else eval_leaf(sub, event, settings)
            details.extend(d if isinstance(d, list) else [d])
            matched_all = matched_all and ok
        return matched_all, details
    if "any" in tree:
        matched_any = False
        details = []
        for sub in tree["any"]:
            ok, d = eval_tree(sub, event, settings) if ("all" in sub or "any" in sub) else eval_leaf(sub, event, settings)
            if ok:
                details.extend(d if isinstance(d, list) else [d])
            matched_any = matched_any or ok
        return matched_any, details
    ok, d = eval_leaf(tree, event, settings)
    return ok, [d]

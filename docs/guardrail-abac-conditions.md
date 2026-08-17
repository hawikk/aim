# ABAC-style policy conditions

Status: **implemented** in `services/guardrail` (engine feature). Policy
*content* that uses these dimensions remains a Security proposal — this
doc is the mechanism.

Parent epic: (Policy engine 8→10).

## What shipped

The guardrail condition language accepts **attribute leaves** alongside the
existing field leaves:

```yaml
when:
  all:
    - attr: tool
      in: [cursor, claude_code]
    - attr: group
      in: [data, security]
    - attr: repo_class
      eq: secret
    - attr: user
      not_in: break_glass_users   # settings list name
```

| Dimension | `attr:` | Source on the evaluation event | Policy operand |
|---|---|---|---|
| **tool** | `tool` | `event.tool` (canonical enum) | tool id, or settings list name |
| **user** | `user` | `event.user_ref` ∪ `event.user_pseudonym` | 64-hex ref, `u_…` pseudonym, or cleartext email HMAC'd with `AIM_HASH_SALT` |
| **group** | `group` | `event.team` ∪ `event.groups[]` ∪ `settings.group_members` | group/team name, or settings list |
| **repo class** | `repo_class` | `event.repo_ref` classified via `settings.repo_classes` (+ `restricted_repos` → class `restricted`) | class name |

Ops on attribute leaves: **`eq` | `neq` | `in` | `not_in`** only (validated at
ruleset load — unknown attr or op fails CI/`validate-rules`).

## Settings

```yaml
settings:
  # Optional multi-class repo catalogue (cleartext paths, HMAC'd like
  # restricted_repos). restricted_repos entries are always class "restricted".
  repo_classes:
    secret:
      - /srv/secrets
    internal:
      - /srv/apps

  # Optional policy-as-code group membership when events lack groups[]/team.
  # Values are user refs / pseudonyms / cleartext emails (HMAC'd with salt).
  group_members:
    break-glass-operators:
      - alice@example.com

  # Named lists work as operands for attr:user / attr:tool / attr:group.
  break_glass_users:
    - bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

## Fail-closed posture

- **Unattributed user** (no `user_ref` / `user_pseudonym`): never matches
  `eq`/`in` *or* `neq`/`not_in` — so a deny-list cannot soft-open on null.
- **Unattributed group** (no team, no groups, no group_members hit): same.
- **Unclassified repo** (no salt, empty catalogue, or ref not listed):
  `repo_class` positive matches fail; negative matches also fail closed.
- **Cleartext user / repo paths without `AIM_HASH_SALT`**: cannot re-derive
  HMACs → treated as non-matching (same posture as `in_restricted_repos`).

## Auditability

Match detail on findings/audit records carries:

```json
{ "attr": "repo_class", "op": "eq", "expected": "secret", "actual": ["secret"] }
```

No cleartext emails or repo paths are written into findings — only the
attribute name, op, expected operand (as authored / resolved list name), and
the pseudonymized/class tokens that matched.

## Files

- `services/guardrail/src/guardrail/conditions.py` — `eval_attr`, class/user
  resolution helpers
- `services/guardrail/src/guardrail/rules.py` — load-time validation
- `apps/api/src/guardrail-policy.js` — humanizer for Rules UI
- `services/guardrail/tests/test_abac_conditions.py` — per-dimension tests

## Deliberate limits

- Dimensions are exactly the four named. Adding one is a small
  change to `KNOWN_ATTRS` + resolver + tests.
- Attribute conditions do **not** change the platform action posture
  (still observe-only on the engine path). Scoping *actions* per
  team/repo/tool remains scoped policies if
  revived; this ticket is the condition language only.
- Group membership from live IdP on every event is optional enrichment;
  `settings.group_members` and `event.team` cover the pilot path without a
  schema bump.

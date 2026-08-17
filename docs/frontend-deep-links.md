# Frontend deep-links

Cross-module navigation for security analysts. Source of truth for builders:
`apps/web/public/lib/deeplinks.js` (`LINK_MAP`, `entityHref`, `findingHrefs`).
Router encoding lives in `apps/web/public/lib/router.js` (`hashFor` / `parseHash`).

## Why this exists

An analyst who filters Security to 7 days, opens a critical finding, and clicks
the user must land on that user's timeline **still on 7 days**. Bare
`#/users/<ref>` silently resets the range to the default 30 days and breaks the
investigation chain.

Rule: **every entity click goes through `entityHref` / runtime `hashFor`
(which wraps the same router helper with live `state.days`).** Never hand-build
`#/${view}/${id}`.

## URL shape

```
#/<view>
#/<view>/<entity>
#/<view>/<entity>?days=7
#/providers/<name>?days=7&source=proxy
```

| Segment | Meaning |
| --- | --- |
| `view` | Static tab or registered module (`findings`, `rules`, …) |
| `entity` | Drill-down id for `providers`, `apps`, `teams`, `tools`, `repos`, `users` only |
| `days` | Shared range filter: `7` \| `30` \| `90` (default 30 omitted from URL) |
| `source` | Providers-only: `all` \| `proxy` \| `endpoint` |

Entity segments are `encodeURIComponent`'d (repos like `acme/payments` survive).

## Link map

| From | Click | To | Preserves |
| --- | --- | --- | --- |
| **Finding** (inbox detail) | user ref | `#/users/<user_ref>` | `days` |
| Finding | tool (`evidence.context.tool_raw` / `tool`) | `#/tools/<tool>` | `days` |
| Finding | repo (`subject.repo_ref` or evidence) | `#/repos/<repo_ref>` | `days` |
| Finding | host present | `#/fleet` (list; no host drill) | `days` |
| **User** detail | tool row / session tools / flags | `#/tools/<tool>` | `days` |
| User detail | team | `#/teams/<team>` | `days` |
| User detail | triage CTA | `#/findings` | `days` |
| **Repo** detail | tool breakdown | `#/tools/<tool>` | `days` |
| **Security** detector detail | user / tool / repo rows | users / tools / repos drills | `days` |
| Security unapproved | tool / provider | tools / providers drills | `days` (+ `source` for providers) |
| Security | Findings triage CTA | `#/findings` | `days` |
| **Activity** stream | user / tool cells | users / tools drills | `days` |
| **Overview** KPIs / alerts / tools | various list + drills | see `LINK_MAP.overview` | `days` |
| **MCP** install rows | user / team / tool | drills | `days` |
| **Fleet** | — | coverage destination only | — |

Machine-readable twin: `LINK_MAP` in `lib/deeplinks.js`. Update both when you
add a hop.

## Context contract

1. **Range (`days`)** — always take the operator's current range from
   `state.days` (dashboard) or the module's own range (Findings saved filters).
   Pass it into `entityHref(view, id, { days })`.
2. **Source** — only meaningful on Providers; `hashFor` omits it elsewhere.
3. **No inventing entities** — if `user_ref` / tool / repo is missing, render
   plain text (or "unattributed"), not a dead link.
4. **Capability gates** — module views (`findings`, …) only route after
   registration. A shared `#/findings` link for a non-security session falls
   back to Overview (router contract).
5. **Privacy** — links use the same pseudonyms the API already returned.
   Never widen a query or reveal redacted prompt content to "make the link work".

## Finding → user → tool → repo chain

Typical SOC path this map supports:

```
#/findings  (open critical)
   └─ subject.user_ref  →  #/users/<ref>?days=7
         └─ tools used    →  #/tools/claude_code?days=7
               └─ (from repo activity / security detector)
                              →  #/repos/<repo_ref>?days=7
```

Builders:

```js
import { entityHref, findingHrefs, findingLinkHtml } from './lib/deeplinks.js';

entityHref('users', userRef, { days: 7 });
// → '#/users/<ref>?days=7'

findingHrefs(finding, { days: state.days });
// → { user, tool, repo, fleet }  // null when entity absent
```

## Tests

- `apps/web/test/deeplinks.test.js` — map shape, finding entity extraction,
  days preservation, chain round-trips through `parseHash`.
- `apps/web/test/router.test.js` — `hashFor` / `parseHash` encoding contract.
- Wiring smoke: key modules must not hand-build entity hashes with
  `` `#/users/${` `` style templates (deeplinks suite enforces the main hops).

## Out of scope (follow-ups)

- Fleet host drill-down (`#/fleet/<host_id>`) — API has no host detail route yet.
- Tool → user / repo tables — tool detail API returns aggregates only.
- Findings list filter-by-user in the hash — saved views own that.

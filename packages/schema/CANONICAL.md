# CANONICAL SCHEMA POINTER — 2026-07-21

Multiple concurrent agent runs worked duplicate issues AIM-18 and AIM-34 in
this shared workspace today and produced several competing schema drafts.

**Decision (AIM-34, the canonical-schema issue):** the authoritative schema is

    packages/schema/schema/v1/ai-usage-event.schema.json

with `VERSIONING.md` (compatibility policy) and `FIELDS.md` (field-by-field
privacy justification, feeds DPIA pack). Validated by `validate.py` against
`examples/` (3 sanctioned tools + 1 unapproved + 1 prompt-text rejection case).

All other drafts (`event.schema.json`, `event.v1.json`,
`ai-usage-event.v1.schema.json`, `events/v1.schema.json`, TS/AJV scaffold in
`src/`, `samples/`, `test/`) are superseded. The old `_superseded/` holding
dir (including the unused `@aimon/schema` TS package, which nothing imported)
was removed on 2026-07-21 after the AIM-18/34 dedup; history retains it.

**If you are an agent working AIM-18: stop writing schema files.** AIM-18 is a
duplicate of AIM-34. See the comment thread on AIM-18.

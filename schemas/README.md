# schemas/ — retired drafts

This directory previously held `event.v1.json`, an early network-event draft
(proxy shape with a `metrics` sub-object). It was **superseded** by the
canonical-schema decision and removed on 2026-07-22.

**Do not add schema files here.** The single source of truth is:

    packages/schema/schema/v1/ai-usage-event.schema.json

with `packages/schema/CANONICAL.md`, `VERSIONING.md` (compatibility policy +
changelog), and `FIELDS.md` (field-by-field privacy justification). Ingest
(`services/ingest/src/schema.ts`) validates against that file only.

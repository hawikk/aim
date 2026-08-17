-- Local dev schema bootstrap for Postgres.
-- Creates the application schema. Migrations will take over once the
-- ingestion service lands (see AIM-16 epic); this is the minimum for
-- `docker compose up` to yield a usable database.

CREATE SCHEMA IF NOT EXISTS aim;

CREATE TABLE IF NOT EXISTS aim.bootstrap_check (
    id integer PRIMARY KEY,
    note text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO aim.bootstrap_check (id, note)
VALUES (1, 'local stack bootstrap ok')
ON CONFLICT (id) DO NOTHING;

-- +goose Up
-- SPEC §6.5 exposure sets: immutable versions binding one catalog snapshot to
-- the entries actually served. Nothing is exposed by default; the latest
-- version is the active one.
CREATE TABLE exposures (
    id              TEXT PRIMARY KEY,
    integration_id  TEXT NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    version         BIGINT NOT NULL,
    catalog_version BIGINT NOT NULL,
    entries         TEXT NOT NULL,
    created_at      BIGINT NOT NULL,
    UNIQUE (integration_id, version)
);

-- +goose Down
DROP TABLE exposures;

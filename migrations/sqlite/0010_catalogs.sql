-- +goose Up
-- SPEC §6.4 catalog snapshots: immutable per-integration tool-set versions.
CREATE TABLE catalogs (
    id             TEXT PRIMARY KEY,
    integration_id TEXT NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    version        INTEGER NOT NULL,
    tools          TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    UNIQUE (integration_id, version)
);

-- +goose Down
DROP TABLE catalogs;

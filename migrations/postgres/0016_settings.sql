-- +goose Up
-- Owner-set configuration (SPEC §8.2, §12.2). The config file and environment
-- remain the bootstrap layer — data dir, binds, store engine — and keep their
-- precedence; this table only fills knobs the owner sets in the portal, so an
-- environment variable an operator pinned is never silently overridden.
--
-- Secret values (a tunnel auth key, an ingress token) are stored keyring-sealed
-- and marked here, so nothing that reads settings can hand one to a template.
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    secret     BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at BIGINT NOT NULL
);

-- +goose Down
DROP TABLE settings;

-- +goose Up
-- SPEC §6.1 integrations: upstream MCP servers. Credentials are NOT here — they
-- live keyring-sealed (SPEC §11.2, §12); this row is config + node-local status.
CREATE TABLE integrations (
    id         TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    slug       TEXT NOT NULL,
    transport  TEXT NOT NULL,
    endpoint   TEXT NOT NULL DEFAULT '',
    command    TEXT NOT NULL DEFAULT '',
    auth_kind  TEXT NOT NULL DEFAULT 'none',
    status     TEXT NOT NULL DEFAULT 'disabled',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (account_id, slug)
);

-- +goose Down
DROP TABLE integrations;

-- +goose Up
-- SPEC §9.2 invites: server-side state reachable by a bearer token whose HASH alone
-- is stored (SPEC §11.2). Settings live here so revocation is deletion-strength.
CREATE TABLE invites (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash  BLOB NOT NULL UNIQUE,
    expires_at  INTEGER NOT NULL,
    max_uses    INTEGER NOT NULL DEFAULT 1,
    uses        INTEGER NOT NULL DEFAULT 0,
    auto_accept INTEGER NOT NULL DEFAULT 0,
    preset      TEXT NOT NULL DEFAULT 'basic',
    permissions TEXT NOT NULL DEFAULT '["message.text"]',
    label       TEXT NOT NULL DEFAULT '',
    revoked_at  INTEGER,
    created_at  INTEGER NOT NULL
);
CREATE INDEX invites_account ON invites(account_id);

-- +goose Down
DROP INDEX invites_account;
DROP TABLE invites;

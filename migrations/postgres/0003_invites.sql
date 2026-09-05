-- +goose Up
-- Mirror of sqlite 0003 (SPEC §9.2 invites).
CREATE TABLE invites (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash  BYTEA NOT NULL UNIQUE,
    expires_at  BIGINT NOT NULL,
    max_uses    BIGINT NOT NULL DEFAULT 1,
    uses        BIGINT NOT NULL DEFAULT 0,
    auto_accept BIGINT NOT NULL DEFAULT 0,
    preset      TEXT NOT NULL DEFAULT 'basic',
    permissions TEXT NOT NULL DEFAULT '["message.text"]',
    label       TEXT NOT NULL DEFAULT '',
    revoked_at  BIGINT,
    created_at  BIGINT NOT NULL
);
CREATE INDEX invites_account ON invites(account_id);

-- +goose Down
DROP INDEX invites_account;
DROP TABLE invites;

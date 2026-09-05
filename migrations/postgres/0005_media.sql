-- +goose Up
-- Mirror of sqlite 0005. SPEC §7.4: media is content-addressed; per-account rows carry metadata and feed
-- the quota; messages gain a kind so media rows are first-class, not sniffed.
ALTER TABLE messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'text' CHECK (kind IN ('text','media'));

CREATE TABLE blobs (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    hash       TEXT NOT NULL,
    size       BIGINT NOT NULL,
    mime       TEXT NOT NULL DEFAULT 'application/octet-stream',
    filename   TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    PRIMARY KEY (account_id, hash)
);

-- +goose Down
DROP TABLE blobs;
ALTER TABLE messages DROP COLUMN kind;

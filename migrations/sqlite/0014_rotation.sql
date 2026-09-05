-- +goose Up
-- SPEC §3.9 key rotation: the retiring key stays live (sealed) until the grace
-- period ends, then is destroyed; fan-out progress per contact is durable so an
-- interrupted rotation resumes.
ALTER TABLE accounts ADD COLUMN prev_fingerprint TEXT;
ALTER TABLE accounts ADD COLUMN prev_key_sealed BLOB;
ALTER TABLE accounts ADD COLUMN grace_until INTEGER NOT NULL DEFAULT 0;

CREATE TABLE rotation_fanout (
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    contact_fpr TEXT NOT NULL,
    new_fpr     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT NOT NULL DEFAULT '',
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (account_id, contact_fpr)
);

-- +goose Down
DROP TABLE rotation_fanout;
ALTER TABLE accounts DROP COLUMN grace_until;
ALTER TABLE accounts DROP COLUMN prev_key_sealed;
ALTER TABLE accounts DROP COLUMN prev_fingerprint;

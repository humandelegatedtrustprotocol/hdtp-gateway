-- +goose Up
-- SPEC §11.2 contacts: relationship state per (account, fingerprint). The pinned
-- SPKI (DER) is stored in full — a fingerprint alone cannot verify an envelope
-- signature, so the key itself is pinned at add time (SPEC §3.5, §4.4).
CREATE TABLE contacts (
    id           TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    fingerprint  TEXT NOT NULL,
    spki         BLOB,
    status       TEXT NOT NULL CHECK (status IN ('active','pending_in','pending_out','blocked')),
    preset       TEXT NOT NULL DEFAULT 'basic',
    permissions  TEXT NOT NULL DEFAULT '["message.text"]',
    trust_flag   TEXT NOT NULL DEFAULT 'messages_only' CHECK (trust_flag IN ('messages_only','may_instruct')),
    display_name TEXT NOT NULL DEFAULT '',
    card         TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    pinned_at    INTEGER,
    UNIQUE (account_id, fingerprint)
);
CREATE INDEX contacts_account ON contacts(account_id);

-- +goose Down
DROP INDEX contacts_account;
DROP TABLE contacts;

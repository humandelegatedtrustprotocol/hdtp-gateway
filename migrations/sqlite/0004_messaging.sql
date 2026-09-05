-- +goose Up
-- SPEC §7 / PACT §7: threads carry a SHARED id both sides use; messages are
-- idempotent on (account, contact, msg_id) — a replay is acknowledged, never
-- re-executed, so the original response columns are part of the row.
CREATE TABLE threads (
    id          TEXT NOT NULL,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    contact_fpr TEXT NOT NULL,
    topic       TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    last_at     INTEGER NOT NULL,
    PRIMARY KEY (account_id, id)
);
CREATE INDEX threads_contact ON threads(account_id, contact_fpr);

CREATE TABLE messages (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    id          TEXT NOT NULL UNIQUE,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    contact_fpr TEXT NOT NULL,
    msg_id      TEXT NOT NULL,
    thread_id   TEXT NOT NULL,
    direction   TEXT NOT NULL CHECK (direction IN ('in','out')),
    sender      TEXT NOT NULL CHECK (sender IN ('agent','human')),
    body        TEXT NOT NULL,
    reply_to    TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL CHECK (status IN ('delivered','queued_for_human')),
    created_at  INTEGER NOT NULL,
    UNIQUE (account_id, contact_fpr, msg_id)
);
CREATE INDEX messages_thread ON messages(account_id, thread_id, seq);

-- +goose Down
DROP INDEX messages_thread;
DROP TABLE messages;
DROP INDEX threads_contact;
DROP TABLE threads;

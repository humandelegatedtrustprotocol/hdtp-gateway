-- +goose Up
-- SPEC 7.1: handing a message to the contact's X-PACT-GATEWAY relay is a
-- FALLBACK, not an arrival. The relay is a third party holding ciphertext for a
-- peer who is offline; it may never be drained. Recording those rows as
-- 'delivered' told the owner their message had reached the person when nothing
-- of the sort had happened, and it is the one delivery state the owner cannot
-- verify for themselves. Give it its own name.
PRAGMA foreign_keys = OFF;

CREATE TABLE messages_new (
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
    status      TEXT NOT NULL CHECK (status IN ('delivered','queued_for_human','pending','failed','queued_at_relay')),
    created_at  INTEGER NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'text' CHECK (kind IN ('text','media')),
    expires_at  INTEGER NOT NULL DEFAULT 0,
    attempts    INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL DEFAULT 0,
    UNIQUE (account_id, contact_fpr, direction, msg_id)
);

INSERT INTO messages_new (seq, id, account_id, contact_fpr, msg_id, thread_id,
                          direction, sender, body, reply_to, status, created_at,
                          kind, expires_at, attempts, next_attempt_at)
SELECT seq, id, account_id, contact_fpr, msg_id, thread_id,
       direction, sender, body, reply_to, status, created_at, kind, expires_at,
       attempts, next_attempt_at
FROM messages;

DROP TABLE messages;
ALTER TABLE messages_new RENAME TO messages;
CREATE INDEX messages_thread ON messages(account_id, thread_id, seq);

PRAGMA foreign_keys = ON;

-- +goose Down
-- Rows in the new state have to become something the old CHECK allows. They were
-- called 'delivered' before this migration existed, so that is what reverting
-- restores — knowingly, and only on the way down.
PRAGMA foreign_keys = OFF;
UPDATE messages SET status = 'delivered' WHERE status = 'queued_at_relay';
CREATE TABLE messages_old (
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
    status      TEXT NOT NULL CHECK (status IN ('delivered','queued_for_human','pending','failed')),
    created_at  INTEGER NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'text' CHECK (kind IN ('text','media')),
    expires_at  INTEGER NOT NULL DEFAULT 0,
    attempts    INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL DEFAULT 0,
    UNIQUE (account_id, contact_fpr, direction, msg_id)
);
INSERT INTO messages_old SELECT seq, id, account_id, contact_fpr, msg_id, thread_id,
       direction, sender, body, reply_to, status, created_at, kind, expires_at,
       attempts, next_attempt_at
FROM messages;
DROP TABLE messages;
ALTER TABLE messages_old RENAME TO messages;
CREATE INDEX messages_thread ON messages(account_id, thread_id, seq);
PRAGMA foreign_keys = ON;

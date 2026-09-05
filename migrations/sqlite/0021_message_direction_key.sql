-- +goose Up
-- SPEC 7.1: msg_id is the CALLER's idempotency key, so its scope is the caller.
-- The key here was (account, contact, msg_id) with no direction, which puts both
-- sides of a conversation in one namespace: an outbound message reusing a msg_id
-- the contact had already used was refused as a duplicate, and the idempotency
-- lookup handed back the INBOUND row — status "delivered". The owner's message
-- was never written, never sent, and shown as delivered. The peer picks its own
-- msg_id, so this is something a contact can do on purpose.
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
    status      TEXT NOT NULL CHECK (status IN ('delivered','queued_for_human','pending','failed')),
    created_at  INTEGER NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'text' CHECK (kind IN ('text','media')),
    expires_at  INTEGER NOT NULL DEFAULT 0,
    UNIQUE (account_id, contact_fpr, direction, msg_id)
);

INSERT INTO messages_new (seq, id, account_id, contact_fpr, msg_id, thread_id,
                          direction, sender, body, reply_to, status, created_at,
                          kind, expires_at)
SELECT seq, id, account_id, contact_fpr, msg_id, thread_id,
       direction, sender, body, reply_to, status, created_at, kind, expires_at
FROM messages;

DROP TABLE messages;
ALTER TABLE messages_new RENAME TO messages;
CREATE INDEX messages_thread ON messages(account_id, thread_id, seq);

PRAGMA foreign_keys = ON;

-- +goose Down
-- Narrowing the key back can collide, because rows that are legitimate under the
-- wider key are duplicates under the narrower one. Drop the outbound side of any
-- such pair: it is the newer row, and the inbound one is evidence of what a peer
-- actually sent.
PRAGMA foreign_keys = OFF;
DELETE FROM messages WHERE direction = 'out' AND EXISTS (
    SELECT 1 FROM messages m2 WHERE m2.account_id = messages.account_id
      AND m2.contact_fpr = messages.contact_fpr AND m2.msg_id = messages.msg_id
      AND m2.direction = 'in');
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
    UNIQUE (account_id, contact_fpr, msg_id)
);
INSERT INTO messages_old SELECT seq, id, account_id, contact_fpr, msg_id, thread_id,
       direction, sender, body, reply_to, status, created_at, kind, expires_at
FROM messages;
DROP TABLE messages;
ALTER TABLE messages_old RENAME TO messages;
CREATE INDEX messages_thread ON messages(account_id, thread_id, seq);
PRAGMA foreign_keys = ON;

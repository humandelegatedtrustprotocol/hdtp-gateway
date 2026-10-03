-- +goose Up
-- The last of the relay: a delivery state nothing can write and nothing can resolve.
--
-- 0024 gave an outbound message a fourth state for "handed to the contact's store-and-forward
-- relay": a fallback, not an arrival, because a relay is a third party holding ciphertext for a
-- peer who may never collect it. The relay role went with pre-HDTP 1.x (0030 dropped its tables), and
-- the state outlived it: no code writes it, the retry sweep reads `pending` and so never touches
-- such a row, and the portal went on labelling it "queued at their relay" about a relay that does
-- not exist.
--
-- A row still in that state was never confirmed delivered and never can be. `failed` is what is
-- known about it — 0024's own argument against calling it `delivered`, which its Down did anyway.
--
-- SQLite cannot alter a CHECK, so the table is rebuilt, as 0019, 0021 and 0024 rebuilt it.
PRAGMA foreign_keys = OFF;

UPDATE messages SET status = 'failed' WHERE status = 'queued_at_relay';

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
-- The state comes back as something the CHECK allows; no row is put back INTO it, because
-- which rows were in it is exactly what Up decided could not be known.
PRAGMA foreign_keys = OFF;

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
    status      TEXT NOT NULL CHECK (status IN ('delivered','queued_for_human','pending','failed','queued_at_relay')),
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

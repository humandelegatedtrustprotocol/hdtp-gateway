-- +goose Up
-- SPEC 7.1: an OUTBOUND message is not delivered when it is written. The
-- messaging package writes rows and has no path to the wire, so the old CHECK
-- set ('delivered','queued_for_human') left no way to say "written, not yet
-- sent" and every outbound row claimed a delivery that had not happened.
--
-- SQLite cannot alter a CHECK constraint, so the table is rebuilt by the
-- standard idiom: create, copy every row, replace, re-index. Existing rows keep
-- their status -- history is not reinterpreted.
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
    UNIQUE (account_id, contact_fpr, msg_id)
);

INSERT INTO messages_new (seq, id, account_id, contact_fpr, msg_id, thread_id,
                          direction, sender, body, reply_to, status, created_at, kind)
SELECT seq, id, account_id, contact_fpr, msg_id, thread_id,
       direction, sender, body, reply_to, status, created_at, kind
FROM messages;

DROP TABLE messages;
ALTER TABLE messages_new RENAME TO messages;
CREATE INDEX messages_thread ON messages(account_id, thread_id, seq);

PRAGMA foreign_keys = ON;

-- +goose Down
PRAGMA foreign_keys = OFF;
UPDATE messages SET status = 'delivered' WHERE status IN ('pending','failed');
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
    status      TEXT NOT NULL CHECK (status IN ('delivered','queued_for_human')),
    created_at  INTEGER NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'text' CHECK (kind IN ('text','media')),
    UNIQUE (account_id, contact_fpr, msg_id)
);
INSERT INTO messages_old SELECT seq, id, account_id, contact_fpr, msg_id, thread_id,
       direction, sender, body, reply_to, status, created_at, kind FROM messages;
DROP TABLE messages;
ALTER TABLE messages_old RENAME TO messages;
CREATE INDEX messages_thread ON messages(account_id, thread_id, seq);
PRAGMA foreign_keys = ON;

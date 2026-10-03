-- +goose Up
-- The relay tables outlived the role. The root-and-leaf generation removed the store-and-forward
-- gateway entirely on 2026-09-18: one would see every sender, recipient and
-- timestamp for its trouble, and what 2.0 makes safe instead is being hosted
-- (HDTP sec. 9). No Go code and no sqlc query has read these two tables since;
-- they were still here only because migrations are append-only and 0015 could
-- not be edited, and SPEC sec. 11.2's table guard is what surfaced them.
--
-- Forward-only, like every migration after 0014. Whatever they hold was queued
-- for a role that no longer exists and no longer has a reader.
DROP TABLE IF EXISTS relay_queue;
DROP TABLE IF EXISTS relay_allowlist;

-- +goose Down
-- Re-created exactly as 0015 made them, so an operator rolling the whole schema
-- back does not meet a Down that drops a table this migration already took.
CREATE TABLE relay_allowlist (
    recipient_fpr TEXT NOT NULL,
    sender_fpr    TEXT NOT NULL,
    updated_at    INTEGER NOT NULL,
    PRIMARY KEY (recipient_fpr, sender_fpr)
);

CREATE TABLE relay_queue (
    id            TEXT PRIMARY KEY,
    recipient_fpr TEXT NOT NULL,
    sender_fpr    TEXT NOT NULL,
    msg_id        TEXT NOT NULL,
    envelope      TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    queued_at     INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
);
CREATE INDEX relay_queue_recipient ON relay_queue(recipient_fpr, queued_at);
CREATE INDEX relay_queue_expiry ON relay_queue(expires_at);

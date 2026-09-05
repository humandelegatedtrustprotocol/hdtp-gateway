-- +goose Up
-- Mirror of sqlite 0006. Local read state (SPEC §7.6): never wire-visible; unread = in-messages with
-- seq above the thread's high-water mark.
ALTER TABLE threads ADD COLUMN last_read_seq BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE threads DROP COLUMN last_read_seq;

-- +goose Up
-- SPEC 7.1: outbound delivery "retries with backoff until the sender-chosen
-- `expires` (default 24 h)". There was nowhere to keep that deadline, so a
-- pending message had no point at which the node could stop trying and tell the
-- owner it had failed. 0 means "unset": the sweeper reads created_at + 24h.
ALTER TABLE messages ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE messages DROP COLUMN expires_at;

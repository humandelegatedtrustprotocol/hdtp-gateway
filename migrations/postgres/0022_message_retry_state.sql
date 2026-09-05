-- +goose Up
-- SPEC 7.1: backoff has to be a function of attempts made, which means the
-- attempts have to be remembered. See the sqlite twin for the full account of
-- what deriving the schedule from message age cost.
-- BIGINT, like every other epoch column in this schema.
ALTER TABLE messages ADD COLUMN attempts BIGINT NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN next_attempt_at BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE messages DROP COLUMN next_attempt_at;
ALTER TABLE messages DROP COLUMN attempts;

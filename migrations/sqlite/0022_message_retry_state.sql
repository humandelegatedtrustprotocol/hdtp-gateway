-- +goose Up
-- SPEC 7.1: "retries with backoff until the sender-chosen `expires`". The
-- schedule was derived from the message's AGE (age%1800 < 15), which only works
-- if a sweep's wall-clock second lands inside a 15-second window. Sweeps are not
-- evenly spaced — one does network I/O with timeouts for up to 128 messages — so
-- every window stepped over cost the message another half hour, and a loaded
-- node managed roughly two retries in six hours. Backoff has to be a function of
-- attempts made, which means the attempts have to be remembered.
ALTER TABLE messages ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN next_attempt_at INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE messages DROP COLUMN next_attempt_at;
ALTER TABLE messages DROP COLUMN attempts;

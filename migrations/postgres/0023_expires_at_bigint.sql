-- +goose Up
-- 0020 declared messages.expires_at as INTEGER while every other epoch column in
-- this schema is BIGINT — 25 of them. On PostgreSQL that is a 32-bit column, so
-- it stops holding a Unix timestamp in 2038, and it rejects one sooner than that:
-- `expires` is chosen by the SENDER (PACT §7), so a peer naming a far-future
-- deadline makes the INSERT fail with "integer out of range" and the message is
-- refused rather than stored. SQLite needs no change: its INTEGER is 64-bit.
ALTER TABLE messages ALTER COLUMN expires_at TYPE BIGINT;

-- +goose Down
ALTER TABLE messages ALTER COLUMN expires_at TYPE INTEGER;

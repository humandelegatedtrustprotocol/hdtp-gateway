-- +goose Up
-- The state of a web wallet's answer that was installed (HDTP sec. 9.1), as its SHA-256: the answer
-- consumes request_state_hash (migration 0041) and the same statement moves it here, so an answer
-- that arrives again is told apart from one for a request this identity never had waiting. It is
-- the hash of a random value that has been used, and is read for nothing else.
ALTER TABLE leaves ADD COLUMN answered_state_hash BLOB;

-- +goose Down
ALTER TABLE leaves DROP COLUMN answered_state_hash;

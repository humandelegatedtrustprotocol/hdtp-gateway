-- +goose Up
-- A signing request sent to a web wallet (PACT sec. 9.1, SPEC.md sec. 3.12): the host mints a random
-- `state` with the pending request and accepts an answer only once, only with that state. The row
-- keeps the state's SHA-256 and never the state; the answer consumes it (request_state_hash back to
-- NULL) in the same statement that checks it. wallet_origin is the wallet origin the request went
-- to, '' for a request handed over by the CLI.
ALTER TABLE leaves ADD COLUMN request_state_hash BLOB;
ALTER TABLE leaves ADD COLUMN wallet_origin TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE leaves DROP COLUMN wallet_origin;
ALTER TABLE leaves DROP COLUMN request_state_hash;

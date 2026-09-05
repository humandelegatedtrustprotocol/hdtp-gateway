-- +goose Up
-- SPEC §6.1/§6.3: one keyring-sealed credential blob per integration (static
-- header or OAuth tokens). Ciphertext only — never plaintext, never in logs.
ALTER TABLE integrations ADD COLUMN secret BLOB;

-- +goose Down
ALTER TABLE integrations DROP COLUMN secret;

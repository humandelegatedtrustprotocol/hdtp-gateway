-- +goose Up
-- Mirror of sqlite 0046 (the pins a sealed call can name, found by index); see that file for
-- rationale. The rows held before it are filled by the store right after it, as on SQLite.
ALTER TABLE contacts ADD COLUMN leaf_fingerprint TEXT;
CREATE INDEX contacts_account_endpoint ON contacts(account_id, endpoint);
CREATE INDEX contacts_account_leaf_fingerprint ON contacts(account_id, leaf_fingerprint);

-- +goose Down
DROP INDEX contacts_account_leaf_fingerprint;
DROP INDEX contacts_account_endpoint;
ALTER TABLE contacts DROP COLUMN leaf_fingerprint;

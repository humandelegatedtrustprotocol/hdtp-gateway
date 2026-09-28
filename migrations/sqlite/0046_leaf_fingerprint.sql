-- +goose Up
-- The pins a sealed call can name, found by index (PACT sec. 13.3, 2026-09-28). decide is handed
-- the contacts the envelope's proof could concern - the root its chain proves, the address its leaf
-- names, the leaf a small form names - and until this every call read and handed over every contact
-- (store.PinCandidates, public/decide.go).
--
-- leaf_fingerprint is the fingerprint of the pinned leaf's key: written with the leaf by every
-- statement that writes one, and NULL exactly when the row holds no leaf. The rows held before
-- this migration are filled by the store right after it (Store.Migrate, fillLeafFingerprints):
-- SQLite has no SHA-256, and the fill is one Go function for both engines.
ALTER TABLE contacts ADD COLUMN leaf_fingerprint TEXT;
CREATE INDEX contacts_account_endpoint ON contacts(account_id, endpoint);
CREATE INDEX contacts_account_leaf_fingerprint ON contacts(account_id, leaf_fingerprint);

-- +goose Down
-- SQLite refuses to drop a column an index names, so the indexes go first.
DROP INDEX contacts_account_leaf_fingerprint;
DROP INDEX contacts_account_endpoint;
ALTER TABLE contacts DROP COLUMN leaf_fingerprint;

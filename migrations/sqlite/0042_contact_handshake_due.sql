-- +goose Up
-- Whether this contact is owed a handshake from this host (PACT sec. 9.2, "Import, and the
-- handshake"). An import writes its contacts pre-recognised, but the peers they name have never
-- heard from THIS host: once the identity's next leaf is installed here, each non-blocked one is
-- sent update_contact, or request_contact when it refuses that. The mark is set by the import and
-- cleared by the campaign when the contact has been told; nothing else writes it.
ALTER TABLE contacts ADD COLUMN handshake_due INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE contacts DROP COLUMN handshake_due;

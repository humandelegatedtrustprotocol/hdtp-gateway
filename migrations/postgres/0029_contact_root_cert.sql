-- +goose Up
-- HDTP 1.0 (HDTP sec. 13.2): the chain travels ONCE. After that a contact sends its
-- leaf fingerprint and nothing else, so the root certificate that named this contact
-- exists nowhere on the host once the envelope that carried it is gone - the pin keeps
-- only the root's FINGERPRINT. A node can still check an arriving chain (the root is
-- inside it), but it cannot prove a stored leaf on its own, and an archive taken here
-- could prove none of its contacts on a return. The cloud added the same column in its
-- identity migration 1003; this is the node's half of it.
ALTER TABLE contacts ADD COLUMN root_cert BYTEA;
ALTER TABLE pending_addresses ADD COLUMN root_cert BYTEA;

-- +goose Down
ALTER TABLE pending_addresses DROP COLUMN root_cert;
ALTER TABLE contacts DROP COLUMN root_cert;

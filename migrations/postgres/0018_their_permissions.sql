-- +goose Up
-- PACT §6.2: `contact_accepted` carries the peer's post-approval card AND the
-- permissions they granted US. Both were being discarded — the handler decoded
-- only the card and the manager ignored even that — so an agent had no way to
-- know what it may call on a contact except by probing.
ALTER TABLE contacts ADD COLUMN their_permissions TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE contacts DROP COLUMN their_permissions;

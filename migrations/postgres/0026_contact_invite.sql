-- +goose Up
-- Which invite admitted this contact. A pending request that arrived through
-- an invite carries that invite's id, so the owner approving it can see "via
-- Pune conference 2026" instead of a bare fingerprint; a cold request_contact
-- or an owner-initiated add carries none. The id, not the label: labels stay
-- live on the invite row (invites are revoked, never deleted), and an
-- unlabeled invite is still "via an invite", which a cold caller is not.
ALTER TABLE contacts ADD COLUMN invite_id TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE contacts DROP COLUMN invite_id;

-- name: InsertContact :exec
INSERT INTO contacts (id, account_id, fingerprint, spki, status, preset, permissions, display_name, card, created_at, pinned_at, invite_id, protocol, endpoint, leaf, chain_sent_kid)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetContact :one
SELECT * FROM contacts WHERE account_id = ? AND fingerprint = ?;

-- name: ListContacts :many
SELECT * FROM contacts WHERE account_id = ? ORDER BY created_at, id;

-- name: UpdateContactStatus :execrows
UPDATE contacts SET status = ? WHERE account_id = ? AND fingerprint = ?;

-- name: UpdateContactPermissions :execrows
UPDATE contacts SET permissions = ?, preset = ? WHERE account_id = ? AND fingerprint = ?;

-- name: DeleteContact :execrows
DELETE FROM contacts WHERE account_id = ? AND fingerprint = ?;

-- name: UpdateContactTrust :execrows
UPDATE contacts SET trust_flag = ? WHERE account_id = ? AND fingerprint = ?;

-- name: UpdateContactCard :execrows
-- The periodic contact sync's write: a re-fetched card whose signature
-- verified under the PINNED key. The key itself never moves here - rotation
-- is update_contact's job - so only the card text and the display name change.
UPDATE contacts SET card = ?, display_name = ? WHERE account_id = ? AND fingerprint = ?;

-- name: UpdateContactPetname :execrows
-- The owner's own name for a contact. Local by construction: no peer surface
-- reaches it, which is the point - display_name is the contact's own claim.
UPDATE contacts SET petname = ? WHERE account_id = ? AND fingerprint = ?;

-- name: SetContactAccepted :execrows
UPDATE contacts SET status = 'active', card = ?, their_permissions = ?, pinned_at = ?
WHERE account_id = ? AND fingerprint = ?;

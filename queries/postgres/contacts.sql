-- name: InsertContact :exec
INSERT INTO contacts (id, account_id, fingerprint, spki, status, preset, permissions, display_name, card, created_at, pinned_at, invite_id, protocol, endpoint, leaf, chain_sent_kid)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16);

-- name: GetContact :one
SELECT * FROM contacts WHERE account_id = $1 AND fingerprint = $2;

-- name: ListContacts :many
SELECT * FROM contacts WHERE account_id = $1 ORDER BY created_at, id;

-- name: UpdateContactStatus :execrows
UPDATE contacts SET status = $1 WHERE account_id = $2 AND fingerprint = $3;

-- name: UpdateContactPermissions :execrows
UPDATE contacts SET permissions = $1, preset = $2 WHERE account_id = $3 AND fingerprint = $4;

-- name: DeleteContact :execrows
DELETE FROM contacts WHERE account_id = $1 AND fingerprint = $2;

-- name: UpdateContactTrust :execrows
UPDATE contacts SET trust_flag = $1 WHERE account_id = $2 AND fingerprint = $3;

-- name: UpdateContactCard :execrows
-- The periodic contact sync's write: a re-fetched card whose signature
-- verified under the PINNED key. The key itself never moves here - rotation
-- is update_contact's job - so only the card text and the display name change.
UPDATE contacts SET card = $1, display_name = $2 WHERE account_id = $3 AND fingerprint = $4;

-- name: UpdateContactPetname :execrows
-- The owner's own name for a contact. Local by construction: no peer surface
-- reaches it, which is the point - display_name is the contact's own claim.
UPDATE contacts SET petname = $1 WHERE account_id = $2 AND fingerprint = $3;

-- name: SetContactAccepted :execrows
UPDATE contacts SET status = 'active', card = $1, their_permissions = $2, pinned_at = $3
WHERE account_id = $4 AND fingerprint = $5;

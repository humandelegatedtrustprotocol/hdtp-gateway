-- name: InsertContact :exec
INSERT INTO contacts (id, account_id, fingerprint, spki, status, preset, permissions, display_name, card, created_at, pinned_at, invite_id, endpoint, leaf, chain_sent_kid, root_cert, ever_active)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17);

-- name: GetContact :one
SELECT * FROM contacts WHERE account_id = $1 AND fingerprint = $2;

-- name: ListContacts :many
SELECT * FROM contacts WHERE account_id = $1 ORDER BY created_at, id;

-- name: UpdateContactStatus :execrows
-- Moving a row to active records that it was ever active (migration 0039); nothing clears it.
UPDATE contacts SET status = $1,
    ever_active = CASE WHEN $1 = 'active' THEN 1 ELSE ever_active END
WHERE account_id = $2 AND fingerprint = $3;

-- name: MoveContactStatus :execrows
-- The owner's decisions (approve, reject, block, unblock): the move happens only from the status
-- the decision was taken on, so a row that changed between the read and this write (a redeem over
-- a pending request, the expiry sweep) is not overwritten. Zero rows means it changed.
UPDATE contacts SET status = $1,
    ever_active = CASE WHEN $1 = 'active' THEN 1 ELSE ever_active END
WHERE account_id = $2 AND fingerprint = $3 AND status = $4;

-- name: DeleteContactInStatus :execrows
-- Unblock's forget: only while the row is still the blocked row the decision read.
DELETE FROM contacts WHERE account_id = $1 AND fingerprint = $2 AND status = $3;

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
UPDATE contacts SET status = 'active', ever_active = 1, card = $1, their_permissions = $2, pinned_at = $3
WHERE account_id = $4 AND fingerprint = $5;

-- name: ImportContact :exec
-- A contact arriving in an export (SPEC sec. 3.10): every column an export carries, in one
-- statement, and none it does not. invite_id stays empty because invites do not travel, and
-- chain_sent_kid stays empty because it records which of THIS host's leaves the contact has
-- seen - and this host has not been issued one yet.
INSERT INTO contacts (id, account_id, fingerprint, spki, status, preset, permissions, their_permissions, trust_flag, display_name, petname, card, created_at, pinned_at, endpoint, leaf, root_cert, ever_active)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18);

-- name: RedeemOverPendingContact :execrows
-- A request still awaiting the owner (pending_in) redeems one of the owner's invites: the row
-- takes the invite's status and grant and the pin this call proved (a sealed call proves no root
-- certificate, and then the one held is kept). Guarded by the status it expects, so a row the
-- owner decided on meanwhile is not overwritten.
UPDATE contacts SET status = $1,
    ever_active = CASE WHEN $1 = 'active' THEN 1 ELSE ever_active END,
    preset = $2, permissions = $3, invite_id = $4,
    display_name = $5, card = $6, spki = $7,
    endpoint = $8, leaf = $9, root_cert = COALESCE($10, root_cert)
WHERE account_id = $11 AND fingerprint = $12 AND status = 'pending_in';

-- name: DeleteExpiredPendingContacts :many
-- An unanswered request, ours or theirs, expires (SPEC sec. 9.1): the relationship returns to
-- none. The status is in the statement, so a request approved between a read and this delete
-- is not the one removed.
DELETE FROM contacts
WHERE account_id = $1 AND status IN ('pending_in', 'pending_out') AND created_at < $2
RETURNING fingerprint, status;

-- name: InsertContact :exec
-- requested_at is the row's created_at when it is inserted as a request (pending_in, pending_out)
-- and NULL otherwise (migration 0043).
INSERT INTO contacts (id, account_id, fingerprint, spki, status, preset, permissions, display_name, card, created_at, pinned_at, invite_id, endpoint, leaf, chain_sent_kid, root_cert, ever_active, requested_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18);

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
-- seen - and this host has not been issued one yet. handshake_due is the time of the import: the
-- contact is owed this host's handshake from the first leaf requested after it (sec. 9.2,
-- migration 0043). requested_at is created_at for a row the file carries as pending_out.
INSERT INTO contacts (id, account_id, fingerprint, spki, status, preset, permissions, their_permissions, trust_flag, display_name, petname, card, created_at, pinned_at, endpoint, leaf, root_cert, ever_active, handshake_due, requested_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20);

-- name: ImportContactPin :execrows
-- An import merging into an identity this host already holds (SPEC sec. 3.10, PACT sec. 9.2):
-- a contact held with no leaf takes the pin a file carries - the endpoint, and the leaf that
-- validated there - and is owed this host's handshake, from the time of the import. A contact held WITH a leaf is never
-- written: a pin this host validated itself is not replaced by one from a file (sec. 14.5).
UPDATE contacts SET endpoint = $1, leaf = $2, spki = $3, root_cert = COALESCE($4, root_cert), handshake_due = $5
WHERE account_id = $6 AND fingerprint = $7 AND (leaf IS NULL OR octet_length(leaf) = 0);

-- name: ClearContactHandshake :execrows
-- The campaign has told this contact: it is owed nothing more (sec. 9.2).
UPDATE contacts SET handshake_due = 0 WHERE account_id = $1 AND fingerprint = $2;

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
-- is not the one removed. The window runs from requested_at, when the request was made (migration
-- 0043), not from when the contact was first known.
DELETE FROM contacts
WHERE account_id = $1 AND status IN ('pending_in', 'pending_out') AND requested_at < $2
RETURNING fingerprint, status;

-- name: MarkContactRequested :execrows
-- The handshake after an import falls back to request_contact (PACT sec. 9.2): the contact becomes
-- an approach of ours BEFORE the request is sent, so a peer that answers at once finds the
-- pending_out its contact_accepted answers. Guarded by the status the campaign read. The request
-- clock starts now; ever_active is left as it was.
UPDATE contacts SET status = 'pending_out', requested_at = $1
WHERE account_id = $2 AND fingerprint = $3 AND status = $4;

-- name: TakeBackContactRequest :execrows
-- A request that did not reach the peer, or that the peer refused, is taken back: the row returns
-- to the status and the request clock it had. Only while it is still the approach that was marked.
UPDATE contacts SET status = $1, requested_at = $2
WHERE account_id = $3 AND fingerprint = $4 AND status = 'pending_out' AND requested_at = $5;

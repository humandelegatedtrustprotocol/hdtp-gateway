-- name: InsertInvite :exec
INSERT INTO invites (id, account_id, token_hash, expires_at, max_uses, auto_accept, preset, permissions, label, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetInviteByHash :one
SELECT * FROM invites WHERE account_id = ? AND token_hash = ?;

-- name: ListInvites :many
SELECT * FROM invites WHERE account_id = ? ORDER BY created_at, id;

-- name: ConsumeInviteUse :execrows
UPDATE invites SET uses = uses + 1
WHERE id = ? AND revoked_at IS NULL AND uses < max_uses AND expires_at > ?;

-- name: RevokeInvite :execrows
UPDATE invites SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL;


-- name: GetInviteByHashGlobal :one
SELECT * FROM invites WHERE token_hash = ?;

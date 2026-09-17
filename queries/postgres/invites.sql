-- name: InsertInvite :exec
INSERT INTO invites (id, account_id, token_hash, expires_at, max_uses, auto_accept, preset, permissions, label, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetInviteByHash :one
SELECT * FROM invites WHERE account_id = $1 AND token_hash = $2;

-- name: ListInvites :many
SELECT * FROM invites WHERE account_id = $1 ORDER BY created_at, id;

-- name: ConsumeInviteUse :execrows
UPDATE invites SET uses = uses + 1
WHERE id = $1 AND revoked_at IS NULL AND uses < max_uses AND expires_at > $2;

-- name: RevokeInvite :execrows
UPDATE invites SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL;


-- name: GetInviteByHashGlobal :one
SELECT * FROM invites WHERE token_hash = $1;

-- name: InsertChange :one
INSERT INTO changes (account_id, kind, thread_id, contact_fpr, ref, at)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: ChangesAfter :many
SELECT * FROM changes WHERE id > ? ORDER BY id LIMIT ?;

-- name: AccountChangesAfter :many
SELECT * FROM changes WHERE account_id = ? AND id > ? ORDER BY id LIMIT ?;

-- name: LastChangeID :one
SELECT CAST(COALESCE(MAX(id), 0) AS INTEGER) AS id FROM changes;

-- name: OldestChangeID :one
SELECT CAST(COALESCE(MIN(id), 0) AS INTEGER) AS id FROM changes;

-- name: DeleteChangesBefore :execrows
DELETE FROM changes WHERE at < ?;

-- name: DeleteChangesByAccount :execrows
-- An identity leaving (PACT sec. 9): its changes go with it.
DELETE FROM changes WHERE account_id = ?;

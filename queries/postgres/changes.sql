-- name: LockChanges :exec
-- Taken before every insert, in its transaction: ids commit in the order they are assigned, so a
-- reader past id N never misses a row a slower transaction commits later below it. A key outside
-- int4, beside LockAuditChain's.
SELECT pg_advisory_xact_lock(7152101200000012);

-- name: InsertChange :one
INSERT INTO changes (account_id, kind, thread_id, contact_fpr, ref, at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id;

-- name: NotifyChanges :exec
-- Sent in the inserting transaction, so it is delivered at commit: a wake for the processes
-- that LISTEN (ListenChanges). Polling finds the row whether or not the wake arrives.
SELECT pg_notify('hdtp_changes', '');

-- name: ListenChanges :exec
LISTEN hdtp_changes;

-- name: ChangesAfter :many
SELECT * FROM changes WHERE id > $1 ORDER BY id LIMIT $2;

-- name: AccountChangesAfter :many
SELECT * FROM changes WHERE account_id = $1 AND id > $2 ORDER BY id LIMIT $3;

-- name: LastChangeID :one
SELECT COALESCE(MAX(id), 0)::BIGINT AS id FROM changes;

-- name: OldestChangeID :one
SELECT COALESCE(MIN(id), 0)::BIGINT AS id FROM changes;

-- name: DeleteChangesBefore :execrows
DELETE FROM changes WHERE at < $1;

-- name: DeleteChangesByAccount :execrows
-- An identity leaving (HDTP sec. 9): its changes go with it.
DELETE FROM changes WHERE account_id = $1;

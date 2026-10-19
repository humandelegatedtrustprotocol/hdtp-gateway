-- Owner asks and notices (internal/services/asks). Every statement is scoped to the account the
-- caller acts for, but the expiry sweep's, which reads every account's due asks.

-- name: InsertOwnerAsk :execrows
-- 0 rows, and nothing written, when the account already has this ask or notice about the message,
-- or the thread already has an open ask: the unique keys say which, read after.
INSERT INTO owner_asks (id, account_id, kind, thread_id, contact_fpr, for_msg_id, surface, status, created_at, updated_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT DO NOTHING;

-- name: GetOwnerAsk :one
SELECT * FROM owner_asks WHERE account_id = $1 AND id = $2;

-- name: GetOwnerAskFor :one
-- The ask or notice already written about one message: what a retry of the same call finds.
SELECT * FROM owner_asks WHERE account_id = $1 AND kind = $2 AND thread_id = $3 AND for_msg_id = $4;

-- name: GetOpenOwnerAsk :one
-- The thread's open ask, if it has one (owner_asks_open_thread allows one).
SELECT * FROM owner_asks WHERE account_id = $1 AND thread_id = $2 AND kind = 'ask' AND status = 'open';

-- name: ListOwnerAsks :many
-- The account's asks and notices, newest first.
SELECT * FROM owner_asks WHERE account_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2;

-- name: ListOpenOwnerAsks :many
-- The account's open asks, newest first: what Needs you shows.
SELECT * FROM owner_asks WHERE account_id = $1 AND kind = 'ask' AND status = 'open' ORDER BY created_at DESC, id DESC LIMIT $2;

-- name: ListContactOwnerAsks :many
-- The asks and notices of every thread with one contact, oldest first: what the conversation shows.
SELECT * FROM owner_asks WHERE account_id = $1 AND contact_fpr = $2 ORDER BY created_at, id LIMIT $3;

-- name: CountOpenOwnerAsks :one
SELECT COUNT(*) FROM owner_asks WHERE account_id = $1 AND kind = 'ask' AND status = 'open' AND expires_at > $2;

-- name: CloseOwnerAsk :execrows
-- An open ask, answered or withdrawn before it expired. One that is no longer open, or whose time
-- has come, changes nothing: 0 rows.
UPDATE owner_asks SET status = $1, answer_text = $2, updated_at = $3
WHERE account_id = $4 AND id = $5 AND kind = 'ask' AND status = 'open' AND expires_at > $6;

-- name: ExpireOwnerAsk :execrows
-- An open ask whose time has come. One already closed changes nothing: 0 rows.
UPDATE owner_asks SET status = 'expired', updated_at = $1
WHERE account_id = $2 AND id = $3 AND kind = 'ask' AND status = 'open' AND expires_at <= $4;

-- name: ListDueOwnerAsks :many
-- Open asks whose time has come, in every account, oldest first: what the expiry sweep closes.
SELECT * FROM owner_asks WHERE status = 'open' AND expires_at <= $1 ORDER BY expires_at, id LIMIT $2;

-- name: DeleteThreadOwnerAsks :execrows
-- A deleted thread's asks and notices go with it.
DELETE FROM owner_asks WHERE account_id = $1 AND thread_id = $2;

-- name: DeleteOrphanOwnerAsks :execrows
-- Asks and notices whose thread retention deleted for being empty.
DELETE FROM owner_asks WHERE owner_asks.account_id = $1
  AND NOT EXISTS (SELECT 1 FROM threads t WHERE t.account_id = owner_asks.account_id AND t.id = owner_asks.thread_id);

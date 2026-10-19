-- Owner asks and notices (internal/services/asks). Every statement is scoped to the account the
-- caller acts for, but the expiry sweep's, which reads every account's due asks.

-- name: InsertOwnerAsk :execrows
-- 0 rows, and nothing written, when the account already has this ask or notice about the message,
-- or the thread already has an open ask: the unique keys say which, read after.
INSERT INTO owner_asks (id, account_id, kind, thread_id, contact_fpr, for_msg_id, surface, status, created_at, updated_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT DO NOTHING;

-- name: GetOwnerAsk :one
SELECT * FROM owner_asks WHERE account_id = ? AND id = ?;

-- name: GetOwnerAskFor :one
-- The ask or notice already written about one message: what a retry of the same call finds.
SELECT * FROM owner_asks WHERE account_id = ? AND kind = ? AND thread_id = ? AND for_msg_id = ?;

-- name: GetOpenOwnerAsk :one
-- The thread's open ask, if it has one (owner_asks_open_thread allows one).
SELECT * FROM owner_asks WHERE account_id = ? AND thread_id = ? AND kind = 'ask' AND status = 'open';

-- name: GetContactOpenOwnerAsk :one
-- The newest open ask of any thread with one contact: the one a message the owner writes to them
-- answers.
SELECT * FROM owner_asks WHERE account_id = ? AND contact_fpr = ? AND kind = 'ask' AND status = 'open'
ORDER BY created_at DESC, id DESC LIMIT 1;

-- name: ListOwnerAsks :many
-- The account's asks and notices, newest first.
SELECT * FROM owner_asks WHERE account_id = ? ORDER BY created_at DESC, id DESC LIMIT ?;

-- name: ListOpenOwnerAsks :many
-- The account's open asks, newest first: what Needs you shows.
SELECT * FROM owner_asks WHERE account_id = ? AND kind = 'ask' AND status = 'open' ORDER BY created_at DESC, id DESC LIMIT ?;

-- name: ListContactOwnerAsks :many
-- The asks and notices of every thread with one contact, oldest first: what the conversation shows.
SELECT * FROM owner_asks WHERE account_id = ? AND contact_fpr = ? ORDER BY created_at, id LIMIT ?;

-- name: CountOpenOwnerAsks :one
SELECT COUNT(*) FROM owner_asks WHERE account_id = ? AND kind = 'ask' AND status = 'open' AND expires_at > ?;

-- name: CloseOwnerAsk :execrows
-- An open ask, answered or withdrawn before it expired. One that is no longer open, or whose time
-- has come, changes nothing: 0 rows.
UPDATE owner_asks SET status = ?, answer_text = ?, updated_at = ?
WHERE account_id = ? AND id = ? AND kind = 'ask' AND status = 'open' AND expires_at > ?;

-- name: ExpireOwnerAsk :execrows
-- An open ask whose time has come. One already closed changes nothing: 0 rows.
UPDATE owner_asks SET status = 'expired', updated_at = ?
WHERE account_id = ? AND id = ? AND kind = 'ask' AND status = 'open' AND expires_at <= ?;

-- name: ListDueOwnerAsks :many
-- Open asks whose time has come, in every account, oldest first: what the expiry sweep closes.
SELECT * FROM owner_asks WHERE status = 'open' AND expires_at <= ? ORDER BY expires_at, id LIMIT ?;

-- name: DeleteThreadOwnerAsks :execrows
-- A deleted thread's asks and notices go with it.
DELETE FROM owner_asks WHERE account_id = ? AND thread_id = ?;

-- name: DeleteOrphanOwnerAsks :execrows
-- Asks and notices whose thread retention deleted for being empty.
DELETE FROM owner_asks WHERE owner_asks.account_id = ?
  AND NOT EXISTS (SELECT 1 FROM threads t WHERE t.account_id = owner_asks.account_id AND t.id = owner_asks.thread_id);

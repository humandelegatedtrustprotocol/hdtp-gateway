-- name: InsertThread :exec
INSERT INTO threads (id, account_id, contact_fpr, topic, created_at, last_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetThread :one
SELECT * FROM threads WHERE account_id = ? AND id = ?;

-- name: TouchThread :exec
UPDATE threads SET last_at = ? WHERE account_id = ? AND id = ?;

-- name: InsertMessage :exec
INSERT INTO messages (id, account_id, contact_fpr, msg_id, thread_id, direction, sender, kind, body, reply_to, status, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetMessageByMsgID :one
SELECT * FROM messages WHERE account_id = ? AND contact_fpr = ? AND direction = ? AND msg_id = ?;

-- name: ListMessagesByThread :many
SELECT * FROM messages WHERE account_id = ? AND thread_id = ? ORDER BY seq;

-- name: InsertBlob :exec
INSERT INTO blobs (account_id, hash, size, mime, filename, created_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetBlob :one
SELECT * FROM blobs WHERE account_id = ? AND hash = ?;

-- name: SumBlobBytes :one
SELECT COALESCE(SUM(size), 0) FROM blobs WHERE account_id = ?;

-- name: ListThreadsByAccount :many
SELECT * FROM threads WHERE account_id = ? ORDER BY last_at DESC, id;

-- name: UnreadCount :one
SELECT COUNT(*) FROM messages m JOIN threads t ON t.account_id = m.account_id AND t.id = m.thread_id
WHERE m.account_id = ? AND m.thread_id = ? AND m.direction = 'in' AND m.seq > t.last_read_seq;

-- name: MarkThreadRead :execrows
UPDATE threads SET last_read_seq = (
  SELECT COALESCE(MAX(m.seq), 0) FROM messages m WHERE m.account_id = ? AND m.thread_id = ?
) WHERE threads.account_id = ? AND threads.id = ?;

-- name: DeleteMessagesBefore :execrows
DELETE FROM messages WHERE account_id = ? AND created_at < ?;

-- name: DeleteEmptyThreads :execrows
DELETE FROM threads WHERE account_id = ?
  AND id NOT IN (SELECT thread_id FROM messages WHERE account_id = ?);

-- name: ListBlobs :many
SELECT * FROM blobs WHERE account_id = ? ORDER BY created_at;

-- name: DeleteBlob :execrows
DELETE FROM blobs WHERE account_id = ? AND hash = ?;

-- name: CountBlobRefs :one
SELECT COUNT(*) FROM blobs WHERE hash = ?;

-- SetMessageStatus records what became of a message AFTER it was written. It is
-- scoped to direction='out' on purpose: only a message we sent has a delivery
-- outcome, and without the scope an outbound msg_id colliding with an inbound
-- one rewrote the peer's row instead.
-- name: SetMessageStatus :execrows
UPDATE messages SET status = ? WHERE account_id = ? AND contact_fpr = ? AND msg_id = ? AND direction = 'out';

-- SetMessageAttempt records that a delivery attempt was made and when the next
-- one is due. Backoff is a function of attempts MADE, so the count has to
-- survive the sweep that made it.
-- name: SetMessageAttempt :execrows
UPDATE messages SET attempts = ?, next_attempt_at = ?
WHERE account_id = ? AND contact_fpr = ? AND msg_id = ? AND direction = 'out';

-- ListPendingOutbound is the retry sweeper's work list (SPEC §7.1): outbound
-- messages still awaiting delivery, oldest first.
-- name: ListPendingOutbound :many
SELECT seq, id, account_id, contact_fpr, msg_id, thread_id, direction, sender, kind, body, reply_to, status, created_at, expires_at, attempts, next_attempt_at
FROM messages WHERE direction = 'out' AND status = 'pending' ORDER BY seq LIMIT ?;

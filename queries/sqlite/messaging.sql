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

-- name: MarkThreadReadThrough :execrows
-- The read marker is a high-water mark, never lowered: a reader marks through the newest message
-- it was shown (`through`), so what arrived after it stays unread, and marking again
-- changes nothing.
UPDATE threads SET last_read_seq = ?
WHERE account_id = ? AND id = ? AND last_read_seq < ?;

-- name: MarkConversationReadThrough :execrows
-- Every thread with one contact, through one message: a conversation is with a person, not a
-- thread id, and seq is one sequence over every message, so every message of the conversation
-- at or below `through` was on the page the reader was shown.
UPDATE threads SET last_read_seq = ?
WHERE account_id = ? AND contact_fpr = ? AND last_read_seq < ?;

-- name: ConversationHasMessage :one
-- Whether `seq` is a message of this account's conversation with this contact: what a read
-- marker may name. Another identity's message, or one of another contact, is not.
SELECT COUNT(*) FROM messages m JOIN threads t ON t.account_id = m.account_id AND t.id = m.thread_id
WHERE m.account_id = ? AND t.contact_fpr = ? AND m.seq = ?;

-- name: UnreadWithContactUpTo :one
-- A conversation's unread, counted no further than a bound: the inbox reads it for every
-- row of a page on every visit, so it stops at a bound instead of walking every unread message.
SELECT COUNT(*) FROM (
  SELECT 1 FROM threads t JOIN messages m ON m.account_id = t.account_id AND m.thread_id = t.id
  WHERE t.account_id = ? AND t.contact_fpr = ?
    AND m.direction = 'in' AND m.seq > t.last_read_seq
  LIMIT ?
) AS u;

-- name: ListContactsWithUnread :many
-- The contacts with at least one unread message, never a count: for each thread, messages_thread
-- is walked from the thread's marker until the first inbound message, past any of ours.
SELECT DISTINCT t.contact_fpr FROM threads t
WHERE t.account_id = ? AND EXISTS (
  SELECT 1 FROM messages m
  WHERE m.account_id = t.account_id AND m.thread_id = t.id AND m.direction = 'in' AND m.seq > t.last_read_seq
)
ORDER BY t.contact_fpr;

-- name: DeleteMessagesBefore :execrows
DELETE FROM messages WHERE account_id = ? AND created_at < ?;

-- name: DeleteEmptyThreads :execrows
-- One index probe per thread. As a NOT IN over the account's messages it listed the thread of
-- every message the account has before it looked at a single thread.
DELETE FROM threads WHERE threads.account_id = ?
  AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.account_id = threads.account_id AND m.thread_id = threads.id);

-- name: ListMediaBodies :many
-- What retention reads to learn which media is still referenced: the media messages, and only
-- those, from `messages_media`. It used to be learned by reading every message of every thread.
SELECT body FROM messages WHERE account_id = ? AND kind = 'media' ORDER BY seq;

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

-- ListPendingOutbound is the retry sweeper's work list (SPEC sec. 7.1): outbound
-- messages still awaiting delivery, oldest first.
-- name: ListPendingOutbound :many
SELECT seq, id, account_id, contact_fpr, msg_id, thread_id, direction, sender, kind, body, reply_to, status, created_at, expires_at, attempts, next_attempt_at
FROM messages WHERE direction = 'out' AND status = 'pending' ORDER BY seq LIMIT ?;

-- name: ImportThread :execrows
-- A thread arriving in an export (SPEC sec. 3.10). One already here, by id, is left as it is:
-- importing into an identity this host already holds adds what it lacks and changes nothing else.
INSERT INTO threads (id, account_id, contact_fpr, topic, created_at, last_at) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT DO NOTHING;

-- name: ImportMessage :execrows
-- A message arriving in an export, with no retry schedule (it was the old host's to deliver).
-- One already here, by id or by its sender's msg_id, is left as it is.
INSERT INTO messages (id, account_id, contact_fpr, msg_id, thread_id, direction, sender, kind, body, reply_to, status, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT DO NOTHING;

-- name: ImportBlob :execrows
-- The record of a file arriving in an export. One already here, by hash, is left as it is.
INSERT INTO blobs (account_id, hash, size, mime, filename, created_at) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT DO NOTHING;

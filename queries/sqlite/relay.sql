-- name: SyncRelayAllow :exec
INSERT INTO relay_allowlist (recipient_fpr, sender_fpr, updated_at) VALUES (?, ?, ?)
ON CONFLICT (recipient_fpr, sender_fpr) DO UPDATE SET updated_at = excluded.updated_at;

-- name: ClearRelayAllow :execrows
DELETE FROM relay_allowlist WHERE recipient_fpr = ?;

-- name: RelayAllowed :one
SELECT COUNT(*) FROM relay_allowlist WHERE recipient_fpr = ? AND sender_fpr = ?;

-- name: EnqueueRelay :exec
INSERT INTO relay_queue (id, recipient_fpr, sender_fpr, msg_id, envelope, size_bytes, queued_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: FetchRelayQueue :many
SELECT * FROM relay_queue WHERE recipient_fpr = ? AND expires_at > ? ORDER BY queued_at, id LIMIT ?;

-- name: CountRelayQueue :one
SELECT COUNT(*) FROM relay_queue WHERE recipient_fpr = ? AND expires_at > ?;

-- name: RelayQueueUsage :one
-- What one recipient's queue holds right now, for the §9 quota check: items
-- and bytes in one read, expired items self-excluded.
SELECT COUNT(*) AS items, COALESCE(SUM(size_bytes), 0) AS bytes
FROM relay_queue WHERE recipient_fpr = ? AND expires_at > ?;

-- name: AckRelay :execrows
DELETE FROM relay_queue WHERE id = ? AND recipient_fpr = ?;

-- name: PurgeExpiredRelay :execrows
DELETE FROM relay_queue WHERE expires_at <= ?;

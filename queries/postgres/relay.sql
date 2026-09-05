-- name: SyncRelayAllow :exec
INSERT INTO relay_allowlist (recipient_fpr, sender_fpr, updated_at) VALUES ($1, $2, $3)
ON CONFLICT (recipient_fpr, sender_fpr) DO UPDATE SET updated_at = EXCLUDED.updated_at;

-- name: ClearRelayAllow :execrows
DELETE FROM relay_allowlist WHERE recipient_fpr = $1;

-- name: RelayAllowed :one
SELECT COUNT(*) FROM relay_allowlist WHERE recipient_fpr = $1 AND sender_fpr = $2;

-- name: EnqueueRelay :exec
INSERT INTO relay_queue (id, recipient_fpr, sender_fpr, msg_id, envelope, size_bytes, queued_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: FetchRelayQueue :many
SELECT * FROM relay_queue WHERE recipient_fpr = $1 AND expires_at > $2 ORDER BY queued_at, id LIMIT $3;

-- name: CountRelayQueue :one
SELECT COUNT(*) FROM relay_queue WHERE recipient_fpr = $1 AND expires_at > $2;

-- name: RelayQueueUsage :one
-- What one recipient's queue holds right now, for the §9 quota check: items
-- and bytes in one read, expired items self-excluded.
SELECT COUNT(*) AS items, COALESCE(SUM(size_bytes), 0)::bigint AS bytes
FROM relay_queue WHERE recipient_fpr = $1 AND expires_at > $2;

-- name: AckRelay :execrows
DELETE FROM relay_queue WHERE id = $1 AND recipient_fpr = $2;

-- name: PurgeExpiredRelay :execrows
DELETE FROM relay_queue WHERE expires_at <= $1;
